use anyhow::{Context, Result};
use colored::*;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

use crate::analyzer::{DockerComposeAnalysis, DockerComposeAnalyzer};
use crate::converter::{KubernetesConverter, KubernetesManifests};
use crate::cost::CostEstimator;
use crate::patterns::PatternDetector;
use crate::security::SecurityScanner;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WizardConfiguration {
    pub docker_compose_path: PathBuf,
    pub output_directory: PathBuf,
    pub deployment_target: DeploymentTarget,
    pub environment_type: EnvironmentType,
    pub scaling_preferences: ScalingPreferences,
    pub security_level: SecurityLevel,
    pub monitoring_enabled: bool,
    pub backup_enabled: bool,
    pub ssl_enabled: bool,
    pub ingress_enabled: bool,
    pub custom_domain: Option<String>,
    pub cloud_provider: CloudProvider,
    pub resource_budget: ResourceBudget,
    pub advanced_features: Vec<AdvancedFeature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeploymentTarget {
    Development,
    Staging,
    Production,
    Testing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnvironmentType {
    Local,
    Cloud,
    OnPremise,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingPreferences {
    pub enable_autoscaling: bool,
    pub min_replicas: u32,
    pub max_replicas: u32,
    pub target_cpu_percentage: u32,
    pub target_memory_percentage: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityLevel {
    Basic,
    Enhanced,
    Strict,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
    DigitalOcean,
    OnPremise,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceBudget {
    Minimal,
    Standard,
    Performance,
    Enterprise,
    Custom(CustomResourceBudget),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomResourceBudget {
    pub max_monthly_cost: f64,
    pub cpu_limit: String,
    pub memory_limit: String,
    pub storage_limit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdvancedFeature {
    ServiceMesh,
    Observability,
    ChaosEngineering,
    GitOps,
    SecretManagement,
    MultiCluster,
    EdgeComputing,
}

pub struct InteractiveWizard {
    analyzer: DockerComposeAnalyzer,
    converter: KubernetesConverter,
    pattern_detector: PatternDetector,
    security_scanner: SecurityScanner,
}

impl Default for InteractiveWizard {
    fn default() -> Self {
        Self::new()
    }
}

impl InteractiveWizard {
    pub fn new() -> Self {
        Self {
            analyzer: DockerComposeAnalyzer::new(),
            converter: KubernetesConverter::new(),
            pattern_detector: PatternDetector::new(),
            security_scanner: SecurityScanner::new(),
        }
    }

    pub async fn run(&self, input_path: Option<PathBuf>) -> Result<()> {
        self.print_welcome();

        let config = self.conduct_interview(input_path).await?;
        let analysis = self.analyzer.analyze(&config.docker_compose_path).await?;

        self.print_analysis_summary(&analysis)?;

        let patterns = self.pattern_detector.detect_patterns(&analysis)?;
        self.print_detected_patterns(&patterns);

        if self.should_perform_security_scan(&config) {
            let security_findings = self.security_scanner.scan(&analysis).await?;
            self.print_security_summary(&security_findings);
        }

        if self.should_estimate_costs(&config) {
            self.estimate_and_display_costs(&config, &analysis).await?;
        }

        let manifests = if config.deployment_target == DeploymentTarget::Production {
            self.converter
                .convert_with_production_patterns(&analysis, &patterns)
                .await?
        } else {
            self.converter.convert_basic(&analysis).await?
        };

        self.review_manifests(&config, &manifests).await?;

        self.save_configuration_and_manifests(&config, &manifests)
            .await?;

        self.print_completion_message(&config);

        Ok(())
    }

    fn print_welcome(&self) {
        println!(
            "{}",
            "🧙 Welcome to K8sify Interactive Wizard!".bold().blue()
        );
        println!("{}", "This wizard will guide you through converting your Docker Compose application to Kubernetes.".white());
        println!();
    }

    async fn conduct_interview(&self, input_path: Option<PathBuf>) -> Result<WizardConfiguration> {
        let mut config = WizardConfiguration {
            docker_compose_path: PathBuf::new(),
            output_directory: PathBuf::from("./k8s"),
            deployment_target: DeploymentTarget::Development,
            environment_type: EnvironmentType::Local,
            scaling_preferences: ScalingPreferences {
                enable_autoscaling: false,
                min_replicas: 1,
                max_replicas: 3,
                target_cpu_percentage: 70,
                target_memory_percentage: 80,
            },
            security_level: SecurityLevel::Basic,
            monitoring_enabled: false,
            backup_enabled: false,
            ssl_enabled: false,
            ingress_enabled: false,
            custom_domain: None,
            cloud_provider: CloudProvider::OnPremise,
            resource_budget: ResourceBudget::Standard,
            advanced_features: Vec::new(),
        };

        // Step 1: Docker Compose file
        config.docker_compose_path = if let Some(path) = input_path {
            path
        } else {
            let path: String = Input::new()
                .with_prompt("📁 Path to your docker-compose.yml file")
                .default("./docker-compose.yml".to_string())
                .interact_text()?;
            PathBuf::from(path)
        };

        // Validate file exists
        if !config.docker_compose_path.exists() {
            return Err(anyhow::anyhow!(
                "Docker Compose file not found: {:?}",
                config.docker_compose_path
            ));
        }

        // Step 2: Output directory
        let output: String = Input::new()
            .with_prompt("📂 Output directory for Kubernetes manifests")
            .default("./k8s".to_string())
            .interact_text()?;
        config.output_directory = PathBuf::from(output);

        // Step 3: Deployment target
        let target_options = vec!["Development", "Staging", "Production", "Testing"];
        let target_selection = Select::new()
            .with_prompt("🎯 What is your deployment target?")
            .default(0)
            .items(&target_options)
            .interact()?;

        config.deployment_target = match target_selection {
            0 => DeploymentTarget::Development,
            1 => DeploymentTarget::Staging,
            2 => DeploymentTarget::Production,
            3 => DeploymentTarget::Testing,
            _ => DeploymentTarget::Development,
        };

        // Step 4: Environment type
        let env_options = vec![
            "Local (minikube, kind)",
            "Cloud (EKS, GKE, AKS)",
            "On-Premise",
            "Hybrid",
        ];
        let env_selection = Select::new()
            .with_prompt("🌍 What type of Kubernetes environment?")
            .default(0)
            .items(&env_options)
            .interact()?;

        config.environment_type = match env_selection {
            0 => EnvironmentType::Local,
            1 => EnvironmentType::Cloud,
            2 => EnvironmentType::OnPremise,
            3 => EnvironmentType::Hybrid,
            _ => EnvironmentType::Local,
        };

        // Step 5: Cloud provider (if cloud environment)
        if matches!(
            config.environment_type,
            EnvironmentType::Cloud | EnvironmentType::Hybrid
        ) {
            let provider_options = vec![
                "AWS (EKS)",
                "Google Cloud (GKE)",
                "Azure (AKS)",
                "DigitalOcean",
            ];
            let provider_selection = Select::new()
                .with_prompt("☁️ Which cloud provider?")
                .default(0)
                .items(&provider_options)
                .interact()?;

            config.cloud_provider = match provider_selection {
                0 => CloudProvider::Aws,
                1 => CloudProvider::Gcp,
                2 => CloudProvider::Azure,
                3 => CloudProvider::DigitalOcean,
                _ => CloudProvider::Aws,
            };
        }

        // Step 6: Scaling preferences
        if matches!(
            config.deployment_target,
            DeploymentTarget::Staging | DeploymentTarget::Production
        ) {
            config.scaling_preferences.enable_autoscaling = Confirm::new()
                .with_prompt("📈 Enable horizontal pod autoscaling?")
                .default(true)
                .interact()?;

            if config.scaling_preferences.enable_autoscaling {
                config.scaling_preferences.min_replicas = Input::new()
                    .with_prompt("📊 Minimum number of replicas")
                    .default(2)
                    .interact()?;

                config.scaling_preferences.max_replicas = Input::new()
                    .with_prompt("📊 Maximum number of replicas")
                    .default(10)
                    .interact()?;

                config.scaling_preferences.target_cpu_percentage = Input::new()
                    .with_prompt("🎯 Target CPU utilization percentage")
                    .default(70)
                    .interact()?;
            }
        }

        // Step 7: Security level
        let security_options = vec![
            "Basic (default security)",
            "Enhanced (network policies, secrets)",
            "Strict (Pod Security Standards, RBAC)",
            "Custom (I'll configure manually)",
        ];
        let security_selection = Select::new()
            .with_prompt("🔒 Security level")
            .default(0)
            .items(&security_options)
            .interact()?;

        config.security_level = match security_selection {
            0 => SecurityLevel::Basic,
            1 => SecurityLevel::Enhanced,
            2 => SecurityLevel::Strict,
            3 => SecurityLevel::Custom,
            _ => SecurityLevel::Basic,
        };

        // Step 8: Additional features
        config.monitoring_enabled = Confirm::new()
            .with_prompt("📊 Enable monitoring and observability?")
            .default(matches!(
                config.deployment_target,
                DeploymentTarget::Production
            ))
            .interact()?;

        config.backup_enabled = Confirm::new()
            .with_prompt("💾 Enable automated backups?")
            .default(matches!(
                config.deployment_target,
                DeploymentTarget::Production
            ))
            .interact()?;

        config.ssl_enabled = Confirm::new()
            .with_prompt("🔐 Enable SSL/TLS certificates?")
            .default(matches!(
                config.deployment_target,
                DeploymentTarget::Staging | DeploymentTarget::Production
            ))
            .interact()?;

        config.ingress_enabled = Confirm::new()
            .with_prompt("🌐 Enable ingress controller for external access?")
            .default(true)
            .interact()?;

        if config.ingress_enabled && config.ssl_enabled {
            let domain: String = Input::new()
                .with_prompt("🌍 Custom domain (optional)")
                .allow_empty(true)
                .interact_text()?;

            if !domain.is_empty() {
                config.custom_domain = Some(domain);
            }
        }

        // Step 9: Resource budget
        let budget_options = vec![
            "Minimal (cost-optimized)",
            "Standard (balanced)",
            "Performance (high-performance)",
            "Enterprise (maximum availability)",
        ];
        let budget_selection = Select::new()
            .with_prompt("💰 Resource budget level")
            .default(1)
            .items(&budget_options)
            .interact()?;

        config.resource_budget = match budget_selection {
            0 => ResourceBudget::Minimal,
            1 => ResourceBudget::Standard,
            2 => ResourceBudget::Performance,
            3 => ResourceBudget::Enterprise,
            _ => ResourceBudget::Standard,
        };

        // Step 10: Advanced features
        if matches!(config.deployment_target, DeploymentTarget::Production) {
            let advanced_options = vec![
                "Service Mesh (Istio)",
                "Advanced Observability (Prometheus, Grafana)",
                "Chaos Engineering (Litmus)",
                "GitOps (ArgoCD)",
                "Secret Management (External Secrets)",
                "Multi-Cluster Support",
                "Edge Computing Support",
            ];

            let advanced_selections = MultiSelect::new()
                .with_prompt("🚀 Advanced features (optional)")
                .items(&advanced_options)
                .interact()?;

            for selection in advanced_selections {
                let feature = match selection {
                    0 => AdvancedFeature::ServiceMesh,
                    1 => AdvancedFeature::Observability,
                    2 => AdvancedFeature::ChaosEngineering,
                    3 => AdvancedFeature::GitOps,
                    4 => AdvancedFeature::SecretManagement,
                    5 => AdvancedFeature::MultiCluster,
                    6 => AdvancedFeature::EdgeComputing,
                    _ => continue,
                };
                config.advanced_features.push(feature);
            }
        }

        Ok(config)
    }

    fn print_analysis_summary(&self, analysis: &DockerComposeAnalysis) -> Result<()> {
        println!("{}", "📊 Analysis Summary".bold().blue());
        println!("Services: {}", analysis.services.len().to_string().yellow());
        println!("Volumes: {}", analysis.volumes.len().to_string().yellow());
        println!("Networks: {}", analysis.networks.len().to_string().yellow());
        println!(
            "Complexity Score: {}",
            analysis.complexity_score.to_string().red()
        );
        println!();

        Ok(())
    }

    fn print_detected_patterns(&self, patterns: &[crate::patterns::DetectedPattern]) {
        if !patterns.is_empty() {
            println!("{}", "🔍 Detected Patterns".bold().green());
            for pattern in patterns {
                println!(
                    "  {} {:?} (confidence: {:.1}%)",
                    "•".blue(),
                    pattern.pattern_type,
                    pattern.confidence * 100.0
                );
            }
            println!();
        }
    }

    fn print_security_summary(&self, findings: &crate::security::SecurityFindings) {
        println!("{}", "🔒 Security Scan Results".bold().red());
        println!("Critical: {}", findings.critical_count.to_string().red());
        println!("High: {}", findings.high_count.to_string().yellow());
        println!("Medium: {}", findings.medium_count.to_string().blue());
        println!("Low: {}", findings.low_count.to_string().green());
        println!();
    }

    fn should_perform_security_scan(&self, config: &WizardConfiguration) -> bool {
        !matches!(config.security_level, SecurityLevel::Basic)
            || matches!(config.deployment_target, DeploymentTarget::Production)
    }

    fn should_estimate_costs(&self, config: &WizardConfiguration) -> bool {
        matches!(
            config.environment_type,
            EnvironmentType::Cloud | EnvironmentType::Hybrid
        )
    }

    async fn estimate_and_display_costs(
        &self,
        config: &WizardConfiguration,
        analysis: &DockerComposeAnalysis,
    ) -> Result<()> {
        let progress = ProgressBar::new_spinner();
        progress.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.blue} {msg}")
                .unwrap(),
        );
        progress.set_message("Estimating costs...");
        progress.enable_steady_tick(Duration::from_millis(100));

        let provider = match config.cloud_provider {
            CloudProvider::Aws => "aws",
            CloudProvider::Gcp => "gcp",
            CloudProvider::Azure => "azure",
            CloudProvider::DigitalOcean => "digitalocean",
            CloudProvider::OnPremise => "on-premise",
        };

        let cost_estimator = CostEstimator::new(provider, "us-east-1");
        let estimate = cost_estimator.estimate_costs(analysis).await?;

        progress.finish_and_clear();

        println!("{}", "💰 Cost Estimation".bold().yellow());
        cost_estimator.print_cost_breakdown(&estimate)?;
        println!();

        Ok(())
    }

    pub async fn review_conversion(&self, manifests: &KubernetesManifests) -> Result<()> {
        println!("{}", "📋 Conversion Review".bold().blue());
        println!("Generated manifests:");
        println!(
            "  Deployments: {}",
            manifests.deployments.len().to_string().yellow()
        );
        println!(
            "  Services: {}",
            manifests.services.len().to_string().yellow()
        );
        println!(
            "  ConfigMaps: {}",
            manifests.config_maps.len().to_string().yellow()
        );
        println!(
            "  Secrets: {}",
            manifests.secrets.len().to_string().yellow()
        );
        println!(
            "  PVCs: {}",
            manifests
                .persistent_volume_claims
                .len()
                .to_string()
                .yellow()
        );
        println!(
            "  Ingress: {}",
            manifests.ingress.len().to_string().yellow()
        );
        println!(
            "  HPAs: {}",
            manifests
                .horizontal_pod_autoscalers
                .len()
                .to_string()
                .yellow()
        );
        println!();

        let proceed = Confirm::new()
            .with_prompt("Proceed with saving these manifests?")
            .default(true)
            .interact()?;

        if !proceed {
            return Err(anyhow::anyhow!("Conversion cancelled by user"));
        }

        Ok(())
    }

    async fn review_manifests(
        &self,
        config: &WizardConfiguration,
        manifests: &KubernetesManifests,
    ) -> Result<()> {
        println!("{}", "📋 Generated Manifests Review".bold().blue());

        // Show summary
        println!("Target: {:?}", config.deployment_target);
        println!("Environment: {:?}", config.environment_type);
        println!("Cloud Provider: {:?}", config.cloud_provider);
        println!();

        println!("Manifests to be created:");
        if !manifests.deployments.is_empty() {
            println!(
                "  📦 Deployments: {}",
                manifests.deployments.len().to_string().yellow()
            );
            for deployment in &manifests.deployments {
                println!("    - {}", deployment.name.cyan());
            }
        }

        if !manifests.services.is_empty() {
            println!(
                "  🌐 Services: {}",
                manifests.services.len().to_string().yellow()
            );
            for service in &manifests.services {
                println!("    - {}", service.name.cyan());
            }
        }

        if !manifests.ingress.is_empty() {
            println!(
                "  🚪 Ingress: {}",
                manifests.ingress.len().to_string().yellow()
            );
            for ingress in &manifests.ingress {
                println!("    - {} ({})", ingress.name.cyan(), ingress.host.green());
            }
        }

        if !manifests.horizontal_pod_autoscalers.is_empty() {
            println!(
                "  📈 HPAs: {}",
                manifests
                    .horizontal_pod_autoscalers
                    .len()
                    .to_string()
                    .yellow()
            );
        }

        println!();

        let proceed = Confirm::new()
            .with_prompt("Do you want to proceed with saving these manifests?")
            .default(true)
            .interact()?;

        if !proceed {
            return Err(anyhow::anyhow!("Operation cancelled by user"));
        }

        Ok(())
    }

    async fn save_configuration_and_manifests(
        &self,
        config: &WizardConfiguration,
        manifests: &KubernetesManifests,
    ) -> Result<()> {
        let progress = ProgressBar::new_spinner();
        progress.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        progress.set_message("Saving manifests...");
        progress.enable_steady_tick(Duration::from_millis(100));

        // Save manifests
        self.converter
            .save_manifests(manifests, &config.output_directory)
            .await?;

        // Save configuration
        let config_path = config.output_directory.join("k8sify-config.json");
        let config_json = serde_json::to_string_pretty(config)?;
        tokio::fs::write(&config_path, config_json)
            .await
            .context("Failed to save configuration")?;

        progress.finish_and_clear();

        Ok(())
    }

    fn print_completion_message(&self, config: &WizardConfiguration) {
        println!("{}", "✅ Conversion Complete!".bold().green());
        println!();
        println!(
            "Your Kubernetes manifests have been saved to: {}",
            config.output_directory.display().to_string().cyan()
        );
        println!();
        println!("{}", "Next steps:".bold().white());
        println!(
            "1. Review the generated manifests in {}",
            config.output_directory.display().to_string().cyan()
        );
        println!("2. Apply them to your Kubernetes cluster:");
        println!(
            "   {}",
            format!("kubectl apply -f {}", config.output_directory.display()).yellow()
        );
        println!("3. Monitor your deployments:");
        println!("   {}", "kubectl get pods,services,ingress".yellow());
        println!();

        if matches!(config.deployment_target, DeploymentTarget::Production) {
            println!("{}", "🚨 Production Deployment Checklist:".bold().red());
            println!("□ Review resource limits and requests");
            println!("□ Verify security configurations");
            println!("□ Set up monitoring and alerting");
            println!("□ Configure backup strategies");
            println!("□ Test disaster recovery procedures");
            println!("□ Review network policies");
            println!("□ Validate SSL/TLS certificates");
            println!();
        }

        println!(
            "{}",
            "💡 Need help? Check out the documentation or run 'k8sify --help'".dimmed()
        );
    }
}
