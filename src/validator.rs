use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::HashMap;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResults {
    pub total_files: u32,
    pub valid_files: u32,
    pub invalid_files: u32,
    pub warnings: u32,
    pub file_results: Vec<FileValidationResult>,
    pub summary: ValidationSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileValidationResult {
    pub file_path: String,
    pub file_type: KubernetesResourceType,
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub error_type: ErrorType,
    pub message: String,
    pub path: String,
    pub severity: ErrorSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationWarning {
    pub warning_type: WarningType,
    pub message: String,
    pub path: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationSummary {
    pub resource_counts: HashMap<KubernetesResourceType, u32>,
    pub common_issues: Vec<String>,
    pub overall_score: f32,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum KubernetesResourceType {
    Deployment,
    Service,
    ConfigMap,
    Secret,
    PersistentVolumeClaim,
    Ingress,
    HorizontalPodAutoscaler,
    NetworkPolicy,
    ServiceMonitor,
    StatefulSet,
    DaemonSet,
    Job,
    CronJob,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorType {
    SyntaxError,
    SchemaViolation,
    MissingRequired,
    InvalidValue,
    ResourceConflict,
    SecurityIssue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WarningType {
    BestPractice,
    Performance,
    Security,
    Maintenance,
    Compatibility,
}

pub struct ManifestValidator {
    resource_validators: HashMap<KubernetesResourceType, Box<dyn ResourceValidator>>,
}

trait ResourceValidator {
    fn validate(&self, resource: &Value) -> Result<(Vec<ValidationError>, Vec<ValidationWarning>)>;
}

struct DeploymentValidator;
struct ServiceValidator;
struct ConfigMapValidator;
struct SecretValidator;
struct PvcValidator;
struct IngressValidator;
struct HpaValidator;
#[allow(dead_code)]
struct GenericValidator;

impl Default for ManifestValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl ManifestValidator {
    pub fn new() -> Self {
        let mut resource_validators: HashMap<KubernetesResourceType, Box<dyn ResourceValidator>> =
            HashMap::new();

        resource_validators.insert(
            KubernetesResourceType::Deployment,
            Box::new(DeploymentValidator),
        );
        resource_validators.insert(KubernetesResourceType::Service, Box::new(ServiceValidator));
        resource_validators.insert(
            KubernetesResourceType::ConfigMap,
            Box::new(ConfigMapValidator),
        );
        resource_validators.insert(KubernetesResourceType::Secret, Box::new(SecretValidator));
        resource_validators.insert(
            KubernetesResourceType::PersistentVolumeClaim,
            Box::new(PvcValidator),
        );
        resource_validators.insert(KubernetesResourceType::Ingress, Box::new(IngressValidator));
        resource_validators.insert(
            KubernetesResourceType::HorizontalPodAutoscaler,
            Box::new(HpaValidator),
        );

        Self {
            resource_validators,
        }
    }

    pub async fn validate_directory(&self, dir_path: &Path) -> Result<ValidationResults> {
        let mut file_results = Vec::new();
        let mut resource_counts = HashMap::new();
        let mut total_files = 0;
        let mut valid_files = 0;
        let mut warnings = 0;

        for entry in WalkDir::new(dir_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                if let Some(ext) = e.path().extension() {
                    ext == "yaml" || ext == "yml"
                } else {
                    false
                }
            })
        {
            total_files += 1;
            let file_result = self.validate_file(entry.path()).await?;

            if file_result.is_valid {
                valid_files += 1;
            }

            warnings += file_result.warnings.len() as u32;

            *resource_counts
                .entry(file_result.file_type.clone())
                .or_insert(0) += 1;
            file_results.push(file_result);
        }

        let invalid_files = total_files - valid_files;
        let common_issues = self.identify_common_issues(&file_results);
        let overall_score = self.calculate_overall_score(valid_files, total_files, warnings);
        let recommendations = self.generate_overall_recommendations(&file_results);

        let summary = ValidationSummary {
            resource_counts,
            common_issues,
            overall_score,
            recommendations,
        };

        Ok(ValidationResults {
            total_files,
            valid_files,
            invalid_files,
            warnings,
            file_results,
            summary,
        })
    }

    async fn validate_file(&self, file_path: &Path) -> Result<FileValidationResult> {
        let content = tokio::fs::read_to_string(file_path)
            .await
            .context("Failed to read file")?;

        // Parse YAML - handle both single documents and multi-document YAML
        let documents: Vec<Value> = if content.trim().contains("---") {
            serde_yaml::Deserializer::from_str(&content)
                .map(|de| Value::deserialize(de))
                .collect::<Result<Vec<_>, _>>()
                .context("Failed to parse multi-document YAML")?
        } else {
            // Single document
            let doc: Value = serde_yaml::from_str(&content).context("Failed to parse YAML")?;
            vec![doc]
        };

        let mut all_errors = Vec::new();
        let mut all_warnings = Vec::new();
        let mut file_type = KubernetesResourceType::Unknown;

        for document in documents {
            if let Some(kind) = document.get("kind").and_then(|k| k.as_str()) {
                file_type = self.determine_resource_type(kind);

                // Basic structure validation
                let (mut errors, mut warnings) = self.validate_basic_structure(&document)?;

                // Resource-specific validation
                if let Some(validator) = self.resource_validators.get(&file_type) {
                    let (resource_errors, resource_warnings) = validator.validate(&document)?;
                    errors.extend(resource_errors);
                    warnings.extend(resource_warnings);
                }

                all_errors.extend(errors);
                all_warnings.extend(warnings);
            }
        }

        let is_valid = all_errors.is_empty();
        let recommendations = self.generate_file_recommendations(&all_errors, &all_warnings);

        Ok(FileValidationResult {
            file_path: file_path.to_string_lossy().to_string(),
            file_type,
            is_valid,
            errors: all_errors,
            warnings: all_warnings,
            recommendations,
        })
    }

    fn determine_resource_type(&self, kind: &str) -> KubernetesResourceType {
        match kind {
            "Deployment" => KubernetesResourceType::Deployment,
            "Service" => KubernetesResourceType::Service,
            "ConfigMap" => KubernetesResourceType::ConfigMap,
            "Secret" => KubernetesResourceType::Secret,
            "PersistentVolumeClaim" => KubernetesResourceType::PersistentVolumeClaim,
            "Ingress" => KubernetesResourceType::Ingress,
            "HorizontalPodAutoscaler" => KubernetesResourceType::HorizontalPodAutoscaler,
            "NetworkPolicy" => KubernetesResourceType::NetworkPolicy,
            "ServiceMonitor" => KubernetesResourceType::ServiceMonitor,
            "StatefulSet" => KubernetesResourceType::StatefulSet,
            "DaemonSet" => KubernetesResourceType::DaemonSet,
            "Job" => KubernetesResourceType::Job,
            "CronJob" => KubernetesResourceType::CronJob,
            _ => KubernetesResourceType::Unknown,
        }
    }

    fn validate_basic_structure(
        &self,
        resource: &Value,
    ) -> Result<(Vec<ValidationError>, Vec<ValidationWarning>)> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Check required fields
        if resource.get("apiVersion").is_none() {
            errors.push(ValidationError {
                error_type: ErrorType::MissingRequired,
                message: "Missing required field: apiVersion".to_string(),
                path: "apiVersion".to_string(),
                severity: ErrorSeverity::Critical,
            });
        }

        if resource.get("kind").is_none() {
            errors.push(ValidationError {
                error_type: ErrorType::MissingRequired,
                message: "Missing required field: kind".to_string(),
                path: "kind".to_string(),
                severity: ErrorSeverity::Critical,
            });
        }

        if resource.get("metadata").is_none() {
            errors.push(ValidationError {
                error_type: ErrorType::MissingRequired,
                message: "Missing required field: metadata".to_string(),
                path: "metadata".to_string(),
                severity: ErrorSeverity::Critical,
            });
        } else if let Some(metadata) = resource.get("metadata") {
            if metadata.get("name").is_none() {
                errors.push(ValidationError {
                    error_type: ErrorType::MissingRequired,
                    message: "Missing required field: metadata.name".to_string(),
                    path: "metadata.name".to_string(),
                    severity: ErrorSeverity::Critical,
                });
            }

            // Check for recommended labels
            if let Some(labels) = metadata.get("labels") {
                let recommended_labels = vec!["app", "version", "component"];
                for label in recommended_labels {
                    if labels.get(label).is_none() {
                        warnings.push(ValidationWarning {
                            warning_type: WarningType::BestPractice,
                            message: format!("Missing recommended label: {}", label),
                            path: format!("metadata.labels.{}", label),
                            recommendation: format!(
                                "Add {} label for better resource management",
                                label
                            ),
                        });
                    }
                }
            } else {
                warnings.push(ValidationWarning {
                    warning_type: WarningType::BestPractice,
                    message: "No labels defined".to_string(),
                    path: "metadata.labels".to_string(),
                    recommendation: "Add labels for better resource management".to_string(),
                });
            }
        }

        Ok((errors, warnings))
    }

    fn identify_common_issues(&self, file_results: &[FileValidationResult]) -> Vec<String> {
        let mut issue_counts = HashMap::new();

        for result in file_results {
            for error in &result.errors {
                *issue_counts.entry(error.message.clone()).or_insert(0) += 1;
            }
            for warning in &result.warnings {
                *issue_counts.entry(warning.message.clone()).or_insert(0) += 1;
            }
        }

        issue_counts
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(issue, count)| format!("{} (occurs {} times)", issue, count))
            .collect()
    }

    fn calculate_overall_score(&self, valid_files: u32, total_files: u32, warnings: u32) -> f32 {
        if total_files == 0 {
            return 100.0;
        }

        let validity_score = (valid_files as f32 / total_files as f32) * 70.0;
        let warning_penalty = (warnings as f32 / total_files as f32) * 10.0;

        (validity_score + 30.0 - warning_penalty).clamp(0.0, 100.0)
    }

    fn generate_overall_recommendations(
        &self,
        file_results: &[FileValidationResult],
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        let error_count: usize = file_results.iter().map(|r| r.errors.len()).sum();
        let warning_count: usize = file_results.iter().map(|r| r.warnings.len()).sum();

        if error_count > 0 {
            recommendations
                .push("Fix all validation errors before deploying to production".to_string());
        }

        if warning_count > 5 {
            recommendations.push(
                "Address warnings to improve manifest quality and maintainability".to_string(),
            );
        }

        recommendations
            .push("Use kubectl dry-run to validate manifests before applying".to_string());
        recommendations.push("Implement CI/CD validation pipelines".to_string());
        recommendations
            .push("Consider using tools like kubeval or kustomize for validation".to_string());

        recommendations
    }

    fn generate_file_recommendations(
        &self,
        errors: &[ValidationError],
        warnings: &[ValidationWarning],
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if !errors.is_empty() {
            recommendations.push("Fix all errors before deploying this manifest".to_string());
        }

        if warnings.len() > 3 {
            recommendations
                .push("Consider addressing warnings to improve resource quality".to_string());
        }

        recommendations.push("Test this manifest in a development environment first".to_string());

        recommendations
    }

    pub fn print_validation_results(&self, results: &ValidationResults) -> Result<()> {
        println!(
            "{}",
            "✅ Kubernetes Manifest Validation Results".bold().green()
        );
        println!();

        println!("{}", "📊 Summary:".bold().white());
        println!("  Total files: {}", results.total_files.to_string().cyan());
        println!("  Valid files: {}", results.valid_files.to_string().green());
        println!(
            "  Invalid files: {}",
            results.invalid_files.to_string().red()
        );
        println!("  Warnings: {}", results.warnings.to_string().yellow());
        println!(
            "  Overall score: {:.1}%",
            results.summary.overall_score.to_string().blue()
        );
        println!();

        // Resource type breakdown
        if !results.summary.resource_counts.is_empty() {
            println!("{}", "📋 Resource Types:".bold().white());
            for (resource_type, count) in &results.summary.resource_counts {
                println!("  {:?}: {}", resource_type, count.to_string().cyan());
            }
            println!();
        }

        // File-by-file results
        if !results.file_results.is_empty() {
            println!("{}", "📄 File Results:".bold().white());
            for file_result in &results.file_results {
                let status = if file_result.is_valid {
                    "✅ VALID".green()
                } else {
                    "❌ INVALID".red()
                };

                println!(
                    "  {} {} ({:?})",
                    status,
                    file_result.file_path.cyan(),
                    file_result.file_type
                );

                // Show errors
                for error in &file_result.errors {
                    let severity_color = match error.severity {
                        ErrorSeverity::Critical => "red",
                        ErrorSeverity::High => "yellow",
                        ErrorSeverity::Medium => "blue",
                        ErrorSeverity::Low => "green",
                    };

                    println!(
                        "    {} {} ({})",
                        "ERROR:".red().bold(),
                        error.message,
                        format!("{:?}", error.severity).color(severity_color)
                    );
                }

                // Show warnings
                for warning in &file_result.warnings {
                    println!("    {} {}", "WARNING:".yellow().bold(), warning.message);
                }

                if !file_result.errors.is_empty() || !file_result.warnings.is_empty() {
                    println!();
                }
            }
        }

        // Common issues
        if !results.summary.common_issues.is_empty() {
            println!("{}", "🔍 Common Issues:".bold().yellow());
            for issue in &results.summary.common_issues {
                println!("  • {}", issue);
            }
            println!();
        }

        // Recommendations
        if !results.summary.recommendations.is_empty() {
            println!("{}", "💡 Recommendations:".bold().blue());
            for (i, recommendation) in results.summary.recommendations.iter().enumerate() {
                println!("{}. {}", i + 1, recommendation);
            }
            println!();
        }

        Ok(())
    }
}

// Resource-specific validators
impl ResourceValidator for DeploymentValidator {
    fn validate(&self, resource: &Value) -> Result<(Vec<ValidationError>, Vec<ValidationWarning>)> {
        let errors = Vec::new();
        let mut warnings = Vec::new();

        if let Some(spec) = resource.get("spec") {
            // Check replicas
            if let Some(replicas) = spec.get("replicas") {
                if let Some(replica_count) = replicas.as_u64() {
                    if replica_count == 0 {
                        warnings.push(ValidationWarning {
                            warning_type: WarningType::Performance,
                            message: "Replica count is 0".to_string(),
                            path: "spec.replicas".to_string(),
                            recommendation: "Consider setting replicas > 0 for availability"
                                .to_string(),
                        });
                    } else if replica_count == 1 {
                        warnings.push(ValidationWarning {
                            warning_type: WarningType::Performance,
                            message: "Single replica deployment".to_string(),
                            path: "spec.replicas".to_string(),
                            recommendation: "Consider multiple replicas for high availability"
                                .to_string(),
                        });
                    }
                }
            }

            // Check container spec
            if let Some(template) = spec.get("template") {
                if let Some(template_spec) = template.get("spec") {
                    if let Some(containers) = template_spec.get("containers") {
                        if let Some(containers_array) = containers.as_sequence() {
                            for container in containers_array {
                                // Check resource limits
                                if container.get("resources").is_none() {
                                    warnings.push(ValidationWarning {
                                        warning_type: WarningType::BestPractice,
                                        message: "Container missing resource limits".to_string(),
                                        path: "spec.template.spec.containers[].resources"
                                            .to_string(),
                                        recommendation: "Add resource requests and limits"
                                            .to_string(),
                                    });
                                }

                                // Check image tag
                                if let Some(image) = container.get("image") {
                                    if let Some(image_str) = image.as_str() {
                                        if image_str.ends_with(":latest") {
                                            warnings.push(ValidationWarning {
                                                warning_type: WarningType::BestPractice,
                                                message: "Using 'latest' image tag".to_string(),
                                                path: "spec.template.spec.containers[].image".to_string(),
                                                recommendation: "Use specific image tags for reproducible deployments".to_string(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok((errors, warnings))
    }
}

impl ResourceValidator for ServiceValidator {
    fn validate(&self, resource: &Value) -> Result<(Vec<ValidationError>, Vec<ValidationWarning>)> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        if let Some(spec) = resource.get("spec") {
            // Check if selector exists
            if spec.get("selector").is_none() {
                errors.push(ValidationError {
                    error_type: ErrorType::MissingRequired,
                    message: "Service missing selector".to_string(),
                    path: "spec.selector".to_string(),
                    severity: ErrorSeverity::High,
                });
            }

            // Check ports
            if let Some(ports) = spec.get("ports") {
                if let Some(ports_array) = ports.as_sequence() {
                    if ports_array.is_empty() {
                        warnings.push(ValidationWarning {
                            warning_type: WarningType::BestPractice,
                            message: "Service has no ports defined".to_string(),
                            path: "spec.ports".to_string(),
                            recommendation: "Define at least one port for the service".to_string(),
                        });
                    }
                }
            }
        }

        Ok((errors, warnings))
    }
}

impl ResourceValidator for ConfigMapValidator {
    fn validate(&self, resource: &Value) -> Result<(Vec<ValidationError>, Vec<ValidationWarning>)> {
        let errors = Vec::new();
        let mut warnings = Vec::new();

        // Check if data exists
        if resource.get("data").is_none() && resource.get("binaryData").is_none() {
            warnings.push(ValidationWarning {
                warning_type: WarningType::BestPractice,
                message: "ConfigMap has no data".to_string(),
                path: "data".to_string(),
                recommendation: "Add configuration data to make the ConfigMap useful".to_string(),
            });
        }

        Ok((errors, warnings))
    }
}

impl ResourceValidator for SecretValidator {
    fn validate(&self, resource: &Value) -> Result<(Vec<ValidationError>, Vec<ValidationWarning>)> {
        let errors = Vec::new();
        let mut warnings = Vec::new();

        // Check if data exists
        if resource.get("data").is_none() && resource.get("stringData").is_none() {
            warnings.push(ValidationWarning {
                warning_type: WarningType::BestPractice,
                message: "Secret has no data".to_string(),
                path: "data".to_string(),
                recommendation: "Add secret data to make the Secret useful".to_string(),
            });
        }

        Ok((errors, warnings))
    }
}

impl ResourceValidator for PvcValidator {
    fn validate(&self, resource: &Value) -> Result<(Vec<ValidationError>, Vec<ValidationWarning>)> {
        let mut errors = Vec::new();
        let warnings = Vec::new();

        if let Some(spec) = resource.get("spec") {
            // Check access modes
            if spec.get("accessModes").is_none() {
                errors.push(ValidationError {
                    error_type: ErrorType::MissingRequired,
                    message: "PVC missing accessModes".to_string(),
                    path: "spec.accessModes".to_string(),
                    severity: ErrorSeverity::High,
                });
            }

            // Check resources
            if spec.get("resources").is_none() {
                errors.push(ValidationError {
                    error_type: ErrorType::MissingRequired,
                    message: "PVC missing resources specification".to_string(),
                    path: "spec.resources".to_string(),
                    severity: ErrorSeverity::High,
                });
            }
        }

        Ok((errors, warnings))
    }
}

impl ResourceValidator for IngressValidator {
    fn validate(&self, resource: &Value) -> Result<(Vec<ValidationError>, Vec<ValidationWarning>)> {
        let errors = Vec::new();
        let mut warnings = Vec::new();

        if let Some(spec) = resource.get("spec") {
            // Check rules
            if spec.get("rules").is_none() {
                warnings.push(ValidationWarning {
                    warning_type: WarningType::BestPractice,
                    message: "Ingress has no rules defined".to_string(),
                    path: "spec.rules".to_string(),
                    recommendation: "Add ingress rules to route traffic".to_string(),
                });
            }
        }

        Ok((errors, warnings))
    }
}

impl ResourceValidator for HpaValidator {
    fn validate(&self, resource: &Value) -> Result<(Vec<ValidationError>, Vec<ValidationWarning>)> {
        let mut errors = Vec::new();
        let warnings = Vec::new();

        if let Some(spec) = resource.get("spec") {
            // Check scale target ref
            if spec.get("scaleTargetRef").is_none() {
                errors.push(ValidationError {
                    error_type: ErrorType::MissingRequired,
                    message: "HPA missing scaleTargetRef".to_string(),
                    path: "spec.scaleTargetRef".to_string(),
                    severity: ErrorSeverity::High,
                });
            }

            // Check min/max replicas
            if let Some(min_replicas) = spec.get("minReplicas").and_then(|v| v.as_u64()) {
                if let Some(max_replicas) = spec.get("maxReplicas").and_then(|v| v.as_u64()) {
                    if min_replicas >= max_replicas {
                        errors.push(ValidationError {
                            error_type: ErrorType::InvalidValue,
                            message: "minReplicas must be less than maxReplicas".to_string(),
                            path: "spec.minReplicas".to_string(),
                            severity: ErrorSeverity::Medium,
                        });
                    }
                }
            }
        }

        Ok((errors, warnings))
    }
}
