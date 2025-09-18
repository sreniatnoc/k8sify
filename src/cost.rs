use anyhow::Result;
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::analyzer::{DockerComposeAnalysis, ServiceAnalysis, ServiceType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostEstimate {
    pub total_monthly_cost: f64,
    pub breakdown: CostBreakdown,
    pub recommendations: Vec<CostRecommendation>,
    pub currency: String,
    pub region: String,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostBreakdown {
    pub compute: ComputeCosts,
    pub storage: StorageCosts,
    pub networking: NetworkingCosts,
    pub additional_services: AdditionalServicesCosts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeCosts {
    pub total: f64,
    pub services: Vec<ServiceCost>,
    pub load_balancers: f64,
    pub cluster_management: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCost {
    pub service_name: String,
    pub service_type: ServiceType,
    pub cpu_cost: f64,
    pub memory_cost: f64,
    pub replicas: u32,
    pub monthly_cost: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCosts {
    pub total: f64,
    pub persistent_volumes: f64,
    pub backup_storage: f64,
    pub container_registry: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkingCosts {
    pub total: f64,
    pub data_transfer: f64,
    pub load_balancer: f64,
    pub nat_gateway: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdditionalServicesCosts {
    pub total: f64,
    pub monitoring: f64,
    pub logging: f64,
    pub secrets_management: f64,
    pub backup_services: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostRecommendation {
    pub recommendation_type: RecommendationType,
    pub description: String,
    pub potential_savings: f64,
    pub effort_level: EffortLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationType {
    RightSizing,
    SpotInstances,
    ReservedInstances,
    StorageOptimization,
    NetworkOptimization,
    AutoScaling,
    ResourceScheduling,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EffortLevel {
    Low,
    Medium,
    High,
}

pub struct CostEstimator {
    provider: CloudProvider,
    region: String,
    pricing_data: PricingData,
}

#[derive(Debug, Clone)]
pub enum CloudProvider {
    AWS,
    GCP,
    Azure,
    DigitalOcean,
    OnPremise,
}

#[derive(Debug, Clone)]
pub struct PricingData {
    pub cpu_per_hour: f64,
    pub memory_per_gb_hour: f64,
    pub storage_per_gb_month: f64,
    pub load_balancer_per_hour: f64,
    pub data_transfer_per_gb: f64,
    pub cluster_management_per_hour: f64,
}

impl CostEstimator {
    pub fn new(provider: &str, region: &str) -> Self {
        let cloud_provider = match provider.to_lowercase().as_str() {
            "aws" => CloudProvider::AWS,
            "gcp" | "google" => CloudProvider::GCP,
            "azure" | "microsoft" => CloudProvider::Azure,
            "digitalocean" | "do" => CloudProvider::DigitalOcean,
            _ => CloudProvider::OnPremise,
        };

        let pricing_data = Self::get_pricing_data(&cloud_provider, region);

        Self {
            provider: cloud_provider,
            region: region.to_string(),
            pricing_data,
        }
    }

    fn get_pricing_data(provider: &CloudProvider, region: &str) -> PricingData {
        match provider {
            CloudProvider::AWS => Self::get_aws_pricing(region),
            CloudProvider::GCP => Self::get_gcp_pricing(region),
            CloudProvider::Azure => Self::get_azure_pricing(region),
            CloudProvider::DigitalOcean => Self::get_digitalocean_pricing(region),
            CloudProvider::OnPremise => Self::get_onpremise_pricing(),
        }
    }

    fn get_aws_pricing(_region: &str) -> PricingData {
        PricingData {
            cpu_per_hour: 0.04,        // EKS node per vCPU
            memory_per_gb_hour: 0.004, // EKS node per GB RAM
            storage_per_gb_month: 0.10, // EBS gp3
            load_balancer_per_hour: 0.025, // ALB
            data_transfer_per_gb: 0.09, // Data transfer out
            cluster_management_per_hour: 0.10, // EKS cluster
        }
    }

    fn get_gcp_pricing(_region: &str) -> PricingData {
        PricingData {
            cpu_per_hour: 0.038,
            memory_per_gb_hour: 0.005,
            storage_per_gb_month: 0.08,
            load_balancer_per_hour: 0.025,
            data_transfer_per_gb: 0.085,
            cluster_management_per_hour: 0.10,
        }
    }

    fn get_azure_pricing(_region: &str) -> PricingData {
        PricingData {
            cpu_per_hour: 0.042,
            memory_per_gb_hour: 0.0045,
            storage_per_gb_month: 0.12,
            load_balancer_per_hour: 0.022,
            data_transfer_per_gb: 0.087,
            cluster_management_per_hour: 0.00, // AKS is free
        }
    }

    fn get_digitalocean_pricing(_region: &str) -> PricingData {
        PricingData {
            cpu_per_hour: 0.060, // Higher cost for managed service
            memory_per_gb_hour: 0.009,
            storage_per_gb_month: 0.10,
            load_balancer_per_hour: 0.012,
            data_transfer_per_gb: 0.01, // First 1TB free
            cluster_management_per_hour: 0.00, // DOKS is free
        }
    }

    fn get_onpremise_pricing() -> PricingData {
        PricingData {
            cpu_per_hour: 0.02, // Estimated hardware amortization
            memory_per_gb_hour: 0.002,
            storage_per_gb_month: 0.05,
            load_balancer_per_hour: 0.00, // Software load balancer
            data_transfer_per_gb: 0.00, // Internal network
            cluster_management_per_hour: 0.02, // Admin overhead
        }
    }

    pub async fn estimate_costs(&self, analysis: &DockerComposeAnalysis) -> Result<CostEstimate> {
        let compute_costs = self.calculate_compute_costs(analysis).await?;
        let storage_costs = self.calculate_storage_costs(analysis).await?;
        let networking_costs = self.calculate_networking_costs(analysis).await?;
        let additional_costs = self.calculate_additional_services_costs(analysis).await?;

        let total_monthly_cost = compute_costs.total + storage_costs.total
            + networking_costs.total + additional_costs.total;

        let breakdown = CostBreakdown {
            compute: compute_costs,
            storage: storage_costs,
            networking: networking_costs,
            additional_services: additional_costs,
        };

        let recommendations = self.generate_cost_recommendations(analysis, &breakdown).await?;

        Ok(CostEstimate {
            total_monthly_cost,
            breakdown,
            recommendations,
            currency: "USD".to_string(),
            region: self.region.clone(),
            provider: format!("{:?}", self.provider),
        })
    }

    async fn calculate_compute_costs(&self, analysis: &DockerComposeAnalysis) -> Result<ComputeCosts> {
        let mut service_costs = Vec::new();
        let mut total_compute_cost = 0.0;

        for service in &analysis.services {
            let service_cost = self.calculate_service_cost(service).await?;
            total_compute_cost += service_cost.monthly_cost;
            service_costs.push(service_cost);
        }

        // Add load balancer costs
        let load_balancer_count = analysis.services.iter()
            .filter(|s| matches!(s.service_type, ServiceType::WebApp | ServiceType::LoadBalancer))
            .count();
        let load_balancer_cost = load_balancer_count as f64 * self.pricing_data.load_balancer_per_hour * 24.0 * 30.0;

        // Add cluster management cost
        let cluster_management_cost = self.pricing_data.cluster_management_per_hour * 24.0 * 30.0;

        total_compute_cost += load_balancer_cost + cluster_management_cost;

        Ok(ComputeCosts {
            total: total_compute_cost,
            services: service_costs,
            load_balancers: load_balancer_cost,
            cluster_management: cluster_management_cost,
        })
    }

    async fn calculate_service_cost(&self, service: &ServiceAnalysis) -> Result<ServiceCost> {
        // Estimate resource requirements based on service type
        let (cpu_cores, memory_gb, replicas) = self.estimate_service_resources(service);

        let cpu_cost = cpu_cores * self.pricing_data.cpu_per_hour * 24.0 * 30.0 * replicas as f64;
        let memory_cost = memory_gb * self.pricing_data.memory_per_gb_hour * 24.0 * 30.0 * replicas as f64;
        let monthly_cost = cpu_cost + memory_cost;

        Ok(ServiceCost {
            service_name: service.name.clone(),
            service_type: service.service_type.clone(),
            cpu_cost,
            memory_cost,
            replicas,
            monthly_cost,
        })
    }

    fn estimate_service_resources(&self, service: &ServiceAnalysis) -> (f64, f64, u32) {
        // Default resources based on service type
        let (base_cpu, base_memory, default_replicas) = match service.service_type {
            ServiceType::Database => (1.0, 2.0, 1),
            ServiceType::Cache => (0.5, 1.0, 1),
            ServiceType::WebApp => (0.5, 1.0, 2),
            ServiceType::MessageQueue => (0.5, 1.0, 1),
            ServiceType::LoadBalancer => (0.25, 0.5, 2),
            ServiceType::Worker => (0.5, 1.0, 2),
            ServiceType::Storage => (0.25, 0.5, 1),
            _ => (0.25, 0.5, 1),
        };

        // Check if service has explicit resource limits
        let cpu = if let Some(cpu_limit) = &service.resource_limits.cpu {
            self.parse_cpu_limit(cpu_limit).unwrap_or(base_cpu)
        } else {
            base_cpu
        };

        let memory = if let Some(memory_limit) = &service.resource_limits.memory {
            self.parse_memory_limit(memory_limit).unwrap_or(base_memory)
        } else {
            base_memory
        };

        // Estimate replicas based on scaling hints
        let replicas = if service.scaling_hints.horizontal_scaling {
            match service.service_type {
                ServiceType::WebApp => 3,
                ServiceType::Worker => 2,
                _ => default_replicas,
            }
        } else {
            default_replicas
        };

        (cpu, memory, replicas)
    }

    fn parse_cpu_limit(&self, cpu_str: &str) -> Option<f64> {
        if cpu_str.ends_with('m') {
            cpu_str.trim_end_matches('m').parse::<f64>().ok().map(|m| m / 1000.0)
        } else {
            cpu_str.parse::<f64>().ok()
        }
    }

    fn parse_memory_limit(&self, memory_str: &str) -> Option<f64> {
        if memory_str.ends_with("Gi") {
            memory_str.trim_end_matches("Gi").parse::<f64>().ok()
        } else if memory_str.ends_with("Mi") {
            memory_str.trim_end_matches("Mi").parse::<f64>().ok().map(|m| m / 1024.0)
        } else if memory_str.ends_with("G") {
            memory_str.trim_end_matches("G").parse::<f64>().ok()
        } else if memory_str.ends_with("M") {
            memory_str.trim_end_matches("M").parse::<f64>().ok().map(|m| m / 1024.0)
        } else {
            memory_str.parse::<f64>().ok().map(|b| b / (1024.0 * 1024.0 * 1024.0))
        }
    }

    async fn calculate_storage_costs(&self, analysis: &DockerComposeAnalysis) -> Result<StorageCosts> {
        let mut total_storage_gb = 0.0;

        // Calculate storage for databases and persistent services
        for service in &analysis.services {
            if matches!(service.service_type, ServiceType::Database | ServiceType::Storage) {
                total_storage_gb += match service.service_type {
                    ServiceType::Database => 50.0, // Default 50GB for database
                    ServiceType::Storage => 100.0, // Default 100GB for storage
                    _ => 0.0,
                };
            }

            // Add storage for persistent volumes
            total_storage_gb += service.volumes.len() as f64 * 10.0; // 10GB per volume
        }

        let persistent_volumes = total_storage_gb * self.pricing_data.storage_per_gb_month;
        let backup_storage = persistent_volumes * 0.3; // 30% for backups
        let container_registry = 5.0; // Estimated $5/month for container registry

        let total = persistent_volumes + backup_storage + container_registry;

        Ok(StorageCosts {
            total,
            persistent_volumes,
            backup_storage,
            container_registry,
        })
    }

    async fn calculate_networking_costs(&self, analysis: &DockerComposeAnalysis) -> Result<NetworkingCosts> {
        // Estimate data transfer based on service types
        let web_services = analysis.services.iter()
            .filter(|s| matches!(s.service_type, ServiceType::WebApp))
            .count();

        let estimated_data_transfer_gb = web_services as f64 * 100.0; // 100GB per web service per month
        let data_transfer = estimated_data_transfer_gb * self.pricing_data.data_transfer_per_gb;

        let load_balancer = self.pricing_data.load_balancer_per_hour * 24.0 * 30.0;
        let nat_gateway = if matches!(self.provider, CloudProvider::AWS) { 45.0 } else { 0.0 };

        let total = data_transfer + load_balancer + nat_gateway;

        Ok(NetworkingCosts {
            total,
            data_transfer,
            load_balancer,
            nat_gateway,
        })
    }

    async fn calculate_additional_services_costs(&self, analysis: &DockerComposeAnalysis) -> Result<AdditionalServicesCosts> {
        let service_count = analysis.services.len() as f64;

        // Estimate additional service costs
        let monitoring = service_count * 5.0; // $5 per service for monitoring
        let logging = service_count * 3.0; // $3 per service for logging
        let secrets_management = if analysis.secrets.is_empty() { 0.0 } else { 10.0 };
        let backup_services = analysis.services.iter()
            .filter(|s| matches!(s.service_type, ServiceType::Database))
            .count() as f64 * 20.0; // $20 per database for backup services

        let total = monitoring + logging + secrets_management + backup_services;

        Ok(AdditionalServicesCosts {
            total,
            monitoring,
            logging,
            secrets_management,
            backup_services,
        })
    }

    async fn generate_cost_recommendations(&self, analysis: &DockerComposeAnalysis, breakdown: &CostBreakdown) -> Result<Vec<CostRecommendation>> {
        let mut recommendations = Vec::new();

        // Right-sizing recommendations
        if breakdown.compute.total > 200.0 {
            recommendations.push(CostRecommendation {
                recommendation_type: RecommendationType::RightSizing,
                description: "Consider right-sizing your instances. Many services may be over-provisioned.".to_string(),
                potential_savings: breakdown.compute.total * 0.2,
                effort_level: EffortLevel::Medium,
            });
        }

        // Spot instances recommendation
        if matches!(self.provider, CloudProvider::AWS | CloudProvider::GCP | CloudProvider::Azure) {
            recommendations.push(CostRecommendation {
                recommendation_type: RecommendationType::SpotInstances,
                description: "Use spot/preemptible instances for non-critical workloads.".to_string(),
                potential_savings: breakdown.compute.total * 0.6,
                effort_level: EffortLevel::High,
            });
        }

        // Auto-scaling recommendations
        let scalable_services = analysis.services.iter()
            .filter(|s| s.scaling_hints.horizontal_scaling)
            .count();

        if scalable_services > 0 {
            recommendations.push(CostRecommendation {
                recommendation_type: RecommendationType::AutoScaling,
                description: "Implement horizontal pod autoscaling to optimize resource usage.".to_string(),
                potential_savings: breakdown.compute.total * 0.15,
                effort_level: EffortLevel::Low,
            });
        }

        // Storage optimization
        if breakdown.storage.total > 50.0 {
            recommendations.push(CostRecommendation {
                recommendation_type: RecommendationType::StorageOptimization,
                description: "Consider using different storage tiers for different data types.".to_string(),
                potential_savings: breakdown.storage.total * 0.3,
                effort_level: EffortLevel::Medium,
            });
        }

        // Reserved instances for stable workloads
        let database_services = analysis.services.iter()
            .filter(|s| matches!(s.service_type, ServiceType::Database))
            .count();

        if database_services > 0 {
            recommendations.push(CostRecommendation {
                recommendation_type: RecommendationType::ReservedInstances,
                description: "Use reserved instances for stable database workloads.".to_string(),
                potential_savings: breakdown.compute.total * 0.4,
                effort_level: EffortLevel::Low,
            });
        }

        Ok(recommendations)
    }

    pub fn print_cost_breakdown(&self, estimate: &CostEstimate) -> Result<()> {
        println!("{}", "💰 Cost Estimation".bold().yellow());
        println!("Provider: {} ({})", estimate.provider.cyan(), estimate.region.dim());
        println!("Currency: {}", estimate.currency.green());
        println!();

        println!("{}", format!("Total Monthly Cost: ${:.2}", estimate.total_monthly_cost).bold().green());
        println!();

        // Compute costs
        println!("{}", "🖥️  Compute Costs".bold().blue());
        println!("  Cluster Management: ${:.2}", estimate.breakdown.compute.cluster_management);
        println!("  Load Balancers: ${:.2}", estimate.breakdown.compute.load_balancers);

        for service in &estimate.breakdown.compute.services {
            println!("  {} ({:?}): ${:.2} ({} replicas)",
                service.service_name.cyan(),
                service.service_type,
                service.monthly_cost,
                service.replicas
            );
        }
        println!("  {}: ${:.2}", "Subtotal".bold(), estimate.breakdown.compute.total);
        println!();

        // Storage costs
        if estimate.breakdown.storage.total > 0.0 {
            println!("{}", "💾 Storage Costs".bold().blue());
            println!("  Persistent Volumes: ${:.2}", estimate.breakdown.storage.persistent_volumes);
            println!("  Backup Storage: ${:.2}", estimate.breakdown.storage.backup_storage);
            println!("  Container Registry: ${:.2}", estimate.breakdown.storage.container_registry);
            println!("  {}: ${:.2}", "Subtotal".bold(), estimate.breakdown.storage.total);
            println!();
        }

        // Networking costs
        if estimate.breakdown.networking.total > 0.0 {
            println!("{}", "🌐 Networking Costs".bold().blue());
            println!("  Data Transfer: ${:.2}", estimate.breakdown.networking.data_transfer);
            println!("  Load Balancer: ${:.2}", estimate.breakdown.networking.load_balancer);
            if estimate.breakdown.networking.nat_gateway > 0.0 {
                println!("  NAT Gateway: ${:.2}", estimate.breakdown.networking.nat_gateway);
            }
            println!("  {}: ${:.2}", "Subtotal".bold(), estimate.breakdown.networking.total);
            println!();
        }

        // Additional services
        if estimate.breakdown.additional_services.total > 0.0 {
            println!("{}", "🔧 Additional Services".bold().blue());
            println!("  Monitoring: ${:.2}", estimate.breakdown.additional_services.monitoring);
            println!("  Logging: ${:.2}", estimate.breakdown.additional_services.logging);
            if estimate.breakdown.additional_services.secrets_management > 0.0 {
                println!("  Secrets Management: ${:.2}", estimate.breakdown.additional_services.secrets_management);
            }
            if estimate.breakdown.additional_services.backup_services > 0.0 {
                println!("  Backup Services: ${:.2}", estimate.breakdown.additional_services.backup_services);
            }
            println!("  {}: ${:.2}", "Subtotal".bold(), estimate.breakdown.additional_services.total);
            println!();
        }

        // Recommendations
        if !estimate.recommendations.is_empty() {
            println!("{}", "💡 Cost Optimization Recommendations".bold().yellow());
            for (i, rec) in estimate.recommendations.iter().enumerate() {
                println!("{}. {} ({:?} effort)",
                    i + 1,
                    rec.description.white(),
                    rec.effort_level
                );
                println!("   Potential savings: ${:.2}/month", rec.potential_savings.to_string().green());
                println!();
            }
        }

        Ok(())
    }
}