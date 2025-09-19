use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::analyzer::{DockerComposeAnalysis, ServiceAnalysis, ServiceType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPattern {
    pub pattern_type: PatternType,
    pub services: Vec<String>,
    pub confidence: f32,
    pub production_pattern: ProductionPattern,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    WebApp,
    Database,
    Cache,
    MessageQueue,
    LoadBalancer,
    MicroservicesStack,
    MonolithWithDatabase,
    ThreeTierArchitecture,
    EventDrivenArchitecture,
    CacheAsidePattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProductionPattern {
    WebAppPattern(WebAppPattern),
    DatabasePattern(DatabasePattern),
    CachePattern(CachePattern),
    MessageQueuePattern(MessageQueuePattern),
    LoadBalancerPattern(LoadBalancerPattern),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAppPattern {
    pub enable_autoscaling: bool,
    pub enable_ingress: bool,
    pub enable_monitoring: bool,
    pub enable_ssl: bool,
    pub min_replicas: u32,
    pub max_replicas: u32,
    pub target_cpu_percentage: u32,
    pub health_check_enabled: bool,
    pub readiness_probe_enabled: bool,
    pub resource_requests: ResourceRequests,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabasePattern {
    pub enable_persistence: bool,
    pub enable_backup: bool,
    pub enable_replication: bool,
    pub storage_class: String,
    pub storage_size: String,
    pub enable_network_policy: bool,
    pub enable_secrets: bool,
    pub enable_monitoring: bool,
    pub backup_schedule: String,
    pub resource_requests: ResourceRequests,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachePattern {
    pub enable_persistence: bool,
    pub enable_clustering: bool,
    pub memory_allocation: String,
    pub eviction_policy: String,
    pub enable_monitoring: bool,
    pub resource_requests: ResourceRequests,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageQueuePattern {
    pub enable_persistence: bool,
    pub enable_clustering: bool,
    pub enable_dead_letter_queue: bool,
    pub queue_durability: bool,
    pub message_ttl: Option<String>,
    pub resource_requests: ResourceRequests,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerPattern {
    pub algorithm: String,
    pub health_check_enabled: bool,
    pub ssl_termination: bool,
    pub rate_limiting: bool,
    pub enable_logging: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequests {
    pub cpu: String,
    pub memory: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu: String,
    pub memory: String,
}

pub struct PatternDetector {
    web_app_indicators: Vec<String>,
    database_indicators: Vec<String>,
    cache_indicators: Vec<String>,
    message_queue_indicators: Vec<String>,
    load_balancer_indicators: Vec<String>,
}

impl PatternDetector {
    pub fn new() -> Self {
        Self {
            web_app_indicators: vec![
                "nginx".to_string(),
                "apache".to_string(),
                "httpd".to_string(),
                "node".to_string(),
                "python".to_string(),
                "php".to_string(),
                "ruby".to_string(),
                "tomcat".to_string(),
                "jetty".to_string(),
            ],
            database_indicators: vec![
                "postgres".to_string(),
                "mysql".to_string(),
                "mariadb".to_string(),
                "mongodb".to_string(),
                "cassandra".to_string(),
                "elasticsearch".to_string(),
                "neo4j".to_string(),
                "couchdb".to_string(),
            ],
            cache_indicators: vec![
                "redis".to_string(),
                "memcached".to_string(),
                "hazelcast".to_string(),
                "varnish".to_string(),
            ],
            message_queue_indicators: vec![
                "rabbitmq".to_string(),
                "kafka".to_string(),
                "activemq".to_string(),
                "nats".to_string(),
                "pulsar".to_string(),
            ],
            load_balancer_indicators: vec![
                "nginx".to_string(),
                "haproxy".to_string(),
                "traefik".to_string(),
                "envoy".to_string(),
            ],
        }
    }

    pub fn detect_patterns(
        &self,
        analysis: &DockerComposeAnalysis,
    ) -> Result<Vec<DetectedPattern>> {
        let mut patterns = Vec::new();

        // Detect individual service patterns
        patterns.extend(self.detect_web_app_patterns(analysis)?);
        patterns.extend(self.detect_database_patterns(analysis)?);
        patterns.extend(self.detect_cache_patterns(analysis)?);
        patterns.extend(self.detect_message_queue_patterns(analysis)?);
        patterns.extend(self.detect_load_balancer_patterns(analysis)?);

        // Detect architectural patterns
        patterns.extend(self.detect_architectural_patterns(analysis)?);

        Ok(patterns)
    }

    fn detect_web_app_patterns(
        &self,
        analysis: &DockerComposeAnalysis,
    ) -> Result<Vec<DetectedPattern>> {
        let mut patterns = Vec::new();

        for service in &analysis.services {
            if matches!(service.service_type, ServiceType::WebApp) {
                let confidence = self.calculate_web_app_confidence(service);

                if confidence > 0.7 {
                    let production_pattern = self.create_web_app_production_pattern(service);
                    let recommendations = self.generate_web_app_recommendations(service);

                    patterns.push(DetectedPattern {
                        pattern_type: PatternType::WebApp,
                        services: vec![service.name.clone()],
                        confidence,
                        production_pattern: ProductionPattern::WebAppPattern(production_pattern),
                        recommendations,
                    });
                }
            }
        }

        Ok(patterns)
    }

    fn detect_database_patterns(
        &self,
        analysis: &DockerComposeAnalysis,
    ) -> Result<Vec<DetectedPattern>> {
        let mut patterns = Vec::new();

        for service in &analysis.services {
            if matches!(service.service_type, ServiceType::Database) {
                let confidence = self.calculate_database_confidence(service);

                if confidence > 0.8 {
                    let production_pattern = self.create_database_production_pattern(service);
                    let recommendations = self.generate_database_recommendations(service);

                    patterns.push(DetectedPattern {
                        pattern_type: PatternType::Database,
                        services: vec![service.name.clone()],
                        confidence,
                        production_pattern: ProductionPattern::DatabasePattern(production_pattern),
                        recommendations,
                    });
                }
            }
        }

        Ok(patterns)
    }

    fn detect_cache_patterns(
        &self,
        analysis: &DockerComposeAnalysis,
    ) -> Result<Vec<DetectedPattern>> {
        let mut patterns = Vec::new();

        for service in &analysis.services {
            if matches!(service.service_type, ServiceType::Cache) {
                let confidence = self.calculate_cache_confidence(service);

                if confidence > 0.8 {
                    let production_pattern = self.create_cache_production_pattern(service);
                    let recommendations = self.generate_cache_recommendations(service);

                    patterns.push(DetectedPattern {
                        pattern_type: PatternType::Cache,
                        services: vec![service.name.clone()],
                        confidence,
                        production_pattern: ProductionPattern::CachePattern(production_pattern),
                        recommendations,
                    });
                }
            }
        }

        Ok(patterns)
    }

    fn detect_message_queue_patterns(
        &self,
        analysis: &DockerComposeAnalysis,
    ) -> Result<Vec<DetectedPattern>> {
        let mut patterns = Vec::new();

        for service in &analysis.services {
            if matches!(service.service_type, ServiceType::MessageQueue) {
                let confidence = self.calculate_message_queue_confidence(service);

                if confidence > 0.8 {
                    let production_pattern = self.create_message_queue_production_pattern(service);
                    let recommendations = self.generate_message_queue_recommendations(service);

                    patterns.push(DetectedPattern {
                        pattern_type: PatternType::MessageQueue,
                        services: vec![service.name.clone()],
                        confidence,
                        production_pattern: ProductionPattern::MessageQueuePattern(
                            production_pattern,
                        ),
                        recommendations,
                    });
                }
            }
        }

        Ok(patterns)
    }

    fn detect_load_balancer_patterns(
        &self,
        analysis: &DockerComposeAnalysis,
    ) -> Result<Vec<DetectedPattern>> {
        let mut patterns = Vec::new();

        for service in &analysis.services {
            if matches!(service.service_type, ServiceType::LoadBalancer) {
                let confidence = self.calculate_load_balancer_confidence(service);

                if confidence > 0.7 {
                    let production_pattern = self.create_load_balancer_production_pattern(service);
                    let recommendations = self.generate_load_balancer_recommendations(service);

                    patterns.push(DetectedPattern {
                        pattern_type: PatternType::LoadBalancer,
                        services: vec![service.name.clone()],
                        confidence,
                        production_pattern: ProductionPattern::LoadBalancerPattern(
                            production_pattern,
                        ),
                        recommendations,
                    });
                }
            }
        }

        Ok(patterns)
    }

    fn detect_architectural_patterns(
        &self,
        analysis: &DockerComposeAnalysis,
    ) -> Result<Vec<DetectedPattern>> {
        let mut patterns = Vec::new();

        // Three-tier architecture detection
        if self.has_three_tier_architecture(analysis) {
            patterns.push(DetectedPattern {
                pattern_type: PatternType::ThreeTierArchitecture,
                services: analysis.services.iter().map(|s| s.name.clone()).collect(),
                confidence: 0.9,
                production_pattern: ProductionPattern::WebAppPattern(
                    self.create_default_web_app_pattern(),
                ),
                recommendations: vec![
                    "Detected three-tier architecture (presentation, business, data)".to_string(),
                    "Consider implementing proper network segmentation".to_string(),
                    "Add load balancing for the presentation tier".to_string(),
                    "Implement database clustering for high availability".to_string(),
                ],
            });
        }

        // Microservices detection
        if analysis.services.len() >= 5 && self.has_microservices_characteristics(analysis) {
            patterns.push(DetectedPattern {
                pattern_type: PatternType::MicroservicesStack,
                services: analysis.services.iter().map(|s| s.name.clone()).collect(),
                confidence: 0.8,
                production_pattern: ProductionPattern::WebAppPattern(
                    self.create_microservices_pattern(),
                ),
                recommendations: vec![
                    "Detected microservices architecture".to_string(),
                    "Implement service discovery (e.g., Consul, Eureka)".to_string(),
                    "Add distributed tracing (e.g., Jaeger, Zipkin)".to_string(),
                    "Consider implementing circuit breakers".to_string(),
                    "Add centralized logging and monitoring".to_string(),
                ],
            });
        }

        // Monolith with database detection
        if analysis.services.len() <= 3 && self.has_monolith_characteristics(analysis) {
            patterns.push(DetectedPattern {
                pattern_type: PatternType::MonolithWithDatabase,
                services: analysis.services.iter().map(|s| s.name.clone()).collect(),
                confidence: 0.85,
                production_pattern: ProductionPattern::WebAppPattern(
                    self.create_monolith_pattern(),
                ),
                recommendations: vec![
                    "Detected monolithic architecture with database".to_string(),
                    "Consider implementing horizontal scaling for the application".to_string(),
                    "Add database backup and recovery procedures".to_string(),
                    "Implement proper resource limits and monitoring".to_string(),
                ],
            });
        }

        Ok(patterns)
    }

    pub fn calculate_web_app_confidence(&self, service: &ServiceAnalysis) -> f32 {
        let mut confidence = 0.0_f32;

        // Check image name
        for indicator in &self.web_app_indicators {
            if service.image.contains(indicator) {
                confidence += 0.4;
                break;
            }
        }

        // Check ports
        for port in &service.ports {
            if port.container_port == 80
                || port.container_port == 443
                || port.container_port == 8080
            {
                confidence += 0.3;
                break;
            }
        }

        // Check environment variables
        if service
            .environment
            .keys()
            .any(|k| k.contains("PORT") || k.contains("HOST"))
        {
            confidence += 0.2;
        }

        // Check service type
        if matches!(service.service_type, ServiceType::WebApp) {
            confidence += 0.1;
        }

        confidence.min(1.0_f32)
    }

    pub fn calculate_database_confidence(&self, service: &ServiceAnalysis) -> f32 {
        let mut confidence = 0.0_f32;

        // Check image name
        for indicator in &self.database_indicators {
            if service.image.contains(indicator) {
                confidence += 0.5;
                break;
            }
        }

        // Check for database-specific environment variables
        if service.environment.keys().any(|k| {
            k.contains("DATABASE")
                || k.contains("DB_")
                || k.contains("POSTGRES")
                || k.contains("MYSQL")
        }) {
            confidence += 0.3;
        }

        // Check for persistent volumes
        if service
            .volumes
            .iter()
            .any(|v| v.target.contains("/var/lib") || v.target.contains("/data"))
        {
            confidence += 0.2;
        }

        confidence.min(1.0_f32)
    }

    pub fn calculate_cache_confidence(&self, service: &ServiceAnalysis) -> f32 {
        let mut confidence = 0.0_f32;

        for indicator in &self.cache_indicators {
            if service.image.contains(indicator) {
                confidence += 0.6;
                break;
            }
        }

        if service
            .environment
            .keys()
            .any(|k| k.contains("REDIS") || k.contains("CACHE"))
        {
            confidence += 0.4;
        }

        confidence.min(1.0_f32)
    }

    fn calculate_message_queue_confidence(&self, service: &ServiceAnalysis) -> f32 {
        let mut confidence = 0.0_f32;

        for indicator in &self.message_queue_indicators {
            if service.image.contains(indicator) {
                confidence += 0.6;
                break;
            }
        }

        if service
            .environment
            .keys()
            .any(|k| k.contains("QUEUE") || k.contains("RABBITMQ") || k.contains("KAFKA"))
        {
            confidence += 0.4;
        }

        confidence.min(1.0_f32)
    }

    fn calculate_load_balancer_confidence(&self, service: &ServiceAnalysis) -> f32 {
        let mut confidence = 0.0_f32;

        for indicator in &self.load_balancer_indicators {
            if service.image.contains(indicator) {
                confidence += 0.5;
                break;
            }
        }

        // Check for load balancer ports
        if service
            .ports
            .iter()
            .any(|p| p.container_port == 80 || p.container_port == 443)
        {
            confidence += 0.3;
        }

        // Check for upstream configuration
        if service
            .environment
            .keys()
            .any(|k| k.contains("UPSTREAM") || k.contains("BACKEND"))
        {
            confidence += 0.2;
        }

        confidence.min(1.0_f32)
    }

    pub fn has_three_tier_architecture(&self, analysis: &DockerComposeAnalysis) -> bool {
        let has_web = analysis
            .services
            .iter()
            .any(|s| matches!(s.service_type, ServiceType::WebApp));
        let has_database = analysis
            .services
            .iter()
            .any(|s| matches!(s.service_type, ServiceType::Database));
        let has_business_logic = analysis.services.len() >= 3;

        has_web && has_database && has_business_logic
    }

    pub fn has_microservices_characteristics(&self, analysis: &DockerComposeAnalysis) -> bool {
        // Multiple services with different responsibilities
        let service_types: std::collections::HashSet<_> =
            analysis.services.iter().map(|s| &s.service_type).collect();

        service_types.len() >= 3 && analysis.services.iter().any(|s| !s.depends_on.is_empty())
    }

    fn has_monolith_characteristics(&self, analysis: &DockerComposeAnalysis) -> bool {
        let has_single_app = analysis
            .services
            .iter()
            .filter(|s| matches!(s.service_type, ServiceType::WebApp))
            .count()
            == 1;

        let has_database = analysis
            .services
            .iter()
            .any(|s| matches!(s.service_type, ServiceType::Database));

        has_single_app && has_database
    }

    fn create_web_app_production_pattern(&self, service: &ServiceAnalysis) -> WebAppPattern {
        WebAppPattern {
            enable_autoscaling: service.scaling_hints.horizontal_scaling,
            enable_ingress: true,
            enable_monitoring: true,
            enable_ssl: true,
            min_replicas: if service.scaling_hints.horizontal_scaling {
                2
            } else {
                1
            },
            max_replicas: if service.scaling_hints.horizontal_scaling {
                10
            } else {
                3
            },
            target_cpu_percentage: 70,
            health_check_enabled: service.health_check.is_some(),
            readiness_probe_enabled: true,
            resource_requests: ResourceRequests {
                cpu: "100m".to_string(),
                memory: "128Mi".to_string(),
            },
            resource_limits: ResourceLimits {
                cpu: "500m".to_string(),
                memory: "512Mi".to_string(),
            },
        }
    }

    fn create_database_production_pattern(&self, service: &ServiceAnalysis) -> DatabasePattern {
        DatabasePattern {
            enable_persistence: true,
            enable_backup: true,
            enable_replication: false,
            storage_class: "fast-ssd".to_string(),
            storage_size: if service.image.contains("postgres") {
                "20Gi"
            } else {
                "10Gi"
            }
            .to_string(),
            enable_network_policy: true,
            enable_secrets: true,
            enable_monitoring: true,
            backup_schedule: "0 2 * * *".to_string(), // Daily at 2 AM
            resource_requests: ResourceRequests {
                cpu: "500m".to_string(),
                memory: "1Gi".to_string(),
            },
            resource_limits: ResourceLimits {
                cpu: "2".to_string(),
                memory: "4Gi".to_string(),
            },
        }
    }

    fn create_cache_production_pattern(&self, _service: &ServiceAnalysis) -> CachePattern {
        CachePattern {
            enable_persistence: false,
            enable_clustering: false,
            memory_allocation: "512mb".to_string(),
            eviction_policy: "allkeys-lru".to_string(),
            enable_monitoring: true,
            resource_requests: ResourceRequests {
                cpu: "100m".to_string(),
                memory: "256Mi".to_string(),
            },
            resource_limits: ResourceLimits {
                cpu: "500m".to_string(),
                memory: "1Gi".to_string(),
            },
        }
    }

    fn create_message_queue_production_pattern(
        &self,
        _service: &ServiceAnalysis,
    ) -> MessageQueuePattern {
        MessageQueuePattern {
            enable_persistence: true,
            enable_clustering: false,
            enable_dead_letter_queue: true,
            queue_durability: true,
            message_ttl: Some("24h".to_string()),
            resource_requests: ResourceRequests {
                cpu: "200m".to_string(),
                memory: "512Mi".to_string(),
            },
            resource_limits: ResourceLimits {
                cpu: "1".to_string(),
                memory: "2Gi".to_string(),
            },
        }
    }

    fn create_load_balancer_production_pattern(
        &self,
        _service: &ServiceAnalysis,
    ) -> LoadBalancerPattern {
        LoadBalancerPattern {
            algorithm: "round_robin".to_string(),
            health_check_enabled: true,
            ssl_termination: true,
            rate_limiting: true,
            enable_logging: true,
        }
    }

    fn create_default_web_app_pattern(&self) -> WebAppPattern {
        WebAppPattern {
            enable_autoscaling: true,
            enable_ingress: true,
            enable_monitoring: true,
            enable_ssl: true,
            min_replicas: 2,
            max_replicas: 10,
            target_cpu_percentage: 70,
            health_check_enabled: true,
            readiness_probe_enabled: true,
            resource_requests: ResourceRequests {
                cpu: "100m".to_string(),
                memory: "128Mi".to_string(),
            },
            resource_limits: ResourceLimits {
                cpu: "500m".to_string(),
                memory: "512Mi".to_string(),
            },
        }
    }

    fn create_microservices_pattern(&self) -> WebAppPattern {
        WebAppPattern {
            enable_autoscaling: true,
            enable_ingress: true,
            enable_monitoring: true,
            enable_ssl: true,
            min_replicas: 2,
            max_replicas: 5,
            target_cpu_percentage: 80,
            health_check_enabled: true,
            readiness_probe_enabled: true,
            resource_requests: ResourceRequests {
                cpu: "50m".to_string(),
                memory: "64Mi".to_string(),
            },
            resource_limits: ResourceLimits {
                cpu: "200m".to_string(),
                memory: "256Mi".to_string(),
            },
        }
    }

    fn create_monolith_pattern(&self) -> WebAppPattern {
        WebAppPattern {
            enable_autoscaling: true,
            enable_ingress: true,
            enable_monitoring: true,
            enable_ssl: true,
            min_replicas: 2,
            max_replicas: 8,
            target_cpu_percentage: 60,
            health_check_enabled: true,
            readiness_probe_enabled: true,
            resource_requests: ResourceRequests {
                cpu: "200m".to_string(),
                memory: "256Mi".to_string(),
            },
            resource_limits: ResourceLimits {
                cpu: "1".to_string(),
                memory: "1Gi".to_string(),
            },
        }
    }

    fn generate_web_app_recommendations(&self, service: &ServiceAnalysis) -> Vec<String> {
        let mut recommendations = Vec::new();

        if service.health_check.is_none() {
            recommendations.push("Add health check endpoints (/health, /ready)".to_string());
        }

        if service.resource_limits.memory.is_none() {
            recommendations.push("Define memory limits to prevent OOM kills".to_string());
        }

        if service.scaling_hints.horizontal_scaling {
            recommendations.push("Enable Horizontal Pod Autoscaler (HPA)".to_string());
        }

        if !service.ports.iter().any(|p| p.container_port == 443) {
            recommendations.push("Consider enabling HTTPS/TLS".to_string());
        }

        recommendations.push("Implement proper logging and monitoring".to_string());
        recommendations.push("Add ingress controller for external access".to_string());

        recommendations
    }

    fn generate_database_recommendations(&self, service: &ServiceAnalysis) -> Vec<String> {
        let mut recommendations = Vec::new();

        recommendations
            .push("Enable persistent storage with appropriate storage class".to_string());
        recommendations.push("Implement database backup strategy".to_string());
        recommendations.push("Use Kubernetes secrets for database credentials".to_string());
        recommendations.push("Apply network policies to restrict database access".to_string());

        if service.resource_limits.memory.is_none() {
            recommendations.push("Set appropriate memory limits for database workload".to_string());
        }

        if service.image.contains("postgres") {
            recommendations
                .push("Consider using PostgreSQL operator for advanced features".to_string());
        } else if service.image.contains("mysql") {
            recommendations.push("Consider using MySQL operator for clustering".to_string());
        }

        recommendations.push("Enable database monitoring and alerting".to_string());

        recommendations
    }

    fn generate_cache_recommendations(&self, service: &ServiceAnalysis) -> Vec<String> {
        let mut recommendations = Vec::new();

        if service.image.contains("redis") {
            recommendations
                .push("Configure Redis persistence if data durability is required".to_string());
            recommendations.push("Set appropriate eviction policy based on use case".to_string());
            recommendations.push("Consider Redis Cluster for high availability".to_string());
        }

        recommendations
            .push("Set memory limits to prevent cache from consuming all memory".to_string());
        recommendations.push("Enable cache monitoring and metrics".to_string());
        recommendations.push("Consider implementing cache warming strategies".to_string());

        recommendations
    }

    fn generate_message_queue_recommendations(&self, _service: &ServiceAnalysis) -> Vec<String> {
        vec![
            "Enable message persistence for durability".to_string(),
            "Configure dead letter queues for failed messages".to_string(),
            "Set appropriate message TTL".to_string(),
            "Implement proper queue monitoring".to_string(),
            "Consider queue clustering for high availability".to_string(),
        ]
    }

    fn generate_load_balancer_recommendations(&self, _service: &ServiceAnalysis) -> Vec<String> {
        vec![
            "Configure health checks for backend services".to_string(),
            "Enable SSL termination at load balancer".to_string(),
            "Implement rate limiting to prevent abuse".to_string(),
            "Enable access logging for debugging".to_string(),
            "Consider implementing circuit breaker pattern".to_string(),
        ]
    }
}
