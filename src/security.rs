use anyhow::Result;
use colored::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::analyzer::{DockerComposeAnalysis, ServiceAnalysis, ServiceType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFindings {
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub findings: Vec<SecurityFinding>,
    pub compliance_score: f32,
    pub recommendations: Vec<SecurityRecommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: SecurityCategory,
    pub affected_services: Vec<String>,
    pub remediation: String,
    pub cwe_id: Option<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityCategory {
    Authentication,
    Authorization,
    DataProtection,
    NetworkSecurity,
    ConfigurationSecurity,
    SecretManagement,
    ContainerSecurity,
    ImageSecurity,
    RuntimeSecurity,
    ComplianceSecurity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRecommendation {
    pub title: String,
    pub description: String,
    pub priority: Priority,
    pub implementation_effort: ImplementationEffort,
    pub security_impact: SecurityImpact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImplementationEffort {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityImpact {
    High,
    Medium,
    Low,
}

pub struct SecurityScanner {
    patterns: SecurityPatterns,
}

struct SecurityPatterns {
    secret_patterns: Vec<(Regex, String)>,
    insecure_protocols: Vec<String>,
    dangerous_permissions: Vec<String>,
    default_passwords: Vec<String>,
    sensitive_environment_vars: Vec<String>,
}

impl SecurityScanner {
    pub fn new() -> Self {
        let secret_patterns = vec![
            (Regex::new(r#"(?i)password\s*=\s*['"]([^'"]{8,})['"]"#).unwrap(), "Password in plaintext".to_string()),
            (Regex::new(r#"(?i)api[_-]?key\s*=\s*['"]([A-Za-z0-9]{20,})['"]"#).unwrap(), "API key in plaintext".to_string()),
            (Regex::new(r#"(?i)secret[_-]?key\s*=\s*['"]([A-Za-z0-9]{20,})['"]"#).unwrap(), "Secret key in plaintext".to_string()),
            (Regex::new(r#"(?i)token\s*=\s*['"]([A-Za-z0-9]{20,})['"]"#).unwrap(), "Token in plaintext".to_string()),
            (Regex::new(r"(?i)private[_-]?key").unwrap(), "Private key reference".to_string()),
            (Regex::new(r#"(?i)aws[_-]?access[_-]?key[_-]?id\s*=\s*['"]([A-Z0-9]{20})['"]"#).unwrap(), "AWS Access Key".to_string()),
            (Regex::new(r#"(?i)aws[_-]?secret[_-]?access[_-]?key\s*=\s*['"]([A-Za-z0-9/+=]{40})['"]"#).unwrap(), "AWS Secret Key".to_string()),
        ];

        let insecure_protocols = vec![
            "http://".to_string(),
            "ftp://".to_string(),
            "telnet://".to_string(),
            "ldap://".to_string(),
        ];

        let dangerous_permissions = vec![
            "privileged".to_string(),
            "cap_add".to_string(),
            "cap_drop".to_string(),
            "security_opt".to_string(),
        ];

        let default_passwords = vec![
            "password".to_string(),
            "admin".to_string(),
            "root".to_string(),
            "123456".to_string(),
            "password123".to_string(),
            "admin123".to_string(),
        ];

        let sensitive_environment_vars = vec![
            "PASSWORD".to_string(),
            "SECRET".to_string(),
            "KEY".to_string(),
            "TOKEN".to_string(),
            "API_KEY".to_string(),
            "PRIVATE_KEY".to_string(),
            "DATABASE_PASSWORD".to_string(),
            "DB_PASSWORD".to_string(),
        ];

        Self {
            patterns: SecurityPatterns {
                secret_patterns,
                insecure_protocols,
                dangerous_permissions,
                default_passwords,
                sensitive_environment_vars,
            },
        }
    }

    pub async fn scan(&self, analysis: &DockerComposeAnalysis) -> Result<SecurityFindings> {
        let mut findings = Vec::new();

        // Scan each service
        for service in &analysis.services {
            findings.extend(self.scan_service(service).await?);
        }

        // Scan volumes
        findings.extend(self.scan_volumes(analysis).await?);

        // Scan networks
        findings.extend(self.scan_networks(analysis).await?);

        // Scan secrets and configs
        findings.extend(self.scan_secrets_and_configs(analysis).await?);

        // Calculate counts
        let critical_count = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count() as u32;
        let high_count = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count() as u32;
        let medium_count = findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count() as u32;
        let low_count = findings.iter().filter(|f| matches!(f.severity, Severity::Low)).count() as u32;

        // Calculate compliance score
        let total_issues = critical_count + high_count + medium_count + low_count;
        let weighted_score = (critical_count * 4 + high_count * 3 + medium_count * 2 + low_count * 1) as f32;
        let max_possible_score = analysis.services.len() as f32 * 10.0; // Arbitrary max score
        let compliance_score = if max_possible_score > 0.0 {
            ((max_possible_score - weighted_score) / max_possible_score * 100.0).max(0.0)
        } else {
            100.0
        };

        let recommendations = self.generate_security_recommendations(&findings, analysis).await?;

        Ok(SecurityFindings {
            critical_count,
            high_count,
            medium_count,
            low_count,
            findings,
            compliance_score,
            recommendations,
        })
    }

    async fn scan_service(&self, service: &ServiceAnalysis) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Check for insecure image tags
        findings.extend(self.check_image_security(service)?);

        // Check environment variables for secrets
        findings.extend(self.check_environment_secrets(service)?);

        // Check for insecure protocols
        findings.extend(self.check_insecure_protocols(service)?);

        // Check port configurations
        findings.extend(self.check_port_security(service)?);

        // Check volume mounts
        findings.extend(self.check_volume_security(service)?);

        // Check resource limits
        findings.extend(self.check_resource_limits(service)?);

        // Check health checks
        findings.extend(self.check_health_check_security(service)?);

        Ok(findings)
    }

    fn check_image_security(&self, service: &ServiceAnalysis) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Check for latest tag
        if service.image.ends_with(":latest") || !service.image.contains(':') {
            findings.push(SecurityFinding {
                id: format!("IMG-001-{}", service.name),
                title: "Image uses 'latest' tag".to_string(),
                description: "Using 'latest' tag can lead to unpredictable deployments and security vulnerabilities.".to_string(),
                severity: Severity::Medium,
                category: SecurityCategory::ImageSecurity,
                affected_services: vec![service.name.clone()],
                remediation: "Use specific image tags or digest pinning for reproducible deployments.".to_string(),
                cwe_id: None,
                references: vec![
                    "https://docs.docker.com/develop/dev-best-practices/".to_string(),
                ],
            });
        }

        // Check for official images vs custom images
        if !self.is_official_image(&service.image) && !service.image.contains('/') {
            findings.push(SecurityFinding {
                id: format!("IMG-002-{}", service.name),
                title: "Non-official image detected".to_string(),
                description: "Using non-official images may introduce security vulnerabilities.".to_string(),
                severity: Severity::Low,
                category: SecurityCategory::ImageSecurity,
                affected_services: vec![service.name.clone()],
                remediation: "Use official images when possible, or scan custom images for vulnerabilities.".to_string(),
                cwe_id: None,
                references: vec![
                    "https://docs.docker.com/docker-hub/official_images/".to_string(),
                ],
            });
        }

        Ok(findings)
    }

    fn check_environment_secrets(&self, service: &ServiceAnalysis) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        for (key, value) in &service.environment {
            // Check for sensitive variable names
            for sensitive_var in &self.patterns.sensitive_environment_vars {
                if key.to_uppercase().contains(sensitive_var) {
                    findings.push(SecurityFinding {
                        id: format!("ENV-001-{}-{}", service.name, key),
                        title: format!("Sensitive environment variable: {}", key),
                        description: "Sensitive information should not be stored in environment variables.".to_string(),
                        severity: Severity::High,
                        category: SecurityCategory::SecretManagement,
                        affected_services: vec![service.name.clone()],
                        remediation: "Use Kubernetes secrets or external secret management systems.".to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        references: vec![
                            "https://kubernetes.io/docs/concepts/configuration/secret/".to_string(),
                        ],
                    });
                }
            }

            // Check for secret patterns in values
            for (pattern, description) in &self.patterns.secret_patterns {
                if pattern.is_match(value) {
                    findings.push(SecurityFinding {
                        id: format!("ENV-002-{}-{}", service.name, key),
                        title: format!("Secret detected in environment variable: {}", key),
                        description: format!("{} found in environment variable value.", description),
                        severity: Severity::Critical,
                        category: SecurityCategory::SecretManagement,
                        affected_services: vec![service.name.clone()],
                        remediation: "Move secrets to Kubernetes secret objects or external secret stores.".to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        references: vec![
                            "https://kubernetes.io/docs/concepts/configuration/secret/".to_string(),
                        ],
                    });
                }
            }

            // Check for default passwords
            for default_password in &self.patterns.default_passwords {
                if value.to_lowercase() == default_password.to_lowercase() {
                    findings.push(SecurityFinding {
                        id: format!("ENV-003-{}-{}", service.name, key),
                        title: format!("Default password detected: {}", key),
                        description: "Default passwords are easily guessable and should be changed.".to_string(),
                        severity: Severity::Critical,
                        category: SecurityCategory::Authentication,
                        affected_services: vec![service.name.clone()],
                        remediation: "Use strong, randomly generated passwords stored in Kubernetes secrets.".to_string(),
                        cwe_id: Some("CWE-521".to_string()),
                        references: vec![
                            "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication".to_string(),
                        ],
                    });
                }
            }
        }

        Ok(findings)
    }

    fn check_insecure_protocols(&self, service: &ServiceAnalysis) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        for (key, value) in &service.environment {
            for insecure_protocol in &self.patterns.insecure_protocols {
                if value.starts_with(insecure_protocol) {
                    findings.push(SecurityFinding {
                        id: format!("NET-001-{}-{}", service.name, key),
                        title: format!("Insecure protocol detected: {}", insecure_protocol),
                        description: format!("Insecure protocol {} found in environment variable {}.", insecure_protocol, key),
                        severity: Severity::High,
                        category: SecurityCategory::NetworkSecurity,
                        affected_services: vec![service.name.clone()],
                        remediation: "Use secure protocols (HTTPS, FTPS, SSH, LDAPS) instead.".to_string(),
                        cwe_id: Some("CWE-319".to_string()),
                        references: vec![
                            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure".to_string(),
                        ],
                    });
                }
            }
        }

        Ok(findings)
    }

    fn check_port_security(&self, service: &ServiceAnalysis) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        for port in &service.ports {
            // Check for exposed privileged ports
            if port.container_port < 1024 && port.host_port.is_some() {
                findings.push(SecurityFinding {
                    id: format!("PORT-001-{}-{}", service.name, port.container_port),
                    title: format!("Privileged port exposed: {}", port.container_port),
                    description: "Exposing privileged ports (< 1024) may require elevated permissions.".to_string(),
                    severity: Severity::Medium,
                    category: SecurityCategory::ConfigurationSecurity,
                    affected_services: vec![service.name.clone()],
                    remediation: "Use non-privileged ports (>= 1024) when possible.".to_string(),
                    cwe_id: None,
                    references: vec![],
                });
            }

            // Check for commonly attacked ports
            let dangerous_ports = vec![22, 23, 25, 53, 135, 139, 445, 3389];
            if dangerous_ports.contains(&port.container_port) && port.host_port.is_some() {
                findings.push(SecurityFinding {
                    id: format!("PORT-002-{}-{}", service.name, port.container_port),
                    title: format!("Dangerous port exposed: {}", port.container_port),
                    description: format!("Port {} is commonly targeted by attackers.", port.container_port),
                    severity: Severity::High,
                    category: SecurityCategory::NetworkSecurity,
                    affected_services: vec![service.name.clone()],
                    remediation: "Avoid exposing commonly attacked ports directly. Use a reverse proxy or VPN.".to_string(),
                    cwe_id: None,
                    references: vec![],
                });
            }
        }

        Ok(findings)
    }

    fn check_volume_security(&self, service: &ServiceAnalysis) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        for volume in &service.volumes {
            // Check for host path mounts
            if volume.source.starts_with('/') {
                findings.push(SecurityFinding {
                    id: format!("VOL-001-{}-{}", service.name, volume.source.replace('/', "-")),
                    title: "Host path volume mount detected".to_string(),
                    description: format!("Host path {} is mounted, which can pose security risks.", volume.source),
                    severity: Severity::Medium,
                    category: SecurityCategory::ContainerSecurity,
                    affected_services: vec![service.name.clone()],
                    remediation: "Use Kubernetes persistent volumes instead of host path mounts.".to_string(),
                    cwe_id: None,
                    references: vec![
                        "https://kubernetes.io/docs/concepts/storage/volumes/#hostpath".to_string(),
                    ],
                });
            }

            // Check for sensitive paths
            let sensitive_paths = vec!["/etc", "/var/run/docker.sock", "/proc", "/sys"];
            for sensitive_path in &sensitive_paths {
                if volume.source.starts_with(sensitive_path) || volume.target.starts_with(sensitive_path) {
                    findings.push(SecurityFinding {
                        id: format!("VOL-002-{}-{}", service.name, volume.source.replace('/', "-")),
                        title: format!("Sensitive path mounted: {}", sensitive_path),
                        description: format!("Mounting {} can provide access to sensitive system information.", sensitive_path),
                        severity: Severity::High,
                        category: SecurityCategory::ContainerSecurity,
                        affected_services: vec![service.name.clone()],
                        remediation: "Avoid mounting sensitive system paths unless absolutely necessary.".to_string(),
                        cwe_id: Some("CWE-22".to_string()),
                        references: vec![],
                    });
                }
            }

            // Check for writable mounts
            if !volume.read_only && volume.target.starts_with('/etc') {
                findings.push(SecurityFinding {
                    id: format!("VOL-003-{}-{}", service.name, volume.target.replace('/', "-")),
                    title: "Writable mount to sensitive directory".to_string(),
                    description: format!("Directory {} is mounted as writable, which can be dangerous.", volume.target),
                    severity: Severity::Medium,
                    category: SecurityCategory::ContainerSecurity,
                    affected_services: vec![service.name.clone()],
                    remediation: "Mount sensitive directories as read-only when possible.".to_string(),
                    cwe_id: None,
                    references: vec![],
                });
            }
        }

        Ok(findings)
    }

    fn check_resource_limits(&self, service: &ServiceAnalysis) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Check for missing resource limits
        if service.resource_limits.memory.is_none() {
            findings.push(SecurityFinding {
                id: format!("RES-001-{}", service.name),
                title: "Missing memory limits".to_string(),
                description: "Container without memory limits can consume all available memory.".to_string(),
                severity: Severity::Medium,
                category: SecurityCategory::RuntimeSecurity,
                affected_services: vec![service.name.clone()],
                remediation: "Set appropriate memory limits to prevent resource exhaustion attacks.".to_string(),
                cwe_id: Some("CWE-400".to_string()),
                references: vec![
                    "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/".to_string(),
                ],
            });
        }

        if service.resource_limits.cpu.is_none() {
            findings.push(SecurityFinding {
                id: format!("RES-002-{}", service.name),
                title: "Missing CPU limits".to_string(),
                description: "Container without CPU limits can consume all available CPU.".to_string(),
                severity: Severity::Low,
                category: SecurityCategory::RuntimeSecurity,
                affected_services: vec![service.name.clone()],
                remediation: "Set appropriate CPU limits to prevent resource exhaustion attacks.".to_string(),
                cwe_id: Some("CWE-400".to_string()),
                references: vec![
                    "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/".to_string(),
                ],
            });
        }

        Ok(findings)
    }

    fn check_health_check_security(&self, service: &ServiceAnalysis) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        if service.health_check.is_none() && matches!(service.service_type, ServiceType::WebApp | ServiceType::Database) {
            findings.push(SecurityFinding {
                id: format!("HC-001-{}", service.name),
                title: "Missing health checks".to_string(),
                description: "Services without health checks may continue running in a compromised state.".to_string(),
                severity: Severity::Low,
                category: SecurityCategory::RuntimeSecurity,
                affected_services: vec![service.name.clone()],
                remediation: "Implement health checks to detect and restart unhealthy containers.".to_string(),
                cwe_id: None,
                references: vec![
                    "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/".to_string(),
                ],
            });
        }

        Ok(findings)
    }

    async fn scan_volumes(&self, _analysis: &DockerComposeAnalysis) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Check for external volumes without proper validation
        // This would typically involve checking volume configurations
        // For now, we'll return empty findings

        Ok(findings)
    }

    async fn scan_networks(&self, analysis: &DockerComposeAnalysis) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Check if default network is being used
        if analysis.networks.is_empty() {
            findings.push(SecurityFinding {
                id: "NET-003".to_string(),
                title: "Using default network".to_string(),
                description: "Using the default network provides no network isolation.".to_string(),
                severity: Severity::Medium,
                category: SecurityCategory::NetworkSecurity,
                affected_services: analysis.services.iter().map(|s| s.name.clone()).collect(),
                remediation: "Create custom networks to provide network segmentation.".to_string(),
                cwe_id: None,
                references: vec![
                    "https://docs.docker.com/network/".to_string(),
                ],
            });
        }

        Ok(findings)
    }

    async fn scan_secrets_and_configs(&self, analysis: &DockerComposeAnalysis) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Check if secrets are defined but not used properly
        for secret in &analysis.secrets {
            if !secret.external && secret.file.is_some() {
                findings.push(SecurityFinding {
                    id: format!("SEC-001-{}", secret.name),
                    title: "Secret defined from file".to_string(),
                    description: format!("Secret '{}' is defined from a file, which may not be secure in Kubernetes.", secret.name),
                    severity: Severity::Medium,
                    category: SecurityCategory::SecretManagement,
                    affected_services: vec![],
                    remediation: "Use Kubernetes secret objects or external secret management systems.".to_string(),
                    cwe_id: None,
                    references: vec![
                        "https://kubernetes.io/docs/concepts/configuration/secret/".to_string(),
                    ],
                });
            }
        }

        Ok(findings)
    }

    async fn generate_security_recommendations(&self, findings: &[SecurityFinding], _analysis: &DockerComposeAnalysis) -> Result<Vec<SecurityRecommendation>> {
        let mut recommendations = Vec::new();

        let critical_count = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count();
        let high_count = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count();

        if critical_count > 0 || high_count > 0 {
            recommendations.push(SecurityRecommendation {
                title: "Implement Pod Security Standards".to_string(),
                description: "Enable Pod Security Standards to enforce security policies across your cluster.".to_string(),
                priority: Priority::High,
                implementation_effort: ImplementationEffort::Medium,
                security_impact: SecurityImpact::High,
            });
        }

        recommendations.push(SecurityRecommendation {
            title: "Enable Network Policies".to_string(),
            description: "Implement network policies to control traffic between pods and external endpoints.".to_string(),
            priority: Priority::High,
            implementation_effort: ImplementationEffort::Medium,
            security_impact: SecurityImpact::High,
        });

        recommendations.push(SecurityRecommendation {
            title: "Implement Secret Management".to_string(),
            description: "Use Kubernetes secrets or external secret management systems for sensitive data.".to_string(),
            priority: Priority::Critical,
            implementation_effort: ImplementationEffort::Low,
            security_impact: SecurityImpact::High,
        });

        recommendations.push(SecurityRecommendation {
            title: "Enable RBAC".to_string(),
            description: "Implement Role-Based Access Control to limit permissions and access.".to_string(),
            priority: Priority::High,
            implementation_effort: ImplementationEffort::High,
            security_impact: SecurityImpact::High,
        });

        recommendations.push(SecurityRecommendation {
            title: "Regular Security Scanning".to_string(),
            description: "Implement automated security scanning for container images and configurations.".to_string(),
            priority: Priority::Medium,
            implementation_effort: ImplementationEffort::Medium,
            security_impact: SecurityImpact::Medium,
        });

        Ok(recommendations)
    }

    fn is_official_image(&self, image: &str) -> bool {
        let official_images = vec![
            "nginx", "apache", "httpd", "postgres", "mysql", "mariadb", "mongodb", "redis",
            "memcached", "rabbitmq", "kafka", "elasticsearch", "node", "python", "java",
            "php", "ruby", "golang", "alpine", "ubuntu", "debian", "centos", "busybox",
        ];

        let image_name = if let Some(index) = image.find(':') {
            &image[..index]
        } else {
            image
        };

        official_images.iter().any(|&official| image_name == official)
    }

    pub fn print_findings_table(&self, findings: &SecurityFindings) -> Result<()> {
        println!("{}", "🔒 Security Scan Results".bold().red());
        println!("Compliance Score: {:.1}%", findings.compliance_score.to_string().green());
        println!();

        println!("{}", "📊 Finding Summary:".bold().white());
        println!("  Critical: {}", findings.critical_count.to_string().red());
        println!("  High: {}", findings.high_count.to_string().yellow());
        println!("  Medium: {}", findings.medium_count.to_string().blue());
        println!("  Low: {}", findings.low_count.to_string().green());
        println!();

        if !findings.findings.is_empty() {
            println!("{}", "🔍 Detailed Findings:".bold().white());
            for finding in &findings.findings {
                let severity_color = match finding.severity {
                    Severity::Critical => "red",
                    Severity::High => "yellow",
                    Severity::Medium => "blue",
                    Severity::Low => "green",
                    Severity::Info => "white",
                };

                println!("  {} {} ({})",
                    "•".blue(),
                    finding.title.bold(),
                    format!("{:?}", finding.severity).color(severity_color)
                );
                println!("    {}", finding.description.white());
                println!("    Services: {}", finding.affected_services.join(", ").cyan());
                println!("    Remediation: {}", finding.remediation.dim());
                println!();
            }
        }

        if !findings.recommendations.is_empty() {
            println!("{}", "💡 Security Recommendations:".bold().yellow());
            for (i, rec) in findings.recommendations.iter().enumerate() {
                println!("{}. {} ({:?} priority, {:?} effort)",
                    i + 1,
                    rec.title.white(),
                    rec.priority,
                    rec.implementation_effort
                );
                println!("   {}", rec.description.dim());
                println!();
            }
        }

        Ok(())
    }
}