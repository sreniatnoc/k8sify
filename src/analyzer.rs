use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerComposeAnalysis {
    pub version: String,
    pub services: Vec<ServiceAnalysis>,
    pub volumes: Vec<VolumeAnalysis>,
    pub networks: Vec<NetworkAnalysis>,
    pub secrets: Vec<SecretAnalysis>,
    pub configs: Vec<ConfigAnalysis>,
    pub complexity_score: u32,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAnalysis {
    pub name: String,
    pub image: String,
    pub ports: Vec<PortMapping>,
    pub environment: HashMap<String, String>,
    pub volumes: Vec<VolumeMount>,
    pub depends_on: Vec<String>,
    pub networks: Vec<String>,
    pub restart_policy: String,
    pub resource_limits: ResourceLimits,
    pub health_check: Option<HealthCheck>,
    pub service_type: ServiceType,
    pub scaling_hints: ScalingHints,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub host_port: Option<u16>,
    pub container_port: u16,
    pub protocol: String,
    pub exposed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    pub source: String,
    pub target: String,
    pub mount_type: VolumeMountType,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VolumeMountType {
    Volume,
    Bind,
    Tmpfs,
    NamedPipe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub memory: Option<String>,
    pub cpu: Option<String>,
    pub cpu_shares: Option<u32>,
    pub pids_limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub test: Vec<String>,
    pub interval: Option<String>,
    pub timeout: Option<String>,
    pub retries: Option<u32>,
    pub start_period: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ServiceType {
    WebApp,
    Database,
    Cache,
    MessageQueue,
    LoadBalancer,
    Proxy,
    Worker,
    CronJob,
    Storage,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingHints {
    pub horizontal_scaling: bool,
    pub vertical_scaling: bool,
    pub stateful: bool,
    pub session_affinity: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeAnalysis {
    pub name: String,
    pub driver: String,
    pub driver_opts: HashMap<String, String>,
    pub external: bool,
    pub size_estimate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAnalysis {
    pub name: String,
    pub driver: String,
    pub driver_opts: HashMap<String, String>,
    pub external: bool,
    pub ipam: Option<IpamConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpamConfig {
    pub driver: String,
    pub config: Vec<IpamSubnet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpamSubnet {
    pub subnet: String,
    pub gateway: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAnalysis {
    pub name: String,
    pub file: Option<String>,
    pub external: bool,
    pub usage_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigAnalysis {
    pub name: String,
    pub file: Option<String>,
    pub external: bool,
    pub usage_count: u32,
}

pub struct DockerComposeAnalyzer {
    service_type_patterns: HashMap<String, ServiceType>,
}

impl Default for DockerComposeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl DockerComposeAnalyzer {
    pub fn new() -> Self {
        let mut service_type_patterns = HashMap::new();

        service_type_patterns.insert("nginx".to_string(), ServiceType::WebApp);
        service_type_patterns.insert("apache".to_string(), ServiceType::WebApp);
        service_type_patterns.insert("httpd".to_string(), ServiceType::WebApp);
        service_type_patterns.insert("postgres".to_string(), ServiceType::Database);
        service_type_patterns.insert("mysql".to_string(), ServiceType::Database);
        service_type_patterns.insert("mariadb".to_string(), ServiceType::Database);
        service_type_patterns.insert("mongodb".to_string(), ServiceType::Database);
        service_type_patterns.insert("redis".to_string(), ServiceType::Cache);
        service_type_patterns.insert("memcached".to_string(), ServiceType::Cache);
        service_type_patterns.insert("rabbitmq".to_string(), ServiceType::MessageQueue);
        service_type_patterns.insert("kafka".to_string(), ServiceType::MessageQueue);
        service_type_patterns.insert("traefik".to_string(), ServiceType::LoadBalancer);
        service_type_patterns.insert("haproxy".to_string(), ServiceType::LoadBalancer);
        service_type_patterns.insert("minio".to_string(), ServiceType::Storage);

        Self {
            service_type_patterns,
        }
    }

    pub async fn analyze(&self, compose_file: &Path) -> Result<DockerComposeAnalysis> {
        let content = tokio::fs::read_to_string(compose_file)
            .await
            .context("Failed to read docker-compose file")?;

        let compose: Value =
            serde_yaml::from_str(&content).context("Failed to parse docker-compose file")?;

        let version = compose
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("3.8")
            .to_string();

        let services = self.analyze_services(&compose).await?;
        let volumes = self.analyze_volumes(&compose).await?;
        let networks = self.analyze_networks(&compose).await?;
        let secrets = self.analyze_secrets(&compose).await?;
        let configs = self.analyze_configs(&compose).await?;

        let complexity_score = self.calculate_complexity_score(&services, &volumes, &networks);
        let recommendations = self.generate_recommendations(&services, &volumes, &networks);

        Ok(DockerComposeAnalysis {
            version,
            services,
            volumes,
            networks,
            secrets,
            configs,
            complexity_score,
            recommendations,
        })
    }

    async fn analyze_services(&self, compose: &Value) -> Result<Vec<ServiceAnalysis>> {
        let services_section = compose
            .get("services")
            .context("No services section found")?
            .as_mapping()
            .context("Services section is not a mapping")?;

        let mut services = Vec::new();

        for (service_name, service_config) in services_section {
            let name = service_name.as_str().unwrap_or("unknown").to_string();
            let image = service_config
                .get("image")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let ports = self.parse_ports(service_config)?;
            let environment = self.parse_environment(service_config)?;
            let volumes = self.parse_volume_mounts(service_config)?;
            let depends_on = self.parse_depends_on(service_config)?;
            let networks = self.parse_networks(service_config)?;
            let restart_policy = self.parse_restart_policy(service_config)?;
            let resource_limits = self.parse_resource_limits(service_config)?;
            let health_check = self.parse_health_check(service_config)?;
            let service_type = self.detect_service_type(&image, &ports, &environment);
            let scaling_hints = self.analyze_scaling_hints(&service_type, &volumes, &environment);

            services.push(ServiceAnalysis {
                name,
                image,
                ports,
                environment,
                volumes,
                depends_on,
                networks,
                restart_policy,
                resource_limits,
                health_check,
                service_type,
                scaling_hints,
            });
        }

        Ok(services)
    }

    fn detect_service_type(
        &self,
        image: &str,
        ports: &[PortMapping],
        environment: &HashMap<String, String>,
    ) -> ServiceType {
        for (pattern, service_type) in &self.service_type_patterns {
            if image.contains(pattern) {
                return service_type.clone();
            }
        }

        if ports
            .iter()
            .any(|p| p.container_port == 80 || p.container_port == 443 || p.container_port == 8080)
        {
            return ServiceType::WebApp;
        }

        if environment
            .keys()
            .any(|k| k.contains("DATABASE") || k.contains("DB_"))
        {
            return ServiceType::Database;
        }

        if environment
            .keys()
            .any(|k| k.contains("REDIS") || k.contains("CACHE"))
        {
            return ServiceType::Cache;
        }

        ServiceType::Unknown
    }

    fn analyze_scaling_hints(
        &self,
        service_type: &ServiceType,
        volumes: &[VolumeMount],
        environment: &HashMap<String, String>,
    ) -> ScalingHints {
        let stateful = matches!(service_type, ServiceType::Database | ServiceType::Storage)
            || volumes
                .iter()
                .any(|v| matches!(v.mount_type, VolumeMountType::Volume));

        let horizontal_scaling =
            !stateful && !matches!(service_type, ServiceType::Database | ServiceType::Storage);

        let vertical_scaling = matches!(service_type, ServiceType::Database | ServiceType::Cache);

        let session_affinity = environment.contains_key("SESSION_STORE")
            || environment.contains_key("SESSION_SECRET")
            || matches!(service_type, ServiceType::Database);

        ScalingHints {
            horizontal_scaling,
            vertical_scaling,
            stateful,
            session_affinity,
        }
    }

    fn parse_ports(&self, service_config: &Value) -> Result<Vec<PortMapping>> {
        let mut ports = Vec::new();

        if let Some(ports_value) = service_config.get("ports") {
            if let Some(ports_array) = ports_value.as_sequence() {
                for port_value in ports_array {
                    if let Some(port_str) = port_value.as_str() {
                        let port_mapping = self.parse_port_string(port_str)?;
                        ports.push(port_mapping);
                    }
                }
            }
        }

        if let Some(expose_value) = service_config.get("expose") {
            if let Some(expose_array) = expose_value.as_sequence() {
                for expose_port in expose_array {
                    if let Some(port_str) = expose_port.as_str() {
                        let port: u16 = port_str.parse().unwrap_or(8080);
                        ports.push(PortMapping {
                            host_port: None,
                            container_port: port,
                            protocol: "TCP".to_string(),
                            exposed: true,
                        });
                    }
                }
            }
        }

        Ok(ports)
    }

    fn parse_port_string(&self, port_str: &str) -> Result<PortMapping> {
        let parts: Vec<&str> = port_str.split(':').collect();

        match parts.len() {
            1 => {
                let container_port = parts[0].parse::<u16>().context("Invalid container port")?;
                Ok(PortMapping {
                    host_port: None,
                    container_port,
                    protocol: "TCP".to_string(),
                    exposed: false,
                })
            }
            2 => {
                let host_port = parts[0].parse::<u16>().ok();
                let container_port = parts[1].parse::<u16>().context("Invalid container port")?;
                Ok(PortMapping {
                    host_port,
                    container_port,
                    protocol: "TCP".to_string(),
                    exposed: false,
                })
            }
            _ => Err(anyhow::anyhow!("Invalid port format: {}", port_str)),
        }
    }

    fn parse_environment(&self, service_config: &Value) -> Result<HashMap<String, String>> {
        let mut environment = HashMap::new();

        if let Some(env_value) = service_config.get("environment") {
            match env_value {
                Value::Mapping(env_map) => {
                    for (key, value) in env_map {
                        if let (Some(k), Some(v)) = (key.as_str(), value.as_str()) {
                            environment.insert(k.to_string(), v.to_string());
                        }
                    }
                }
                Value::Sequence(env_array) => {
                    for env_item in env_array {
                        if let Some(env_str) = env_item.as_str() {
                            if let Some((key, value)) = env_str.split_once('=') {
                                environment.insert(key.to_string(), value.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(environment)
    }

    fn parse_volume_mounts(&self, service_config: &Value) -> Result<Vec<VolumeMount>> {
        let mut volumes = Vec::new();

        if let Some(volumes_value) = service_config.get("volumes") {
            if let Some(volumes_array) = volumes_value.as_sequence() {
                for volume_value in volumes_array {
                    if let Some(volume_str) = volume_value.as_str() {
                        let volume_mount = self.parse_volume_string(volume_str)?;
                        volumes.push(volume_mount);
                    }
                }
            }
        }

        Ok(volumes)
    }

    fn parse_volume_string(&self, volume_str: &str) -> Result<VolumeMount> {
        let parts: Vec<&str> = volume_str.split(':').collect();

        if parts.len() >= 2 {
            let source = parts[0].to_string();
            let target = parts[1].to_string();
            let read_only = parts.get(2).is_some_and(|&opt| opt.contains("ro"));

            let mount_type =
                if source.starts_with('/') || source.starts_with("./") || source.starts_with("../")
                {
                    VolumeMountType::Bind
                } else {
                    VolumeMountType::Volume
                };

            Ok(VolumeMount {
                source,
                target,
                mount_type,
                read_only,
            })
        } else {
            Err(anyhow::anyhow!("Invalid volume format: {}", volume_str))
        }
    }

    fn parse_depends_on(&self, service_config: &Value) -> Result<Vec<String>> {
        let mut depends_on = Vec::new();

        if let Some(depends_value) = service_config.get("depends_on") {
            match depends_value {
                Value::Sequence(deps_array) => {
                    for dep in deps_array {
                        if let Some(dep_str) = dep.as_str() {
                            depends_on.push(dep_str.to_string());
                        }
                    }
                }
                Value::Mapping(deps_map) => {
                    for (dep_name, _) in deps_map {
                        if let Some(dep_str) = dep_name.as_str() {
                            depends_on.push(dep_str.to_string());
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(depends_on)
    }

    fn parse_networks(&self, service_config: &Value) -> Result<Vec<String>> {
        let mut networks = Vec::new();

        if let Some(networks_value) = service_config.get("networks") {
            match networks_value {
                Value::Sequence(networks_array) => {
                    for network in networks_array {
                        if let Some(network_str) = network.as_str() {
                            networks.push(network_str.to_string());
                        }
                    }
                }
                Value::Mapping(networks_map) => {
                    for (network_name, _) in networks_map {
                        if let Some(network_str) = network_name.as_str() {
                            networks.push(network_str.to_string());
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(networks)
    }

    fn parse_restart_policy(&self, service_config: &Value) -> Result<String> {
        Ok(service_config
            .get("restart")
            .and_then(|v| v.as_str())
            .unwrap_or("no")
            .to_string())
    }

    fn parse_resource_limits(&self, service_config: &Value) -> Result<ResourceLimits> {
        let mut limits = ResourceLimits {
            memory: None,
            cpu: None,
            cpu_shares: None,
            pids_limit: None,
        };

        if let Some(deploy) = service_config.get("deploy") {
            if let Some(resources) = deploy.get("resources") {
                if let Some(limits_section) = resources.get("limits") {
                    limits.memory = limits_section
                        .get("memory")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    limits.cpu = limits_section
                        .get("cpus")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
        }

        limits.cpu_shares = service_config
            .get("cpu_shares")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        limits.pids_limit = service_config
            .get("pids_limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        Ok(limits)
    }

    fn parse_health_check(&self, service_config: &Value) -> Result<Option<HealthCheck>> {
        if let Some(healthcheck) = service_config.get("healthcheck") {
            let test = if let Some(test_value) = healthcheck.get("test") {
                match test_value {
                    Value::String(test_str) => vec![test_str.clone()],
                    Value::Sequence(test_array) => test_array
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect(),
                    _ => vec![],
                }
            } else {
                vec![]
            };

            let interval = healthcheck
                .get("interval")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let timeout = healthcheck
                .get("timeout")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let retries = healthcheck
                .get("retries")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32);
            let start_period = healthcheck
                .get("start_period")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            return Ok(Some(HealthCheck {
                test,
                interval,
                timeout,
                retries,
                start_period,
            }));
        }

        Ok(None)
    }

    async fn analyze_volumes(&self, compose: &Value) -> Result<Vec<VolumeAnalysis>> {
        let mut volumes = Vec::new();

        if let Some(volumes_section) = compose.get("volumes") {
            if let Some(volumes_map) = volumes_section.as_mapping() {
                for (volume_name, volume_config) in volumes_map {
                    let name = volume_name.as_str().unwrap_or("unknown").to_string();

                    let (driver, driver_opts, external) =
                        if let Some(config) = volume_config.as_mapping() {
                            let driver = config
                                .get("driver")
                                .and_then(|v| v.as_str())
                                .unwrap_or("local")
                                .to_string();

                            let driver_opts = if let Some(opts) = config.get("driver_opts") {
                                if let Some(opts_map) = opts.as_mapping() {
                                    opts_map
                                        .iter()
                                        .filter_map(|(k, v)| {
                                            Some((k.as_str()?.to_string(), v.as_str()?.to_string()))
                                        })
                                        .collect()
                                } else {
                                    HashMap::new()
                                }
                            } else {
                                HashMap::new()
                            };

                            let external = config
                                .get("external")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);

                            (driver, driver_opts, external)
                        } else {
                            ("local".to_string(), HashMap::new(), false)
                        };

                    volumes.push(VolumeAnalysis {
                        name,
                        driver,
                        driver_opts,
                        external,
                        size_estimate: None,
                    });
                }
            }
        }

        Ok(volumes)
    }

    async fn analyze_networks(&self, compose: &Value) -> Result<Vec<NetworkAnalysis>> {
        let mut networks = Vec::new();

        if let Some(networks_section) = compose.get("networks") {
            if let Some(networks_map) = networks_section.as_mapping() {
                for (network_name, network_config) in networks_map {
                    let name = network_name.as_str().unwrap_or("unknown").to_string();

                    let (driver, driver_opts, external, ipam) = if let Some(config) =
                        network_config.as_mapping()
                    {
                        let driver = config
                            .get("driver")
                            .and_then(|v| v.as_str())
                            .unwrap_or("bridge")
                            .to_string();

                        let driver_opts = if let Some(opts) = config.get("driver_opts") {
                            if let Some(opts_map) = opts.as_mapping() {
                                opts_map
                                    .iter()
                                    .filter_map(|(k, v)| {
                                        Some((k.as_str()?.to_string(), v.as_str()?.to_string()))
                                    })
                                    .collect()
                            } else {
                                HashMap::new()
                            }
                        } else {
                            HashMap::new()
                        };

                        let external = config
                            .get("external")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);

                        let ipam = config.get("ipam").and_then(|ipam_config| {
                            if let Some(ipam_map) = ipam_config.as_mapping() {
                                let driver = ipam_map
                                    .get("driver")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("default")
                                    .to_string();

                                let config = if let Some(config_array) =
                                    ipam_map.get("config").and_then(|v| v.as_sequence())
                                {
                                    config_array
                                        .iter()
                                        .filter_map(|subnet_config| {
                                            if let Some(subnet_map) = subnet_config.as_mapping() {
                                                let subnet = subnet_map
                                                    .get("subnet")
                                                    .and_then(|v| v.as_str())?
                                                    .to_string();
                                                let gateway = subnet_map
                                                    .get("gateway")
                                                    .and_then(|v| v.as_str())
                                                    .map(|s| s.to_string());
                                                Some(IpamSubnet { subnet, gateway })
                                            } else {
                                                None
                                            }
                                        })
                                        .collect()
                                } else {
                                    vec![]
                                };

                                Some(IpamConfig { driver, config })
                            } else {
                                None
                            }
                        });

                        (driver, driver_opts, external, ipam)
                    } else {
                        ("bridge".to_string(), HashMap::new(), false, None)
                    };

                    networks.push(NetworkAnalysis {
                        name,
                        driver,
                        driver_opts,
                        external,
                        ipam,
                    });
                }
            }
        }

        Ok(networks)
    }

    async fn analyze_secrets(&self, compose: &Value) -> Result<Vec<SecretAnalysis>> {
        let mut secrets = Vec::new();

        if let Some(secrets_section) = compose.get("secrets") {
            if let Some(secrets_map) = secrets_section.as_mapping() {
                for (secret_name, secret_config) in secrets_map {
                    let name = secret_name.as_str().unwrap_or("unknown").to_string();

                    let (file, external) = if let Some(config) = secret_config.as_mapping() {
                        let file = config
                            .get("file")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());

                        let external = config
                            .get("external")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);

                        (file, external)
                    } else {
                        (None, false)
                    };

                    secrets.push(SecretAnalysis {
                        name,
                        file,
                        external,
                        usage_count: 0,
                    });
                }
            }
        }

        Ok(secrets)
    }

    async fn analyze_configs(&self, compose: &Value) -> Result<Vec<ConfigAnalysis>> {
        let mut configs = Vec::new();

        if let Some(configs_section) = compose.get("configs") {
            if let Some(configs_map) = configs_section.as_mapping() {
                for (config_name, config_config) in configs_map {
                    let name = config_name.as_str().unwrap_or("unknown").to_string();

                    let (file, external) = if let Some(config) = config_config.as_mapping() {
                        let file = config
                            .get("file")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());

                        let external = config
                            .get("external")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);

                        (file, external)
                    } else {
                        (None, false)
                    };

                    configs.push(ConfigAnalysis {
                        name,
                        file,
                        external,
                        usage_count: 0,
                    });
                }
            }
        }

        Ok(configs)
    }

    pub fn calculate_complexity_score(
        &self,
        services: &[ServiceAnalysis],
        volumes: &[VolumeAnalysis],
        networks: &[NetworkAnalysis],
    ) -> u32 {
        let mut score = 0;

        score += services.len() as u32 * 10;
        score += volumes.len() as u32 * 5;
        score += networks.len() as u32 * 3;

        for service in services {
            score += service.depends_on.len() as u32 * 2;
            score += service.ports.len() as u32;
            score += service.volumes.len() as u32;

            if service.health_check.is_some() {
                score += 5;
            }

            if matches!(
                service.service_type,
                ServiceType::Database | ServiceType::Storage
            ) {
                score += 10;
            }
        }

        score
    }

    fn generate_recommendations(
        &self,
        services: &[ServiceAnalysis],
        _volumes: &[VolumeAnalysis],
        _networks: &[NetworkAnalysis],
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        for service in services {
            if service.health_check.is_none()
                && matches!(
                    service.service_type,
                    ServiceType::WebApp | ServiceType::Database
                )
            {
                recommendations.push(format!("Add health check for service '{}'", service.name));
            }

            if service.resource_limits.memory.is_none() || service.resource_limits.cpu.is_none() {
                recommendations.push(format!(
                    "Define resource limits for service '{}'",
                    service.name
                ));
            }

            if service.scaling_hints.stateful && service.scaling_hints.horizontal_scaling {
                recommendations.push(format!(
                    "Service '{}' appears stateful but configured for horizontal scaling",
                    service.name
                ));
            }

            if matches!(service.service_type, ServiceType::Database)
                && !service
                    .volumes
                    .iter()
                    .any(|v| matches!(v.mount_type, VolumeMountType::Volume))
            {
                recommendations.push(format!(
                    "Database service '{}' should use persistent volumes",
                    service.name
                ));
            }
        }

        if services.len() > 10 {
            recommendations.push(
                "Consider breaking down the application into smaller microservices".to_string(),
            );
        }

        recommendations
    }

    pub fn print_analysis_table(&self, analysis: &DockerComposeAnalysis) -> Result<()> {
        println!("{}", "📊 Docker Compose Analysis".bold().blue());
        println!("Version: {}", analysis.version.yellow());
        println!(
            "Complexity Score: {}",
            analysis.complexity_score.to_string().red()
        );
        println!();

        println!("{}", "🔧 Services:".bold().green());
        for service in &analysis.services {
            println!(
                "  {} {} ({})",
                "•".blue(),
                service.name.bold(),
                format!("{:?}", service.service_type).yellow()
            );
            println!("    Image: {}", service.image.cyan());
            if !service.ports.is_empty() {
                println!(
                    "    Ports: {}",
                    service
                        .ports
                        .iter()
                        .map(|p| format!(
                            "{}:{}",
                            p.host_port.map_or("*".to_string(), |hp| hp.to_string()),
                            p.container_port
                        ))
                        .collect::<Vec<_>>()
                        .join(", ")
                        .yellow()
                );
            }
            if !service.depends_on.is_empty() {
                println!(
                    "    Depends on: {}",
                    service.depends_on.join(", ").magenta()
                );
            }
            println!();
        }

        if !analysis.volumes.is_empty() {
            println!("{}", "💾 Volumes:".bold().green());
            for volume in &analysis.volumes {
                println!(
                    "  {} {} ({})",
                    "•".blue(),
                    volume.name.bold(),
                    volume.driver.yellow()
                );
            }
            println!();
        }

        if !analysis.networks.is_empty() {
            println!("{}", "🌐 Networks:".bold().green());
            for network in &analysis.networks {
                println!(
                    "  {} {} ({})",
                    "•".blue(),
                    network.name.bold(),
                    network.driver.yellow()
                );
            }
            println!();
        }

        if !analysis.recommendations.is_empty() {
            println!("{}", "💡 Recommendations:".bold().yellow());
            for rec in &analysis.recommendations {
                println!("  {} {}", "•".yellow(), rec);
            }
        }

        Ok(())
    }
}
