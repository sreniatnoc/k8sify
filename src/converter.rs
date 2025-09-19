use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use handlebars::Handlebars;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;
use tokio::fs;

use crate::analyzer::{
    DockerComposeAnalysis, ServiceAnalysis, ServiceType, VolumeMount, VolumeMountType,
};
use crate::patterns::{DetectedPattern, ProductionPattern};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesManifests {
    pub deployments: Vec<DeploymentManifest>,
    pub services: Vec<ServiceManifest>,
    pub config_maps: Vec<ConfigMapManifest>,
    pub secrets: Vec<SecretManifest>,
    pub persistent_volume_claims: Vec<PvcManifest>,
    pub ingress: Vec<IngressManifest>,
    pub horizontal_pod_autoscalers: Vec<HpaManifest>,
    pub network_policies: Vec<NetworkPolicyManifest>,
    pub service_monitors: Vec<ServiceMonitorManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentManifest {
    pub name: String,
    pub content: String,
    pub service_type: ServiceType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceManifest {
    pub name: String,
    pub content: String,
    pub service_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigMapManifest {
    pub name: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretManifest {
    pub name: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PvcManifest {
    pub name: String,
    pub content: String,
    pub size: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressManifest {
    pub name: String,
    pub content: String,
    pub host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpaManifest {
    pub name: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicyManifest {
    pub name: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMonitorManifest {
    pub name: String,
    pub content: String,
}

pub struct KubernetesConverter {
    handlebars: Handlebars<'static>,
}

impl Default for KubernetesConverter {
    fn default() -> Self {
        Self::new()
    }
}

impl KubernetesConverter {
    pub fn new() -> Self {
        let mut handlebars = Handlebars::new();

        // Register templates
        handlebars
            .register_template_string("deployment", DEPLOYMENT_TEMPLATE)
            .unwrap();
        handlebars
            .register_template_string("service", SERVICE_TEMPLATE)
            .unwrap();
        handlebars
            .register_template_string("configmap", CONFIGMAP_TEMPLATE)
            .unwrap();
        handlebars
            .register_template_string("secret", SECRET_TEMPLATE)
            .unwrap();
        handlebars
            .register_template_string("pvc", PVC_TEMPLATE)
            .unwrap();
        handlebars
            .register_template_string("ingress", INGRESS_TEMPLATE)
            .unwrap();
        handlebars
            .register_template_string("hpa", HPA_TEMPLATE)
            .unwrap();
        handlebars
            .register_template_string("network_policy", NETWORK_POLICY_TEMPLATE)
            .unwrap();
        handlebars
            .register_template_string("service_monitor", SERVICE_MONITOR_TEMPLATE)
            .unwrap();

        Self { handlebars }
    }

    pub async fn convert_basic(
        &self,
        analysis: &DockerComposeAnalysis,
    ) -> Result<KubernetesManifests> {
        let mut manifests = KubernetesManifests {
            deployments: Vec::new(),
            services: Vec::new(),
            config_maps: Vec::new(),
            secrets: Vec::new(),
            persistent_volume_claims: Vec::new(),
            ingress: Vec::new(),
            horizontal_pod_autoscalers: Vec::new(),
            network_policies: Vec::new(),
            service_monitors: Vec::new(),
        };

        for service in &analysis.services {
            // Generate deployment
            let deployment = self.generate_deployment(service, false).await?;
            manifests.deployments.push(deployment);

            // Generate service if service has ports
            if !service.ports.is_empty() {
                let svc = self.generate_service(service).await?;
                manifests.services.push(svc);
            }

            // Generate ConfigMap for environment variables
            if !service.environment.is_empty() {
                let config_map = self.generate_config_map(service).await?;
                manifests.config_maps.push(config_map);
            }

            // Generate PVCs for volumes
            for volume in &service.volumes {
                if matches!(volume.mount_type, VolumeMountType::Volume) {
                    let pvc = self.generate_pvc(service, volume).await?;
                    manifests.persistent_volume_claims.push(pvc);
                }
            }
        }

        Ok(manifests)
    }

    pub async fn convert_with_production_patterns(
        &self,
        analysis: &DockerComposeAnalysis,
        patterns: &[DetectedPattern],
    ) -> Result<KubernetesManifests> {
        let mut manifests = self.convert_basic(analysis).await?;

        // Apply production patterns
        for pattern in patterns {
            match &pattern.production_pattern {
                ProductionPattern::WebAppPattern(web_pattern) => {
                    self.apply_web_app_pattern(&mut manifests, analysis, web_pattern)
                        .await?;
                }
                ProductionPattern::DatabasePattern(db_pattern) => {
                    self.apply_database_pattern(&mut manifests, analysis, db_pattern)
                        .await?;
                }
                ProductionPattern::CachePattern(cache_pattern) => {
                    self.apply_cache_pattern(&mut manifests, analysis, cache_pattern)
                        .await?;
                }
                ProductionPattern::MessageQueuePattern(mq_pattern) => {
                    self.apply_message_queue_pattern(&mut manifests, analysis, mq_pattern)
                        .await?;
                }
                ProductionPattern::LoadBalancerPattern(lb_pattern) => {
                    self.apply_load_balancer_pattern(&mut manifests, analysis, lb_pattern)
                        .await?;
                }
            }
        }

        Ok(manifests)
    }

    async fn generate_deployment(
        &self,
        service: &ServiceAnalysis,
        production_mode: bool,
    ) -> Result<DeploymentManifest> {
        let mut replicas = 1;
        let mut strategy_type = "RollingUpdate";

        if production_mode && service.scaling_hints.horizontal_scaling {
            replicas = match service.service_type {
                ServiceType::WebApp => 3,
                ServiceType::Worker => 2,
                _ => 1,
            };
        }

        if service.scaling_hints.stateful {
            strategy_type = "Recreate";
        }

        let data = json!({
            "name": service.name,
            "image": service.image,
            "replicas": replicas,
            "strategy_type": strategy_type,
            "ports": service.ports,
            "environment": service.environment,
            "volumes": service.volumes,
            "health_check": service.health_check,
            "resource_limits": service.resource_limits,
            "production_mode": production_mode,
            "service_type": service.service_type,
            "restart_policy": service.restart_policy,
        });

        let content = self
            .handlebars
            .render("deployment", &data)
            .context("Failed to render deployment template")?;

        Ok(DeploymentManifest {
            name: format!("{}-deployment", service.name),
            content,
            service_type: service.service_type.clone(),
        })
    }

    async fn generate_service(&self, service: &ServiceAnalysis) -> Result<ServiceManifest> {
        let service_type = match service.service_type {
            ServiceType::WebApp | ServiceType::LoadBalancer => "LoadBalancer",
            ServiceType::Database | ServiceType::Cache | ServiceType::MessageQueue => "ClusterIP",
            _ => "ClusterIP",
        };

        let data = json!({
            "name": service.name,
            "ports": service.ports,
            "service_type": service_type,
            "session_affinity": if service.scaling_hints.session_affinity { "ClientIP" } else { "None" }
        });

        let content = self
            .handlebars
            .render("service", &data)
            .context("Failed to render service template")?;

        Ok(ServiceManifest {
            name: format!("{}-service", service.name),
            content,
            service_type: service_type.to_string(),
        })
    }

    async fn generate_config_map(&self, service: &ServiceAnalysis) -> Result<ConfigMapManifest> {
        let data = json!({
            "name": service.name,
            "environment": service.environment
        });

        let content = self
            .handlebars
            .render("configmap", &data)
            .context("Failed to render configmap template")?;

        Ok(ConfigMapManifest {
            name: format!("{}-config", service.name),
            content,
        })
    }

    async fn generate_pvc(
        &self,
        service: &ServiceAnalysis,
        volume: &VolumeMount,
    ) -> Result<PvcManifest> {
        let size = match service.service_type {
            ServiceType::Database => "10Gi",
            ServiceType::Storage => "50Gi",
            _ => "1Gi",
        };

        let access_mode = if service.scaling_hints.stateful {
            "ReadWriteOnce"
        } else {
            "ReadWriteMany"
        };

        let data = json!({
            "name": format!("{}-{}", service.name, volume.source.replace("/", "-").replace("_", "-")),
            "size": size,
            "access_mode": access_mode,
            "storage_class": "standard"
        });

        let content = self
            .handlebars
            .render("pvc", &data)
            .context("Failed to render pvc template")?;

        Ok(PvcManifest {
            name: format!("{}-pvc", service.name),
            content,
            size: size.to_string(),
        })
    }

    async fn apply_web_app_pattern(
        &self,
        manifests: &mut KubernetesManifests,
        analysis: &DockerComposeAnalysis,
        _pattern: &crate::patterns::WebAppPattern,
    ) -> Result<()> {
        // Find web services
        for service in &analysis.services {
            if matches!(service.service_type, ServiceType::WebApp) {
                // Add HPA
                let hpa = self.generate_hpa(service).await?;
                manifests.horizontal_pod_autoscalers.push(hpa);

                // Add Ingress
                let ingress = self.generate_ingress(service, "example.com").await?;
                manifests.ingress.push(ingress);

                // Add Service Monitor for Prometheus
                let service_monitor = self.generate_service_monitor(service).await?;
                manifests.service_monitors.push(service_monitor);
            }
        }

        Ok(())
    }

    async fn apply_database_pattern(
        &self,
        manifests: &mut KubernetesManifests,
        analysis: &DockerComposeAnalysis,
        _pattern: &crate::patterns::DatabasePattern,
    ) -> Result<()> {
        // Find database services
        for service in &analysis.services {
            if matches!(service.service_type, ServiceType::Database) {
                // Add Network Policy for database isolation
                let network_policy = self.generate_network_policy(service).await?;
                manifests.network_policies.push(network_policy);

                // Add Secret for database credentials
                let secret = self.generate_database_secret(service).await?;
                manifests.secrets.push(secret);
            }
        }

        Ok(())
    }

    async fn apply_cache_pattern(
        &self,
        _manifests: &mut KubernetesManifests,
        _analysis: &DockerComposeAnalysis,
        _pattern: &crate::patterns::CachePattern,
    ) -> Result<()> {
        // Cache-specific optimizations
        // Add Redis-specific configurations, memory limits, etc.
        Ok(())
    }

    async fn apply_message_queue_pattern(
        &self,
        _manifests: &mut KubernetesManifests,
        _analysis: &DockerComposeAnalysis,
        _pattern: &crate::patterns::MessageQueuePattern,
    ) -> Result<()> {
        // Message queue specific optimizations
        // Add persistent volumes, clustering configs, etc.
        Ok(())
    }

    async fn apply_load_balancer_pattern(
        &self,
        _manifests: &mut KubernetesManifests,
        _analysis: &DockerComposeAnalysis,
        _pattern: &crate::patterns::LoadBalancerPattern,
    ) -> Result<()> {
        // Load balancer specific optimizations
        Ok(())
    }

    async fn generate_hpa(&self, service: &ServiceAnalysis) -> Result<HpaManifest> {
        let data = json!({
            "name": service.name,
            "min_replicas": 2,
            "max_replicas": 10,
            "target_cpu": 70,
            "target_memory": 80
        });

        let content = self
            .handlebars
            .render("hpa", &data)
            .context("Failed to render hpa template")?;

        Ok(HpaManifest {
            name: format!("{}-hpa", service.name),
            content,
        })
    }

    async fn generate_ingress(
        &self,
        service: &ServiceAnalysis,
        host: &str,
    ) -> Result<IngressManifest> {
        let data = json!({
            "name": service.name,
            "host": host,
            "service_name": format!("{}-service", service.name),
            "service_port": service.ports.first().map(|p| p.container_port).unwrap_or(80)
        });

        let content = self
            .handlebars
            .render("ingress", &data)
            .context("Failed to render ingress template")?;

        Ok(IngressManifest {
            name: format!("{}-ingress", service.name),
            content,
            host: host.to_string(),
        })
    }

    async fn generate_network_policy(
        &self,
        service: &ServiceAnalysis,
    ) -> Result<NetworkPolicyManifest> {
        let data = json!({
            "name": service.name,
            "namespace": "default"
        });

        let content = self
            .handlebars
            .render("network_policy", &data)
            .context("Failed to render network policy template")?;

        Ok(NetworkPolicyManifest {
            name: format!("{}-network-policy", service.name),
            content,
        })
    }

    async fn generate_service_monitor(
        &self,
        service: &ServiceAnalysis,
    ) -> Result<ServiceMonitorManifest> {
        let data = json!({
            "name": service.name,
            "port": "metrics",
            "path": "/metrics"
        });

        let content = self
            .handlebars
            .render("service_monitor", &data)
            .context("Failed to render service monitor template")?;

        Ok(ServiceMonitorManifest {
            name: format!("{}-monitor", service.name),
            content,
        })
    }

    async fn generate_database_secret(&self, service: &ServiceAnalysis) -> Result<SecretManifest> {
        let data = json!({
            "name": service.name,
            "username": general_purpose::STANDARD.encode("admin"),
            "password": general_purpose::STANDARD.encode("changeme"),
            "database": general_purpose::STANDARD.encode(&service.name)
        });

        let content = self
            .handlebars
            .render("secret", &data)
            .context("Failed to render secret template")?;

        Ok(SecretManifest {
            name: format!("{}-secret", service.name),
            content,
        })
    }

    pub async fn save_manifests(
        &self,
        manifests: &KubernetesManifests,
        output_dir: &Path,
    ) -> Result<()> {
        fs::create_dir_all(output_dir)
            .await
            .context("Failed to create output directory")?;

        // Save deployments
        for deployment in &manifests.deployments {
            let file_path = output_dir.join(format!("{}.yaml", deployment.name));
            fs::write(&file_path, &deployment.content)
                .await
                .context(format!("Failed to write deployment file: {:?}", file_path))?;
        }

        // Save services
        for service in &manifests.services {
            let file_path = output_dir.join(format!("{}.yaml", service.name));
            fs::write(&file_path, &service.content)
                .await
                .context(format!("Failed to write service file: {:?}", file_path))?;
        }

        // Save config maps
        for config_map in &manifests.config_maps {
            let file_path = output_dir.join(format!("{}.yaml", config_map.name));
            fs::write(&file_path, &config_map.content)
                .await
                .context(format!("Failed to write configmap file: {:?}", file_path))?;
        }

        // Save secrets
        for secret in &manifests.secrets {
            let file_path = output_dir.join(format!("{}.yaml", secret.name));
            fs::write(&file_path, &secret.content)
                .await
                .context(format!("Failed to write secret file: {:?}", file_path))?;
        }

        // Save PVCs
        for pvc in &manifests.persistent_volume_claims {
            let file_path = output_dir.join(format!("{}.yaml", pvc.name));
            fs::write(&file_path, &pvc.content)
                .await
                .context(format!("Failed to write pvc file: {:?}", file_path))?;
        }

        // Save ingress
        for ingress in &manifests.ingress {
            let file_path = output_dir.join(format!("{}.yaml", ingress.name));
            fs::write(&file_path, &ingress.content)
                .await
                .context(format!("Failed to write ingress file: {:?}", file_path))?;
        }

        // Save HPAs
        for hpa in &manifests.horizontal_pod_autoscalers {
            let file_path = output_dir.join(format!("{}.yaml", hpa.name));
            fs::write(&file_path, &hpa.content)
                .await
                .context(format!("Failed to write hpa file: {:?}", file_path))?;
        }

        // Save network policies
        for np in &manifests.network_policies {
            let file_path = output_dir.join(format!("{}.yaml", np.name));
            fs::write(&file_path, &np.content).await.context(format!(
                "Failed to write network policy file: {:?}",
                file_path
            ))?;
        }

        // Save service monitors
        for sm in &manifests.service_monitors {
            let file_path = output_dir.join(format!("{}.yaml", sm.name));
            fs::write(&file_path, &sm.content).await.context(format!(
                "Failed to write service monitor file: {:?}",
                file_path
            ))?;
        }

        Ok(())
    }
}

// Kubernetes manifest templates
const DEPLOYMENT_TEMPLATE: &str = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{name}}
  labels:
    app: {{name}}
spec:
  replicas: {{replicas}}
  strategy:
    type: {{strategy_type}}
  selector:
    matchLabels:
      app: {{name}}
  template:
    metadata:
      labels:
        app: {{name}}
    spec:
      containers:
      - name: {{name}}
        image: {{image}}
        {{#if ports}}
        ports:
        {{#each ports}}
        - containerPort: {{container_port}}
          protocol: {{protocol}}
        {{/each}}
        {{/if}}
        {{#if environment}}
        envFrom:
        - configMapRef:
            name: {{name}}-config
        {{/if}}
        {{#if health_check}}
        livenessProbe:
          {{#if health_check.test}}
          exec:
            command:
            {{#each health_check.test}}
            - {{this}}
            {{/each}}
          {{else}}
          httpGet:
            path: /health
            port: {{#if ports}}{{ports.[0].container_port}}{{else}}8080{{/if}}
          {{/if}}
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          {{#if health_check.test}}
          exec:
            command:
            {{#each health_check.test}}
            - {{this}}
            {{/each}}
          {{else}}
          httpGet:
            path: /ready
            port: {{#if ports}}{{ports.[0].container_port}}{{else}}8080{{/if}}
          {{/if}}
          initialDelaySeconds: 5
          periodSeconds: 5
        {{/if}}
        {{#if resource_limits}}
        resources:
          {{#if production_mode}}
          requests:
            {{#if resource_limits.memory}}memory: {{resource_limits.memory}}{{else}}memory: "128Mi"{{/if}}
            {{#if resource_limits.cpu}}cpu: {{resource_limits.cpu}}{{else}}cpu: "100m"{{/if}}
          limits:
            {{#if resource_limits.memory}}memory: {{resource_limits.memory}}{{else}}memory: "512Mi"{{/if}}
            {{#if resource_limits.cpu}}cpu: {{resource_limits.cpu}}{{else}}cpu: "500m"{{/if}}
          {{/if}}
        {{/if}}
        {{#if volumes}}
        volumeMounts:
        {{#each volumes}}
        - name: {{source}}
          mountPath: {{target}}
          {{#if read_only}}readOnly: true{{/if}}
        {{/each}}
        {{/if}}
      {{#if volumes}}
      volumes:
      {{#each volumes}}
      - name: {{source}}
        {{#if (eq mount_type "Volume")}}
        persistentVolumeClaim:
          claimName: {{../name}}-{{source}}-pvc
        {{else}}
        hostPath:
          path: {{source}}
        {{/if}}
      {{/each}}
      {{/if}}
"#;

const SERVICE_TEMPLATE: &str = r#"
apiVersion: v1
kind: Service
metadata:
  name: {{name}}-service
  labels:
    app: {{name}}
spec:
  type: {{service_type}}
  sessionAffinity: {{session_affinity}}
  selector:
    app: {{name}}
  ports:
  {{#each ports}}
  - port: {{container_port}}
    targetPort: {{container_port}}
    {{#if host_port}}
    nodePort: {{host_port}}
    {{/if}}
    protocol: {{protocol}}
  {{/each}}
"#;

const CONFIGMAP_TEMPLATE: &str = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{name}}-config
data:
{{#each environment}}
  {{@key}}: "{{this}}"
{{/each}}
"#;

const SECRET_TEMPLATE: &str = r#"
apiVersion: v1
kind: Secret
metadata:
  name: {{name}}-secret
type: Opaque
data:
  username: {{username}}
  password: {{password}}
  database: {{database}}
"#;

const PVC_TEMPLATE: &str = r#"
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{name}}-pvc
spec:
  accessModes:
    - {{access_mode}}
  storageClassName: {{storage_class}}
  resources:
    requests:
      storage: {{size}}
"#;

const INGRESS_TEMPLATE: &str = r#"
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{name}}-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - {{host}}
    secretName: {{name}}-tls
  rules:
  - host: {{host}}
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: {{service_name}}
            port:
              number: {{service_port}}
"#;

const HPA_TEMPLATE: &str = r#"
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{name}}-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{name}}
  minReplicas: {{min_replicas}}
  maxReplicas: {{max_replicas}}
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: {{target_cpu}}
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: {{target_memory}}
"#;

const NETWORK_POLICY_TEMPLATE: &str = r#"
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{name}}-network-policy
  namespace: {{namespace}}
spec:
  podSelector:
    matchLabels:
      app: {{name}}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: {{namespace}}
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: {{namespace}}
"#;

const SERVICE_MONITOR_TEMPLATE: &str = r#"
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: {{name}}-monitor
spec:
  selector:
    matchLabels:
      app: {{name}}
  endpoints:
  - port: {{port}}
    path: {{path}}
    interval: 30s
"#;
