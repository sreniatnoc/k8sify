//! # K8sify - Intelligent Docker Compose to Kubernetes Migration Tool
//!
//! K8sify is a powerful CLI tool and library that analyzes Docker Compose applications
//! and generates production-ready Kubernetes manifests with intelligent pattern detection,
//! cost estimation, security scanning, and best practices built-in.
//!
//! ## Features
//!
//! - **Intelligent Analysis**: Pattern detection and service classification
//! - **Production-Ready Conversion**: Best practices and optimization
//! - **Security & Compliance**: Vulnerability scanning and security policies
//! - **Cost Management**: Multi-cloud cost analysis and optimization
//! - **Interactive Experience**: Guided wizard and customization
//! - **Validation**: Built-in manifest validation and testing
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use k8sify::analyzer::DockerComposeAnalyzer;
//! use k8sify::converter::KubernetesConverter;
//! use k8sify::patterns::PatternDetector;
//! use std::path::Path;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Analyze Docker Compose file
//!     let analyzer = DockerComposeAnalyzer::new();
//!     let analysis = analyzer.analyze(Path::new("docker-compose.yml")).await?;
//!
//!     // Detect patterns
//!     let pattern_detector = PatternDetector::new();
//!     let patterns = pattern_detector.detect_patterns(&analysis)?;
//!
//!     // Convert to Kubernetes manifests
//!     let converter = KubernetesConverter::new();
//!     let manifests = converter.convert_with_production_patterns(&analysis, &patterns).await?;
//!
//!     // Save manifests
//!     converter.save_manifests(&manifests, Path::new("./k8s")).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Modules
//!
//! - [`analyzer`] - Docker Compose file analysis and parsing
//! - [`converter`] - Kubernetes manifest generation and templating
//! - [`patterns`] - Pattern detection and production optimizations
//! - [`security`] - Security scanning and vulnerability detection
//! - [`cost`] - Cloud cost estimation and optimization
//! - [`validator`] - Kubernetes manifest validation
//! - [`interview`] - Interactive wizard and user interface

pub mod analyzer;
pub mod converter;
pub mod cost;
pub mod interview;
pub mod patterns;
pub mod security;
pub mod validator;

// Re-export commonly used types for convenience
pub use analyzer::{DockerComposeAnalysis, DockerComposeAnalyzer, ServiceAnalysis, ServiceType};
pub use converter::{KubernetesConverter, KubernetesManifests};
pub use cost::{CostEstimate, CostEstimator};
pub use interview::InteractiveWizard;
pub use patterns::{DetectedPattern, PatternDetector, PatternType};
pub use security::{SecurityFindings, SecurityScanner, Severity};
pub use validator::{ManifestValidator, ValidationResults};

/// Current version of K8sify
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// K8sify library error types
#[derive(thiserror::Error, Debug)]
pub enum K8sifyError {
    /// IO error occurred during file operations
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// YAML parsing error
    #[error("YAML parsing error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// JSON parsing error
    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    /// Template rendering error
    #[error("Template rendering error: {0}")]
    Template(#[from] handlebars::RenderError),

    /// Analysis error
    #[error("Analysis error: {0}")]
    Analysis(String),

    /// Conversion error
    #[error("Conversion error: {0}")]
    Conversion(String),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Security scanning error
    #[error("Security scanning error: {0}")]
    Security(String),

    /// Cost estimation error
    #[error("Cost estimation error: {0}")]
    Cost(String),

    /// Pattern detection error
    #[error("Pattern detection error: {0}")]
    Pattern(String),

    /// Generic error with custom message
    #[error("{0}")]
    Generic(String),
}

/// Result type alias for K8sify operations
pub type Result<T> = std::result::Result<T, K8sifyError>;

/// K8sify library configuration
#[derive(Debug, Clone)]
pub struct K8sifyConfig {
    /// Enable verbose logging
    pub verbose: bool,
    /// Default output directory
    pub output_dir: std::path::PathBuf,
    /// Default cloud provider for cost estimation
    pub default_provider: String,
    /// Default region for cost estimation
    pub default_region: String,
    /// Enable production patterns by default
    pub production_mode: bool,
    /// Default namespace for Kubernetes resources
    pub default_namespace: String,
}

impl Default for K8sifyConfig {
    fn default() -> Self {
        Self {
            verbose: false,
            output_dir: std::path::PathBuf::from("./k8s"),
            default_provider: "aws".to_string(),
            default_region: "us-east-1".to_string(),
            production_mode: false,
            default_namespace: "default".to_string(),
        }
    }
}

/// Main K8sify client for programmatic usage
pub struct K8sify {
    config: K8sifyConfig,
    analyzer: DockerComposeAnalyzer,
    pattern_detector: PatternDetector,
    converter: KubernetesConverter,
    security_scanner: SecurityScanner,
    validator: ManifestValidator,
}

impl K8sify {
    /// Create a new K8sify client with default configuration
    pub fn new() -> Self {
        Self::with_config(K8sifyConfig::default())
    }

    /// Create a new K8sify client with custom configuration
    pub fn with_config(config: K8sifyConfig) -> Self {
        Self {
            config,
            analyzer: DockerComposeAnalyzer::new(),
            pattern_detector: PatternDetector::new(),
            converter: KubernetesConverter::new(),
            security_scanner: SecurityScanner::new(),
            validator: ManifestValidator::new(),
        }
    }

    /// Analyze a Docker Compose file
    pub async fn analyze<P: AsRef<std::path::Path>>(
        &self,
        compose_file: P,
    ) -> anyhow::Result<DockerComposeAnalysis> {
        self.analyzer.analyze(compose_file.as_ref()).await
    }

    /// Detect patterns in a Docker Compose analysis
    pub fn detect_patterns(
        &self,
        analysis: &DockerComposeAnalysis,
    ) -> anyhow::Result<Vec<DetectedPattern>> {
        self.pattern_detector.detect_patterns(analysis)
    }

    /// Convert Docker Compose to Kubernetes manifests
    pub async fn convert(
        &self,
        analysis: &DockerComposeAnalysis,
        patterns: &[DetectedPattern],
    ) -> anyhow::Result<KubernetesManifests> {
        if self.config.production_mode {
            self.converter
                .convert_with_production_patterns(analysis, patterns)
                .await
        } else {
            self.converter.convert_basic(analysis).await
        }
    }

    /// Perform security scanning
    pub async fn scan_security(
        &self,
        analysis: &DockerComposeAnalysis,
    ) -> anyhow::Result<SecurityFindings> {
        self.security_scanner.scan(analysis).await
    }

    /// Estimate costs
    pub async fn estimate_costs(
        &self,
        analysis: &DockerComposeAnalysis,
    ) -> anyhow::Result<CostEstimate> {
        let cost_estimator =
            CostEstimator::new(&self.config.default_provider, &self.config.default_region);
        cost_estimator.estimate_costs(analysis).await
    }

    /// Validate Kubernetes manifests
    pub async fn validate_manifests<P: AsRef<std::path::Path>>(
        &self,
        manifest_dir: P,
    ) -> anyhow::Result<ValidationResults> {
        self.validator
            .validate_directory(manifest_dir.as_ref())
            .await
    }

    /// Save manifests to disk
    pub async fn save_manifests<P: AsRef<std::path::Path>>(
        &self,
        manifests: &KubernetesManifests,
        output_dir: P,
    ) -> anyhow::Result<()> {
        self.converter
            .save_manifests(manifests, output_dir.as_ref())
            .await
    }

    /// Full conversion pipeline
    pub async fn convert_file<P: AsRef<std::path::Path>>(
        &self,
        compose_file: P,
        output_dir: Option<P>,
    ) -> anyhow::Result<KubernetesManifests> {
        // Analyze
        let analysis = self.analyze(&compose_file).await?;

        // Detect patterns
        let patterns = self.detect_patterns(&analysis)?;

        // Convert
        let manifests = self.convert(&analysis, &patterns).await?;

        // Save if output directory is provided
        if let Some(output) = output_dir {
            self.save_manifests(&manifests, output).await?;
        }

        Ok(manifests)
    }

    /// Get current configuration
    pub fn config(&self) -> &K8sifyConfig {
        &self.config
    }

    /// Update configuration
    pub fn with_updated_config(mut self, config: K8sifyConfig) -> Self {
        self.config = config;
        self
    }
}

impl Default for K8sify {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::fs;

    #[tokio::test]
    async fn test_k8sify_client() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let compose_file = temp_dir.path().join("docker-compose.yml");

        let compose_content = r#"
version: '3.8'
services:
  web:
    image: nginx:1.20
    ports:
      - "80:80"
"#;

        fs::write(&compose_file, compose_content).await?;

        let k8sify = K8sify::new();
        let manifests = k8sify
            .convert_file(&compose_file, None::<&std::path::PathBuf>)
            .await?;

        assert_eq!(manifests.deployments.len(), 1);
        assert_eq!(manifests.services.len(), 1);

        Ok(())
    }

    #[test]
    fn test_k8sify_config() {
        let config = K8sifyConfig {
            verbose: true,
            production_mode: true,
            default_provider: "gcp".to_string(),
            ..Default::default()
        };

        let k8sify = K8sify::with_config(config);
        assert!(k8sify.config().verbose);
        assert!(k8sify.config().production_mode);
        assert_eq!(k8sify.config().default_provider, "gcp");
    }
}
