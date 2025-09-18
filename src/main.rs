use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;

mod analyzer;
mod converter;
mod cost;
mod interview;
mod patterns;
mod security;
mod validator;

use analyzer::DockerComposeAnalyzer;
use converter::KubernetesConverter;
use cost::CostEstimator;
use interview::InteractiveWizard;
use patterns::PatternDetector;
use security::SecurityScanner;
use validator::ManifestValidator;

#[derive(Parser)]
#[command(name = "k8sify")]
#[command(about = "Intelligent Docker Compose to Kubernetes migration tool")]
#[command(version = "0.1.0")]
#[command(author = "K8sify Contributors")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Convert Docker Compose to Kubernetes manifests
    Convert {
        /// Path to docker-compose.yml file
        #[arg(short, long)]
        input: PathBuf,
        /// Output directory for Kubernetes manifests
        #[arg(short, long, default_value = "./k8s")]
        output: PathBuf,
        /// Enable production patterns
        #[arg(short, long)]
        production: bool,
        /// Skip interactive prompts
        #[arg(short, long)]
        yes: bool,
    },
    /// Interactive migration wizard
    Wizard {
        /// Path to docker-compose.yml file
        #[arg(short, long)]
        input: Option<PathBuf>,
    },
    /// Analyze Docker Compose file
    Analyze {
        /// Path to docker-compose.yml file
        #[arg(short, long)]
        input: PathBuf,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        format: String,
    },
    /// Estimate cloud costs
    Cost {
        /// Path to docker-compose.yml file
        #[arg(short, long)]
        input: PathBuf,
        /// Cloud provider (aws, gcp, azure)
        #[arg(short, long, default_value = "aws")]
        provider: String,
        /// Region for cost estimation
        #[arg(short, long, default_value = "us-east-1")]
        region: String,
    },
    /// Scan for security issues
    Security {
        /// Path to docker-compose.yml file
        #[arg(short, long)]
        input: PathBuf,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        format: String,
    },
    /// Validate generated Kubernetes manifests
    Validate {
        /// Path to Kubernetes manifests directory
        #[arg(short, long)]
        input: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Convert { input, output, production, yes } => {
            println!("{}", "🚀 Starting Docker Compose to Kubernetes conversion...".bold().green());

            let analyzer = DockerComposeAnalyzer::new();
            let analysis = analyzer.analyze(&input).await?;

            let pattern_detector = PatternDetector::new();
            let patterns = pattern_detector.detect_patterns(&analysis)?;

            let converter = KubernetesConverter::new();
            let manifests = if production {
                converter.convert_with_production_patterns(&analysis, &patterns).await?
            } else {
                converter.convert_basic(&analysis).await?
            };

            if !yes {
                let wizard = InteractiveWizard::new();
                wizard.review_conversion(&manifests).await?;
            }

            converter.save_manifests(&manifests, &output).await?;

            println!("{}", format!("✅ Conversion complete! Manifests saved to {}", output.display()).bold().green());
        }

        Commands::Wizard { input } => {
            println!("{}", "🧙 Welcome to the K8sify Interactive Wizard!".bold().blue());

            let wizard = InteractiveWizard::new();
            wizard.run(input).await?;
        }

        Commands::Analyze { input, format } => {
            println!("{}", "🔍 Analyzing Docker Compose file...".bold().blue());

            let analyzer = DockerComposeAnalyzer::new();
            let analysis = analyzer.analyze(&input).await?;

            match format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&analysis)?),
                "yaml" => println!("{}", serde_yaml::to_string(&analysis)?),
                "table" => analyzer.print_analysis_table(&analysis)?,
                _ => return Err(anyhow::anyhow!("Unsupported format: {}", format)),
            }
        }

        Commands::Cost { input, provider, region } => {
            println!("{}", "💰 Estimating cloud costs...".bold().yellow());

            let analyzer = DockerComposeAnalyzer::new();
            let analysis = analyzer.analyze(&input).await?;

            let cost_estimator = CostEstimator::new(&provider, &region);
            let estimate = cost_estimator.estimate_costs(&analysis).await?;

            cost_estimator.print_cost_breakdown(&estimate)?;
        }

        Commands::Security { input, format } => {
            println!("{}", "🔒 Scanning for security issues...".bold().red());

            let analyzer = DockerComposeAnalyzer::new();
            let analysis = analyzer.analyze(&input).await?;

            let scanner = SecurityScanner::new();
            let findings = scanner.scan(&analysis).await?;

            match format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&findings)?),
                "yaml" => println!("{}", serde_yaml::to_string(&findings)?),
                "table" => scanner.print_findings_table(&findings)?,
                _ => return Err(anyhow::anyhow!("Unsupported format: {}", format)),
            }
        }

        Commands::Validate { input } => {
            println!("{}", "✅ Validating Kubernetes manifests...".bold().green());

            let validator = ManifestValidator::new();
            let results = validator.validate_directory(&input).await?;

            validator.print_validation_results(&results)?;
        }
    }

    Ok(())
}