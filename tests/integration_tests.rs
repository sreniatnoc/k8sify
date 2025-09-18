use anyhow::Result;
use std::path::PathBuf;
use tempfile::TempDir;
use tokio::fs;

use k8sify::analyzer::DockerComposeAnalyzer;
use k8sify::converter::KubernetesConverter;
use k8sify::patterns::PatternDetector;
use k8sify::security::SecurityScanner;
use k8sify::validator::ManifestValidator;

#[tokio::test]
async fn test_full_conversion_pipeline() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let compose_file = temp_dir.path().join("docker-compose.yml");

    // Create a test docker-compose.yml
    let compose_content = r#"
version: '3.8'
services:
  web:
    image: nginx:1.20
    ports:
      - "80:80"
    environment:
      - ENV=production
    depends_on:
      - db
  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=myapp
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password
    volumes:
      - db_data:/var/lib/postgresql/data
volumes:
  db_data:
"#;

    fs::write(&compose_file, compose_content).await?;

    // Test analyzer
    let analyzer = DockerComposeAnalyzer::new();
    let analysis = analyzer.analyze(&compose_file).await?;

    assert_eq!(analysis.services.len(), 2);
    assert_eq!(analysis.volumes.len(), 1);

    // Test pattern detection
    let pattern_detector = PatternDetector::new();
    let patterns = pattern_detector.detect_patterns(&analysis)?;

    assert!(!patterns.is_empty());

    // Test converter
    let converter = KubernetesConverter::new();
    let manifests = converter.convert_basic(&analysis).await?;

    assert_eq!(manifests.deployments.len(), 2);
    assert_eq!(manifests.services.len(), 2);

    // Test security scanner
    let security_scanner = SecurityScanner::new();
    let findings = security_scanner.scan(&analysis).await?;

    // Should find issues with the plaintext password
    assert!(findings.critical_count > 0 || findings.high_count > 0);

    Ok(())
}

#[tokio::test]
async fn test_manifest_validation() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let manifest_dir = temp_dir.path().join("manifests");
    fs::create_dir_all(&manifest_dir).await?;

    // Create a valid deployment manifest
    let deployment_content = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  labels:
    app: test-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: test-app
  template:
    metadata:
      labels:
        app: test-app
    spec:
      containers:
      - name: app
        image: nginx:1.20
        ports:
        - containerPort: 80
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"
            cpu: "500m"
"#;

    let deployment_file = manifest_dir.join("deployment.yaml");
    fs::write(&deployment_file, deployment_content).await?;

    // Create an invalid service manifest (missing selector)
    let service_content = r#"
apiVersion: v1
kind: Service
metadata:
  name: test-service
spec:
  ports:
  - port: 80
    targetPort: 80
"#;

    let service_file = manifest_dir.join("service.yaml");
    fs::write(&service_file, service_content).await?;

    // Test validator
    let validator = ManifestValidator::new();
    let results = validator.validate_directory(&manifest_dir).await?;

    assert_eq!(results.total_files, 2);
    assert_eq!(results.valid_files, 1);
    assert_eq!(results.invalid_files, 1);

    Ok(())
}

#[tokio::test]
async fn test_web_app_pattern_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let compose_file = temp_dir.path().join("docker-compose.yml");

    let compose_content = r#"
version: '3.8'
services:
  frontend:
    image: nginx:1.20
    ports:
      - "80:80"
      - "443:443"
  backend:
    image: node:16
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000
  cache:
    image: redis:6
    ports:
      - "6379:6379"
"#;

    fs::write(&compose_file, compose_content).await?;

    let analyzer = DockerComposeAnalyzer::new();
    let analysis = analyzer.analyze(&compose_file).await?;

    let pattern_detector = PatternDetector::new();
    let patterns = pattern_detector.detect_patterns(&analysis)?;

    // Should detect web app patterns
    let web_patterns: Vec<_> = patterns.iter()
        .filter(|p| matches!(p.pattern_type, k8sify::patterns::PatternType::WebApp))
        .collect();

    assert!(!web_patterns.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_production_conversion() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let compose_file = temp_dir.path().join("docker-compose.yml");

    let compose_content = r#"
version: '3.8'
services:
  web:
    image: nginx:1.20
    ports:
      - "80:80"
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M
"#;

    fs::write(&compose_file, compose_content).await?;

    let analyzer = DockerComposeAnalyzer::new();
    let analysis = analyzer.analyze(&compose_file).await?;

    let pattern_detector = PatternDetector::new();
    let patterns = pattern_detector.detect_patterns(&analysis)?;

    let converter = KubernetesConverter::new();
    let manifests = converter.convert_with_production_patterns(&analysis, &patterns).await?;

    // Production conversion should include more resources
    assert!(!manifests.horizontal_pod_autoscalers.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_security_vulnerability_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let compose_file = temp_dir.path().join("docker-compose.yml");

    let compose_content = r#"
version: '3.8'
services:
  insecure-app:
    image: app:latest  # Using latest tag (vulnerability)
    ports:
      - "22:22"  # Exposing SSH port (vulnerability)
    environment:
      - PASSWORD=password123  # Plaintext password (vulnerability)
      - API_KEY=abcd1234567890  # API key in plaintext (vulnerability)
    volumes:
      - /etc:/host-etc  # Mounting sensitive host path (vulnerability)
"#;

    fs::write(&compose_file, compose_content).await?;

    let analyzer = DockerComposeAnalyzer::new();
    let analysis = analyzer.analyze(&compose_file).await?;

    let security_scanner = SecurityScanner::new();
    let findings = security_scanner.scan(&analysis).await?;

    // Should detect multiple security issues
    assert!(findings.critical_count > 0);
    assert!(findings.high_count > 0);
    assert!(findings.findings.len() >= 4);

    Ok(())
}

#[test]
fn test_resource_parsing() {
    // Test CPU parsing
    let converter = KubernetesConverter::new();
    // Note: This would require making parse_cpu_limit public or adding a test-specific method
    // For now, we'll test the overall functionality through integration tests
}

#[tokio::test]
async fn test_error_handling() -> Result<()> {
    let analyzer = DockerComposeAnalyzer::new();

    // Test with non-existent file
    let result = analyzer.analyze(&PathBuf::from("non-existent-file.yml")).await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_empty_compose_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let compose_file = temp_dir.path().join("docker-compose.yml");

    let compose_content = r#"
version: '3.8'
services: {}
"#;

    fs::write(&compose_file, compose_content).await?;

    let analyzer = DockerComposeAnalyzer::new();
    let analysis = analyzer.analyze(&compose_file).await?;

    assert_eq!(analysis.services.len(), 0);
    assert_eq!(analysis.complexity_score, 0);

    Ok(())
}

#[tokio::test]
async fn test_complex_application() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let compose_file = temp_dir.path().join("docker-compose.yml");

    let compose_content = r#"
version: '3.8'
services:
  frontend:
    image: nginx:1.20
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - backend
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro

  backend:
    image: node:16
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://user:pass@db:5432/app
    depends_on:
      - db
      - redis
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=app
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password
    volumes:
      - db_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user -d app"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:6-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data

  worker:
    image: node:16
    environment:
      - NODE_ENV=production
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis
      - db
    command: ["npm", "run", "worker"]

volumes:
  db_data:
  redis_data:

networks:
  default:
    driver: bridge
"#;

    fs::write(&compose_file, compose_content).await?;

    let analyzer = DockerComposeAnalyzer::new();
    let analysis = analyzer.analyze(&compose_file).await?;

    assert_eq!(analysis.services.len(), 5);
    assert_eq!(analysis.volumes.len(), 2);
    assert!(analysis.complexity_score > 50);

    let pattern_detector = PatternDetector::new();
    let patterns = pattern_detector.detect_patterns(&analysis)?;

    // Should detect multiple patterns
    assert!(patterns.len() >= 3);

    let converter = KubernetesConverter::new();
    let manifests = converter.convert_with_production_patterns(&analysis, &patterns).await?;

    // Should generate comprehensive manifests
    assert_eq!(manifests.deployments.len(), 5);
    assert_eq!(manifests.services.len(), 4); // All except worker
    assert_eq!(manifests.persistent_volume_claims.len(), 2);

    Ok(())
}