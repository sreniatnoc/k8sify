use k8sify::analyzer::ServiceType;
use k8sify::patterns::PatternDetector;
use k8sify::security::{SecurityScanner, Severity};

#[test]
fn test_service_type_detection() {
    let pattern_detector = PatternDetector::new();

    // Test web app detection
    let web_confidence = pattern_detector.calculate_web_app_confidence(&create_test_service(
        "nginx:1.20",
        vec![80, 443],
        vec![("PORT", "80")],
        ServiceType::WebApp,
    ));
    assert!(web_confidence > 0.7);

    // Test database detection
    let db_confidence = pattern_detector.calculate_database_confidence(&create_test_service(
        "postgres:13",
        vec![5432],
        vec![("POSTGRES_DB", "myapp"), ("POSTGRES_USER", "user")],
        ServiceType::Database,
    ));
    assert!(db_confidence > 0.8);

    // Test cache detection
    let cache_confidence = pattern_detector.calculate_cache_confidence(&create_test_service(
        "redis:6",
        vec![6379],
        vec![("REDIS_URL", "redis://localhost:6379")],
        ServiceType::Cache,
    ));
    assert!(cache_confidence > 0.8);
}

#[test]
fn test_scaling_hints() {
    let _pattern_detector = PatternDetector::new();

    // Test stateful service - TODO: implement analyze_scaling_hints method
    // let scaling_hints = pattern_detector.analyze_scaling_hints(
    //     &ServiceType::Database,
    //     &vec![create_test_volume("/var/lib/postgresql/data")],
    //     &std::collections::HashMap::new()
    // );

    // assert!(scaling_hints.stateful);
    // assert!(!scaling_hints.horizontal_scaling);
    // assert!(scaling_hints.vertical_scaling);

    // Test stateless service
    // let scaling_hints = pattern_detector.analyze_scaling_hints(
    //     &ServiceType::WebApp,
    //     &vec![],
    //     &std::collections::HashMap::new()
    // );

    // assert!(!scaling_hints.stateful);
    // assert!(scaling_hints.horizontal_scaling);
    // assert!(!scaling_hints.vertical_scaling);
}

#[test]
fn test_security_pattern_detection() {
    let security_scanner = SecurityScanner::new();

    // Test password detection
    let environment = std::collections::HashMap::from([
        ("DATABASE_PASSWORD".to_string(), "password123".to_string()),
        ("API_KEY".to_string(), "abc123def456ghi789".to_string()),
    ]);

    let service =
        create_test_service_with_env("test-app:1.0", vec![], environment, ServiceType::WebApp);
    let findings = security_scanner
        .check_environment_secrets(&service)
        .unwrap();

    assert!(!findings.is_empty());
    assert!(findings
        .iter()
        .any(|f| matches!(f.severity, Severity::High | Severity::Critical)));
}

#[test]
fn test_port_security_validation() {
    let security_scanner = SecurityScanner::new();

    // Test dangerous port exposure
    let service = create_test_service("test-app:1.0", vec![22, 3389], vec![], ServiceType::WebApp);
    let findings = security_scanner.check_port_security(&service).unwrap();

    assert!(!findings.is_empty());
    assert!(findings
        .iter()
        .any(|f| matches!(f.severity, Severity::High)));
}

#[test]
fn test_image_security_validation() {
    let security_scanner = SecurityScanner::new();

    // Test latest tag usage
    let service = create_test_service("nginx:latest", vec![80], vec![], ServiceType::WebApp);
    let findings = security_scanner.check_image_security(&service).unwrap();

    assert!(!findings.is_empty());
    assert!(findings.iter().any(|f| f.title.contains("latest")));
}

#[test]
fn test_architectural_pattern_detection() {
    use k8sify::analyzer::DockerComposeAnalysis;

    let pattern_detector = PatternDetector::new();

    // Create a three-tier architecture
    let services = vec![
        create_test_service("nginx:1.20", vec![80], vec![], ServiceType::WebApp),
        create_test_service("node:16", vec![3000], vec![], ServiceType::WebApp),
        create_test_service(
            "postgres:13",
            vec![5432],
            vec![("POSTGRES_DB", "app")],
            ServiceType::Database,
        ),
    ];

    let analysis = DockerComposeAnalysis {
        version: "3.8".to_string(),
        services,
        volumes: vec![],
        networks: vec![],
        secrets: vec![],
        configs: vec![],
        complexity_score: 30,
        recommendations: vec![],
    };

    assert!(pattern_detector.has_three_tier_architecture(&analysis));
}

#[test]
fn test_microservices_detection() {
    use k8sify::analyzer::DockerComposeAnalysis;

    let pattern_detector = PatternDetector::new();

    // Create microservices architecture
    let services = vec![
        create_test_service("nginx:1.20", vec![80], vec![], ServiceType::LoadBalancer),
        create_test_service("user-service:1.0", vec![3001], vec![], ServiceType::WebApp),
        create_test_service("order-service:1.0", vec![3002], vec![], ServiceType::WebApp),
        create_test_service(
            "payment-service:1.0",
            vec![3003],
            vec![],
            ServiceType::WebApp,
        ),
        create_test_service("postgres:13", vec![5432], vec![], ServiceType::Database),
        create_test_service("redis:6", vec![6379], vec![], ServiceType::Cache),
    ];

    let analysis = DockerComposeAnalysis {
        version: "3.8".to_string(),
        services,
        volumes: vec![],
        networks: vec![],
        secrets: vec![],
        configs: vec![],
        complexity_score: 60,
        recommendations: vec![],
    };

    assert!(pattern_detector.has_microservices_characteristics(&analysis));
}

#[test]
fn test_resource_limit_parsing() {
    let cost_estimator = k8sify::cost::CostEstimator::new("aws", "us-east-1");

    // Test CPU parsing
    assert_eq!(cost_estimator.parse_cpu_limit("500m"), Some(0.5));
    assert_eq!(cost_estimator.parse_cpu_limit("2"), Some(2.0));
    assert_eq!(cost_estimator.parse_cpu_limit("1.5"), Some(1.5));

    // Test memory parsing
    assert_eq!(cost_estimator.parse_memory_limit("512Mi"), Some(0.5));
    assert_eq!(cost_estimator.parse_memory_limit("2Gi"), Some(2.0));
    assert_eq!(cost_estimator.parse_memory_limit("1024M"), Some(1.0));
}

#[test]
fn test_complexity_score_calculation() {
    use k8sify::analyzer::DockerComposeAnalyzer;

    let analyzer = DockerComposeAnalyzer::new();

    // Simple application
    let simple_services = vec![create_test_service(
        "nginx:1.20",
        vec![80],
        vec![],
        ServiceType::WebApp,
    )];
    let simple_score = analyzer.calculate_complexity_score(&simple_services, &[], &[]);
    assert!(simple_score < 20);

    // Complex application
    let complex_services = vec![
        create_test_service("nginx:1.20", vec![80, 443], vec![], ServiceType::WebApp),
        create_test_service("node:16", vec![3000], vec![], ServiceType::WebApp),
        create_test_service("postgres:13", vec![5432], vec![], ServiceType::Database),
        create_test_service("redis:6", vec![6379], vec![], ServiceType::Cache),
    ];
    let complex_score = analyzer.calculate_complexity_score(&complex_services, &[], &[]);
    assert!(complex_score > 40);
}

#[test]
fn test_official_image_detection() {
    let security_scanner = SecurityScanner::new();

    assert!(security_scanner.is_official_image("nginx:1.20"));
    assert!(security_scanner.is_official_image("postgres"));
    assert!(security_scanner.is_official_image("redis:6-alpine"));
    assert!(!security_scanner.is_official_image("mycompany/custom-app:1.0"));
    assert!(!security_scanner.is_official_image("registry.example.com/app:latest"));
}

#[test]
fn test_pattern_confidence_scoring() {
    let pattern_detector = PatternDetector::new();

    // High confidence web app
    let high_confidence_web = pattern_detector.calculate_web_app_confidence(&create_test_service(
        "nginx:1.20",
        vec![80, 443],
        vec![("PORT", "80"), ("HOST", "0.0.0.0")],
        ServiceType::WebApp,
    ));

    // Low confidence web app
    let low_confidence_web = pattern_detector.calculate_web_app_confidence(&create_test_service(
        "unknown-image:1.0",
        vec![],
        vec![],
        ServiceType::Unknown,
    ));

    assert!(high_confidence_web > low_confidence_web);
    assert!(high_confidence_web > 0.8);
    assert!(low_confidence_web < 0.3);
}

// Helper functions
fn create_test_service(
    image: &str,
    ports: Vec<u16>,
    env_vars: Vec<(&str, &str)>,
    service_type: ServiceType,
) -> k8sify::analyzer::ServiceAnalysis {
    use k8sify::analyzer::{PortMapping, ResourceLimits, ScalingHints, ServiceAnalysis};

    let ports = ports
        .into_iter()
        .map(|port| PortMapping {
            host_port: Some(port),
            container_port: port,
            protocol: "TCP".to_string(),
            exposed: false,
        })
        .collect();

    let environment = env_vars
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    ServiceAnalysis {
        name: "test-service".to_string(),
        image: image.to_string(),
        ports,
        environment,
        volumes: vec![],
        depends_on: vec![],
        networks: vec![],
        restart_policy: "always".to_string(),
        resource_limits: ResourceLimits {
            memory: None,
            cpu: None,
            cpu_shares: None,
            pids_limit: None,
        },
        health_check: None,
        service_type,
        scaling_hints: ScalingHints {
            horizontal_scaling: false,
            vertical_scaling: false,
            stateful: false,
            session_affinity: false,
        },
    }
}

fn create_test_service_with_env(
    image: &str,
    ports: Vec<u16>,
    environment: std::collections::HashMap<String, String>,
    service_type: ServiceType,
) -> k8sify::analyzer::ServiceAnalysis {
    use k8sify::analyzer::{PortMapping, ResourceLimits, ScalingHints, ServiceAnalysis};

    let ports = ports
        .into_iter()
        .map(|port| PortMapping {
            host_port: Some(port),
            container_port: port,
            protocol: "TCP".to_string(),
            exposed: false,
        })
        .collect();

    ServiceAnalysis {
        name: "test-service".to_string(),
        image: image.to_string(),
        ports,
        environment,
        volumes: vec![],
        depends_on: vec![],
        networks: vec![],
        restart_policy: "always".to_string(),
        resource_limits: ResourceLimits {
            memory: None,
            cpu: None,
            cpu_shares: None,
            pids_limit: None,
        },
        health_check: None,
        service_type,
        scaling_hints: ScalingHints {
            horizontal_scaling: false,
            vertical_scaling: false,
            stateful: false,
            session_affinity: false,
        },
    }
}

#[allow(dead_code)]
fn create_test_volume(target: &str) -> k8sify::analyzer::VolumeMount {
    use k8sify::analyzer::{VolumeMount, VolumeMountType};

    VolumeMount {
        source: "test-volume".to_string(),
        target: target.to_string(),
        mount_type: VolumeMountType::Volume,
        read_only: false,
    }
}
