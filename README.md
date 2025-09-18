# K8sify 🚀

**Intelligent Docker Compose to Kubernetes Migration Tool**

K8sify is a powerful CLI tool that analyzes your Docker Compose applications and generates production-ready Kubernetes manifests with intelligent pattern detection, cost estimation, security scanning, and best practices built-in.

[![CI](https://github.com/sreniatnoc/k8sify/workflows/CI/badge.svg)](https://github.com/sreniatnoc/k8sify/actions)
[![Crates.io](https://img.shields.io/crates/v/k8sify.svg)](https://crates.io/crates/k8sify)
[![Docker](https://img.shields.io/docker/v/sreniatnoc/k8sify?label=docker)](https://hub.docker.com/r/sreniatnoc/k8sify)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

### 🔍 **Intelligent Analysis**
- **Pattern Detection**: Automatically detects web apps, databases, caches, message queues, and architectural patterns
- **Service Classification**: Identifies service types and provides tailored conversion strategies
- **Dependency Analysis**: Maps service dependencies and relationships

### 🎯 **Production-Ready Conversion**
- **Best Practices**: Applies Kubernetes best practices automatically
- **Resource Optimization**: Intelligent resource limits and requests
- **Scaling Configuration**: Horizontal Pod Autoscalers and scaling strategies
- **Health Checks**: Converts and enhances health check configurations

### 🛡️ **Security & Compliance**
- **Security Scanning**: Detects security vulnerabilities and misconfigurations
- **Secret Management**: Identifies and converts secrets properly
- **Network Policies**: Generates network isolation rules
- **Pod Security Standards**: Applies security policies

### 💰 **Cost Management**
- **Cost Estimation**: Multi-cloud cost analysis (AWS, GCP, Azure, DigitalOcean)
- **Resource Optimization**: Recommendations for cost savings
- **Right-sizing**: Intelligent resource allocation suggestions

### 🧙 **Interactive Experience**
- **Wizard Mode**: Step-by-step guided conversion
- **Interactive Review**: Review and customize generated manifests
- **Progress Tracking**: Visual feedback during conversion

### ⚡ **Advanced Features**
- **Multi-format Output**: YAML manifests with proper organization
- **Validation**: Built-in Kubernetes manifest validation
- **Extensible**: Plugin architecture for custom patterns
- **CI/CD Ready**: Perfect for automation pipelines

## 🚀 Quick Start

### Installation

#### Homebrew (macOS/Linux)
```bash
brew install sreniatnoc/tap/k8sify
```

#### Cargo (Rust)
```bash
cargo install k8sify
```

#### Docker
```bash
docker run --rm -v $(pwd):/workspace sreniatnoc/k8sify convert -i docker-compose.yml
```

#### Download Binary
Download the latest release from [GitHub Releases](https://github.com/sreniatnoc/k8sify/releases).

### Basic Usage

```bash
# Convert a docker-compose.yml file
k8sify convert -i docker-compose.yml -o ./k8s

# Use the interactive wizard
k8sify wizard

# Analyze your compose file
k8sify analyze -i docker-compose.yml

# Estimate costs
k8sify cost -i docker-compose.yml --provider aws --region us-east-1

# Security scan
k8sify security -i docker-compose.yml

# Validate generated manifests
k8sify validate -i ./k8s
```

## 📖 Examples

### Simple Web Application

**Input** (`docker-compose.yml`):
```yaml
version: '3.8'
services:
  web:
    image: nginx:1.20
    ports:
      - "80:80"
    environment:
      - ENV=production
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
```

**Command**:
```bash
k8sify convert -i docker-compose.yml -o ./k8s --production
```

**Output** (Generated Kubernetes manifests):
```
k8s/
├── web-deployment.yaml
├── web-service.yaml
├── web-ingress.yaml
├── web-hpa.yaml
├── db-deployment.yaml
├── db-service.yaml
├── db-pvc.yaml
├── db-secret.yaml
└── db-network-policy.yaml
```

### Interactive Wizard

```bash
$ k8sify wizard

🧙 Welcome to K8sify Interactive Wizard!

📁 Path to your docker-compose.yml file: ./docker-compose.yml
📂 Output directory for Kubernetes manifests: ./k8s
🎯 What is your deployment target?
  > Production
    Staging
    Development
    Testing

🌍 What type of Kubernetes environment?
  > Cloud (EKS, GKE, AKS)
    Local (minikube, kind)
    On-Premise
    Hybrid

☁️ Which cloud provider?
  > AWS (EKS)
    Google Cloud (GKE)
    Azure (AKS)
    DigitalOcean

📈 Enable horizontal pod autoscaling? Yes
📊 Minimum number of replicas: 2
📊 Maximum number of replicas: 10
🎯 Target CPU utilization percentage: 70

🔒 Security level:
  > Enhanced (network policies, secrets)
    Basic (default security)
    Strict (Pod Security Standards, RBAC)
    Custom (I'll configure manually)

📊 Enable monitoring and observability? Yes
💾 Enable automated backups? Yes
🔐 Enable SSL/TLS certificates? Yes
🌐 Enable ingress controller for external access? Yes
🌍 Custom domain (optional): myapp.example.com

💰 Resource budget level:
  > Standard (balanced)
    Minimal (cost-optimized)
    Performance (high-performance)
    Enterprise (maximum availability)

🚀 Advanced features (optional):
  [x] Advanced Observability (Prometheus, Grafana)
  [x] GitOps (ArgoCD)
  [ ] Service Mesh (Istio)
  [ ] Chaos Engineering (Litmus)

📊 Analysis Summary
Services: 2
Volumes: 1
Networks: 0
Complexity Score: 25

🔍 Detected Patterns
• WebApp (confidence: 85.0%)
• Database (confidence: 90.0%)

💰 Cost Estimation
Provider: AWS (us-east-1)
Total Monthly Cost: $127.50

🖥️  Compute Costs
  Cluster Management: $72.00
  Load Balancers: $18.00
  web (WebApp): $21.60 (2 replicas)
  db (Database): $43.20 (1 replicas)

💾 Storage Costs
  Persistent Volumes: $5.00
  Backup Storage: $1.50

🌐 Networking Costs
  Data Transfer: $9.00
  Load Balancer: $18.00

📋 Generated Manifests Review
Target: Production
Environment: Cloud
Cloud Provider: AWS

Manifests to be created:
  📦 Deployments: 2
    - web-deployment
    - db-deployment
  🌐 Services: 2
    - web-service
    - db-service
  🚪 Ingress: 1
    - web-ingress (myapp.example.com)
  📈 HPAs: 1

✅ Conversion Complete!

Your Kubernetes manifests have been saved to: ./k8s

Next steps:
1. Review the generated manifests in ./k8s
2. Apply them to your Kubernetes cluster:
   kubectl apply -f ./k8s
3. Monitor your deployments:
   kubectl get pods,services,ingress
```

## 🏗️ Architecture Patterns

K8sify automatically detects and optimizes for common architectural patterns:

### 🌐 **Three-Tier Architecture**
- **Presentation Tier**: Load balancers, reverse proxies
- **Business Tier**: Application servers, APIs
- **Data Tier**: Databases, caches

### 🔧 **Microservices**
- Service discovery optimization
- Inter-service communication
- Distributed tracing setup
- Circuit breaker patterns

### 🏢 **Monolith + Database**
- Vertical scaling strategies
- Database connection optimization
- Session affinity configuration

### 📊 **Event-Driven Architecture**
- Message queue optimization
- Dead letter queue setup
- Event sourcing patterns

## 🔒 Security Features

### **Vulnerability Detection**
- Plaintext secrets in environment variables
- Insecure image tags (`:latest`)
- Dangerous port exposures
- Insecure protocols (HTTP, FTP, Telnet)
- Host path volume mounts
- Missing resource limits

### **Security Enhancements**
- Kubernetes secrets generation
- Network policy creation
- Pod Security Standards
- RBAC recommendations
- Secret scanning and remediation

### **Compliance**
- CIS Kubernetes Benchmark alignment
- NIST Cybersecurity Framework
- SOC 2 Type II considerations
- GDPR data protection measures

## 💰 Cost Optimization

### **Multi-Cloud Support**
- **AWS**: EKS, EC2, EBS, ALB pricing
- **Google Cloud**: GKE, Compute Engine, Persistent Disk
- **Azure**: AKS, Virtual Machines, Managed Disks
- **DigitalOcean**: DOKS, Droplets, Block Storage

### **Cost Optimization Strategies**
- Right-sizing recommendations
- Spot/preemptible instance suggestions
- Reserved instance analysis
- Storage tier optimization
- Auto-scaling configuration

### **Budget Management**
- Monthly cost projections
- Resource usage forecasting
- Cost alert thresholds
- Optimization opportunities

## 🎛️ Advanced Configuration

### **Custom Patterns**
Create custom patterns for your specific use cases:

```toml
# .k8sify/patterns.toml
[patterns.custom_api]
name = "Custom API Pattern"
confidence_threshold = 0.8
indicators = ["custom-api", "api-gateway"]

[patterns.custom_api.production]
enable_autoscaling = true
min_replicas = 3
max_replicas = 20
resource_requests = { cpu = "200m", memory = "256Mi" }
resource_limits = { cpu = "1", memory = "1Gi" }
```

### **Environment-Specific Configurations**
```yaml
# .k8sify/environments/production.yml
metadata:
  namespace: production
  labels:
    environment: production
    managed-by: k8sify

scaling:
  default_replicas: 3
  enable_hpa: true
  target_cpu: 70

security:
  pod_security_standard: restricted
  network_policies: true
  secrets_management: external

monitoring:
  prometheus: true
  grafana: true
  jaeger: true
```

## 🔧 CLI Reference

### **Global Options**
```
-v, --verbose    Enable verbose output
-q, --quiet      Suppress non-error output
-h, --help       Show help information
-V, --version    Show version information
```

### **Commands**

#### `convert`
Convert Docker Compose to Kubernetes manifests.
```bash
k8sify convert [OPTIONS]

OPTIONS:
  -i, --input <FILE>        Path to docker-compose.yml file
  -o, --output <DIR>        Output directory for manifests [default: ./k8s]
  -p, --production          Enable production patterns
  -y, --yes                 Skip interactive prompts
      --namespace <NAME>    Kubernetes namespace [default: default]
      --dry-run             Show what would be generated without writing
```

#### `wizard`
Interactive migration wizard.
```bash
k8sify wizard [OPTIONS]

OPTIONS:
  -i, --input <FILE>    Path to docker-compose.yml file (optional)
```

#### `analyze`
Analyze Docker Compose file.
```bash
k8sify analyze [OPTIONS]

OPTIONS:
  -i, --input <FILE>           Path to docker-compose.yml file
  -f, --format <FORMAT>        Output format [default: table] [possible: json, yaml, table]
      --show-recommendations   Show optimization recommendations
```

#### `cost`
Estimate cloud costs.
```bash
k8sify cost [OPTIONS]

OPTIONS:
  -i, --input <FILE>           Path to docker-compose.yml file
  -p, --provider <PROVIDER>    Cloud provider [default: aws] [possible: aws, gcp, azure, digitalocean]
  -r, --region <REGION>        Cloud region [default: us-east-1]
      --currency <CURRENCY>    Currency code [default: USD]
```

#### `security`
Scan for security issues.
```bash
k8sify security [OPTIONS]

OPTIONS:
  -i, --input <FILE>       Path to docker-compose.yml file
  -f, --format <FORMAT>    Output format [default: table] [possible: json, yaml, table]
      --severity <LEVEL>   Minimum severity level [default: low] [possible: critical, high, medium, low]
```

#### `validate`
Validate Kubernetes manifests.
```bash
k8sify validate [OPTIONS]

OPTIONS:
  -i, --input <DIR>        Path to Kubernetes manifests directory
  -f, --format <FORMAT>    Output format [default: table] [possible: json, yaml, table]
      --strict             Enable strict validation
```

## 🧩 Integrations

### **CI/CD Pipelines**

#### GitHub Actions
```yaml
name: K8s Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Install K8sify
      run: |
        curl -sSL https://github.com/sreniatnoc/k8sify/releases/latest/download/k8sify-linux-amd64 -o k8sify
        chmod +x k8sify
        sudo mv k8sify /usr/local/bin/

    - name: Convert to Kubernetes
      run: k8sify convert -i docker-compose.yml -o ./k8s --production --yes

    - name: Security Scan
      run: k8sify security -i docker-compose.yml

    - name: Validate Manifests
      run: k8sify validate -i ./k8s

    - name: Deploy to Kubernetes
      run: kubectl apply -f ./k8s
```

#### GitLab CI
```yaml
stages:
  - convert
  - validate
  - deploy

convert:
  stage: convert
  image: sreniatnoc/k8sify:latest
  script:
    - k8sify convert -i docker-compose.yml -o ./k8s --production --yes
    - k8sify security -i docker-compose.yml
  artifacts:
    paths:
      - k8s/

validate:
  stage: validate
  image: sreniatnoc/k8sify:latest
  script:
    - k8sify validate -i ./k8s --strict

deploy:
  stage: deploy
  image: bitnami/kubectl:latest
  script:
    - kubectl apply -f ./k8s
  only:
    - main
```

### **Development Tools**

#### VS Code Extension
K8sify provides a VS Code extension for seamless integration:
- Syntax highlighting for K8sify configs
- IntelliSense for pattern definitions
- One-click conversion from editor
- Integrated cost estimation

#### Helm Integration
```bash
# Generate Helm chart from Kubernetes manifests
k8sify convert -i docker-compose.yml -o ./k8s --helm-chart

# Customize values
k8sify helm-values -i ./k8s -o values.yaml
```

## 🛠️ Development

### **Building from Source**
```bash
git clone https://github.com/sreniatnoc/k8sify.git
cd k8sify
cargo build --release
```

### **Running Tests**
```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration_tests

# All tests with coverage
cargo llvm-cov --html
```

### **Contributing**
We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### **Development Setup**
```bash
# Install development dependencies
cargo install cargo-watch cargo-llvm-cov

# Run in development mode
cargo watch -x "run -- wizard"

# Run tests continuously
cargo watch -x test
```

## 📚 Documentation

- [User Guide](docs/user-guide.md) - Comprehensive usage guide
- [Pattern System](docs/patterns.md) - Custom pattern development
- [Security Guide](docs/security.md) - Security best practices
- [Cost Optimization](docs/cost-optimization.md) - Cost management strategies
- [API Reference](docs/api.md) - Programmatic usage
- [Examples](examples/) - Real-world examples

## 🤝 Community

- [Discord](https://discord.gg/k8sify) - Community chat
- [GitHub Discussions](https://github.com/sreniatnoc/k8sify/discussions) - Q&A and ideas
- [Stack Overflow](https://stackoverflow.com/questions/tagged/k8sify) - Technical questions
- [Twitter](https://twitter.com/k8sify) - Updates and announcements

## 📋 Roadmap

### **Version 1.0** (Current)
- ✅ Docker Compose to Kubernetes conversion
- ✅ Pattern detection and optimization
- ✅ Security scanning
- ✅ Cost estimation
- ✅ Interactive wizard

### **Version 1.1**
- 🔄 Helm chart generation
- 🔄 Kustomize support
- 🔄 Advanced networking (Istio, Linkerd)
- 🔄 Multi-cluster deployments

### **Version 1.2**
- 📋 Terraform integration
- 📋 Policy as Code (OPA/Gatekeeper)
- 📋 Advanced monitoring setup
- 📋 Disaster recovery planning

### **Version 2.0**
- 📋 AI-powered optimization
- 📋 Real-time cost tracking
- 📋 Compliance automation
- 📋 Multi-cloud orchestration

## 🐛 Troubleshooting

### **Common Issues**

#### Conversion Errors
```bash
# Enable verbose output for debugging
k8sify convert -i docker-compose.yml -v

# Validate your docker-compose.yml
docker-compose config

# Check for unsupported features
k8sify analyze -i docker-compose.yml --show-recommendations
```

#### Resource Limit Issues
```bash
# Use production mode for better resource allocation
k8sify convert -i docker-compose.yml --production

# Manually specify resource limits in docker-compose.yml
deploy:
  resources:
    limits:
      cpus: '0.5'
      memory: 512M
```

#### Permission Issues
```bash
# Ensure output directory is writable
chmod 755 ./k8s

# Check file permissions
ls -la docker-compose.yml
```

### **Getting Help**

1. Check the [FAQ](docs/faq.md)
2. Search [existing issues](https://github.com/sreniatnoc/k8sify/issues)
3. Join our [Discord community](https://discord.gg/k8sify)
4. Create a [new issue](https://github.com/sreniatnoc/k8sify/issues/new)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Docker Compose](https://docs.docker.com/compose/) - Container orchestration inspiration
- [Kubernetes](https://kubernetes.io/) - Container orchestration platform
- [Rust Community](https://www.rust-lang.org/community) - Amazing ecosystem and tools
- [Contributors](https://github.com/sreniatnoc/k8sify/graphs/contributors) - Everyone who helps make K8sify better

---

**Made with ❤️ by the K8sify community**

[⬆ Back to top](#k8sify-)