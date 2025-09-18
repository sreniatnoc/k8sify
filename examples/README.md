# K8sify Examples

This directory contains example Docker Compose applications that demonstrate K8sify's capabilities for different architectural patterns and use cases.

## Examples Overview

### 🌐 Simple Web Application (`simple-webapp/`)
A classic three-tier web application with:
- **Frontend**: Nginx web server
- **Backend**: Node.js API service
- **Database**: PostgreSQL
- **Cache**: Redis

**Features demonstrated:**
- Basic service conversion
- Health checks
- Resource limits
- Volume management
- Service dependencies

**Usage:**
```bash
cd examples/simple-webapp
k8sify convert -i docker-compose.yml -o ./k8s --production
```

### 🔧 Microservices Architecture (`microservices/`)
A complex microservices application with:
- **API Gateway**: Nginx load balancer
- **Services**: User, Order, Payment, Notification services
- **Workers**: Background job processors
- **Infrastructure**: PostgreSQL, Redis, RabbitMQ
- **Monitoring**: Prometheus, Grafana

**Features demonstrated:**
- Microservices pattern detection
- Message queue integration
- Service mesh readiness
- Monitoring and observability
- Complex service dependencies

**Usage:**
```bash
cd examples/microservices
k8sify wizard -i docker-compose.yml
```

### 📝 WordPress CMS (`wordpress/`)
A production-ready WordPress setup with:
- **CMS**: WordPress with PHP-FPM
- **Database**: MySQL with optimized configuration
- **Cache**: Redis for object caching
- **Proxy**: Nginx for SSL termination and caching
- **Backup**: Automated database backups

**Features demonstrated:**
- CMS pattern recognition
- SSL/TLS configuration
- Backup strategies
- Performance optimization
- Production hardening

**Usage:**
```bash
cd examples/wordpress
k8sify convert -i docker-compose.yml -o ./k8s --production
k8sify cost -i docker-compose.yml --provider aws
```

## Running the Examples

### Prerequisites
- Docker and Docker Compose
- Kubernetes cluster (minikube, kind, or cloud provider)
- kubectl configured
- K8sify installed

### Step-by-Step Guide

1. **Choose an example:**
   ```bash
   cd examples/simple-webapp
   ```

2. **Analyze the application:**
   ```bash
   k8sify analyze -i docker-compose.yml
   ```

3. **Check security:**
   ```bash
   k8sify security -i docker-compose.yml
   ```

4. **Estimate costs (for cloud deployments):**
   ```bash
   k8sify cost -i docker-compose.yml --provider aws --region us-east-1
   ```

5. **Convert to Kubernetes:**
   ```bash
   k8sify convert -i docker-compose.yml -o ./k8s --production
   ```

6. **Validate generated manifests:**
   ```bash
   k8sify validate -i ./k8s
   ```

7. **Deploy to Kubernetes:**
   ```bash
   kubectl apply -f ./k8s
   ```

8. **Monitor the deployment:**
   ```bash
   kubectl get pods,services,ingress
   kubectl logs -f deployment/web
   ```

## Pattern Detection Examples

### Web Application Patterns
K8sify automatically detects and optimizes for:
- **Load balancer services** → Kubernetes LoadBalancer/Ingress
- **Web servers** → Horizontal Pod Autoscaling
- **API services** → Health checks and readiness probes
- **Static content** → ConfigMaps and volume mounts

### Database Patterns
- **Relational databases** → StatefulSets with persistent volumes
- **NoSQL databases** → Appropriate storage classes
- **Database clustering** → Anti-affinity rules
- **Backup strategies** → CronJobs for automated backups

### Cache Patterns
- **In-memory caches** → Memory-optimized pods
- **Persistent caches** → Appropriate eviction policies
- **Cache clustering** → Service discovery configuration

### Message Queue Patterns
- **Pub/Sub systems** → Persistent volumes for durability
- **Worker queues** → Deployment scaling strategies
- **Dead letter queues** → Error handling configuration

## Customization Examples

### Environment-Specific Configurations

Create environment-specific overrides:

```bash
# Development
k8sify convert -i docker-compose.yml -o ./k8s-dev
kubectl apply -f ./k8s-dev -n development

# Staging
k8sify convert -i docker-compose.yml -o ./k8s-staging --production
kubectl apply -f ./k8s-staging -n staging

# Production
k8sify wizard -i docker-compose.yml
kubectl apply -f ./k8s -n production
```

### Advanced Features

#### Service Mesh Integration
```bash
k8sify convert -i docker-compose.yml -o ./k8s \
  --production \
  --service-mesh=istio \
  --enable-tracing
```

#### GitOps Workflow
```bash
k8sify convert -i docker-compose.yml -o ./k8s \
  --production \
  --gitops \
  --argocd-app-name=myapp
```

#### Multi-Cloud Deployment
```bash
k8sify convert -i docker-compose.yml -o ./k8s-aws --provider=aws
k8sify convert -i docker-compose.yml -o ./k8s-gcp --provider=gcp
k8sify convert -i docker-compose.yml -o ./k8s-azure --provider=azure
```

## Testing the Examples

### Local Testing with Minikube
```bash
# Start minikube
minikube start --memory=4096 --cpus=2

# Enable ingress
minikube addons enable ingress

# Deploy example
cd examples/simple-webapp
k8sify convert -i docker-compose.yml -o ./k8s
kubectl apply -f ./k8s

# Access application
minikube service web-service
```

### Testing with Kind
```bash
# Create cluster
kind create cluster --config kind-config.yaml

# Deploy example
cd examples/microservices
k8sify wizard -i docker-compose.yml
kubectl apply -f ./k8s

# Port forward to access services
kubectl port-forward service/gateway-service 8080:80
```

### Load Testing
```bash
# Install load testing tools
kubectl apply -f https://raw.githubusercontent.com/fortio/fortio/master/k8s/fortio-deploy.yaml

# Run load test
kubectl exec -it deployment/fortio -- fortio load -qps 100 -t 60s http://web-service/
```

## Troubleshooting

### Common Issues

#### Resource Constraints
```bash
# Check resource usage
kubectl top nodes
kubectl top pods

# Adjust resource limits
k8sify convert -i docker-compose.yml -o ./k8s --resource-preset=minimal
```

#### Service Discovery Issues
```bash
# Check service endpoints
kubectl get endpoints

# Verify DNS resolution
kubectl run -it --rm debug --image=busybox --restart=Never -- nslookup web-service
```

#### Storage Issues
```bash
# Check persistent volumes
kubectl get pv,pvc

# Check storage class
kubectl get storageclass
```

### Debugging Commands
```bash
# Get all resources
kubectl get all

# Describe problematic pods
kubectl describe pod <pod-name>

# Check logs
kubectl logs -f deployment/<deployment-name>

# Debug networking
kubectl exec -it <pod-name> -- ping <service-name>
```

## Contributing Examples

We welcome new examples! To contribute:

1. Create a new directory under `examples/`
2. Add a `docker-compose.yml` file
3. Include a `README.md` with:
   - Description of the application
   - Architecture diagram
   - Key features demonstrated
   - Usage instructions
4. Test the conversion with K8sify
5. Submit a pull request

### Example Template
```
examples/
└── my-example/
    ├── docker-compose.yml
    ├── README.md
    ├── config/
    │   ├── nginx.conf
    │   └── app.env
    └── k8s/
        ├── deployment.yaml
        ├── service.yaml
        └── ingress.yaml
```

## Additional Resources

- [K8sify Documentation](../docs/)
- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
- [Docker Compose Reference](https://docs.docker.com/compose/compose-file/)
- [Helm Charts](https://helm.sh/docs/chart_template_guide/)

---

**Questions or suggestions?** Join our [community](https://discord.gg/k8sify) or open an [issue](https://github.com/k8sify/k8sify/issues)!