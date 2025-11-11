# Deployment Guide

Comprehensive guide for deploying QueryForge in various environments.

## Table of Contents

- [Deployment Options](#deployment-options)
- [Local Development Deployment](#local-development-deployment)
- [Docker Deployment](#docker-deployment)
- [Production Deployment](#production-deployment)
- [Cloud Deployments](#cloud-deployments)
- [Configuration](#configuration)
- [Security Considerations](#security-considerations)
- [Monitoring and Logging](#monitoring-and-logging)
- [Backup and Recovery](#backup-and-recovery)
- [Scaling](#scaling)

## Deployment Options

| Method | Use Case | Complexity | Scalability |
|--------|----------|------------|-------------|
| Local Python | Development, testing | Low | Single instance |
| Docker Compose | Single server, small team | Medium | Vertical only |
| Kubernetes | Production, enterprise | High | Horizontal & vertical |
| Cloud Managed | Quick production deployment | Medium | Horizontal & vertical |

## Local Development Deployment

### Prerequisites

- Python 3.10 or higher
- pip and virtualenv
- Git

### Step-by-Step

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ParadoxReagent/MCPs.git
   cd MCPs
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the server**:
   ```bash
   # stdio transport (default)
   export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
python -m queryforge.server.server

   # SSE transport
   MCP_TRANSPORT=sse export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
python -m queryforge.server.server
   ```

5. **Verify deployment**:
   ```bash
   # For SSE
   curl http://localhost:8080/sse

   # For stdio, test with MCP client
   ```

### Configuration

Create `.env` file in the `` directory for local configuration:

```bash
# Transport configuration
MCP_TRANSPORT=sse
MCP_HOST=0.0.0.0
MCP_PORT=8080

# Logging
LOG_LEVEL=INFO

# Cache directory
CACHE_DIR=.cache
```

Load environment:
```bash
export $(cat .env | xargs)
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
python -m queryforge.server.server
```

## Docker Deployment

### Single Container (QueryForge)

**Using Docker Compose (Recommended):**

1. **Navigate to directory**:
   ```bash
   cd queryforge
   ```

2. **Build image**:
   ```bash
   docker compose build
   ```

3. **Run container**:
   ```bash
   docker compose up -d
   ```

4. **Verify deployment**:
   ```bash
   docker ps
   docker compose logs -f
   curl http://localhost:8080/sse
   ```

**Using Docker Directly:**

1. **Navigate to directory**:
   ```bash
   cd queryforge
   ```

2. **Build image**:
   ```bash
   docker build -t queryforge --no-cache .
   ```

3. **Run container**:
   ```bash
   docker run -d -p 8080:8080 --name queryforge queryforge:latest
   ```

4. **Verify deployment**:
   ```bash
   docker ps
   docker logs queryforge
   curl http://localhost:8080/sse
   ```

### Multi-Container Setup

For running multiple builders separately:

1. **Create docker-compose.override.yml**:
   ```yaml
   version: '3.8'

   services:
     queryforge:
       ports:
         - "8080:8080"

     kql-builder:
       build:
         context: ../kql_builder
       ports:
         - "8083:8083"
       environment:
         - MCP_TRANSPORT=sse
         - MCP_PORT=8083
       volumes:
         - kql_cache:/app/.cache
       healthcheck:
         test: ["CMD", "curl", "-f", "http://localhost:8083/sse"]
         interval: 10s
         timeout: 5s
         retries: 3

   volumes:
     kql_cache:
   ```

2. **Start all services**:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.override.yml up -d
   ```

### Docker Configuration Options

**Environment Variables**:
```yaml
environment:
  - MCP_TRANSPORT=sse
  - MCP_HOST=0.0.0.0
  - MCP_PORT=8080
  - LOG_LEVEL=INFO
  - PYTHONUNBUFFERED=1
```

**Volume Mounts**:
```yaml
volumes:
  # Persistent cache
  - builder_cache:/app/.cache

  # Custom schemas (optional)
  - ./custom_schemas:/app/custom_schemas:ro

  # Logs (optional)
  - ./logs:/app/logs
```

**Resource Limits**:
```yaml
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 2G
    reservations:
      cpus: '1'
      memory: 1G
```

**Health Checks**:
```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8080/sse"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

### Docker Networking

**Bridge Network (default)**:
```yaml
networks:
  default:
    name: mcp_network
    driver: bridge
```

**Custom Network**:
```yaml
networks:
  mcp_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16

services:
  unified-builder:
    networks:
      mcp_network:
        ipv4_address: 172.28.0.10
```

## Production Deployment

### Prerequisites

- Docker 24+ or Kubernetes 1.24+
- Reverse proxy (nginx, Traefik)
- SSL certificates
- Monitoring tools (Prometheus, Grafana)
- Log aggregation (ELK, Loki)

### Using Nginx as Reverse Proxy

1. **Install nginx**:
   ```bash
   sudo apt install nginx
   ```

2. **Configure nginx** (`/etc/nginx/sites-available/mcp-builder`):
   ```nginx
   upstream mcp_backend {
       server localhost:8080;
   }

   server {
       listen 80;
       server_name mcp.example.com;

       # Redirect to HTTPS
       return 301 https://$server_name$request_uri;
   }

   server {
       listen 443 ssl http2;
       server_name mcp.example.com;

       ssl_certificate /etc/letsencrypt/live/mcp.example.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/mcp.example.com/privkey.pem;

       # Security headers
       add_header Strict-Transport-Security "max-age=31536000" always;
       add_header X-Frame-Options "SAMEORIGIN" always;
       add_header X-Content-Type-Options "nosniff" always;

       # SSE specific settings
       location /sse {
           proxy_pass http://mcp_backend;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection "upgrade";
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;

           # SSE timeouts
           proxy_read_timeout 86400s;
           proxy_send_timeout 86400s;

           # Buffering must be off for SSE
           proxy_buffering off;
           proxy_cache off;
       }

       # Health check endpoint
       location /health {
           proxy_pass http://mcp_backend/sse;
           access_log off;
       }
   }
   ```

3. **Enable site**:
   ```bash
   sudo ln -s /etc/nginx/sites-available/mcp-builder /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl reload nginx
   ```

### Using Traefik (Docker)

1. **Create traefik docker-compose.yml**:
   ```yaml
   version: '3.8'

   services:
     traefik:
       image: traefik:v2.10
       command:
         - "--api.insecure=true"
         - "--providers.docker=true"
         - "--providers.docker.exposedbydefault=false"
         - "--entrypoints.web.address=:80"
         - "--entrypoints.websecure.address=:443"
         - "--certificatesresolvers.letsencrypt.acme.httpchallenge=true"
         - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
         - "--certificatesresolvers.letsencrypt.acme.email=admin@example.com"
         - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
       ports:
         - "80:80"
         - "443:443"
         - "8080:8080"  # Traefik dashboard
       volumes:
         - /var/run/docker.sock:/var/run/docker.sock:ro
         - traefik-certificates:/letsencrypt
       networks:
         - mcp_network

     queryforge:
       build: ./queryforge
       labels:
         - "traefik.enable=true"
         - "traefik.http.routers.mcp.rule=Host(`mcp.example.com`)"
         - "traefik.http.routers.mcp.entrypoints=websecure"
         - "traefik.http.routers.mcp.tls.certresolver=letsencrypt"
         - "traefik.http.services.mcp.loadbalancer.server.port=8080"
       networks:
         - mcp_network
       volumes:
         - builder_cache:/app/.cache

   networks:
     mcp_network:
       driver: bridge

   volumes:
     traefik-certificates:
     builder_cache:
   ```

2. **Start services**:
   ```bash
   docker compose up -d
   ```

### Systemd Service (Non-Docker)

1. **Create service file** (`/etc/systemd/system/mcp-builder.service`):
   ```ini
   [Unit]
   Description=MCP QueryForge
   After=network.target

   [Service]
   Type=simple
   User=mcp
   Group=mcp
   WorkingDirectory=/opt/mcp-builder/queryforge
   Environment="PATH=/opt/mcp-builder/.venv/bin"
   Environment="MCP_TRANSPORT=sse"
   Environment="MCP_PORT=8080"
   ExecStart=/opt/mcp-builder/.venv/bin/export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
python -m queryforge.server.server
   Restart=always
   RestartSec=10

   # Logging
   StandardOutput=journal
   StandardError=journal
   SyslogIdentifier=mcp-builder

   # Security
   NoNewPrivileges=true
   PrivateTmp=true
   ProtectSystem=strict
   ProtectHome=true
   ReadWritePaths=/opt/mcp-builder/.cache

   [Install]
   WantedBy=multi-user.target
   ```

2. **Enable and start**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable mcp-builder
   sudo systemctl start mcp-builder
   sudo systemctl status mcp-builder
   ```

## Cloud Deployments

### AWS (Elastic Container Service)

1. **Build and push image to ECR**:
   ```bash
   # Authenticate
   aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com

   # Build
   docker build -t mcp-builder:latest 

   # Tag
   docker tag mcp-builder:latest <account>.dkr.ecr.us-east-1.amazonaws.com/mcp-builder:latest

   # Push
   docker push <account>.dkr.ecr.us-east-1.amazonaws.com/mcp-builder:latest
   ```

2. **Create ECS task definition** (`task-definition.json`):
   ```json
   {
     "family": "mcp-builder",
     "networkMode": "awsvpc",
     "requiresCompatibilities": ["FARGATE"],
     "cpu": "1024",
     "memory": "2048",
     "containerDefinitions": [
       {
         "name": "mcp-builder",
         "image": "<account>.dkr.ecr.us-east-1.amazonaws.com/mcp-builder:latest",
         "portMappings": [
           {
             "containerPort": 8080,
             "protocol": "tcp"
           }
         ],
         "environment": [
           {"name": "MCP_TRANSPORT", "value": "sse"},
           {"name": "MCP_PORT", "value": "8080"}
         ],
         "logConfiguration": {
           "logDriver": "awslogs",
           "options": {
             "awslogs-group": "/ecs/mcp-builder",
             "awslogs-region": "us-east-1",
             "awslogs-stream-prefix": "ecs"
           }
         },
         "mountPoints": [
           {
             "sourceVolume": "cache",
             "containerPath": "/app/.cache"
           }
         ]
       }
     ],
     "volumes": [
       {
         "name": "cache",
         "efsVolumeConfiguration": {
           "fileSystemId": "fs-xxxxx",
           "transitEncryption": "ENABLED"
         }
       }
     ]
   }
   ```

3. **Create ECS service**:
   ```bash
   aws ecs create-service \
     --cluster mcp-cluster \
     --service-name mcp-builder \
     --task-definition mcp-builder \
     --desired-count 2 \
     --launch-type FARGATE \
     --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}" \
     --load-balancers "targetGroupArn=arn:aws:elasticloadbalancing:...,containerName=mcp-builder,containerPort=8080"
   ```

### Google Cloud Platform (Cloud Run)

1. **Build and push to Container Registry**:
   ```bash
   gcloud builds submit --tag gcr.io/PROJECT_ID/mcp-builder 
   ```

2. **Deploy to Cloud Run**:
   ```bash
   gcloud run deploy mcp-builder \
     --image gcr.io/PROJECT_ID/mcp-builder \
     --platform managed \
     --region us-central1 \
     --allow-unauthenticated \
     --port 8080 \
     --memory 2Gi \
     --cpu 2 \
     --set-env-vars "MCP_TRANSPORT=sse,MCP_PORT=8080" \
     --timeout 3600
   ```

### Azure (Container Instances)

```bash
az container create \
  --resource-group mcp-rg \
  --name mcp-builder \
  --image <registry>.azurecr.io/mcp-builder:latest \
  --dns-name-label mcp-builder \
  --ports 8080 \
  --cpu 2 \
  --memory 4 \
  --environment-variables MCP_TRANSPORT=sse MCP_PORT=8080 \
  --azure-file-volume-account-name <storage-account> \
  --azure-file-volume-account-key <key> \
  --azure-file-volume-share-name mcp-cache \
  --azure-file-volume-mount-path /app/.cache
```

### Kubernetes Deployment

1. **Create deployment** (`k8s/deployment.yaml`):
   ```yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: mcp-builder
     labels:
       app: mcp-builder
   spec:
     replicas: 3
     selector:
       matchLabels:
         app: mcp-builder
     template:
       metadata:
         labels:
           app: mcp-builder
       spec:
         containers:
         - name: mcp-builder
           image: mcp-builder:latest
           ports:
           - containerPort: 8080
             name: http
           env:
           - name: MCP_TRANSPORT
             value: "sse"
           - name: MCP_PORT
             value: "8080"
           resources:
             requests:
               memory: "1Gi"
               cpu: "500m"
             limits:
               memory: "2Gi"
               cpu: "2000m"
           volumeMounts:
           - name: cache
             mountPath: /app/.cache
           livenessProbe:
             httpGet:
               path: /sse
               port: 8080
             initialDelaySeconds: 30
             periodSeconds: 10
           readinessProbe:
             httpGet:
               path: /sse
               port: 8080
             initialDelaySeconds: 5
             periodSeconds: 5
         volumes:
         - name: cache
           persistentVolumeClaim:
             claimName: mcp-cache-pvc
   ```

2. **Create service** (`k8s/service.yaml`):
   ```yaml
   apiVersion: v1
   kind: Service
   metadata:
     name: mcp-builder
   spec:
     selector:
       app: mcp-builder
     ports:
     - protocol: TCP
       port: 80
       targetPort: 8080
     type: LoadBalancer
   ```

3. **Create PVC** (`k8s/pvc.yaml`):
   ```yaml
   apiVersion: v1
   kind: PersistentVolumeClaim
   metadata:
     name: mcp-cache-pvc
   spec:
     accessModes:
     - ReadWriteMany
     resources:
       requests:
         storage: 10Gi
     storageClassName: standard
   ```

4. **Deploy**:
   ```bash
   kubectl apply -f k8s/
   kubectl get pods
   kubectl get svc mcp-builder
   ```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_TRANSPORT` | stdio | Transport type (sse or stdio) |
| `MCP_HOST` | 0.0.0.0 | Bind address (SSE only) |
| `MCP_PORT` | 8080 | Port (SSE only) |
| `LOG_LEVEL` | INFO | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `CACHE_DIR` | .cache | Cache directory path |
| `PYTHONUNBUFFERED` | - | Set to 1 for real-time logs |

### Configuration Files

**config.yaml** (if implementing):
```yaml
server:
  transport: sse
  host: 0.0.0.0
  port: 8080

logging:
  level: INFO
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

cache:
  directory: .cache
  ttl: 86400

rag:
  enabled: true
  k_default: 5
  cache_embeddings: true

platforms:
  kql:
    enabled: true
    schema_path: kql/defender_xdr_kql_schema_fuller
  cbc:
    enabled: true
    schema_path: cbc/cbc_schema.json
  cortex:
    enabled: true
    schema_path: cortex/cortex_xdr_schema.json
  s1:
    enabled: true
    schema_path: ../s1_builder/s1_schemas
```

## Security Considerations

### Authentication

Implement authentication layer:

```python
# In server.py, add middleware
from fastapi import Security, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

async def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    if credentials.credentials != "your-secret-token":
        raise HTTPException(status_code=401, detail="Invalid token")
    return credentials

# Protect endpoints
@app.get("/sse", dependencies=[Depends(verify_token)])
async def sse_endpoint():
    ...
```

### TLS/SSL

1. **Generate certificates**:
   ```bash
   certbot certonly --standalone -d mcp.example.com
   ```

2. **Configure in nginx** (see production deployment section)

### Network Security

**Firewall rules**:
```bash
# Allow only from specific IP
sudo ufw allow from 192.168.1.0/24 to any port 8080

# Or allow from VPN
sudo ufw allow from 10.8.0.0/24 to any port 8080
```

**Docker network isolation**:
```yaml
networks:
  internal:
    driver: bridge
    internal: true
  external:
    driver: bridge

services:
  mcp-builder:
    networks:
      - internal  # Not directly accessible

  nginx:
    networks:
      - internal
      - external  # Public-facing
```

### Secrets Management

**Using Docker Secrets**:
```yaml
services:
  mcp-builder:
    secrets:
      - api_token
    environment:
      - API_TOKEN_FILE=/run/secrets/api_token

secrets:
  api_token:
    file: ./secrets/api_token.txt
```

**Using Kubernetes Secrets**:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mcp-secrets
type: Opaque
stringData:
  api-token: "your-secret-token"
```

## Monitoring and Logging

### Prometheus Metrics

Add metrics endpoint:

```python
from prometheus_client import Counter, Histogram, generate_latest

query_counter = Counter('mcp_queries_total', 'Total queries', ['platform'])
query_duration = Histogram('mcp_query_duration_seconds', 'Query duration', ['platform'])

@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")
```

### Grafana Dashboard

Example queries:
```promql
# Query rate
rate(mcp_queries_total[5m])

# Query duration
histogram_quantile(0.95, mcp_query_duration_seconds_bucket)

# Error rate
rate(mcp_errors_total[5m])
```

### Log Aggregation

**ELK Stack** (Elasticsearch, Logstash, Kibana):
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
    labels: "service=mcp-builder"
```

**Loki**:
```yaml
logging:
  driver: loki
  options:
    loki-url: "http://loki:3100/loki/api/v1/push"
    labels: "service=mcp-builder"
```

## Backup and Recovery

### Cache Backup

```bash
# Backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/mcp-cache"

# Create backup
tar -czf "$BACKUP_DIR/cache_$DATE.tar.gz" .cache/

# Keep only last 7 days
find "$BACKUP_DIR" -name "cache_*.tar.gz" -mtime +7 -delete
```

### Restore Cache

```bash
tar -xzf cache_20240101_120000.tar.gz -C /path/to/mcp/
```

### Automated Backups

**Cron job**:
```cron
0 2 * * * /opt/mcp-builder/backup.sh
```

**Kubernetes CronJob**:
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: mcp-cache-backup
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: alpine:latest
            command:
            - /bin/sh
            - -c
            - tar -czf /backup/cache_$(date +%Y%m%d).tar.gz /app/.cache
            volumeMounts:
            - name: cache
              mountPath: /app/.cache
            - name: backup
              mountPath: /backup
          restartPolicy: OnFailure
          volumes:
          - name: cache
            persistentVolumeClaim:
              claimName: mcp-cache-pvc
          - name: backup
            persistentVolumeClaim:
              claimName: backup-pvc
```

## Scaling

### Vertical Scaling

Increase resources per instance:

**Docker**:
```yaml
deploy:
  resources:
    limits:
      cpus: '4'
      memory: 8G
```

**Kubernetes**:
```yaml
resources:
  requests:
    memory: "2Gi"
    cpu: "1000m"
  limits:
    memory: "8Gi"
    cpu: "4000m"
```

### Horizontal Scaling

Multiple instances behind load balancer:

**Docker Compose**:
```yaml
services:
  mcp-builder:
    deploy:
      replicas: 3
```

**Kubernetes**:
```bash
kubectl scale deployment mcp-builder --replicas=5
```

**Auto-scaling** (Kubernetes HPA):
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: mcp-builder-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: mcp-builder
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

### Cache Sharing

Use shared cache for multiple instances:

1. **Redis cache** (future enhancement)
2. **NFS/EFS** for file-based cache
3. **Distributed cache** (Memcached)

## Health Checks

### Docker Health Check

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8080/sse || exit 1
```

### Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /sse
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /sse
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
```

## Maintenance

### Zero-Downtime Updates

**Docker Compose**:
```bash
docker compose pull
docker compose up -d --no-deps --build mcp-builder
```

**Kubernetes Rolling Update**:
```bash
kubectl set image deployment/mcp-builder mcp-builder=mcp-builder:v2
kubectl rollout status deployment/mcp-builder
```

### Rollback

**Docker**:
```bash
docker compose down
docker compose up -d --build <previous-version>
```

**Kubernetes**:
```bash
kubectl rollout undo deployment/mcp-builder
kubectl rollout status deployment/mcp-builder
```

## Performance Tuning

### Python Optimizations

```python
# Use faster JSON library
import orjson instead of json

# Enable async where possible
async def build_query(...):
    ...

# Connection pooling for external APIs
from aiohttp import ClientSession, TCPConnector
connector = TCPConnector(limit=100)
```

### Container Optimizations

```dockerfile
# Multi-stage build
FROM python:3.12-slim as builder
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

FROM python:3.12-slim
COPY --from=builder /wheels /wheels
RUN pip install --no-cache /wheels/*

# Use smaller base image
FROM python:3.12-alpine
```

### Database/Cache Optimization

- Pre-warm cache on startup
- Optimize JSON schema structure
- Use binary formats for embeddings (pickle vs joblib)
- Enable compression for cache files

---

This deployment guide covers the most common deployment scenarios. For specific requirements or troubleshooting, refer to [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
