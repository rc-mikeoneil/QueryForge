# MCP Query Builder - AWS ECS Deployment Guide

This comprehensive guide will walk you through deploying the MCP Query Builder server to AWS ECS with an internal Application Load Balancer (ALB) in the **us-east-2** region.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Architecture Overview](#architecture-overview)
4. [Step 1: Prepare IAM Roles](#step-1-prepare-iam-roles)
5. [Step 2: Build and Push Docker Image](#step-2-build-and-push-docker-image)
6. [Step 3: Create Security Groups](#step-3-create-security-groups)
7. [Step 4: Create Application Load Balancer](#step-4-create-application-load-balancer)
8. [Step 5: Create ECS Cluster](#step-5-create-ecs-cluster)
9. [Step 6: Register Task Definition](#step-6-register-task-definition)
10. [Step 7: Create ECS Service](#step-7-create-ecs-service)
11. [Step 8: Verify Deployment](#step-8-verify-deployment)
12. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before starting, ensure you have:

- AWS Account with appropriate permissions
- AWS CLI installed and configured
- Docker installed locally
- VPN access configured (for testing the internal ALB)
- LiteLLM API key for embeddings functionality

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         AWS Region: us-east-2               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                    Your VPC                          │   │
│  │                                                      │   │
│  │  ┌──────────────────────────────────────────────┐    │   │
│  │  │            Private Subnets                   │    │   │
│  │  │                                              │    │   │
│  │  │  ┌──────────────────────────────────────┐    │    │   │
│  │  │  │   Internal Application Load Balancer │    │    │   │
│  │  │  │         (Port 80/443)                │    │    │   │
│  │  │  └──────────────┬───────────────────────┘    │    │   │
│  │  │                 │                            │    │   │
│  │  │     ┌───────────┴───────────┐                │    │   │
│  │  │     │                       │                │    │   │
│  │  │  ┌──▼───┐    ┌──▼───┐    ┌──▼───┐            │    │   │
│  │  │  │Task 1│    │Task 2│    │Task 3│            │    │   │
│  │  │  │:8080 │    │:8080 │    │:8080 │            │    │   │
│  │  │  └──────┘    └──────┘    └──────┘            │    │   │
│  │  │       ECS Fargate Tasks (3 instances)        │    │   │
│  │  └──────────────────────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                           ▲
                           │
                    VPN Connection
                           │
                    [Your Network]
```

---

## Step 1: Prepare IAM Roles

### Using AWS Console

1. **Navigate to IAM Console:**
   - Open AWS Console → Services → IAM
   - Region doesn't matter for IAM (it's global)

2. **Create ECS Task Execution Role:**
   
   a. Click **"Roles"** in the left sidebar
   
   b. Click **"Create role"** button
   
   c. Select trusted entity:
      - Choose **"AWS service"**
      - Select **"Elastic Container Service"**
      - Select **"Elastic Container Service Task"**
      - Click **"Next"**
   
   d. Add permissions:
      - Search and select: **"AmazonECSTaskExecutionRolePolicy"**
      - Click **"Next"**
   
   e. Name the role:
      - Role name: `test-MCP-role`
      - Click **"Create role"**

3. **Create ECS Task Role:**
   
   a. Click **"Create role"** again
   
   b. Select trusted entity (same as above):
      - AWS service → Elastic Container Service → Elastic Container Service Task
   
   c. Add permissions:
      - Search and select: **"CloudWatchLogsFullAccess"**
      - Click **"Next"**
   
   d. Name the role:
      - Role name: `test-MCP-logging-role`
      - Click **"Create role"**

4. **Note the Role ARNs:**
   - Click on each role you created
   - Copy the ARN (looks like: `arn:aws:iam::123456789012:role/test-MCP-role`)
   - Save these for later use

   arn:aws:iam::340047602715:role/test-MCP-cemhoff
   arn:aws:iam::340047602715:role/test-MCP-logging-cemhoff

---

## Step 2: Build and Push Docker Image

### Prerequisites for this step:
- Docker Desktop running
- AWS CLI configured (either regular or SSO)

### For AWS SSO Users:

If you're using AWS SSO (Single Sign-On):

1. **Login to your AWS SSO profile:**
   ```bash
   aws sso login --profile $PROFILE  # Replace with your profile name
   ```

2. **Verify you're in the correct account:**
   ```bash
   aws sts get-caller-identity --profile $PROFILE
   ```

   This will show Account ID for the associated $PROFILE name. Note this account number somewhere, you'll need it later.

3. **Use the SSO-compatible build script:**
   ```bash
   cd ecs
   chmod +x build-and-push-sso.sh
   AWS_PROFILE=$PROFILE ./build-and-push-sso.sh
   ```

### What the Build Script Does:
   
   The script will:
   - Authenticate Docker to ECR
   - Create the ECR repository if needed
   - Build the Docker image
   - Tag and push to ECR
   - Display the image URI (save this!)

   Note that the script is currently configured for deployment of the MCP server image, can be modified for other use.

---

## Step 3: Setup AWS Secrets Manager for API Keys

### Important: LiteLLM API Key Configuration

The MCP Query Builder requires a LiteLLM API key to function. This step sets up secure storage for the API key using AWS Secrets Manager.

### Using the Setup Script:

1. **Create the secret in AWS Secrets Manager (Change "mcp-query-builder" portion to reflect your project):**
   ```bash
   aws secretsmanager create-secret \
     --name mcp-query-builder/litellm-api-key \
     --secret-string "your-api-key-here" \
     --region us-east-2 \
     --profile $PROFILE
   ```

2. **Grant ECS access to the secret:**
   - Go to IAM Console
   - Find your execution role (`test-MCP-role`)
   - Add an inline policy allowing `secretsmanager:GetSecretValue` for your secret ARN

---

## Step 4: Create Security Groups

### Using AWS Console:

1. **Navigate to EC2 Console:**
   - AWS Console → Services → EC2
   - **IMPORTANT:** Select **us-east-2** region (top-right corner)

2. **Create ALB Security Group:**
   
   a. Left sidebar → **"Security Groups"**
   
   b. Click **"Create security group"**
   
   c. Basic details:
      - Security group name: `mcp-alb-test-sg`
      - Description: `Security group for MCP Query Builder ALB - TH Testing`
      - VPC: Select your VPC
   
   d. Inbound rules - Click **"Add rule"**:
      - Type: **HTTP**
      - Source: **Custom**
      - CIDR: '10.0.0.0/8'
      - Description: `Allow HTTP from VPN`
   
      NOTE: This will not allow traffic in YellsAtCloud as routes haven't been configured accordingly here. In order to test in YellsAtCloud, you will need to make the associated port for your deployment publicly accessible, however, I STRONGLY recommend only doing this once everything is setup and you're ready to test in that moment.

      AFTER YOU'VE TESTED, ENSURE THIS SECURITY GROUP IS NOT SET TO "0.0.0.0/0" FOR INBOUND TRAFFIC.
   
   e. Outbound rules (leave default - allow all)
   
   f. Click **"Create security group"**
   
   g. **Save the Security Group ID** (Note the Security Group ID: )

3. **Create ECS Task Security Group:**
   
   a. Click **"Create security group"** again
   
   b. Basic details:
      - Security group name: `mcp-ecs-task-test-sg`
      - Description: `Security group for MCP Query Builder ECS tasks`
      - VPC: Select your VPC
   
   c. Inbound rules - Click **"Add rule"**:
      - Type: **Custom TCP**
      - Port range: `8080`
      - Source: **Custom**
      - Source: Select the ALB security group (`mcp-alb-test--sg`)
      - Description: `Allow traffic from ALB`
   
   d. Click **"Create security group"**
   
   e. **Save the Security Group ID** (Note the Security Group ID: )

---

## Step 4: Create Application Load Balancer

### Using AWS Console:

1. **Navigate to EC2 Load Balancers:**
   - EC2 Console → Left sidebar → **"Load Balancers"**
   - Click **"Create load balancer"**

2. **Select Load Balancer Type:**
   - Choose **"Application Load Balancer"**
   - Click **"Create"**

3. **Configure Load Balancer:**
   
   a. Basic configuration:
      - Name: `mcp-query-builder-alb`
      - Scheme: **Internal** (IMPORTANT!)
      - IP address type: **IPv4**
   
   b. Network mapping:
      - VPC: Select your VPC
      - Mappings: Select at least 2 availability zones
      - **For each AZ, select a PRIVATE subnet:**
        - Look for subnet names containing "private"
        - Avoid subnets with "public" in the name
        - If unsure, verify in VPC Console → Subnets → Route Table tab
        - ✅ Should NOT have route to Internet Gateway (igw-xxxxx)
        - ✅ May have route to NAT Gateway (nat-xxxxx)
   
   c. Security groups:
      - Remove the default security group
      - Select: `mcp-alb-test-sg` (created earlier)
   
   d. Listeners and routing:
      - Protocol: **HTTP**
      - Port: **80**
      - Default action: **Create target group**

4. **Create Target Group (in the same flow):**
   
   When you click "Create target group", a new tab opens:
   
   a. Target type:
      - Choose: **IP addresses**
      - Click **"Next"**
   
   b. Basic configuration:
      - Target group name: `mcp-query-builder-tg`
      - Protocol: **HTTP**
      - Port: **8080**
      - VPC: Select your VPC
      - Protocol version: **HTTP1**
   
   c. Health checks:
      - Health check protocol: **HTTP**
      - Health check path: `/health` (Note: This path may change depending on how your application is configured.)
      - Advanced health check settings:
        - Healthy threshold: **2**
        - Unhealthy threshold: **3**
        - Timeout: **10** seconds
        - Interval: **30** seconds
        - Success codes: **200**
   
   d. Register targets:
      - Skip this step (ECS will register automatically)
      - Click **"Create target group"**
   
   e. Return to the ALB creation tab:
      - Refresh the target group list
      - Select: `mcp-query-builder-tg`

5. **Review and Create:**
   - Review all settings
   - Click **"Create load balancer"**
   - **Save the ALB DNS name** (will look like: internal-mcp-query-builder-alb-XXXXXXX.us-east-2.elb.amazonaws.com)

6. **Wait for ALB to be Active:**
   - The ALB will show "provisioning" status
   - Wait 2-3 minutes until status is "active"

---

## Step 5: Create ECS Cluster

### Using AWS Console:

1. **Navigate to ECS Console:**
   - AWS Console → Services → **ECS**
   - Ensure region is **us-east-2**

2. **Create Cluster:**
   
   a. Click **"Clusters"** in left sidebar
   
   b. Click **"Create cluster"**
   
   c. Cluster configuration:
      - Cluster name: `mcp-query-builder-cluster`
   
   d. Infrastructure:
      - Select: **AWS Fargate (serverless)**
      - Leave other options as default
   
   e. Click **"Create"**

---

## Step 6: Register Task Definition

### Using AWS Console:

1. **Navigate to Task Definitions:**
   - ECS Console → **"Task definitions"**
   - Click **"Create new task definition"**
   - Choose **"Create new task definition with JSON"**

2. **Prepare the JSON:**
   
   First, update the `task-definition.json` file with your values:
   
   You need to update:
   - executionRoleArn
   - taskRoleArn
   - image URI
   - LITELLM_API_KEY "valueFrom" field (ARN)
   - awslogs-group key (Go to CloudWatch and create a new log group if needed for testing.)

3. **Register via Console:**
   
   a. Copy the entire contents of your updated `task-definition.json`
   
   b. Paste into the JSON editor in the console
   
   c. Click **"Create"**

---

## Step 7: Create ECS Service

### Using AWS Console:

1. **Navigate to your Cluster:**
   - ECS Console → Clusters → **mcp-query-builder-cluster**

2. **Create Service:**
   
   a. In the Services tab, click **"Create"**
   
   b. Environment:
      - Compute options: **Launch type**
      - Launch type: **FARGATE**
   
   c. Deployment configuration:
      - Application type: **Service**
      - Desired tasks: **3**
      - Health check grace period: **60** seconds
   
   d. Networking:
      - VPC: Select your VPC
      - Subnets: Select your private subnets (same as ALB)
      - Security group: Select `mcp-ecs-task-test-sg`
      - Public IP: **Turned on**
   
   e. Load balancing:
      - Load balancer type: **Application Load Balancer**
      - Container: **mcp-server : 8080:8080**
      - Choose: **Use an existing load balancer**
      - Load balancer: **mcp-query-builder-alb**
      - Choose: **Use an existing target group**
      - Target group: **mcp-query-builder-tg**
   
   f. Service auto scaling:
      - Leave as **"Do not adjust the service's desired count"**
   
   g. Click **"Create"**

3. **Monitor Service Creation:**
   - The service will take 2-3 minutes to start all tasks
   - Click on the service name to view details
   - Check the "Tasks" tab to see task status
   - All 3 tasks should show "RUNNING" status

---

## Step 8: Verify Deployment

### 1. Check ECS Service Health:

In the ECS Console:
- Go to Clusters → mcp-query-builder-cluster → Services
- Click on your service
- Check:
  - **Desired tasks:** 3
  - **Running tasks:** 3
  - **Health status:** All tasks healthy

### 2. Check Target Group Health:

In the EC2 Console:
- Go to Target Groups
- Select `mcp-query-builder-tg`
- Click "Targets" tab
- All 3 targets should show "healthy"

### 3. Check CloudWatch Logs:

In the CloudWatch Console:
- Go to Log groups
- Find `/ecs/mcp-query-builder`
- Check for any error messages

### 4. Test the Endpoint:

**From a machine connected to your VPN:**

```bash
# Get the ALB DNS name from the EC2 console
ALB_DNS="external-mcp-query-builder-alb-xxxxxxxxx.us-east-2.elb.amazonaws.com"

# Test the health endpoint
curl -i http://$ALB_DNS/health
```

### 5. Test with MCP Client:

Configure your MCP client to connect to:
```
http://external-mcp-query-builder-alb-xxxxxxxxx.us-east-2.elb.amazonaws.com/
```

---

## Troubleshooting

### Common Issues and Solutions:

#### Tasks Not Starting:

1. **Check CloudWatch Logs:**
   ```bash
   aws logs tail /ecs/mcp-query-builder --follow --region us-east-2
   ```

2. **Common causes:**
   - Image not found → Verify ECR image URI
   - Permission denied → Check IAM roles
   - Port already in use → Check container port configuration

#### Tasks Unhealthy:

1. **Check Security Groups:**
   - ALB SG must allow inbound from external IP (ONLY DO THIS WHEN READY TO TEST LIVE)
   - Task SG must allow inbound from ALB SG on port 8080

2. **Check Health Check Path:**
   - Target group health check must use `/health`
   - Increase health check timeout if needed

#### Cannot Access from VPN:

1. **Verify ALB is Internal:**
   - Check ALB scheme is "external"
   
2. **Check DNS Resolution:**
   ```bash
   nslookup internal-mcp-query-builder-alb-xxx.us-east-2.elb.amazonaws.com
   ```

#### High Memory/CPU Usage:

1. **Scale the Task Definition:**
   - Edit task definition
   - Increase CPU to 2048 (2 vCPU)
   - Increase Memory to 4096 (4 GB)
   - Create new revision
   - Update service to use new revision

### Useful CLI Commands:

```bash
# List all tasks in the service
aws ecs list-tasks \
  --cluster mcp-query-builder-cluster \
  --service-name mcp-query-builder-service \
  --region us-east-2

# Describe a specific task (get task ARN from list-tasks)
aws ecs describe-tasks \
  --cluster mcp-query-builder-cluster \
  --tasks "arn:aws:ecs:us-east-2:xxx:task/xxx" \
  --region us-east-2

# Force service redeployment
aws ecs update-service \
  --cluster mcp-query-builder-cluster \
  --service mcp-query-builder-service \
  --force-new-deployment \
  --region us-east-2

# View service events
aws ecs describe-services \
  --cluster mcp-query-builder-cluster \
  --services mcp-query-builder-service \
  --region us-east-2 \
  --query 'services[0].events[0:10]'
```

---

## Updating the Application

When you need to deploy a new version:

1. **Build and push new image:**
   ```bash
   cd ecs
   AWS_PROFILE=$AWS_PROFILE ./build-and-push-sso.sh
   ```

2. **Force service to pull new image:**
   ```bash
   aws ecs update-service \
     --cluster mcp-query-builder-cluster \
     --service mcp-query-builder-service \
     --force-new-deployment \
     --region us-east-2
   ```

3. **Monitor the deployment:**
   - ECS performs a rolling update
   - Old tasks are drained and stopped
   - New tasks are started and health-checked
   - Zero-downtime deployment

---

## Cost Optimization Tips

1. **Fargate Spot:**
   - Consider using Fargate Spot for 70% cost savings
   - Good for non-critical workloads

2. **Right-sizing:**
   - Monitor CloudWatch metrics
   - Adjust CPU/Memory based on actual usage

3. **Savings Plans:**
   - Consider Compute Savings Plans for Fargate

---

## Security Best Practices

1. **Secrets Management:**
   - Use AWS Secrets Manager for sensitive data
   - Reference secrets in task definition
   - Rotate credentials regularly

2. **Network Isolation:**
   - Keep tasks in private subnets
   - Use VPC endpoints for AWS services
   - Implement network segmentation

3. **Least Privilege:**
   - Grant minimum required IAM permissions
   - Use separate roles for task execution and task runtime
   - Regularly audit IAM policies

4. **Container Security:**
   - Scan images for vulnerabilities (ECR scanning enabled)
   - Use specific image tags (not 'latest' in production)
   - Keep base images updated

5. **Monitoring:**
   - Enable CloudWatch Container Insights
   - Set up alerts for anomalous behavior
   - Enable VPC Flow Logs

---

## Cleanup Instructions

If you need to remove the deployment:

1. **Delete ECS Service:**
   ```bash
   aws ecs delete-service \
     --cluster mcp-query-builder-cluster \
     --service mcp-query-builder-service \
     --force \
     --region us-east-2
   ```

2. **Delete Load Balancer:**
   - EC2 Console → Load Balancers
   - Select and delete `mcp-query-builder-alb`

3. **Delete Target Group:**
   - EC2 Console → Target Groups
   - Select and delete `mcp-query-builder-tg`

4. **Delete ECS Cluster:**
   ```bash
   aws ecs delete-cluster \
     --cluster mcp-query-builder-cluster \
     --region us-east-2
   ```

5. **Delete ECR Repository:**
   ```bash
   aws ecr delete-repository \
     --repository-name mcp-query-builder \
     --force \
     --region us-east-2
   ```

6. **Delete Security Groups:**
   - EC2 Console → Security Groups
   - Delete `mcp-ecs-task-test-sg` and `mcp-alb-test-sg`

7. **Delete CloudWatch Log Group:**
   ```bash
   aws logs delete-log-group \
     --log-group-name /ecs/mcp-query-builder \
     --region us-east-2
   ```

---

## Support and Maintenance

For ongoing support:

- Monitor CloudWatch dashboards regularly
- Review ECS service events for deployment issues
- Check ALB access logs for usage patterns
- Update container images monthly for security patches
