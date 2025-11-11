# QueryForge Terraform Deployment Guide

This guide explains how to deploy the QueryForge MCP Server to AWS ECS using Terraform.

## Architecture Overview

```
Internet → ALB (sticky sessions) → Target Group → ECS Fargate Tasks (2) → QueryForge Container
                                                         ↓
                                                   CloudWatch Logs
                                                         ↓
                                                   Secrets Manager
```

## Components

- **ECR Repository**: `queryForge` for container images
- **ECS Cluster**: Fargate cluster with 2 tasks for redundancy
- **Application Load Balancer**: HTTP load balancer with sticky sessions (24h)
- **Security Groups**: ALB and ECS task security groups
- **IAM Roles**: Task execution and task runtime roles
- **CloudWatch**: Log group for container logs
- **Secrets Manager**: API key storage

## Prerequisites

1. **AWS CLI configured** with appropriate credentials
2. **Terraform installed** (v1.0+)
3. **Existing VPC and subnets** in AWS
4. **Secrets Manager secret** created with LiteLLM API key
5. **Docker image** built and ready to push to ECR

## Step 1: Add Required Variables

Add these variables to your existing `variables.tf`:

```hcl
# QueryForge VPC Configuration
variable "queryforge_vpc_id" {
  description = "VPC ID for QueryForge deployment"
  type        = string
  default     = "vpc-xxxxx"  # Replace with your VPC ID
}

variable "queryforge_private_subnet_ids" {
  description = "Private subnet IDs for QueryForge ECS tasks"
  type        = list(string)
  default     = [
    "subnet-xxxxx",  # Replace with your subnet IDs
    "subnet-yyyyy"
  ]
}

# QueryForge Secrets
variable "queryforge_litellm_api_key_secret_arn" {
  description = "ARN of Secrets Manager secret containing LiteLLM API key"
  type        = string
  default     = "arn:aws:secretsmanager:us-east-2:ACCOUNT_ID:secret:queryforge/litellm-api-key-xxxxx"
}
```

## Step 2: Update QueryForge.tf Variable References

In `QueryForge.tf`, update the variable references:
- Change `var.vpc_id` to `var.queryforge_vpc_id`
- Change `var.private_subnet_ids` to `var.queryforge_private_subnet_ids`

## Step 3: Add IAM Roles to iam.tf

Copy the contents of `QueryForge_IAM.tf` into your `iam.tf` file. The file contains instructions on where to place them.

## Step 4: Create Secrets Manager Secret

If not already created:

```bash
aws secretsmanager create-secret \
  --name queryforge/litellm-api-key \
  --description "LiteLLM API key for QueryForge MCP server" \
  --secret-string "your-api-key-here" \
  --region us-east-2 \
  --profile your-profile
```

Note the ARN returned and update your `variables.tf`.

## Step 5: Create Git PR for Terraform planning

This will create:
- ECR repository
- ECS cluster and service
- Application Load Balancer
- Security groups
- CloudWatch log group
- IAM roles and policies

## Step 7: Build and Push Docker Image

After Terraform creates the infrastructure:

```bash
# Authenticate Docker to ECR
aws ecr get-login-password --region us-east-2 --profile your-profile | \
  docker login --username AWS --password-stdin ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com

# Build the image (from QueryForge project root)
cd /Users/cemhoff/Documents/QueryForge
docker build --platform linux/amd64 -f Dockerfile.ecs.python -t queryforge .

# Tag the image
docker tag queryforge:latest ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com/queryforge:latest

# Push to ECR
docker push ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com/queryforge:latest
```

## Step 8: Verify Deployment

```bash
# Get the ALB DNS name
terraform output queryforge_alb_dns_name

# Test the health endpoint
curl http://YOUR-ALB-DNS/health

# Check ECS service status
aws ecs describe-services \
  --cluster queryforge-cluster \
  --services queryforge-service \
  --region us-east-2 \
  --profile your-profile

# View logs
aws logs tail /ecs/queryforge --follow \
  --region us-east-2 \
  --profile your-profile
```

## Updating the Service

To deploy a new version:

```bash
# Build and push new image
docker build --platform linux/amd64 -f Dockerfile.ecs.python -t queryforge .
docker tag queryforge:latest ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com/queryforge:latest
docker push ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com/queryforge:latest

# Force new deployment
aws ecs update-service \
  --cluster queryforge-cluster \
  --service queryforge-service \
  --force-new-deployment \
  --region us-east-2 \
  --profile your-profile
```

## MCP Client Configuration

Configure your MCP client (e.g., Claude Desktop) to use the ALB endpoint:

```json
{
  "mcpServers": {
    "queryforge": {
      "url": "http://YOUR-ALB-DNS/sse",
      "transport": "sse"
    }
  }
}
```

## Sticky Sessions

Sticky sessions are **automatically enabled** with a 24-hour duration. This ensures:
- Session continuity across requests
- Proper routing to the same container
- No session state issues with multiple containers

The ALB automatically sets cookies (`AWSALB`) to maintain session affinity.

## Monitoring

### CloudWatch Logs
View container logs:
```bash
aws logs tail /ecs/queryforge --follow --region us-east-2 --profile your-profile
```

### ECS Service Health
Monitor service status in AWS Console or CLI:
```bash
aws ecs describe-services \
  --cluster queryforge-cluster \
  --services queryforge-service \
  --region us-east-2 \
  --profile your-profile
```

### ALB Health Checks
The ALB performs health checks on `/health` every 30 seconds.

## Scaling

To change the number of running tasks:

```bash
# Update desired count in QueryForge.tf
# Change: desired_count = 2
# To:     desired_count = 3

terraform apply
```

Or via CLI:
```bash
aws ecs update-service \
  --cluster queryforge-cluster \
  --service queryforge-service \
  --desired-count 3 \
  --region us-east-2 \
  --profile your-profile
```

## Troubleshooting

### Service Won't Start
1. Check ECS task logs in CloudWatch
2. Verify Secrets Manager secret exists and is accessible
3. Check security group rules allow ALB → ECS communication

### Health Check Failures
1. Verify container is listening on port 8080
2. Check `/health` endpoint returns 200
3. Review container logs for errors

### Can't Pull Image from ECR
1. Verify IAM execution role has ECR permissions
2. Check image exists in ECR repository
3. Ensure task execution role has proper trust policy

### Session Issues
- Sticky sessions are enabled by default (24h duration)
- Clients must support cookies
- Check ALB target group settings if issues persist

## Cost Optimization

- **ECS Tasks**: 2 x Fargate vCPU/memory charges (24/7)
- **ALB**: Hourly charge + LCU charges
- **ECR**: Storage charges (lifecycle policy limits to 10 images)
- **CloudWatch**: Log storage (7-day retention)

To reduce costs:
- Reduce `desired_count` to 1 (loses redundancy)
- Use smaller task sizes (reduce CPU/memory)
- Reduce log retention period

## Destroying Infrastructure

To remove all resources:

```bash
# Destroy all resources
terraform destroy

# Type 'yes' to confirm
```

Note: This will delete all resources including logs (but not the Secrets Manager secret).

## Support

For issues or questions:
1. Check CloudWatch logs: `/ecs/queryforge`
2. Review ECS service events in AWS Console
3. Verify all variables are set correctly
4. Check security group rules

## Additional Resources

- [AWS ECS Documentation](https://docs.aws.amazon.com/ecs/)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [QueryForge GitHub Repository](https://github.com/cemhoff/QueryForge)
