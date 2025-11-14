# GitHub Actions Setup for QueryForge ECS Deployment

This guide explains how to set up automated deployments of QueryForge to AWS ECS using GitHub Actions.

---

## Overview

The GitHub Actions workflow (`.github/workflows/deploy-to-ecs.yml`) automatically deploys your QueryForge application to AWS ECS whenever you push to the `main` branch.

**Workflow:**
1. Push code to `main` branch
2. GitHub Actions triggers
3. Builds Docker image using `Dockerfile.ecs`
4. Pushes image to Amazon ECR
5. Updates ECS task definition
6. Forces ECS service deployment with new image
7. Waits for deployment stability

---

## Prerequisites

Before the workflow can run, you need to complete these AWS setup steps:

### 1. ✅ Deploy Infrastructure with Terraform

Your ECS infrastructure must be deployed using the Terraform files in `ecs/`:

```bash
cd ecs/
terraform init
terraform plan
terraform apply
```

This creates:
- **ECR Repository**: `queryforge`
- **ECS Cluster**: `queryforge-cluster`
- **ECS Service**: `queryforge-service`
- **Task Definition**: `queryforge`
- **Application Load Balancer**: `queryforge-alb`

### 2. ✅ Create GitHub OIDC IAM Role

Create an IAM role that allows GitHub Actions to authenticate with AWS using OIDC (recommended over using AWS access keys).

#### Create the IAM Role

```bash
# Set your AWS account ID
AWS_ACCOUNT_ID="123456789012"  # Replace with your account ID

# Set your GitHub repository (format: username/repo)
GITHUB_REPO="rc-mikeoneil/QueryForge"  # Replace with your repo
```

#### IAM Trust Policy

Create `github-trust-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:rc-mikeoneil/QueryForge:*"
        }
      }
    }
  ]
}
```

**Note:** Replace `123456789012` with your AWS account ID and `rc-mikeoneil/QueryForge` with your GitHub repository.

#### IAM Permissions Policy

Create `github-deploy-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ECRAccess",
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:PutImage",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ECSTaskDefinition",
      "Effect": "Allow",
      "Action": [
        "ecs:DescribeTaskDefinition",
        "ecs:RegisterTaskDefinition"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ECSServiceUpdate",
      "Effect": "Allow",
      "Action": [
        "ecs:UpdateService",
        "ecs:DescribeServices"
      ],
      "Resource": "arn:aws:ecs:us-east-2:123456789012:service/queryforge-cluster/queryforge-service"
    },
    {
      "Sid": "IAMPassRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": [
        "arn:aws:iam::123456789012:role/queryforge-ecs-execution-role",
        "arn:aws:iam::123456789012:role/queryforge-ecs-task-role"
      ]
    },
    {
      "Sid": "ELBDescribe",
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeLoadBalancers"
      ],
      "Resource": "*"
    }
  ]
}
```

**Note:** Replace `123456789012` with your AWS account ID.

#### Create the IAM OIDC Provider (if not already created)

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1 \
  --region us-east-2
```

**Note:** Only run this once per AWS account. If it already exists, skip this step.

#### Create the IAM Role

```bash
# Create the role
aws iam create-role \
  --role-name github-ecs-deploy-role \
  --assume-role-policy-document file://github-trust-policy.json \
  --region us-east-2

# Attach the permissions policy
aws iam put-role-policy \
  --role-name github-ecs-deploy-role \
  --policy-name github-ecs-deploy-policy \
  --policy-document file://github-deploy-policy.json \
  --region us-east-2
```

### 3. ✅ Configure GitHub Secrets

Add the following secret to your GitHub repository:

**Settings → Secrets and variables → Actions → New repository secret**

| Secret Name | Value | Description |
|------------|-------|-------------|
| `AWS_ACCOUNT_ID` | `123456789012` | Your AWS account ID |

**To find your AWS account ID:**
```bash
aws sts get-caller-identity --query Account --output text
```

---

## Workflow Configuration

The workflow is already configured with your project-specific values:

### Environment Variables (already set)

```yaml
env:
  AWS_REGION: us-east-2                    # Your AWS region
  ECR_REPOSITORY: queryforge               # From Terraform
  ECS_SERVICE: queryforge-service          # From Terraform
  ECS_CLUSTER: queryforge-cluster          # From Terraform
  ECS_TASK_DEFINITION: queryforge          # From Terraform
  CONTAINER_NAME: queryforge               # From Terraform
```

### Key Features

1. **Dockerfile**: Uses `Dockerfile.ecs` (ECS-optimized)
2. **Multi-tag Push**: Tags images with both commit SHA and `latest`
3. **Task Definition Update**: Downloads current task def, updates image, registers new revision
4. **Stability Wait**: Waits for ECS service to stabilize after deployment
5. **Verification**: Displays deployment info and ALB URL

---

## Testing the Workflow

### Option 1: Push to Main Branch

```bash
git checkout main
git add .
git commit -m "Test deployment"
git push origin main
```

### Option 2: Manual Trigger

1. Go to GitHub → Actions tab
2. Select "Deploy QueryForge to ECS"
3. Click "Run workflow"
4. Select `main` branch
5. Click "Run workflow"

### Monitor the Deployment

1. **GitHub Actions**: Watch the workflow progress in the Actions tab
2. **AWS Console**: Monitor ECS service deployment
3. **Logs**: Check CloudWatch Logs at `/ecs/queryforge`
4. **Health Check**: Visit `http://<ALB-DNS>/health`

---

## Workflow Stages

### 1. Checkout Repository
Downloads your code from GitHub.

### 2. Configure AWS Credentials
Authenticates with AWS using OIDC (no access keys needed).

### 3. Login to Amazon ECR
Gets ECR authentication token.

### 4. Build & Push Image
- Builds Docker image using `Dockerfile.ecs`
- Tags with commit SHA and `latest`
- Pushes both tags to ECR

### 5. Download Task Definition
Downloads current ECS task definition and cleans it for registration.

### 6. Update Task Definition
Updates the task definition with the new image URL.

### 7. Deploy to ECS
Registers new task definition revision and updates the ECS service.

### 8. Verify Deployment
Displays deployment information and ALB URL.

---

## Troubleshooting

### "Error: Could not assume role"

**Issue**: GitHub Actions cannot assume the IAM role.

**Solution**:
1. Verify OIDC provider is created
2. Check trust policy has correct GitHub repo
3. Ensure `AWS_ACCOUNT_ID` secret is set correctly

### "Error: No basic auth credentials"

**Issue**: Cannot authenticate with ECR.

**Solution**:
1. Verify IAM role has `ecr:GetAuthorizationToken` permission
2. Check ECR repository exists in correct region

### "Error: Task definition does not exist"

**Issue**: Task definition hasn't been created yet.

**Solution**:
1. Run `terraform apply` to create infrastructure first
2. Verify task definition name matches in Terraform and workflow

### "Deployment failed: Service did not stabilize"

**Issue**: ECS tasks are failing health checks.

**Solution**:
1. Check CloudWatch Logs: `/ecs/queryforge`
2. Verify health check endpoint: `http://localhost:8080/health`
3. Check task definition environment variables
4. Verify Secrets Manager secret is accessible

### Image Build Fails

**Issue**: Docker build fails during workflow.

**Solution**:
1. Test locally: `docker build -f Dockerfile.ecs -t queryforge:test .`
2. Check `requirements.txt` is up to date
3. Verify `.cache` directory exists (for embeddings)

---

## Customization

### Change Deployment Trigger

Edit `.github/workflows/deploy-to-ecs.yml`:

```yaml
on:
  push:
    branches: [ "main", "production" ]  # Add more branches
  pull_request:
    branches: [ "main" ]                # Deploy on PR
  workflow_dispatch:                     # Manual trigger
```

### Add Slack Notifications

Add this step at the end:

```yaml
- name: Notify Slack
  if: always()
  uses: 8398a7/action-slack@v3
  with:
    status: ${{ job.status }}
    webhook_url: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### Deploy to Multiple Environments

Create separate workflows:
- `.github/workflows/deploy-dev.yml`
- `.github/workflows/deploy-staging.yml`
- `.github/workflows/deploy-prod.yml`

Use different ECS clusters/services per environment.

---

## Security Best Practices

1. **Use OIDC**: Never commit AWS access keys to GitHub
2. **Least Privilege**: IAM role has minimal required permissions
3. **Environment Protection**: Use GitHub environments for approval gates
4. **Secret Scanning**: Enable GitHub secret scanning
5. **Image Scanning**: ECR automatically scans images (enabled in Terraform)

---

## Rollback Procedure

If a deployment fails:

### Option 1: Revert Git Commit

```bash
git revert HEAD
git push origin main
```

This triggers a new deployment with the previous code.

### Option 2: Manual ECS Rollback

```bash
# List previous task definition revisions
aws ecs list-task-definitions \
  --family-prefix queryforge \
  --region us-east-2

# Update service to previous revision
aws ecs update-service \
  --cluster queryforge-cluster \
  --service queryforge-service \
  --task-definition queryforge:PREVIOUS_REVISION \
  --region us-east-2
```

### Option 3: Re-run Previous Workflow

1. Go to GitHub Actions
2. Find the last successful workflow run
3. Click "Re-run jobs"

---

## Next Steps

1. **Set up monitoring**: Configure CloudWatch alarms for failed deployments
2. **Add tests**: Run tests before deployment in workflow
3. **Blue/Green deployments**: Use ECS blue/green deployment strategy
4. **Multi-region**: Extend workflow for multiple AWS regions
5. **Approval gates**: Add manual approval step for production deployments

---

## Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [AWS ECS Deployment with GitHub Actions](https://docs.github.com/en/actions/deployment/deploying-to-your-cloud-provider/deploying-to-amazon-elastic-container-service)
- [Configuring OpenID Connect in AWS](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
- [QueryForge Terraform Deployment Guide](./DEPLOYMENT_GUIDE_TERRAFORM.md)

---

## Questions?

If you encounter issues not covered in this guide:
1. Check CloudWatch Logs: `/ecs/queryforge`
2. Review GitHub Actions workflow logs
3. Verify IAM permissions
4. Check ECS service events in AWS Console
