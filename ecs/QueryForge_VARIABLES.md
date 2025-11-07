# QueryForge Terraform Variables Reference

This document lists all variables needed for the QueryForge deployment.

## Required Variables

Add these to your `variables.tf` file:

### VPC Configuration

```hcl
variable "queryforge_vpc_id" {
  description = "VPC ID for QueryForge deployment"
  type        = string
  default     = "vpc-xxxxx"  # Replace with your VPC ID
}
```

**How to find your VPC ID:**
```bash
aws ec2 describe-vpcs --region us-east-2 --profile your-profile
```

### Subnet Configuration

```hcl
variable "queryforge_private_subnet_ids" {
  description = "Private subnet IDs for QueryForge ECS tasks (minimum 2 for redundancy)"
  type        = list(string)
  default     = [
    "subnet-xxxxx",  # Replace with your private subnet IDs
    "subnet-yyyyy"
  ]
}
```

**How to find your subnet IDs:**
```bash
aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=vpc-xxxxx" \
  --region us-east-2 \
  --profile your-profile
```

**Important:** 
- Use **private subnets** (not public)
- Provide at least **2 subnets** in different availability zones for high availability
- Subnets must have routes to NAT Gateway or VPC endpoints for ECR/Secrets Manager access

### Secrets Manager Configuration

```hcl
variable "queryforge_litellm_api_key_secret_arn" {
  description = "ARN of Secrets Manager secret containing LiteLLM API key"
  type        = string
  default     = "arn:aws:secretsmanager:us-east-2:ACCOUNT_ID:secret:queryforge/litellm-api-key-xxxxx"
}
```

**How to create the secret:**
```bash
# Create the secret
aws secretsmanager create-secret \
  --name queryforge/litellm-api-key \
  --description "LiteLLM API key for QueryForge MCP server" \
  --secret-string "your-litellm-api-key-here" \
  --region us-east-2 \
  --profile your-profile

# Get the ARN (copy this to your variable)
aws secretsmanager describe-secret \
  --secret-id queryforge/litellm-api-key \
  --region us-east-2 \
  --profile your-profile \
  --query 'ARN' \
  --output text
```

## Variable Updates in QueryForge.tf

After adding variables to `variables.tf`, update `QueryForge.tf` to use the new variable names:

### Find and Replace

1. Replace `var.vpc_id` with `var.queryforge_vpc_id`
2. Replace `var.private_subnet_ids` with `var.queryforge_private_subnet_ids`

These appear in:
- `aws_security_group.queryforge_alb` (line ~98)
- `aws_security_group.queryforge_ecs_tasks` (line ~124)
- `aws_lb_target_group.queryforge` (line ~181)
- `aws_lb.queryforge` (line ~168)
- `aws_ecs_service.queryforge` network_configuration (line ~335)

## Existing Variables Referenced

The QueryForge configuration also references these existing variables from your Terraform setup:

```hcl
variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-2"
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}
```

These should already exist in your `variables.tf` - no changes needed.

## Complete Variables Block

Here's the complete block to add to your `variables.tf`:

```hcl
# ================================================================
# QueryForge Configuration Variables
# ================================================================

variable "queryforge_vpc_id" {
  description = "VPC ID for QueryForge deployment"
  type        = string
  default     = "vpc-xxxxx"  # TODO: Replace with your VPC ID
}

variable "queryforge_private_subnet_ids" {
  description = "Private subnet IDs for QueryForge ECS tasks (minimum 2)"
  type        = list(string)
  default     = [
    "subnet-xxxxx",  # TODO: Replace with your private subnet IDs
    "subnet-yyyyy"
  ]
}

variable "queryforge_litellm_api_key_secret_arn" {
  description = "ARN of Secrets Manager secret containing LiteLLM API key"
  type        = string
  default     = "arn:aws:secretsmanager:us-east-2:ACCOUNT_ID:secret:queryforge/litellm-api-key-xxxxx"  # TODO: Replace with actual ARN
}
```

## Validation Checklist

Before running `terraform plan`, ensure:

- [ ] VPC ID is correct and exists
- [ ] Subnet IDs are correct and in the specified VPC
- [ ] Subnets are **private** (not public)
- [ ] At least 2 subnets in different AZs
- [ ] Secrets Manager secret created with API key
- [ ] Secret ARN is correct and accessible
- [ ] AWS region is set to `us-east-2`
- [ ] All TODOs in variable defaults are replaced

## Testing Variables

Test your variable values:

```bash
# Test VPC exists
aws ec2 describe-vpcs \
  --vpc-ids vpc-xxxxx \
  --region us-east-2 \
  --profile your-profile

# Test subnets exist and are in VPC
aws ec2 describe-subnets \
  --subnet-ids subnet-xxxxx subnet-yyyyy \
  --region us-east-2 \
  --profile your-profile

# Test secret exists and is accessible
aws secretsmanager get-secret-value \
  --secret-id queryforge/litellm-api-key \
  --region us-east-2 \
  --profile your-profile
```

## Environment-Specific Variables

If deploying to multiple environments (dev, staging, prod), consider using Terraform workspaces or separate `.tfvars` files:

### Option 1: Using terraform.tfvars

Create `terraform.tfvars`:
```hcl
queryforge_vpc_id                      = "vpc-actual-id"
queryforge_private_subnet_ids          = ["subnet-id-1", "subnet-id-2"]
queryforge_litellm_api_key_secret_arn  = "arn:aws:secretsmanager:us-east-2:123456789:secret:queryforge/litellm-api-key-xxxxx"
```

### Option 2: Environment-Specific Files

Create `prod.tfvars`, `dev.tfvars`, etc.:
```bash
terraform plan -var-file="prod.tfvars"
terraform apply -var-file="prod.tfvars"
```

## Security Best Practices

1. **Never commit secrets to version control**
   - Add `*.tfvars` to `.gitignore` (except `example.tfvars`)
   - Use Secrets Manager for sensitive data

2. **Use least-privilege IAM roles**
   - The provided IAM roles follow AWS best practices
   - Grant only necessary permissions

3. **Private subnets only**
   - ECS tasks should be in private subnets
   - Use NAT Gateway or VPC endpoints for internet access

4. **Encryption**
   - Secrets Manager encrypts data at rest
   - Use KMS for additional encryption if needed

## Troubleshooting

### "VPC not found" error
- Verify VPC ID is correct
- Check you're using the right AWS account/profile
- Ensure region is correct (us-east-2)

### "Subnet not found" error
- Verify subnet IDs are correct
- Check subnets belong to the specified VPC
- Ensure region matches

### "Access denied" to Secrets Manager
- Verify secret ARN is correct
- Check IAM execution role has secretsmanager:GetSecretValue permission
- Ensure secret is in the same region

### Subnet routing issues
- Private subnets need route to NAT Gateway OR
- Configure VPC endpoints for ECR, Secrets Manager, CloudWatch Logs
- See commented-out VPC endpoint resources in mcp_infrastructure.tf for examples
