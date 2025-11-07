# ================================================================
# QueryForge IAM Roles and Policies
# ================================================================
# INSTRUCTIONS: Add these IAM resources to your existing iam.tf file
# 
# Recommended Placement: Add at the end of iam.tf, or group with 
# other ECS-related IAM roles if you have them.
# ================================================================

# ---------------------------------------------------------------
# ECS Task Execution Role
# ---------------------------------------------------------------
# This role is used by ECS to pull images from ECR, fetch secrets
# from Secrets Manager, and send logs to CloudWatch.
# Place this near other ECS execution roles in iam.tf

data "aws_iam_policy_document" "queryforge_ecs_execution_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "queryforge_ecs_execution" {
  name               = "queryforge-ecs-execution-role"
  assume_role_policy = data.aws_iam_policy_document.queryforge_ecs_execution_assume_role.json

  tags = {
    Project = "QueryForge"
  }
}

# Attach AWS managed policy for ECS task execution
resource "aws_iam_role_policy_attachment" "queryforge_ecs_execution_policy" {
  role       = aws_iam_role.queryforge_ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Custom policy for Secrets Manager access
data "aws_iam_policy_document" "queryforge_ecs_execution_secrets" {
  statement {
    sid    = "GetSecretsManagerSecret"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue"
    ]
    resources = [
      var.queryforge_litellm_api_key_secret_arn
    ]
  }

  statement {
    sid    = "DecryptSecrets"
    effect = "Allow"
    actions = [
      "kms:Decrypt"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "queryforge_ecs_execution_secrets" {
  name   = "queryforge-ecs-execution-secrets-policy"
  role   = aws_iam_role.queryforge_ecs_execution.id
  policy = data.aws_iam_policy_document.queryforge_ecs_execution_secrets.json
}

# ---------------------------------------------------------------
# ECS Task Role
# ---------------------------------------------------------------
# This role is used by the running container for any AWS API calls
# it needs to make. Currently minimal permissions - extend as needed.
# Place this near other ECS task roles in iam.tf

data "aws_iam_policy_document" "queryforge_ecs_task_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "queryforge_ecs_task" {
  name               = "queryforge-ecs-task-role"
  assume_role_policy = data.aws_iam_policy_document.queryforge_ecs_task_assume_role.json

  tags = {
    Project = "QueryForge"
  }
}

# Custom task policy - currently minimal, extend as needed
data "aws_iam_policy_document" "queryforge_ecs_task_policy" {
  # Placeholder for future runtime permissions
  # Add statements here if the container needs to access AWS services
  
  statement {
    sid    = "AllowCloudWatchMetrics"
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricData"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["QueryForge"]
    }
  }
}

resource "aws_iam_role_policy" "queryforge_ecs_task_policy" {
  name   = "queryforge-ecs-task-policy"
  role   = aws_iam_role.queryforge_ecs_task.id
  policy = data.aws_iam_policy_document.queryforge_ecs_task_policy.json
}

# ================================================================
# END OF QUERYFORGE IAM ADDITIONS
# ================================================================
# After adding these to iam.tf, the QueryForge.tf file will be able
# to reference:
#   - aws_iam_role.queryforge_ecs_execution
#   - aws_iam_role.queryforge_ecs_task
# ================================================================
