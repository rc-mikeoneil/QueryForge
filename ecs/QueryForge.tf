# ================================================================
# QueryForge MCP Server Infrastructure
# ================================================================
# This file contains all infrastructure for the QueryForge MCP server
# deployment on AWS ECS Fargate with Application Load Balancer.
#
# Required Variables (add to variables.tf):
#   - vpc_id
#   - private_subnet_ids (list)
#   - queryforge_litellm_api_key_secret_arn
#
# Architecture:
#   Internet → ALB (sticky sessions) → Target Group → ECS Fargate (2 tasks)
# ================================================================

# ---------------------------------------------------------------
# ECR Repository for QueryForge Container Images
# ---------------------------------------------------------------
resource "aws_ecr_repository" "queryforge" {
  name                 = "queryforge"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Project     = "QueryForge"
    Description = "MCP Query Builder for security platforms"
  }
}

# ECR Lifecycle Policy - Keep last 10 images
resource "aws_ecr_lifecycle_policy" "queryforge" {
  repository = aws_ecr_repository.queryforge.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection = {
        tagStatus     = "any"
        countType     = "imageCountMoreThan"
        countNumber   = 10
      }
      action = {
        type = "expire"
      }
    }]
  })
}

# ---------------------------------------------------------------
# ECS Cluster
# ---------------------------------------------------------------
resource "aws_ecs_cluster" "queryforge" {
  name = "queryforge-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Project = "QueryForge"
  }
}

# ---------------------------------------------------------------
# CloudWatch Log Group for ECS Tasks
# ---------------------------------------------------------------
resource "aws_cloudwatch_log_group" "queryforge_ecs" {
  name              = "/ecs/queryforge"
  retention_in_days = 7

  tags = {
    Project = "QueryForge"
  }
}

# ---------------------------------------------------------------
# Security Group for Application Load Balancer
# ---------------------------------------------------------------
resource "aws_security_group" "queryforge_alb" {
  name        = "queryforge-alb-sg"
  description = "Security group for QueryForge ALB"
  vpc_id      = var.vpc_id

  # Inbound HTTP from anywhere
  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Outbound to ECS tasks
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "queryforge-alb-sg"
    Project = "QueryForge"
  }
}

# ---------------------------------------------------------------
# Security Group for ECS Tasks
# ---------------------------------------------------------------
resource "aws_security_group" "queryforge_ecs_tasks" {
  name        = "queryforge-ecs-tasks-sg"
  description = "Security group for QueryForge ECS tasks"
  vpc_id      = var.vpc_id

  # Inbound from ALB only
  ingress {
    description     = "Traffic from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.queryforge_alb.id]
  }

  # Outbound HTTPS for ECR, Secrets Manager, etc.
  egress {
    description = "HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "queryforge-ecs-tasks-sg"
    Project = "QueryForge"
  }
}

# ---------------------------------------------------------------
# Application Load Balancer
# ---------------------------------------------------------------
resource "aws_lb" "queryforge" {
  name               = "queryforge-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.queryforge_alb.id]
  subnets            = var.private_subnet_ids

  enable_deletion_protection = false
  enable_http2              = true

  tags = {
    Project = "QueryForge"
  }
}

# ---------------------------------------------------------------
# ALB Target Group with Sticky Sessions
# ---------------------------------------------------------------
resource "aws_lb_target_group" "queryforge" {
  name                 = "queryforge-tg"
  port                 = 8080
  protocol             = "HTTP"
  vpc_id               = var.vpc_id
  target_type          = "ip"
  deregistration_delay = 30

  # Health check configuration
  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/health"
    protocol            = "HTTP"
    matcher             = "200"
  }

  # Sticky sessions enabled (24 hours)
  stickiness {
    enabled         = true
    type            = "lb_cookie"
    cookie_duration = 86400
  }

  tags = {
    Project = "QueryForge"
  }
}

# ---------------------------------------------------------------
# ALB Listener (HTTP)
# ---------------------------------------------------------------
resource "aws_lb_listener" "queryforge_http" {
  load_balancer_arn = aws_lb.queryforge.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.queryforge.arn
  }

  tags = {
    Project = "QueryForge"
  }
}

# ---------------------------------------------------------------
# ECS Task Definition
# ---------------------------------------------------------------
resource "aws_ecs_task_definition" "queryforge" {
  family                   = "queryforge"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.queryforge_ecs_execution.arn
  task_role_arn            = aws_iam_role.queryforge_ecs_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name      = "queryforge"
      image     = "${aws_ecr_repository.queryforge.repository_url}:latest"
      cpu       = 1024
      memory    = 2048
      essential = true

      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
          name          = "queryforge-8080-tcp"
          appProtocol   = "http"
        }
      ]

      environment = [
        {
          name  = "MCP_TRANSPORT"
          value = "sse"
        },
        {
          name  = "MCP_HOST"
          value = "0.0.0.0"
        },
        {
          name  = "MCP_PORT"
          value = "8080"
        },
        {
          name  = "CACHE_DIR"
          value = "/app/.cache"
        }
      ]

      secrets = [
        {
          name      = "LITELLM_API_KEY"
          valueFrom = var.queryforge_litellm_api_key_secret_arn
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.queryforge_ecs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "queryforge"
          "mode"                  = "non-blocking"
          "max-buffer-size"       = "25m"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }
  ])

  tags = {
    Project = "QueryForge"
  }
}

# ---------------------------------------------------------------
# ECS Service
# ---------------------------------------------------------------
resource "aws_ecs_service" "queryforge" {
  name            = "queryforge-service"
  cluster         = aws_ecs_cluster.queryforge.id
  task_definition = aws_ecs_task_definition.queryforge.arn
  launch_type     = "FARGATE"
  desired_count   = 2

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.queryforge_ecs_tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.queryforge.arn
    container_name   = "queryforge"
    container_port   = 8080
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_configuration {
    minimum_healthy_percent = 50
    maximum_percent         = 200
  }

  depends_on = [
    aws_lb_listener.queryforge_http,
    aws_iam_role_policy_attachment.queryforge_ecs_execution_policy
  ]

  tags = {
    Project = "QueryForge"
  }
}

# ---------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------
output "queryforge_alb_dns_name" {
  description = "DNS name of the QueryForge ALB"
  value       = aws_lb.queryforge.dns_name
}

output "queryforge_ecr_repository_url" {
  description = "URL of the QueryForge ECR repository"
  value       = aws_ecr_repository.queryforge.repository_url
}

output "queryforge_ecs_cluster_name" {
  description = "Name of the QueryForge ECS cluster"
  value       = aws_ecs_cluster.queryforge.name
}

output "queryforge_ecs_service_name" {
  description = "Name of the QueryForge ECS service"
  value       = aws_ecs_service.queryforge.name
}
