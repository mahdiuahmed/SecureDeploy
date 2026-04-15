# SecureDeploy Infrastructure
# Provisions: ECR, Lambda posture monitor, SNS alerts, IAM roles
# Cost: ~$0.50/day (Lambda + SNS free tier, ECR storage pennies)

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.5" }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default     = "eu-west-2"
  description = "AWS region"
}

variable "project_name" {
  default     = "securedeploy"
  description = "Prefix for all resources"
}

variable "db_password" {
  description = "RDS master password — pass via TF_VAR_db_password env var, never hardcode"
  type        = string
  sensitive   = true
}

# Get current AWS account ID for use in resource names
data "aws_caller_identity" "current" {}

# ─────────────────────────────────────────
# ECR: Private Docker registry for our app
# ─────────────────────────────────────────
resource "aws_ecr_repository" "app" {
  name                 = "${var.project_name}-app"
  image_tag_mutability = "IMMUTABLE"

  # Scan images automatically on push (AWS native scanning)
  image_scanning_configuration {
    scan_on_push = true
  }

  # Encrypt images at rest
  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Project = var.project_name
    Purpose = "container-registry"
  }
}

# Lifecycle policy: keep only last 10 images (cost control)
resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

# ─────────────────────────────────────────
# SNS: Topic for security alerts
# ─────────────────────────────────────────
resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts"

  tags = {
    Project = var.project_name
    Purpose = "security-alerts"
  }
}

# Subscribe your email (replace with yours)
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = "imahdiahmed01@gmail.com" # Confirm via link in inbox
}

# ─────────────────────────────────────────
# IAM: Role for Lambda with LEAST-PRIVILEGE
# Lambda can only: read S3/IAM/EC2 metadata, publish to our SNS topic
# ─────────────────────────────────────────
resource "aws_iam_role" "lambda_posture" {
  name = "${var.project_name}-lambda-posture-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# Inline policy — NARROW scope only
resource "aws_iam_role_policy" "lambda_posture" {
  name = "${var.project_name}-lambda-posture-policy"
  role = aws_iam_role.lambda_posture.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Read S3 (find public buckets)
      {
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketAcl",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketEncryption"
        ]
        Resource = "*"
      },
      # Read IAM (find old keys)
      {
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed"
        ]
        Resource = "*"
      },
      # Read EC2 (find unencrypted volumes + bad SGs)
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeVolumes",
          "ec2:DescribeSecurityGroups"
        ]
        Resource = "*"
      },
      # Publish to OUR SNS topic only (not all topics)
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      },
      # CloudWatch Logs for debugging
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
      }
    ]
  })
}

# ─────────────────────────────────────────
# Lambda: Cloud posture monitor
# Runs daily, audits AWS account, publishes findings to SNS
# ─────────────────────────────────────────
resource "aws_lambda_function" "posture_monitor" {
  filename      = "${path.module}/../lambda/posture.zip"
  function_name = "${var.project_name}-posture-monitor"
  role          = aws_iam_role.lambda_posture.arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.11"
  timeout       = 120
  memory_size   = 256

  source_code_hash = filebase64sha256("${path.module}/../lambda/posture.zip")

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
      PROJECT_NAME  = var.project_name
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Project = var.project_name
    Purpose = "cloud-posture"
  }
}

# Schedule: run daily at 02:00 UTC
resource "aws_cloudwatch_event_rule" "daily" {
  name                = "${var.project_name}-daily-posture-check"
  description         = "Trigger posture monitor daily at 2am UTC"
  schedule_expression = "cron(0 2 * * ? *)"
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.daily.name
  target_id = "posture-monitor-lambda"
  arn       = aws_lambda_function.posture_monitor.arn
}

# Allow EventBridge to invoke Lambda
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.posture_monitor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily.arn
}

# ─────────────────────────────────────────
# IAM: Role for GitHub Actions (OIDC federation — no long-lived keys!)
# ─────────────────────────────────────────
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "github_actions" {
  name = "${var.project_name}-github-actions"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          # IMPORTANT: change this to YOUR repo
          "token.actions.githubusercontent.com:sub" = "repo:mahdiuahmed/securedeploy:*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "github_actions_ecr" {
  name = "${var.project_name}-github-actions-ecr"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ECRPush"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:PutImage"
        ]
        Resource = "*"
      },
      {
        Sid    = "EKSDeploy"
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster" # required for aws eks update-kubeconfig
        ]
        Resource = aws_eks_cluster.main.arn
      }
    ]
  })
}

# ─────────────────────────────────────────
# Outputs — values we need for the pipeline
# ─────────────────────────────────────────
output "ecr_repository_url" {
  value       = aws_ecr_repository.app.repository_url
  description = "ECR repo URL for docker push"
}

output "sns_topic_arn" {
  value       = aws_sns_topic.alerts.arn
  description = "SNS topic for security alerts"
}

output "github_actions_role_arn" {
  value       = aws_iam_role.github_actions.arn
  description = "IAM role ARN for GitHub Actions OIDC auth"
}

output "lambda_function_name" {
  value       = aws_lambda_function.posture_monitor.function_name
  description = "Lambda function name"
}
