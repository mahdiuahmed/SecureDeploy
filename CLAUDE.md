# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**SecureDeploy** is a DevSecOps demo: a minimal Flask app wrapped in a full security-hardened pipeline. The app itself is trivial — the substance is the pipeline, infrastructure, and cloud posture monitor.

## Running Locally

```bash
# Run the Flask app directly
pip install -r requirements.txt
python app.py                      # listens on :8080

# Build the Docker image
docker build -t securedeploy-app:dev .

# Spin up a local Kubernetes cluster (kind required)
kind create cluster --config kind-config.yaml
kubectl apply -f k8s/deployment.yaml
# App reachable at http://localhost:8080 (NodePort 30080 → host 8080)

# Package the Lambda function after editing lambda/handler.py
cd lambda && zip posture.zip handler.py
```

## Terraform (AWS Infrastructure)

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

Provisions: ECR private registry, Lambda posture monitor, SNS alert topic, IAM roles for Lambda and GitHub Actions (OIDC). Region: `eu-west-1`.

Required GitHub Actions secrets: `AWS_ROLE_ARN`, `SNYK_TOKEN`, `SLACK_WEBHOOK_URL`. These map to the values in the local `.env` file (which must stay out of git).

## CI/CD Pipeline Architecture

The pipeline (`.github/workflows/devsecops.yml`) has a strict gate: **Job 6 (build-push to ECR) only runs if all 5 scan jobs pass.**

| Job | Tool | What it catches |
|-----|------|-----------------|
| `sast` | Semgrep | OWASP top-10, Flask vulns, secrets in code |
| `secrets-scan` | TruffleHog | Committed credentials (full git history) |
| `dependencies` | Snyk | Vulnerable Python packages (`continue-on-error: true` — reports but doesn't block) |
| `iac-scan` | Checkov | Terraform misconfigs → SARIF uploaded to GitHub Security tab |
| `container-scan` | Trivy | HIGH/CRITICAL CVEs in the Docker image |
| `build-push` | — | Builds, tags with SHA, pushes to ECR; auth via OIDC (no long-lived keys) |
| `notify-failure` | Slack | Fires on any scan failure |

## Lambda Posture Monitor

`lambda/handler.py` runs daily at 02:00 UTC via EventBridge. It audits the AWS account and publishes findings to SNS. Current checks:
- S3 buckets with public access block disabled/missing
- IAM access keys older than 90 days
- Unencrypted EBS volumes
- Security groups allowing `0.0.0.0/0` on ports: 22, 3389, 3306, 5432, 6379, 27017, 9200

SNS topic ARN and project name are injected via Lambda env vars.

## Security Posture Built Into the Infra

- **Container**: multi-stage build, non-root user (uid 1000), read-only root filesystem, all Linux capabilities dropped
- **Kubernetes**: `runAsNonRoot`, seccomp `RuntimeDefault`, no privilege escalation, resource limits enforced
- **AWS auth**: GitHub Actions uses OIDC federation — no long-lived IAM keys stored as secrets
- **ECR**: scan-on-push enabled, AES256 encryption, lifecycle policy keeps last 10 images
- **IAM**: Lambda role is least-privilege inline policy; GitHub Actions role scoped to ECR push only
