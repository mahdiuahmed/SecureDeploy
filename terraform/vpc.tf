# VPC, subnets, and security groups.
# Demonstrates: network segmentation, least-privilege ingress, defense in depth.
# The app-sg and db-sg enforce that the DB is never directly reachable from
# the internet — only from the app tier.

# ── VPC ──────────────────────────────────────────────────────────────────────

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.project_name}-vpc" }
}

# ── Subnets (2 AZs for HA) ────────────────────────────────────────────────────

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_name}-public-a" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_name}-public-b" }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "${var.aws_region}a"

  tags = { Name = "${var.project_name}-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.12.0/24"
  availability_zone = "${var.aws_region}b"

  tags = { Name = "${var.project_name}-private-b" }
}

# ── Internet Gateway (public subnets) ────────────────────────────────────────

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.project_name}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# ── NAT Gateway (private subnets need outbound for EKS bootstrap + ECR) ───────

resource "aws_eip" "nat" {
  domain     = "vpc"
  depends_on = [aws_internet_gateway.main]

  tags = { Name = "${var.project_name}-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_a.id

  tags = { Name = "${var.project_name}-nat" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = { Name = "${var.project_name}-private-rt" }
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

# ── Security Groups ───────────────────────────────────────────────────────────

# App tier: accepts HTTPS from internet, egress to DB only on 5432.
resource "aws_security_group" "app" {
  name        = "${var.project_name}-app-sg"
  description = "App tier - inbound HTTPS only, outbound to DB"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP redirect (will 301 to HTTPS)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTPS out (ECR, SNS, AWS APIs)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-app-sg" }
}

# DB tier: accepts PostgreSQL from app-sg only — no direct internet access.
resource "aws_security_group" "db" {
  name        = "${var.project_name}-db-sg"
  description = "DB tier - inbound PostgreSQL from app-sg only"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "No outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["127.0.0.1/32"]
  }

  tags = { Name = "${var.project_name}-db-sg" }
}

# Standalone cross-SG rules — avoids the cycle that inline rules create
resource "aws_security_group_rule" "app_to_db" {
  type                     = "egress"
  description              = "PostgreSQL to DB tier only"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.app.id
  source_security_group_id = aws_security_group.db.id
}

resource "aws_security_group_rule" "db_from_app" {
  type                     = "ingress"
  description              = "PostgreSQL from app tier only"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.db.id
  source_security_group_id = aws_security_group.app.id
}

# ── RDS (PostgreSQL, encrypted, private subnets) ──────────────────────────────

resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-db-subnet-group"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  tags = { Name = "${var.project_name}-db-subnet-group" }
}

resource "aws_db_instance" "main" {
  identifier        = "${var.project_name}-db"
  engine            = "postgres"
  engine_version    = "16"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_type      = "gp2"
  storage_encrypted = true   # CIS Benchmark: encryption at rest

  db_name  = "securedeploy"
  username = "sdadmin"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]

  multi_az               = false   # set true for prod HA
  publicly_accessible    = false   # never expose DB to internet
  deletion_protection    = false   # set true for prod
  skip_final_snapshot    = true    # set false for prod

  backup_retention_period = 7
  backup_window           = "02:00-03:00"

  tags = { Name = "${var.project_name}-db" }
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "vpc_id" {
  value       = aws_vpc.main.id
  description = "VPC ID"
}

output "app_security_group_id" {
  value       = aws_security_group.app.id
  description = "App-tier security group"
}

output "db_security_group_id" {
  value       = aws_security_group.db.id
  description = "DB-tier security group (no direct internet access)"
}

output "rds_endpoint" {
  value       = aws_db_instance.main.endpoint
  description = "RDS connection endpoint (private)"
}
