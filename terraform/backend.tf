# Remote state backend — S3 for state, DynamoDB for locking.
# Demonstrates: encryption at rest, state locking, team-safe operations.
#
# Bootstrap: create the bucket and table manually (or via a separate bootstrap module)
# before running `terraform init` with this backend.
#
#   aws s3 mb s3://securedeploy-tfstate-221082175129 --region eu-west-2
#   aws s3api put-bucket-versioning \
#     --bucket securedeploy-tfstate-221082175129 \
#     --versioning-configuration Status=Enabled

terraform {
  backend "s3" {
    bucket       = "securedeploy-tfstate-221082175129"
    key          = "securedeploy/terraform.tfstate"
    region       = "eu-west-2"
    use_lockfile = true
    encrypt      = true
  }
}
