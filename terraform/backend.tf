# Remote state backend — S3 for state, DynamoDB for locking.
# Demonstrates: encryption at rest, state locking, team-safe operations.
#
# Bootstrap: create the bucket and table manually (or via a separate bootstrap module)
# before running `terraform init` with this backend.
#
#   aws s3 mb s3://securedeploy-tfstate-221082175129 --region eu-west-1
#   aws s3api put-bucket-versioning \
#     --bucket securedeploy-tfstate-221082175129 \
#     --versioning-configuration Status=Enabled
#   aws dynamodb create-table \
#     --table-name securedeploy-tfstate-lock \
#     --attribute-definitions AttributeName=LockID,AttributeType=S \
#     --key-schema AttributeName=LockID,KeyType=HASH \
#     --billing-mode PAY_PER_REQUEST \
#     --region eu-west-1

terraform {
  backend "s3" {
    bucket         = "securedeploy-tfstate-221082175129"
    key            = "securedeploy/terraform.tfstate"
    region         = "eu-west-1"
    dynamodb_table = "securedeploy-tfstate-lock"
    encrypt        = true
  }
}
