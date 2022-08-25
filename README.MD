# Terraform AWS ECR

### Example

```yaml
provider "aws" {
  region = "us-east-1"
}

module "ecr" {
  source       = "./"
  name         = "ecr"
  environment  = "test"
  label_order  = ["environment", "name"]
  scan_on_push = true
  image_tag_mutability = "MUTABLE"

}
```