# Contributing / Deployment Rules

## ⚠️ NEVER use `terraform taint`

```bash
# ❌ FORBIDDEN — breaks Lambda permissions (resource policies get orphaned)
terraform taint aws_lambda_function.XXX

# ✅ CORRECT — modify code, Terraform detects hash change, updates in-place
# Just edit the .py file → terraform apply (source_code_hash triggers update)
```

**Why:** `taint` destroys and recreates the Lambda. The new Lambda gets a fresh ARN version,
but `aws_lambda_permission` resources (EventBridge, API Gateway) reference the old one.
Result: Lambda exists but can't be invoked by its triggers → silent failures.

## Deployment workflow

```bash
cd ./terraform

# Set state backend auth (add to ~/.zshrc for persistence)
export TF_HTTP_USERNAME=session
export TF_HTTP_PASSWORD="<stategraph-api-key>"

# Deploy
AWS_PROFILE=<YOUR_PROFILE> terraform plan     # always review first
AWS_PROFILE=<YOUR_PROFILE> terraform apply    # never use -auto-approve in prod

# After apply, verify no drift
AWS_PROFILE=<YOUR_PROFILE> terraform plan     # should show "No changes"
```

## Updating Lambda code

```bash
# 1. Edit the Python file
vi terraform/lambda/classifier.py

# 2. Apply — Terraform detects source_code_hash changed → updates function in-place
AWS_PROFILE=<YOUR_PROFILE> terraform apply

# Permissions stay intact. No taint needed.
```

## If permissions break (emergency recovery)

```bash
# Re-apply all permissions without touching Lambdas
AWS_PROFILE=<YOUR_PROFILE> terraform apply \
  -target=aws_lambda_permission.apigw \
  -target=aws_lambda_permission.comparison \
  -target=aws_lambda_permission.classifier \
  -target=aws_lambda_permission.admin_apigw \
  -target=aws_lambda_permission.query_url
```

## Credential refresh

```bash
mwinit                          # refresh Midway/Isengard auth
AWS_PROFILE=<YOUR_PROFILE> ...      # all AWS commands use this profile
```

## Git workflow

```bash
git add -A && git commit -m "description"   # commit after every logical change
# State is in Stategraph — no .tfstate in git
```

## Infrastructure layout

```
./    ← main project (uses Stategraph backend)
../stategraph/       ← Stategraph infra (separate, local state)
```
