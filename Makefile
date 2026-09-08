.PHONY: help lint guard test security validate deploy clean setup check-evidence

# Default target
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# -------------------------------------------------------------------
# Setup
# -------------------------------------------------------------------
setup: ## Install development dependencies (creates .venv if not present)
	@test -d .venv || python3 -m venv .venv
	.venv/bin/pip install -r requirements-dev.txt
	@echo "Activate with: source .venv/bin/activate"

# -------------------------------------------------------------------
# Validation
# -------------------------------------------------------------------
lint: ## Run cfn-lint on all templates
	cfn-lint templates/*.yaml || test $$? -le 12

guard: ## Run cfn-guard on all templates
	@for tmpl in templates/*.yaml; do \
		echo "Checking $$tmpl..."; \
		cfn-guard validate \
			--data "$$tmpl" \
			--rules security/guard-rules/ \
			--show-summary fail 2>/dev/null || true; \
	done

validate: ## Validate templates with AWS CloudFormation API (requires credentials)
	@for tmpl in templates/*.yaml; do \
		echo "Validating $$tmpl..."; \
		aws cloudformation validate-template --template-body "file://$$tmpl" --region ap-northeast-1; \
	done

# -------------------------------------------------------------------
# Testing
# -------------------------------------------------------------------
test: check-evidence ## Run all tests (cfn-lint + pytest + evidence gate)
	cfn-lint templates/*.yaml || test $$? -le 12
	pytest tests/ shared/tests/ -v --tb=short

# A claim that a vendor cannot do something, used as a design premise, with nobody
# having asked the vendor. Its own tests run first: this gate has been wrong four times
# so far -- a Japanese pattern that matched only the passive voice, a missing
# `does not expose`, a stale-baseline rule that failed every single-path run, and an
# empty ledger that blocked every commit on the day of adoption -- and a test found each
# one. A gate never seen to fail is not evidence that it runs.
check-evidence: ## Check evidence for claims that a vendor cannot do something
	pytest scripts/tests/ --tb=short -q
	python3 scripts/check_evidence_claims.py

test-cov: ## Run tests with coverage report
	pytest tests/ shared/tests/ -v --cov=solutions --cov-report=term-missing --cov-fail-under=80

# -------------------------------------------------------------------
# Security
# -------------------------------------------------------------------
security: guard ## Run security checks (cfn-guard + gitleaks + checkov)
	gitleaks detect --config .gitleaks.toml --no-git --source . --verbose
	checkov -d templates/ --framework cloudformation --quiet || true

# -------------------------------------------------------------------
# Deploy
# -------------------------------------------------------------------
ENV ?= dev
STACK_NAME ?= fsxn-cyber-resilience-network-$(ENV)
REGION ?= ap-northeast-1

deploy: lint ## Deploy network stack (ENV=dev|staging|production)
	aws cloudformation deploy \
		--template-file templates/network.yaml \
		--stack-name $(STACK_NAME) \
		--parameter-overrides file://parameters/$(ENV).json \
		--region $(REGION) \
		--capabilities CAPABILITY_NAMED_IAM \
		--tags Project=fsxn-cyber-resilience Environment=$(ENV) ManagedBy=cloudformation

deploy-existing: lint ## Deploy using existing VPC/FSx (requires .env file)
	@test -f .env || (echo "ERROR: .env file not found. Copy env.example to .env and fill in values." && exit 1)
	aws cloudformation deploy \
		--template-file templates/network.yaml \
		--stack-name $(PROJECT_NAME)-network-$(ENVIRONMENT) \
		--parameter-overrides \
			ProjectName=$(PROJECT_NAME) \
			Environment=$(ENVIRONMENT) \
			UseExistingVpc=$(USE_EXISTING_VPC) \
			ExistingVpcId=$(EXISTING_VPC_ID) \
			ExistingSubnetFsx1Id=$(EXISTING_SUBNET_FSX_1) \
			ExistingSubnetFsx2Id=$(EXISTING_SUBNET_FSX_2) \
			ExistingSubnetCompute1Id=$(EXISTING_SUBNET_COMPUTE_1) \
			ExistingSubnetCompute2Id=$(EXISTING_SUBNET_COMPUTE_2) \
			ExistingSgFsxId=$(EXISTING_SG_FSX) \
			ExistingSgLambdaId=$(EXISTING_SG_LAMBDA) \
			ExistingActiveDirectoryId=$(EXISTING_AD_ID) \
		--region $(AWS_REGION) \
		--capabilities CAPABILITY_NAMED_IAM \
		--no-fail-on-empty-changeset \
		--tags Project=$(PROJECT_NAME) Environment=$(ENVIRONMENT) ManagedBy=cloudformation
	@echo "Network stack deployed (existing VPC mode)."
	@echo "Deploying event-driven stack..."
	aws cloudformation deploy \
		--template-file templates/event-driven.yaml \
		--stack-name $(PROJECT_NAME)-events-$(ENVIRONMENT) \
		--parameter-overrides \
			ProjectName=$(PROJECT_NAME) \
			Environment=$(ENVIRONMENT) \
			NotificationEmail=$(NOTIFICATION_EMAIL) \
		--region $(AWS_REGION) \
		--capabilities CAPABILITY_NAMED_IAM \
		--no-fail-on-empty-changeset \
		--tags Project=$(PROJECT_NAME) Environment=$(ENVIRONMENT) ManagedBy=cloudformation
	@echo "Event-driven stack deployed."
	@echo ""
	@echo "Next steps:"
	@echo "  1. Store fsxadmin credentials: aws secretsmanager create-secret --name $(FSX_ADMIN_SECRET_NAME) --secret-string '{\"username\":\"fsxadmin\",\"password\":\"YOUR_PASSWORD\"}'"
	@echo "  2. Deploy storage stack: make deploy-storage-existing"

deploy-storage-existing: ## Deploy storage stack with existing FSx for ONTAP
	@test -f .env || (echo "ERROR: .env file not found." && exit 1)
	aws cloudformation deploy \
		--template-file templates/storage.yaml \
		--stack-name $(PROJECT_NAME)-storage-$(ENVIRONMENT) \
		--parameter-overrides \
			ProjectName=$(PROJECT_NAME) \
			Environment=$(ENVIRONMENT) \
			UseExistingFileSystem=$(USE_EXISTING_FSX) \
			ExistingFileSystemId=$(EXISTING_FS_ID) \
			ExistingManagementEndpoint=$(EXISTING_MANAGEMENT_ENDPOINT) \
			ExistingSvmId=$(EXISTING_SVM_ID) \
			ExistingVolumeId=$(EXISTING_VOLUME_ID) \
			FsxAdminPassword=placeholder \
		--region $(AWS_REGION) \
		--capabilities CAPABILITY_NAMED_IAM \
		--no-fail-on-empty-changeset \
		--tags Project=$(PROJECT_NAME) Environment=$(ENVIRONMENT) ManagedBy=cloudformation
	@echo "Storage stack deployed (existing FSx for ONTAP mode)."

deploy-status: ## Check deployment status
	aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME) \
		--region $(REGION) \
		--query 'Stacks[0].StackStatus' \
		--output text

destroy: ## Delete the stack (USE WITH CAUTION)
	@echo "WARNING: This will delete stack $(STACK_NAME) in $(REGION)"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] && \
		aws cloudformation delete-stack --stack-name $(STACK_NAME) --region $(REGION) || \
		echo "Aborted."

# -------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------
clean: ## Remove generated files
	find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '.pytest_cache' -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	rm -rf .mypy_cache/ htmlcov/ .coverage
