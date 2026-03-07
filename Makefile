#!/usr/bin/env make
# CloudFreeze v7 — Build System
# Usage: make package | make test | make plan | make deploy | make clean

LAMBDA_DIR = lambda
TESTS_DIR  = tests

.PHONY: help package test plan deploy clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

package:  ## Package all Lambda functions into zip files (includes utils.py)
	@echo "📦 Packaging Lambda functions..."
	cd $(LAMBDA_DIR) && zip -j lambda_function.zip lambda_function.py utils.py
	cd $(LAMBDA_DIR) && zip -j lambda_restore.zip lambda_restore.py utils.py
	cd $(LAMBDA_DIR) && zip -j lambda_forensic.zip lambda_forensic.py utils.py
	cd $(LAMBDA_DIR) && zip -j lambda_watchdog.zip lambda_watchdog.py utils.py
	@echo "✅ All Lambda zips created (with shared utils.py)"

test:  ## Run the pytest test suite (zero AWS cost via moto)
	@echo "🧪 Running test suite..."
	python -m pytest $(TESTS_DIR)/ -v --tb=short
	@echo "✅ Tests complete"

plan: package  ## Package + terraform plan
	@echo "📋 Running Terraform plan..."
	terraform plan -var="alert_email=placeholder@example.com"

deploy: package  ## Package + terraform apply
	@echo "🚀 Deploying CloudFreeze..."
	@read -p "Enter alert email: " email; \
	terraform apply -auto-approve -var="alert_email=$$email"

clean:  ## Remove zip artifacts
	@echo "🧹 Cleaning up..."
	rm -f $(LAMBDA_DIR)/lambda_function.zip
	rm -f $(LAMBDA_DIR)/lambda_restore.zip
	rm -f $(LAMBDA_DIR)/lambda_forensic.zip
	rm -f $(LAMBDA_DIR)/lambda_watchdog.zip
	@echo "✅ Clean complete"

fmt:  ## Format Terraform files
	terraform fmt -recursive

validate: package  ## Package + terraform validate
	terraform init -backend=false
	terraform validate
