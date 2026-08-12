.PHONY: help baseline scan triage destroy
.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

baseline: ## Enable SRA-aligned security services
	terraform -chdir=terraform init -upgrade
	terraform -chdir=terraform apply

scan: ## Run Prowler against the account/org
	@command -v prowler >/dev/null || pip install prowler
	prowler aws \
		--compliance cis_3.0_aws aws_foundational_security_best_practices_aws \
		--output-formats html json-ocsf \
		--output-directory findings
	@echo "Report in findings/. Open the HTML."

triage: ## Summarise findings by severity
	python3 scripts/triage.py findings/*.ocsf.json

destroy: ## Disable the paid services
	terraform -chdir=terraform destroy
