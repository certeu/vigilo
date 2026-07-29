.PHONY: build scan resume stop logs status clean help build-greybox build-greybox-opencode build-greybox-codex greybox greybox-opencode greybox-codex greybox-stop greybox-logs greybox-graph greybox-clean

SHELL := /bin/bash
-include .env
export

SCAN_ID ?= $(shell date +%s)
DIR ?= .
URL ?=
CONFIG ?=
IMAGE := vigilo:latest

help: ## Show this help
	@printf '\n\033[1mVigilo\033[0m — AI Pentest Pipeline\n\n'
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@printf '\n'

build: ## Build worker image with repo baked in: make build DIR=/path/to/repo
	@printf '\n'
	@printf '\033[1;36m╔══════════════════════════════════════════╗\033[0m\n'
	@printf '\033[1;36m║      Vigilo — Build                      ║\033[0m\n'
	@printf '\033[1;36m╚══════════════════════════════════════════╝\033[0m\n'
	@printf '\n'
	@printf '  \033[2mRepository:\033[0m  %s\n' "$(DIR)"
	@printf '\n'
	@rm -rf .target-repo
	@printf '  \033[33m⟳\033[0m  Copying repository into build context...\n'
	@rsync -a --exclude='node_modules' --exclude='.venv' --exclude='__pycache__' --exclude='.idea' --exclude='deliverables' --include='.vigilo/config.yaml' --exclude='.vigilo/*' $(DIR)/ .target-repo/
	@cd "$(DIR)" && git remote get-url origin 2>/dev/null > $(CURDIR)/.target-repo/.vigilo-remote-url || touch $(CURDIR)/.target-repo/.vigilo-remote-url
	@printf '  \033[33m⟳\033[0m  Building Docker image...\n\n'
	@REPO_DIR=.target-repo docker compose build worker
	@rm -rf .target-repo
	@cd "$(DIR)" && pwd > $(CURDIR)/.vigilo-dir
	@printf '\n  \033[32m✓\033[0m  Build complete!\n\n'

scan: ## Run pipeline: make scan URL=http://target (URL optional, code-only if omitted)
	@if [ ! -f .vigilo-dir ]; then \
		printf '  \033[31m✗\033[0m  No previous build found. Run: make build DIR=/path/to/repo\n'; \
		exit 1; \
	fi
	@printf '\n'
	@printf '\033[1;36m╔══════════════════════════════════════════╗\033[0m\n'
	@printf '\033[1;36m║      Vigilo — Scan                       ║\033[0m\n'
	@printf '\033[1;36m╚══════════════════════════════════════════╝\033[0m\n'
	@printf '\n'
	@printf '  \033[2mTarget:\033[0m    %s\n' "$(if $(URL),$(URL),code-only (no URL))"
	@printf '  \033[2mScan ID:\033[0m   %s\n' "$(SCAN_ID)"
	@printf '  \033[2mOutput:\033[0m    %s/.vigilo/\n' "$$(cat .vigilo-dir)"
	@printf '  \033[2mTemporal:\033[0m  http://localhost:8233\n'
	@printf '  \033[2mPush:\033[0m      %s\n' "$(if $(filter 1,$(PUSH)),enabled,disabled)"
	@printf '\n'
	@printf '  \033[33m⟳\033[0m  Starting Temporal server...\n'
	@HOST_REPO_DIR=$$(cat .vigilo-dir) \
	SCAN_ID=$(SCAN_ID) TARGET_URL=$(URL) \
	$(if $(CONFIG),CONFIG_ARGS="--config /app/configs/$(CONFIG:configs/%=%)",) \
	docker compose up -d temporal 2>&1 | sed 's/^/     /'
	@printf '  \033[33m⟳\033[0m  Waiting for Temporal to be healthy...\n'
	@until docker inspect --format='{{.State.Health.Status}}' vigilo-temporal 2>/dev/null | grep -q healthy; do \
		sleep 2; \
	done
	@printf '  \033[32m✓\033[0m  Temporal is ready\n\n'
	@printf '  \033[33m⟳\033[0m  Launching pipeline worker...\n\n'
	@HOST_REPO_DIR=$$(cat .vigilo-dir) \
	SCAN_ID=$(SCAN_ID) TARGET_URL=$(URL) \
	VIGILO_HOST_UID=$$(id -u) VIGILO_HOST_GID=$$(id -g) \
	$(if $(filter 1,$(PUSH)),VIGILO_PUSH_BRANCHES=true,) \
	$(if $(CONFIG),CONFIG_ARGS="--config /app/configs/$(CONFIG:configs/%=%)",) \
	docker compose run --rm -v "$$(cat .vigilo-dir)/.vigilo:/repos/target/.vigilo" worker

resume: ## Resume pipeline from workspace: make resume W=<workspace> [URL=http://target]
	@if [ -z "$(W)" ]; then \
		printf '  \033[31m✗\033[0m  Usage: make resume W=<workspace> [URL=http://target]\n'; \
		exit 1; \
	fi
	@if [ ! -f .vigilo-dir ]; then \
		printf '  \033[31m✗\033[0m  No previous build found. Run: make build DIR=/path/to/repo\n'; \
		exit 1; \
	fi
	@printf '\n'
	@printf '\033[1;36m╔══════════════════════════════════════════╗\033[0m\n'
	@printf '\033[1;36m║      Vigilo — Resume                     ║\033[0m\n'
	@printf '\033[1;36m╚══════════════════════════════════════════╝\033[0m\n'
	@printf '\n'
	@printf '  \033[2mTarget:\033[0m      %s\n' "$(if $(URL),$(URL),code-only (no URL))"
	@printf '  \033[2mWorkspace:\033[0m   %s\n' "$(W)"
	@printf '  \033[2mOutput:\033[0m      %s/.vigilo/\n' "$$(cat .vigilo-dir)"
	@printf '  \033[2mPush:\033[0m        %s\n' "$(if $(filter 1,$(PUSH)),enabled,disabled)"
	@printf '\n'
	@printf '  \033[33m⟳\033[0m  Starting Temporal server...\n'
	@HOST_REPO_DIR=$$(cat .vigilo-dir) \
	SCAN_ID=$(SCAN_ID) TARGET_URL=$(URL) \
	$(if $(CONFIG),CONFIG_ARGS="--config /app/configs/$(CONFIG:configs/%=%)",) \
	docker compose up -d temporal 2>&1 | sed 's/^/     /'
	@printf '  \033[33m⟳\033[0m  Waiting for Temporal to be healthy...\n'
	@until docker inspect --format='{{.State.Health.Status}}' vigilo-temporal 2>/dev/null | grep -q healthy; do \
		sleep 2; \
	done
	@printf '  \033[32m✓\033[0m  Temporal is ready\n\n'
	@printf '  \033[33m⟳\033[0m  Resuming pipeline...\n\n'
	@HOST_REPO_DIR=$$(cat .vigilo-dir) \
	SCAN_ID=$(SCAN_ID) TARGET_URL=$(URL) \
	VIGILO_HOST_UID=$$(id -u) VIGILO_HOST_GID=$$(id -g) \
	$(if $(filter 1,$(PUSH)),VIGILO_PUSH_BRANCHES=true,) \
	$(if $(CONFIG),CONFIG_ARGS="--config /app/configs/$(CONFIG:configs/%=%) --workspace $(W)",CONFIG_ARGS="--workspace $(W)") \
	docker compose run --rm -v "$$(cat .vigilo-dir)/.vigilo:/repos/target/.vigilo" worker

stop: ## Stop all containers
	@printf '  \033[33m⟳\033[0m  Stopping containers...\n'
	@docker compose down
	@printf '  \033[32m✓\033[0m  Stopped\n'

logs: ## Tail workflow log: make logs W=<workspace>
	@if [ -z "$(W)" ]; then \
		printf '  \033[31m✗\033[0m  Usage: make logs W=<workspace>\n'; \
		exit 1; \
	fi
	@REPO=$$(cat .vigilo-dir 2>/dev/null || echo ".") && \
	tail -f "$$REPO/.vigilo/$(W)/workflow.log"

status: ## Show running containers
	@docker compose ps

clean: ## Remove .vigilo scan outputs and Docker volumes
	@printf '  \033[33m⟳\033[0m  Removing scan outputs and volumes...\n'
	@REPO=$$(cat .vigilo-dir 2>/dev/null) && \
	if [ -n "$$REPO" ] && [ -d "$$REPO/.vigilo" ]; then \
		rm -rf "$$REPO/.vigilo"; \
		printf '  \033[32m✓\033[0m  Removed %s/.vigilo/\n' "$$REPO"; \
	fi
	@docker compose down -v
	@printf '  \033[32m✓\033[0m  Clean\n'

# --- Grey-Box Pipeline ---

build-greybox: ## Build grey-box worker image (Claude Code executor)
	@printf '\n'
	@printf '\033[1;36m╔══════════════════════════════════════════╗\033[0m\n'
	@printf '\033[1;36m║      Vigilo — Build Grey-Box             ║\033[0m\n'
	@printf '\033[1;36m╚══════════════════════════════════════════╝\033[0m\n'
	@printf '\n'
	docker compose -f docker-compose.greybox.yml build worker
	@printf '\n  \033[32m✓\033[0m  Grey-box build complete!\n\n'

build-greybox-opencode: ## Build grey-box worker image (OpenCode + local LLM)
	@printf '\n'
	@printf '\033[1;36m╔══════════════════════════════════════════╗\033[0m\n'
	@printf '\033[1;36m║  Vigilo — Build Grey-Box (OpenCode)      ║\033[0m\n'
	@printf '\033[1;36m╚══════════════════════════════════════════╝\033[0m\n'
	@printf '\n'
	docker compose -f docker-compose.greybox.yml -f docker-compose.opencode.yml build worker
	@printf '\n  \033[32m✓\033[0m  Grey-box OpenCode build complete!\n\n'

build-greybox-codex: ## Build grey-box worker image (Codex + OpenAI-compatible endpoint)
	@printf '\n'
	@printf '\033[1;36m╔══════════════════════════════════════════╗\033[0m\n'
	@printf '\033[1;36m║  Vigilo — Build Grey-Box (Codex)         ║\033[0m\n'
	@printf '\033[1;36m╚══════════════════════════════════════════╝\033[0m\n'
	@printf '\n'
	docker compose -f docker-compose.greybox.yml -f docker-compose.codex.yml build worker
	@printf '\n  \033[32m✓\033[0m  Grey-box Codex build complete!\n\n'

greybox: ## Run grey-box scan: make greybox URL=http://target CREDS=configs/creds.yaml
	@if [ -z "$(URL)" ]; then printf '  \033[31m✗\033[0m  Usage: make greybox URL=http://target CREDS=configs/creds.yaml\n'; exit 1; fi
	@if [ -z "$(CREDS)" ]; then printf '  \033[31m✗\033[0m  Usage: make greybox URL=http://target CREDS=configs/creds.yaml\n'; exit 1; fi
	@mkdir -p "$(CURDIR)/.vigilo" && chmod 777 "$(CURDIR)/.vigilo"
	@printf '\n'
	@printf '\033[1;36m╔══════════════════════════════════════════╗\033[0m\n'
	@printf '\033[1;36m║      Vigilo — Grey-Box Scan              ║\033[0m\n'
	@printf '\033[1;36m╚══════════════════════════════════════════╝\033[0m\n'
	@printf '\n'
	CREDS_FILE="$(CURDIR)/configs" OUTPUT_DIR="$(CURDIR)/.vigilo" \
		docker compose -f docker-compose.greybox.yml up -d temporal surrealdb surrealist
	@until docker inspect --format='{{.State.Health.Status}}' vigilo-surrealdb 2>/dev/null | grep -q healthy; do sleep 2; done
	@until docker inspect --format='{{.State.Health.Status}}' vigilo-temporal-greybox 2>/dev/null | grep -q healthy; do sleep 2; done
	@printf '  \033[32m✓\033[0m  Surrealist UI: http://localhost:8800\n'
	@printf '  \033[32m✓\033[0m  Temporal UI:   http://localhost:8233\n\n'
	CREDS_FILE="$(CURDIR)/configs" OUTPUT_DIR="$(CURDIR)/.vigilo" \
		docker compose -f docker-compose.greybox.yml run --rm worker \
		python3 -m src.greybox.temporal.worker \
		--url "$(URL)" --creds "/app/configs/$(CREDS:configs/%=%)" \
		$(if $(CONFIG),--config "/app/configs/$(CONFIG:configs/%=%)")

greybox-opencode: ## Run grey-box scan with OpenCode + local LLM: make greybox-opencode URL=http://target CREDS=configs/creds.yaml
	@if [ -z "$(URL)" ]; then printf '  \033[31m✗\033[0m  Usage: make greybox-opencode URL=http://target CREDS=configs/creds.yaml\n'; exit 1; fi
	@if [ -z "$(CREDS)" ]; then printf '  \033[31m✗\033[0m  Usage: make greybox-opencode URL=http://target CREDS=configs/creds.yaml\n'; exit 1; fi
	@mkdir -p "$(CURDIR)/.vigilo" && chmod 777 "$(CURDIR)/.vigilo"
	@printf '\n'
	@printf '\033[1;36m╔══════════════════════════════════════════╗\033[0m\n'
	@printf '\033[1;36m║  Vigilo — Grey-Box Scan (OpenCode)       ║\033[0m\n'
	@printf '\033[1;36m╚══════════════════════════════════════════╝\033[0m\n'
	@printf '\n'
	CREDS_FILE="$(CURDIR)/configs" OUTPUT_DIR="$(CURDIR)/.vigilo" \
		docker compose -f docker-compose.greybox.yml -f docker-compose.opencode.yml up -d temporal surrealdb surrealist
	@until docker inspect --format='{{.State.Health.Status}}' vigilo-surrealdb 2>/dev/null | grep -q healthy; do sleep 2; done
	@until docker inspect --format='{{.State.Health.Status}}' vigilo-temporal-greybox 2>/dev/null | grep -q healthy; do sleep 2; done
	@printf '  \033[32m✓\033[0m  Surrealist UI: http://localhost:8800\n'
	@printf '  \033[32m✓\033[0m  Temporal UI:   http://localhost:8233\n\n'
	CREDS_FILE="$(CURDIR)/configs" OUTPUT_DIR="$(CURDIR)/.vigilo" \
		docker compose -f docker-compose.greybox.yml -f docker-compose.opencode.yml run --rm worker \
		opencode-entrypoint --url "$(URL)" --creds "/app/configs/$(CREDS:configs/%=%)" \
		$(if $(CONFIG),--config "/app/configs/$(CONFIG:configs/%=%)")

greybox-codex: ## Run grey-box scan with Codex: make greybox-codex URL=http://target CREDS=configs/creds.yaml
	@if [ -z "$(URL)" ]; then printf '  \033[31m✗\033[0m  Usage: make greybox-codex URL=http://target CREDS=configs/creds.yaml\n'; exit 1; fi
	@if [ -z "$(CREDS)" ]; then printf '  \033[31m✗\033[0m  Usage: make greybox-codex URL=http://target CREDS=configs/creds.yaml\n'; exit 1; fi
	@mkdir -p "$(CURDIR)/.vigilo" && chmod 777 "$(CURDIR)/.vigilo"
	@printf '\n'
	@printf '\033[1;36m╔══════════════════════════════════════════╗\033[0m\n'
	@printf '\033[1;36m║  Vigilo — Grey-Box Scan (Codex)          ║\033[0m\n'
	@printf '\033[1;36m╚══════════════════════════════════════════╝\033[0m\n'
	@printf '\n'
	CREDS_FILE="$(CURDIR)/configs" OUTPUT_DIR="$(CURDIR)/.vigilo" \
		docker compose -f docker-compose.greybox.yml -f docker-compose.codex.yml up -d temporal surrealdb surrealist
	@until docker inspect --format='{{.State.Health.Status}}' vigilo-surrealdb 2>/dev/null | grep -q healthy; do sleep 2; done
	@until docker inspect --format='{{.State.Health.Status}}' vigilo-temporal-greybox 2>/dev/null | grep -q healthy; do sleep 2; done
	@printf '  \033[32m✓\033[0m  Surrealist UI: http://localhost:8800\n'
	@printf '  \033[32m✓\033[0m  Temporal UI:   http://localhost:8233\n\n'
	CREDS_FILE="$(CURDIR)/configs" OUTPUT_DIR="$(CURDIR)/.vigilo" \
		docker compose -f docker-compose.greybox.yml -f docker-compose.codex.yml run --rm worker \
		codex-entrypoint --url "$(URL)" --creds "/app/configs/$(CREDS:configs/%=%)" \
		$(if $(CONFIG),--config "/app/configs/$(CONFIG:configs/%=%)")

greybox-stop: ## Stop grey-box containers
	@printf '  Stopping grey-box containers...\n'
	docker compose -f docker-compose.greybox.yml down
	@printf '  \033[32m✓\033[0m  Stopped\n'

greybox-clean: ## Stop containers + wipe Temporal/SurrealDB state (aborts stale workflows)
	@printf '  Stopping grey-box containers and wiping volumes...\n'
	docker compose -f docker-compose.greybox.yml down -v
	@printf '  \033[32m✓\033[0m  Cleaned (Temporal + SurrealDB state removed)\n'

greybox-logs: ## Tail grey-box workflow log: make greybox-logs W=<workspace>
	@if [ -z "$(W)" ]; then printf '  \033[31m✗\033[0m  Usage: make greybox-logs W=<workspace>\n'; exit 1; fi
	tail -f "$(W)/workflow.log"

greybox-graph: ## Export grey-box graph
	docker compose -f docker-compose.greybox.yml exec worker graph-tool export --format yaml

greybox-ui: ## Open Surrealist graph UI at http://localhost:8800
	@docker compose -f docker-compose.greybox.yml up -d surrealdb surrealist
	@until docker inspect --format='{{.State.Health.Status}}' vigilo-surrealdb 2>/dev/null | grep -q healthy; do sleep 1; done
	@printf '\n  \033[32m✓\033[0m  SurrealDB running at http://localhost:$${SURREALDB_HOST_PORT:-8010}\n'
	@printf '  \033[32m✓\033[0m  Surrealist UI at http://localhost:8800\n'
	@printf '\n  Connection details:\n'
	@printf '    URL:       ws://localhost:$${SURREALDB_HOST_PORT:-8010}\n'
	@printf '    Namespace: vigilo\n'
	@printf '    Database:  <your session ID>\n'
	@printf '    User:      root\n'
	@printf '    Password:  (SURREALDB_PASS from .env, default: changeme)\n\n'
