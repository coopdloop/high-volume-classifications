PY ?= $(shell [ -x .venv/bin/python3 ] && echo .venv/bin/python3 || echo python3)
RUN_DIR := .run

.PHONY: dev up down stop install attack attack-burst logs lint clean

install: ## python deps + .env scaffold
	$(PY) -m pip install -r requirements.txt || uv pip install --python $(PY) -r requirements.txt
	@test -f .env || cp env.example .env

up: ## log platform (loki, alloy, grafana, phoenix)
	docker compose up -d

down: ## stop platform
	docker compose down

dev: up ## start the full stack (platform + classify + correlate + api)
	@mkdir -p $(RUN_DIR) data/logs
	@nohup $(PY) -m soc.classify  > $(RUN_DIR)/classify.log 2>&1 & echo $$! > $(RUN_DIR)/classify.pid
	@nohup $(PY) -m soc.correlate > $(RUN_DIR)/correlate.log 2>&1 & echo $$! > $(RUN_DIR)/correlate.pid
	@nohup $(PY) -m uvicorn soc.api:app --port 8000 > $(RUN_DIR)/api.log 2>&1 & echo $$! > $(RUN_DIR)/api.pid
	@echo "grafana  http://localhost:3000"
	@echo "phoenix  http://localhost:6006"
	@echo "api      http://localhost:8000/docs"
	@echo "logs     make logs   |   attack: make attack"

stop: ## stop pipeline daemons
	@for f in $(RUN_DIR)/*.pid; do [ -f "$$f" ] && kill $$(cat $$f) 2>/dev/null; rm -f $$f; done; true

attack: ## replay campaign in real time (~30s at 60x)
	$(PY) generator/campaign.py --speed 60

attack-burst: ## write all events at once
	$(PY) generator/campaign.py --burst

attack-botsv1: clean ## blind replay of real BOTS v1 attack slices (~9k events, ~40min)
	docker compose down
	mkdir -p data/logs && touch data/logs/sysmon.log data/logs/firewall.log data/logs/okta.log
	docker compose up -d
	sleep 10
	$(PY) generator/botsv1_slice.py
	@$(MAKE) dev
	@echo "ground truth: docs/botsv1-ground-truth.md — do NOT share with the agents"

status: ## show daemon + platform health
	@for s in classify correlate api; do \
		if [ -f $(RUN_DIR)/$$s.pid ] && kill -0 $$(cat $(RUN_DIR)/$$s.pid) 2>/dev/null; then \
			echo "$$s  UP (pid $$(cat $(RUN_DIR)/$$s.pid))"; \
		else echo "$$s  DOWN"; fi; \
	done
	@curl -s -m 2 localhost:8000/health > /dev/null && echo "api http://localhost:8000 OK" || echo "api http://localhost:8000 UNREACHABLE"
	@docker compose ps --format '{{.Name}}\t{{.Status}}'

logs: ## tail daemon logs
	tail -f $(RUN_DIR)/*.log

lint: ## validate mermaid diagrams
	$(PY) scripts/lint_mermaid.py

clean: stop ## wipe generated data + pid files
	rm -rf data $(RUN_DIR)
