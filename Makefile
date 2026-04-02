SHELL := /bin/bash

.PHONY: help
help:
	@echo ""
	@echo "Environments:"
	@echo "  make dev-shell        Dev Django shell"
	@echo "  make dev-run          Dev runserver"
	@echo "  make dev-migrate      Dev migrate"
	@echo ""

.PHONY: dev-shell dev-run dev-migrate
dev-shell:
	./bin/dj dev shell

dev-run:
	./bin/dj dev runserver

dev-migrate:
	./bin/dj dev migrate
