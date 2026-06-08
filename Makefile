# NOTE:
# Environment selection and loading is handled exclusively by bin/dj.
# Make targets are thin wrappers for developer convenience only.

SHELL := /bin/bash

# -------------------------
# Help
# -------------------------

.PHONY: help
help:
	@echo ""
	@echo "Environments:"
	@echo "  make dev-shell        Dev Django shell (SQLite)"
	@echo "  make dev-run          Dev runserver (SQLite)"
	@echo "  make dev-migrate      Dev migrate (SQLite)"
	@echo "  make dev-manage       Dev manage (SQLite, CMD=\"command args\")"
	@echo ""
	@echo "  make devpg-shell      Dev Django shell (production Postgres)"
	@echo "  make devpg-run        Dev runserver (production Postgres)"
	@echo "  make devpg-migrate    Dev migrate (production Postgres)"
	@echo "  make devpg-manage     Dev manage (production Postgres, CMD=\"command args\")"
	@echo ""
	@echo "  make staging-shell    Staging Django shell (local simulation)"
	@echo "  make staging-migrate  Staging migrate (local simulation)"
	@echo ""
	@echo "  make prod-shell       Prod Django shell (local simulation)"
	@echo "  make prod-migrate     Prod migrate (local simulation)"
	@echo ""
	@echo "Notes:"
	@echo "  dev-*    uses the dev environment (SQLite)"
	@echo "  devpg-*  uses production Postgres (read carefully before migrating!)"
	@echo ""

# -------------------------
# Dev
# -------------------------

.PHONY: dev-shell dev-run dev-migrate dev-manage

dev-shell:
	./bin/dj dev shell

dev-run:
	./bin/dj dev runserver

dev-migrate:
	./bin/dj dev migrate

dev-manage:
	./bin/dj dev $(CMD)

# -------------------------
# Dev (production Postgres)
# -------------------------

.PHONY: devpg-shell devpg-run devpg-migrate devpg-manage

devpg-shell:
	./bin/dj devpg shell

devpg-run:
	./bin/dj devpg runserver

devpg-migrate:
	./bin/dj devpg migrate

devpg-manage:
	./bin/dj devpg $(CMD)

# -------------------------
# Staging (simulated locally)
# -------------------------

.PHONY: staging-shell staging-migrate

staging-shell:
	./bin/dj staging shell

staging-migrate:
	./bin/dj staging migrate

# -------------------------
# Production (simulated locally)
# -------------------------

.PHONY: prod-shell prod-migrate

prod-shell:
	./bin/dj prod shell

prod-migrate:
	./bin/dj prod migrate
