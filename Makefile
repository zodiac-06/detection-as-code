PYTHON ?= python3

.DEFAULT_GOAL := all

.PHONY: help install lint test build coverage all deploy-dry deploy clean

help:
	@echo "install      install the Sigma toolchain"
	@echo "lint         static checks on every rule (metadata, naming, hygiene)"
	@echo "test         run every rule against its true/false positive fixtures"
	@echo "build        compile rules into Splunk, Elastic and Kusto queries"
	@echo "coverage     regenerate the ATT&CK coverage map"
	@echo "all          lint + test + build + coverage"
	@echo "deploy-dry   show the Sentinel payloads without calling Azure"
	@echo "deploy       publish analytics rules to Microsoft Sentinel"
	@echo "clean        remove build artefacts"

install:
	$(PYTHON) -m pip install -r requirements.txt

lint:
	$(PYTHON) tools/validate_rules.py

test:
	$(PYTHON) tools/rule_tests.py

build:
	$(PYTHON) tools/convert.py

coverage:
	$(PYTHON) tools/coverage_map.py

all: lint test build coverage

deploy-dry: build
	$(PYTHON) deploy/sentinel.py --dry-run

deploy: build
	$(PYTHON) deploy/sentinel.py

clean:
	rm -rf build .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {} +
