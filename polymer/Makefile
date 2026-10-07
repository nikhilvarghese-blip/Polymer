.PHONY: install validate test scan docker-build

install:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -e .

validate:
	. .venv/bin/activate && polymer validate --targets targets.txt --config config/polymer.yaml

scan:
	. .venv/bin/activate && polymer scan --targets targets.txt --config config/polymer.yaml

test:
	. .venv/bin/activate && python -m pytest -q

docker-build:
	docker compose build
