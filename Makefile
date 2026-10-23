.PHONY: help install test lint security run

help:
	@echo "Commandes disponibles pour protection-biometrie-athletes :"
	@echo "  make install    - Installe les dépendances du projet"
	@echo "  make test       - Lance la suite complète de tests pytest"
	@echo "  make lint       - Analyse statique avec ruff"
	@echo "  make security   - Scan de vulnérabilités avec bandit"
	@echo "  make run        - Lance le serveur FastAPI en local"

install:
	pip install -r requirements/test.txt

test:
	pytest -v --cov=src

lint:
	ruff check .

security:
	bandit -r src/ -ll

run:
	uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
