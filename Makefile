.PHONY: help install train test test-coverage lint format clean run-api run-live run-simulate docker-build docker-up docker-down

# Colors for terminal output
CYAN := \033[0;36m
GREEN := \033[0;32m
RED := \033[0;31m
NC := \033[0m # No Color

help:
	@echo "$(CYAN)DDoS AI Agent - Makefile Commands$(NC)"
	@echo ""
	@echo "$(GREEN)Development:$(NC)"
	@echo "  make install          Install dependencies"
	@echo "  make train            Train ML models"
	@echo "  make test             Run unit tests"
	@echo "  make test-coverage    Run tests with coverage report"
	@echo "  make lint             Run code linting"
	@echo "  make format           Format code with black"
	@echo "  make clean            Clean up cache and temp files"
	@echo ""
	@echo "$(GREEN)Running:$(NC)"
	@echo "  make run-api          Start FastAPI server"
	@echo "  make run-live         Run live packet capture"
	@echo "  make run-simulate     Run simulation on sample data"
	@echo ""
	@echo "$(GREEN)Docker:$(NC)"
	@echo "  make docker-build     Build Docker image"
	@echo "  make docker-up        Start services with docker-compose"
	@echo "  make docker-down      Stop docker-compose services"
	@echo "  make docker-logs      View docker-compose logs"
	@echo ""

install:
	@echo "$(CYAN)Installing dependencies...$(NC)"
	pip install -r requirements.txt
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

train:
	@echo "$(CYAN)Training ML models...$(NC)"
	python model_training.py
	@echo "$(GREEN)✓ Training complete$(NC)"

preprocess:
	@echo "$(CYAN)Preprocessing data...$(NC)"
	python data_preprocessing.py
	@echo "$(GREEN)✓ Preprocessing complete$(NC)"

test:
	@echo "$(CYAN)Running unit tests...$(NC)"
	pytest tests/ -v
	@echo "$(GREEN)✓ Tests complete$(NC)"

test-coverage:
	@echo "$(CYAN)Running tests with coverage...$(NC)"
	pytest tests/ -v --cov=. --cov-report=html --cov-report=term
	@echo "$(GREEN)✓ Coverage report generated in htmlcov/$(NC)"

lint:
	@echo "$(CYAN)Linting code...$(NC)"
	pylint *.py tests/ || true
	@echo "$(GREEN)✓ Linting complete$(NC)"

format:
	@echo "$(CYAN)Formatting code with black...$(NC)"
	black *.py tests/
	@echo "$(GREEN)✓ Code formatted$(NC)"

clean:
	@echo "$(CYAN)Cleaning up...$(NC)"
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".hypothesis" -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✓ Cleanup complete$(NC)"

run-api:
	@echo "$(CYAN)Starting FastAPI server...$(NC)"
	@echo "$(GREEN)📚 Docs: http://localhost:8000/docs$(NC)"
	python app.py

run-live:
	@echo "$(CYAN)Starting live packet capture...$(NC)"
	@echo "$(GREEN)Press Ctrl+C to stop$(NC)"
	python agent_core.py --mode live

run-simulate:
	@echo "$(CYAN)Running simulation on sample data...$(NC)"
	python agent_core.py --mode simulate --data data/raw/Syn-testing.parquet --max_rows 10000

docker-build:
	@echo "$(CYAN)Building Docker image...$(NC)"
	docker build -t ddos-ai-agent:latest .
	@echo "$(GREEN)✓ Image built successfully$(NC)"

docker-up:
	@echo "$(CYAN)Starting services with docker-compose...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)✓ Services started$(NC)"
	@echo "📚 API: http://localhost:8000/docs"
	@echo "📊 PostgreSQL: localhost:5432"
	@echo "📦 Redis: localhost:6379"

docker-down:
	@echo "$(CYAN)Stopping docker-compose services...$(NC)"
	docker-compose down
	@echo "$(GREEN)✓ Services stopped$(NC)"

docker-logs:
	@echo "$(CYAN)Showing docker-compose logs...$(NC)"
	docker-compose logs -f

docker-rebuild:
	@echo "$(CYAN)Rebuilding Docker image...$(NC)"
	docker-compose down
	docker-compose build --no-cache
	docker-compose up -d
	@echo "$(GREEN)✓ Rebuilt and started$(NC)"

.DEFAULT_GOAL := help
