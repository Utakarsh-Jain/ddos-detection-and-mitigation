# 🚀 Quick Start Guide

## Installation

```bash
# 1. Install dependencies
pip install -r requirements.txt

# Or use make:
make install
```

## Data & Model Setup

```bash
# 2. Preprocess data (if raw data is in data/raw/)
python data_preprocessing.py
# or: make preprocess

# 3. Train ML models
python model_training.py
# or: make train
```

## Running the Agent

### Option 1: FastAPI REST API
```bash
python app.py
# or: make run-api

# Access docs at: http://localhost:8000/docs
```

### Option 2: Live Packet Capture
```bash
python agent_core.py --mode live
# or: make run-live
# Press Ctrl+C to stop
```

### Option 3: Simulation Mode
```bash
python agent_core.py --mode simulate --data data/raw/Syn-testing.parquet
# or: make run-simulate
```

## Testing

```bash
# Run all tests
make test

# Run with coverage report
make test-coverage

# Run specific test file
pytest tests/test_config.py -v
```

## Docker Deployment

```bash
# Build image
make docker-build

# Start services (API + Redis + PostgreSQL)
make docker-up

# View logs
make docker-logs

# Stop services
make docker-down
```

## API Usage Examples

### 1. Single Flow Detection
```bash
curl -X POST "http://localhost:8000/detect" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.100",
    "destination_ip": "10.0.0.1",
    "destination_port": 443,
    "flow_bytes_per_sec": 50000,
    "flow_packets_per_sec": 5000
  }'
```

### 2. Batch Detection
```bash
curl -X POST "http://localhost:8000/batch" \
  -H "Content-Type: application/json" \
  -d '[
    {"source_ip": "192.168.1.100", "destination_ip": "10.0.0.1", "destination_port": 443},
    {"source_ip": "192.168.1.101", "destination_ip": "10.0.0.2", "destination_port": 80}
  ]'
```

### 3. Health Check
```bash
curl http://localhost:8000/health
```

### 4. View Stats
```bash
curl http://localhost:8000/stats
```

## Available Commands

```bash
make help              # Show all available commands
make clean             # Clean cache and temp files
make format            # Format code with black
make lint              # Run linting
```

## Project Structure

```
ddos-ai-agent/
├── config.py                 # Centralized configuration
├── model_training.py         # Train ML models
├── data_preprocessing.py      # Data processing
├── agent_core.py             # Main agent logic
├── app.py                    # FastAPI REST API
├── Dockerfile                # Docker image definition
├── docker-compose.yml        # Multi-service deployment
├── Makefile                  # Common commands
├── tests/                    # Unit tests
│   ├── conftest.py
│   ├── test_agent.py
│   └── test_config.py
├── data/
│   ├── raw/                  # Raw dataset files
│   └── processed/            # Preprocessed data
├── models/                   # Trained ML models
├── logs/                     # Application logs
└── plots/                    # Visualizations
```

## Configuration

All hardcoded values are now in `config.py`. Edit this file to customize:
- Model hyperparameters
- Detection thresholds
- API settings
- Docker settings
- Logging configuration

## Troubleshooting

### Models not found
```bash
# Retrain models
make train
```

### Port already in use
```bash
# Change API_PORT in config.py or use:
python app.py --port 8001
```

### Docker build fails
```bash
# Rebuild without cache
make docker-rebuild
```

### Tests failing
```bash
# Run with verbose output
pytest tests/ -vv

# Run specific test
pytest tests/test_config.py::TestConfigPaths::test_project_root_exists -v
```

## Performance Tips

1. **Batch processing** is enabled by default (much faster than row-by-row)
2. **Use GPU** for XGBoost by setting `tree_method="gpu_hist"` in config.py
3. **Scale horizontally** using docker-compose
4. **Cache predictions** for duplicate flows

## Next Steps

✅ Configuration management complete  
✅ Unit tests implemented  
✅ REST API created  
✅ Docker containerization ready  

Now:
1. Run `make train` to train models (if not done)
2. Test API: `make run-api` then visit http://localhost:8000/docs
3. Run tests: `make test`
4. Deploy: `make docker-up`

Questions? Check the main README.md!