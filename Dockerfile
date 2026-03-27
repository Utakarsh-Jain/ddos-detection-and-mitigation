# DDoS AI Agent - Docker Container
# Build: docker build -t ddos-ai-agent .
# Run: docker run -p 8000:8000 ddos-ai-agent

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
# These are needed for: numpy, pandas, scikit-learn, xgboost, scapy
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    gfortran \
    iptables \
    iproute2 \
    libopenblas-dev \
    liblapack-dev \
    libgomp1 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip and setuptools
RUN pip install --upgrade pip setuptools wheel

# Copy requirements first (better layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install FastAPI and Uvicorn for API
RUN pip install --no-cache-dir fastapi uvicorn[standard]

# Copy project files
COPY . .

# Create necessary directories
RUN mkdir -p data/raw data/processed models plots logs

# Expose port for API
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

# Default command - run FastAPI
CMD ["python", "app.py"]

# Alternative commands (uncomment one):
# CMD ["python", "agent_core.py", "--mode", "simulate", "--data", "data/raw/Syn-testing.parquet"]
# CMD ["python", "model_training.py"]
