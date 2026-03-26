# Docker Troubleshooting Guide

## Common Issues & Solutions

### 1. ❌ Dependencies Missing During Docker Build

**Symptom:** Build fails with errors like:
- `error: Microsoft Visual C++ 14.0 is required`
- `ImportError: No module named 'numpy'`
- `gcc: command not found`

**Solution:**
The updated Dockerfile now includes all required system packages:
```dockerfile
build-essential, gcc, g++, gfortran, libopenblas-dev, liblapack-dev
```

**Fix:**
```bash
# Rebuild with updated Dockerfile
docker build --no-cache -t ddos-ai-agent .

# Or use docker-compose
docker-compose build --no-cache
```

---

### 2. ❌ Port Already in Use

**Symptom:** Error when running container:
```
Error response from daemon: Ports are not available
```

**Solution:** Change the port in `docker-compose.yml`:
```yaml
services:
  ddos-api:
    ports:
      - "8001:8000"  # Change 8000 to 8001 or any free port
```

Or kill the existing service:
```bash
docker-compose down
```

---

### 3. ❌ Docker Not Found

**Symptom:**
```
'docker' is not recognized as an internal or external command
```

**Solution:**
1. Install Docker: https://docs.docker.com/install/
2. Restart your terminal/PowerShell
3. Verify: `docker --version`

---

### 4. ❌ Insufficient Memory

**Symptom:** Container crashes with out-of-memory errors

**Solution:** Increase Docker memory allocation:
- **Windows/Mac**: Docker Desktop → Settings → Resources → Memory
- **Linux**: No limit by default

Or use resource limits in `docker-compose.yml`:
```yaml
services:
  ddos-api:
    deploy:
      resources:
        limits:
          memory: 2G
```

---

### 5. ❌ Volume/File Permissions

**Symptom:** `Permission denied` errors

**Solution:**
```bash
# Run with proper permissions
docker-compose down
docker-compose up --force-recreate
```

---

## Quick Diagnostic Steps

### 1. Test Local Installation First
```bash
python docker_check.py
```

### 2. Build with Verbose Output
```bash
docker build -t ddos-ai-agent . --progress=plain
```

### 3. Run Container with Interactive Shell
```bash
docker run -it ddos-ai-agent /bin/bash
# Inside container, test:
python -c "import xgboost; print('XGBoost OK')"
```

### 4. Check Container Logs
```bash
docker-compose logs -f ddos-api
```

### 5. Inspect Image
```bash
docker inspect ddos-ai-agent
```

---

## Alternative Solutions

### Option A: Use Pre-built Image
```bash
# Use official Python image with more libraries
docker pull python:3.11
```

### Option B: Skip Docker Locally
```bash
# Test without Docker first
python app.py
# Then docker-compose up one service at a time
```

### Option C: Use Lightweight Image
```dockerfile
FROM python:3.11-alpine
# (More lightweight but fewer pre-installed packages)
```

---

## Full Working Docker Example

### 1. Diagnose
```bash
python docker_check.py
```

### 2. Build
```bash
docker build -t ddos-ai-agent:latest .
```

### 3. Test Single Container
```bash
docker run -p 8000:8000 ddos-ai-agent:latest
# Visit: http://localhost:8000/docs
```

### 4. Use Docker Compose (Recommended)
```bash
docker-compose build
docker-compose up -d
docker-compose logs -f
```

### 5. Stop & Cleanup
```bash
docker-compose down
docker system prune  # Remove unused images
```

---

## Platform-Specific Issues

### Windows (PowerShell)
```powershell
# Use backticks for line continuation
docker build `
  -t ddos-ai-agent `
  .
```

### macOS/Linux
```bash
docker build \
  -t ddos-ai-agent \
  .
```

---

## Testing Commands

```bash
# Check if build succeeded
docker images | grep ddos-ai-agent

# Test API endpoint inside container
docker run -p 8000:8000 ddos-ai-agent:latest &
sleep 5
curl http://localhost:8000/health

# Run tests inside container
docker run ddos-ai-agent:latest python -m pytest tests/ -v

# Interactive debugging
docker run -it ddos-ai-agent:latest bash
```

---

## Getting Help

If you still have issues:

1. **Check logs:** `docker-compose logs`
2. **Run diagnostics:** `python docker_check.py`
3. **Test locally first:** `python app.py`
4. **Rebuild:** `docker-compose build --no-cache`
5. **Clean restart:** `docker system prune && docker-compose up`

---

## Key Files for Docker

- `Dockerfile` - Container image definition
- `docker-compose.yml` - Multi-service orchestration
- `.dockerignore` - Files to exclude from build
- `requirements.txt` - Python dependencies
- `docker_check.py` - Diagnostic script
- `DOCKER_TROUBLESHOOTING.md` - This file!
