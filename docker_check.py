"""
Docker Build Helper Script
Tests dependencies locally before Docker build
"""

import subprocess
import sys

def run_command(cmd, description):
    """Run a command and report result."""
    print(f"\n{'='*60}")
    print(f"🔍 {description}")
    print(f"{'='*60}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Success")
            if result.stdout:
                print(result.stdout[:500])  # First 500 chars
        else:
            print(f"❌ Failed")
            if result.stderr:
                print(f"Error: {result.stderr[:500]}")
        return result.returncode == 0
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False


def main():
    """Test Docker and dependencies."""
    print("\n" + "="*60)
    print("🐳 DDoS AI Agent - Docker & Dependency Check")
    print("="*60)
    
    checks = [
        ("docker --version", "Docker installed"),
        ("docker-compose --version", "Docker Compose installed"),
        ("python --version", "Python installed"),
        (f"{sys.executable} -m pip show fastapi", "FastAPI installed"),
        ("python -m pytest --version", "Pytest installed"),
    ]
    
    results = []
    for cmd, desc in checks:
        results.append(run_command(cmd, desc))
    
    print("\n" + "="*60)
    print("📋 Summary")
    print("="*60)
    if all(results):
        print("✅ All checks passed!")
        print("\n🚀 Ready to build Docker image:")
        print("   docker build -t ddos-ai-agent .")
        print("   docker run -p 8000:8000 ddos-ai-agent")
    else:
        print("❌ Some checks failed. See details above.")
        print("\n💡 Troubleshooting:")
        print("   - Install Docker: https://docs.docker.com/install/")
        print("   - Install dependencies: pip install -r requirements.txt")


if __name__ == "__main__":
    main()
