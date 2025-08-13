# 📦 AODS Requirements Organization

This directory contains modular dependency files for different AODS use cases.

##  Quick Selection Guide

### For Most Users (Default)
```bash
pip install -r requirements.txt  # Full analysis capabilities
```

### For Specific Use Cases

| Use Case | File | Packages | Install Command |
|----------|------|----------|-----------------|
| **Basic functionality** | `base.txt` | ~20 | `pip install -r requirements/base.txt` |
| **Full analysis** | `analysis.txt` | ~45 | `pip install -r requirements/analysis.txt` |
| **Docker deployment** | `docker.txt` | ~25 | `pip install -r requirements/docker.txt` |
| **Development** | `dev.txt` | ~65 | `pip install -r requirements/dev.txt` |

## 📋 File Descriptions

### 📦 `base.txt` - Core Requirements
**Essential dependencies for basic AODS functionality**
- CLI interface and terminal formatting
- Basic Android APK analysis
- Core data processing
- Essential security analysis
- Basic reporting

**Use when**: You need minimal AODS functionality, CI/CD environments, or container base images.

### 🔬 `analysis.txt` - Full Analysis
**Complete AODS analysis capabilities**
- Includes all base requirements
- Advanced dynamic analysis (Frida, mitmproxy)
- Enhanced static analysis (YARA, JADX)
- Machine learning pattern detection
- Advanced reporting (PDF, visualization)
- Network and cryptographic analysis

**Use when**: You want full AODS functionality (recommended for most users).

### 🐳 `docker.txt` - Docker Deployment
**Optimized for containerized environments**
- Includes base requirements
- API framework (FastAPI, uvicorn)
- Database connectivity (PostgreSQL, Redis)
- Monitoring and metrics
- Excludes development tools

**Use when**: Building Docker images or production deployments.

### 🛠️ `dev.txt` - Development Environment
**Complete development environment**
- Includes full analysis capabilities
- Testing frameworks and coverage
- Code quality tools (black, flake8, mypy)
- Documentation tools
- Debugging and profiling tools
- Build and distribution tools

**Use when**: Contributing to AODS or setting up development environment.

## 🔄 Dependency Hierarchy

```
dev.txt
└── analysis.txt
    └── base.txt

docker.txt
└── base.txt
```

## 🚀 Installation Examples

### Fresh Installation
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Choose your requirements
pip install -r requirements/analysis.txt  # Full functionality
```

### Docker Build
```bash
# In Dockerfile
COPY requirements/docker.txt requirements.txt
RUN pip install -r requirements.txt
```

### Development Setup
```bash
# For contributors
pip install -r requirements/dev.txt
pre-commit install
```

### Minimal Installation
```bash
# For CI/CD or resource-constrained environments
pip install -r requirements/base.txt
```

## 🔧 Maintenance

### Adding New Dependencies
1. **Core functionality** → Add to `base.txt`
2. **Analysis features** → Add to `analysis.txt`
3. **Docker/API features** → Add to `docker.txt` 
4. **Development tools** → Add to `dev.txt`

### Testing Changes
```bash
# Test each configuration
pip install -r requirements/base.txt && python -c "import src.core"
pip install -r requirements/analysis.txt && python dyna.py --help
pip install -r requirements/docker.txt && python -c "import fastapi"
pip install -r requirements/dev.txt && pytest --version
```

## 📊 Size Comparison

| File | Packages | Purpose | Install Time |
|------|----------|---------|--------------|
| `base.txt` | ~20 | Core functionality | ~2 minutes |
| `analysis.txt` | ~45 | Full analysis | ~5 minutes |
| `docker.txt` | ~25 | Production API | ~3 minutes |
| `dev.txt` | ~65 | Development | ~8 minutes |

## 🎯 Benefits of This Structure

✅ **Modular** - Install only what you need  
✅ **Maintainable** - Clear separation of concerns  
✅ **Fast CI/CD** - Minimal dependencies for testing  
✅ **Docker Optimized** - Smaller container images  
✅ **Developer Friendly** - Complete development environment  
✅ **Backward Compatible** - `requirements.txt` still works 