# AODS - Automated OWASP Dynamic Scan Framework

## 🚀 Overview

AODS (Automated OWASP Dynamic Scan) is a comprehensive enterprise-grade mobile application security testing framework for Android APK analysis. It combines static analysis, dynamic runtime testing, and machine learning-enhanced vulnerability detection to provide thorough security assessments.

## 🎯 Key Features

- **Comprehensive Analysis**: Static code analysis with JADX decompilation combined with dynamic runtime testing
- **ML-Enhanced Detection**: Machine learning algorithms for false positive reduction and pattern recognition
- **30+ Security Plugins**: Extensive vulnerability detection covering OWASP Mobile Top 10
- **Multiple Scan Modes**: From quick scans to deep comprehensive analysis
- **Advanced Reporting**: Professional HTML reports, JSON output, and executive summaries
- **Parallel Processing**: Optimized multi-threaded execution for faster analysis
- **Runtime Instrumentation**: Frida-based dynamic analysis and behavior monitoring

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu/Kali recommended), macOS, Windows WSL2
- **Python**: 3.8 or higher
- **Java**: OpenJDK 11 or higher (for JADX decompilation)
- **Memory**: Minimum 4GB RAM, 8GB+ recommended
- **Storage**: At least 2GB free space

### Optional Dependencies
- **Android SDK**: For enhanced device interaction and ADB commands
- **Frida Server**: For advanced dynamic analysis (automatically managed)
- **Docker**: For containerized analysis environments

## 🛠️ Installation

### Method 1: Automated Setup (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd automated-owasp-dynamic-scan-dyna_update

# Run automated setup
chmod +x scripts/setup_venv.sh
./scripts/setup_venv.sh

# Verify installation
./aods_venv/bin/python dyna.py --help
```

### Method 2: Manual Installation

```bash
# Create virtual environment
python3 -m venv aods_venv
source aods_venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install additional ML dependencies
pip install scikit-learn matplotlib seaborn nltk

# Verify installation
python dyna.py --help
```

### Method 3: Docker Installation

```bash
# Build Docker image
docker build -t aods-framework .

# Run container
docker run -it --rm -v $(pwd)/apks:/app/apks aods-framework
```

## 🚀 Quick Start Guide

### Basic Usage

```bash
# Activate virtual environment (if not using automated setup)
source aods_venv/bin/activate

# Basic scan
python dyna.py --apk /path/to/app.apk --pkg com.example.app

# Deep comprehensive scan
python dyna.py --apk /path/to/app.apk --pkg com.example.app --mode deep

# Scan with specific output directory
python dyna.py --apk /path/to/app.apk --pkg com.example.app --output-dir ./scan_results
```

### Using the Convenience Scripts

```bash
# Use the automated runner (recommended)
./run_aods_venv.sh /path/to/app.apk com.example.app

# Run with specific scan mode
./run_aods_venv.sh /path/to/app.apk com.example.app deep
```

## 📊 Scan Modes Explained

### 1. Safe Mode (Default)
- **Purpose**: Quick security assessment with minimal system impact
- **Features**: Essential vulnerability detection, basic static analysis
- **Duration**: 5-15 minutes
- **Use Case**: Initial security assessment, CI/CD integration

```bash
python dyna.py --apk app.apk --pkg com.example.app --mode safe
```

### 2. Deep Mode
- **Purpose**: Comprehensive security analysis with extensive coverage
- **Features**: Full static analysis, dynamic testing, ML enhancement
- **Duration**: 20-60 minutes
- **Use Case**: Thorough security audit, compliance assessment

```bash
python dyna.py --apk app.apk --pkg com.example.app --mode deep
```

### 3. Vulnerable App Mode
- **Purpose**: Specialized analysis for penetration testing apps
- **Features**: Enhanced vulnerability detection for training applications
- **Duration**: 10-30 minutes
- **Use Case**: Security training, vulnerability research

```bash
python dyna.py --apk app.apk --pkg com.example.app --vulnerable-app-mode
```

### 4. Sequential vs Parallel Execution

**Parallel Execution (Default)**:
```bash
python dyna.py --apk app.apk --pkg com.example.app
# Runs static and dynamic analysis simultaneously
```

**Sequential Execution**:
```bash
python dyna.py --apk app.apk --pkg com.example.app --sequential
# Runs static analysis first, then dynamic analysis
```

### 5. Targeted Analysis

**Static Analysis Only**:
```bash
python dyna.py --apk app.apk --pkg com.example.app --static-only
```

**Dynamic Analysis Only**:
```bash
python dyna.py --apk app.apk --pkg com.example.app --dynamic-only
```

## 🔬 Advanced Features

### Machine Learning Integration

AODS includes sophisticated ML capabilities for enhanced analysis:

#### 1. False Positive Reduction
```bash
# Enable ML-enhanced filtering
python dyna.py --apk app.apk --pkg com.example.app --enable-ml

# Configure ML sensitivity
python dyna.py --apk app.apk --pkg com.example.app --ml-threshold 0.8
```

#### 2. Pattern Recognition
The ML system automatically:
- Identifies recurring vulnerability patterns
- Reduces false positives by up to 95%
- Enhances detection accuracy
- Provides confidence scoring

#### 3. Adaptive Learning
```bash
# Train custom ML models (advanced users)
python -m core.ml_false_positive_reducer_optimized --train

# Export ML model performance metrics
python dyna.py --apk app.apk --pkg com.example.app --export-ml-metrics
```

### Dynamic Analysis Features

#### 1. Runtime Behavior Analysis
```bash
# Enable comprehensive runtime monitoring
python dyna.py --apk app.apk --pkg com.example.app --with-runtime-analysis

# Extended monitoring duration
python dyna.py --apk app.apk --pkg com.example.app --runtime-duration 300
```

#### 2. Frida Integration
```bash
# Enable Frida-based dynamic analysis
python dyna.py --apk app.apk --pkg com.example.app --with-frida

# Custom Frida scripts
python dyna.py --apk app.apk --pkg com.example.app --frida-script custom_script.js
```

#### 3. Network Traffic Analysis
```bash
# Enable network monitoring
python dyna.py --apk app.apk --pkg com.example.app --with-network-analysis

# Proxy-based traffic capture
python dyna.py --apk app.apk --pkg com.example.app --proxy-mode
```

## 📈 Output and Reporting

### Report Formats

#### 1. HTML Reports (Default)
```bash
python dyna.py --apk app.apk --pkg com.example.app --format html
```
- Professional styled reports
- Interactive vulnerability details
- Executive summaries
- MASVS compliance mapping

#### 2. JSON Reports
```bash
python dyna.py --apk app.apk --pkg com.example.app --format json
```
- Machine-readable output
- API integration friendly
- Detailed vulnerability metadata
- Structured findings data

#### 3. Multiple Format Output
```bash
python dyna.py --apk app.apk --pkg com.example.app --format html,json,csv
```

### Report Customization

#### 1. Executive Reports
```bash
python dyna.py --apk app.apk --pkg com.example.app --executive-summary
```

#### 2. Technical Reports
```bash
python dyna.py --apk app.apk --pkg com.example.app --technical-details
```

#### 3. Compliance Reports
```bash
# OWASP MASVS compliance
python dyna.py --apk app.apk --pkg com.example.app --masvs-compliance

# NIST framework mapping
python dyna.py --apk app.apk --pkg com.example.app --nist-mapping
```

## 🔧 Configuration

### Environment Variables

```bash
# Disable ML components (if dependencies missing)
export AODS_DISABLE_ML=1

# Configure output verbosity
export AODS_LOG_LEVEL=DEBUG

# Set custom workspace directory
export AODS_WORKSPACE=/path/to/workspace

# Configure parallel processing
export AODS_MAX_WORKERS=4
```

### Configuration Files

AODS uses YAML configuration files in the `config/` directory:

- `vulnerability_patterns.yaml`: Custom vulnerability detection patterns
- `enhanced_detection_config.yaml`: Analysis behavior configuration
- `framework_vulnerability_patterns.yaml`: Framework-specific patterns

#### Example Custom Configuration:
```yaml
# config/custom_patterns.yaml
custom_patterns:
  api_keys:
    pattern: "api[_-]?key\\s*[=:]\\s*['\"][^'\"]{20,}['\"]"
    severity: "HIGH"
    confidence: 0.9
  
  hardcoded_urls:
    pattern: "https?://[^\\s\"'<>]+"
    severity: "MEDIUM"
    confidence: 0.7
```

## 🔍 Vulnerability Categories

AODS detects 30+ vulnerability categories:

### OWASP Mobile Top 10
1. **M1: Improper Platform Usage**
2. **M2: Insecure Data Storage**
3. **M3: Insecure Communication**
4. **M4: Insecure Authentication**
5. **M5: Insufficient Cryptography**
6. **M6: Insecure Authorization**
7. **M7: Poor Code Quality**
8. **M8: Code Tampering**
9. **M9: Reverse Engineering**
10. **M10: Extraneous Functionality**

### Additional Categories
- SQL Injection vulnerabilities
- XSS and injection attacks
- Path traversal vulnerabilities
- Hardcoded secrets and credentials
- Weak cryptographic implementations
- Network security misconfigurations
- Privacy data leakage
- Component vulnerabilities
- And many more...

## 🔧 Troubleshooting

### Common Issues

#### 1. "No module named" Errors
```bash
# Solution: Use virtual environment
source aods_venv/bin/activate
python dyna.py --apk app.apk --pkg com.example.app

# Or reinstall dependencies
pip install -r requirements.txt
```

#### 2. Java/JADX Issues
```bash
# Verify Java installation
java -version

# Install OpenJDK 11
sudo apt-get install openjdk-11-jdk

# Set JAVA_HOME if needed
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
```

#### 3. Memory Issues
```bash
# Increase memory limits
export AODS_MAX_MEMORY=8G

# Use lightweight mode
python dyna.py --apk app.apk --pkg com.example.app --lightweight
```

#### 4. Permission Issues
```bash
# Fix permissions
chmod +x scripts/*.sh
chmod +x dyna.py

# Run with appropriate permissions
sudo python dyna.py --apk app.apk --pkg com.example.app
```

### Performance Optimization

#### 1. Parallel Processing
```bash
# Optimize for your system
python dyna.py --apk app.apk --pkg com.example.app --workers 8

# Profile-based optimization
python dyna.py --apk app.apk --pkg com.example.app --profile fast
```

#### 2. Resource Management
```bash
# Limit memory usage
python dyna.py --apk app.apk --pkg com.example.app --max-memory 4G

# Timeout configuration
python dyna.py --apk app.apk --pkg com.example.app --timeout 1800
```

## 📚 Integration Examples

### CI/CD Integration

#### GitHub Actions
```yaml
name: AODS Security Scan
on: [push]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup AODS
        run: |
          ./scripts/setup_venv.sh
      - name: Run Security Scan
        run: |
          ./aods_venv/bin/python dyna.py --apk app.apk --pkg com.example.app --format json
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: '*_security_report.json'
```

#### Jenkins Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh './scripts/setup_venv.sh'
                sh './aods_venv/bin/python dyna.py --apk ${APK_PATH} --pkg ${PACKAGE_NAME} --format json'
                archiveArtifacts artifacts: '*_security_report.*'
            }
        }
    }
}
```

### API Integration

```python
import subprocess
import json

def run_aods_scan(apk_path, package_name):
    """Run AODS scan programmatically"""
    cmd = [
        './aods_venv/bin/python', 'dyna.py',
        '--apk', apk_path,
        '--pkg', package_name,
        '--format', 'json',
        '--quiet'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        # Parse JSON output
        return json.loads(result.stdout)
    else:
        raise Exception(f"AODS scan failed: {result.stderr}")

# Usage
findings = run_aods_scan('/path/to/app.apk', 'com.example.app')
print(f"Found {len(findings['vulnerabilities'])} vulnerabilities")
```

## 🔐 Security Considerations

### Safe Usage Guidelines

1. **Isolated Environment**: Run AODS in isolated environments when analyzing untrusted APKs
2. **Network Isolation**: Consider network isolation for dynamic analysis
3. **Resource Limits**: Set appropriate memory and CPU limits
4. **Cleanup**: Clean workspace directories after analysis

### Enterprise Deployment

```bash
# Docker-based enterprise deployment
docker run -d \
  --name aods-enterprise \
  --memory 8g \
  --cpus 4 \
  -v /secure/workspace:/app/workspace \
  -v /apk/storage:/app/apks:ro \
  aods-framework:enterprise

# Kubernetes deployment
kubectl apply -f deployments/aods-enterprise.yaml
```

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Development Setup

```bash
# Clone for development
git clone <repository-url>
cd automated-owasp-dynamic-scan-dyna_update

# Install development dependencies
pip install -r requirements/dev.txt

# Run tests
python -m pytest tests/

# Code quality checks
flake8 core/ plugins/
black core/ plugins/
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Documentation**: Check the `docs/` directory for detailed documentation
- **Issues**: Report bugs and request features through GitHub issues
- **Community**: Join our community discussions
- **Professional Support**: Enterprise support available for organizations

## 🚀 Roadmap

### Upcoming Features
- iOS application support
- Cloud-native deployment options
- Advanced ML model training
- Real-time vulnerability feeds
- Integration with more security tools

### Version History
- **v2.0**: Current version with ML enhancement and parallel processing
- **v1.5**: Added dynamic analysis capabilities
- **v1.0**: Initial release with static analysis

---

**Happy Scanning! 🛡️**

For more detailed information, refer to the documentation in the `docs/` directory or visit our project homepage.