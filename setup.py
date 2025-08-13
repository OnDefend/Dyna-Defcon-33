#!/usr/bin/env python3
"""
AODS (Automated OWASP Dynamic Scan) Framework Setup
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="aods-framework",
    version="2.0.0",
    author="AODS Development Team",
    author_email="contact@isi-ttusds.com",
    description="Enterprise-Grade Android Security Analysis Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/OnDefend/Dyna-Defcon-33",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9", 
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=22.0.0", 
            "flake8>=5.0.0",
            "mypy>=1.0.0",
            "coverage>=6.0.0"
        ],
        "analysis": [
            "frida>=16.0.0",
            "mitmproxy>=9.0.0",
            "objection>=1.11.0"
        ],
        "ml": [
            "scikit-learn>=1.3.0",
            "tensorflow>=2.13.0",
            "numpy>=1.24.0"
        ],
        "docs": [
            "mkdocs>=1.5.0",
            "mkdocs-material>=9.0.0"
        ],
    },
    entry_points={
        "console_scripts": [
            "aods=dyna:main",
            "dyna=dyna:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
