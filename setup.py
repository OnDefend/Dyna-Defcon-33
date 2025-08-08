#!/usr/bin/env python3
"""
AODS (Automated OWASP Dynamic Scan) Framework Setup
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements/base.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="aods-framework",
    version="2.0.0",
    author="AODS Development Team",
    author_email="dev@aods.org",
    description="Enterprise-Grade Android Security Analysis Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/aods/aods-framework",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    extras_require={
        "dev": ["pytest", "black", "flake8", "mypy"],
        "docs": ["mkdocs", "mkdocs-material"],
    },
    entry_points={
        "console_scripts": [
            "aods=dyna:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
