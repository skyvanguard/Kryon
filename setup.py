"""
Setup script for Skynet CTF Framework.
"""
from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="skynet-ctf",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="CTF Agent Framework with RAG powered by Claude",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/skynet",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "anthropic>=0.40.0",
        "openai>=1.0.0",
        "chromadb>=0.4.0",
        "sentence-transformers>=2.2.0",
        "numpy>=1.24.0",
        "pandas>=2.0.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "skynet=skynet.cli.main:main",
        ],
    },
)
