from setuptools import setup, find_packages

setup(
    name="llm-pr-reviewer",
    version="1.0.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.12",
    install_requires=[
        "anthropic>=0.34.0",
        "httpx>=0.27.0",
        "pylint>=3.2.0",
        "bandit>=1.7.9",
        "safety>=3.2.0",
        "pyyaml>=6.0.1",
    ],
    extras_require={
        "dev": ["pytest>=8.0", "pytest-cov>=5.0"],
    },
)
