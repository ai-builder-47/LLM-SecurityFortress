from setuptools import setup, find_packages

setup(
    name="llm-securityfortress",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "numpy>=1.21.0",
    ],
    python_requires=">=3.8",
    author="Security Research Team",
    description="Multi-Scenario LLM Security Evaluation Platform",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/wuyv-sur/LLM-SecurityFortress",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
