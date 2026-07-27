from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="secretscope",
    version="1.0.0",
    description="A pure-Python secret & credential leak scanner with optional Claude AI risk analysis.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Amir",
    license="MIT",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.9",
    extras_require={
        "ai": ["anthropic>=0.34.0"],
    },
    entry_points={
        "console_scripts": [
            "secretscope=secretscope.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Environment :: Console",
    ],
)
