from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = f.read().splitlines()

setup(
    name="professor-osint",
    version="1.0.0",
    author="Rokibul",
    author_email="rokibul@example.com",
    description="Advanced Data Breach & Intelligence Gathering Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rokibul/Databreach-Finder",
    packages=find_packages(include=["professor_osint", "professor_osint.*"]),
    install_requires=requirements,
    extras_require={
        # Heavyweight deep-social-media extraction deps (Social X-Ray engine).
        # Kept optional so the core install stays light:
        #   pip install professor-osint[social]
        "social": ["yt-dlp"],
    },
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "professor-osint=professor_osint.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
