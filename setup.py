from setuptools import setup, find_packages

setup(
    name="safepaste-enterprise",
    version="3.4.1",
    description="Zero-trust DLP for Linux pipelines — 35+ threat patterns across 8+ countries",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="LogicGrid AI, LLC",
    author_email="support@logicgrid.ai",
    url="https://safepaste.app",
    packages=find_packages(),
    python_requires=">=3.9",
    extras_require={"redis": ["redis>=4.0"]},
    entry_points={"console_scripts": ["safepaste=safepaste.__main__:main"]},
    license="Proprietary",
    keywords="ai-safety api-keys cli dlp pii redaction security zero-trust",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
