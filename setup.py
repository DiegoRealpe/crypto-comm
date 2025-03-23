from setuptools import find_packages, setup

setup(
    name="crypto_app",
    version="1.0",
    author="Diego Realpe Tobar",
    author_email="diegort@iastate.edu",
    description="Cybersecurity Exercise for ComS 559",
    url="https://github.com/DiegoRealpe/crypto-comms",
    packages=find_packages(),
    install_requires=[
        "cryptography==39.0.1",
        "pycryptodome==3.17",
    ],
    scripts=[
        "bin/crypto-generate-keys",
        "bin/crypto-encrypt",
        "bin/crypto-decrypt",
        "bin/crypto-server",
        "bin/crypto-client",
    ],
    entry_points={
        "console_scripts": [
            "crypto-generate-keys=crypto_app.main:generate_keys",
            "crypto-encrypt=crypto_app.main:encrypt",
            "crypto-decrypt=crypto_app.main:decrypt",
            "crypto-server=crypto_app.main:run_server",
            "crypto-client=crypto_app.main:run_client",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    include_package_data=True,
)
