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
    python_requires=">=3.10",
    include_package_data=True,
)
