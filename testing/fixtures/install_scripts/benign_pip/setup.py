from setuptools import setup

# Harmless pip package — declarative metadata only, no install-time hooks.
setup(
    name="benign-pip-fixture",
    version="1.0.0",
    description="Harmless pip package.",
    packages=["benign_fixture"],
)
