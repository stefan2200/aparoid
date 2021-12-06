"""Install packages as defined in this file into the Python environment."""
from setuptools import setup, find_packages

from pathlib import Path

# The version of this tool is based on the following steps:
# https://packaging.python.org/guides/single-sourcing-package-version/
VERSION = {}

with open("./__init__.py") as fp:
    # pylint: disable=W0122
    exec(fp.read(), VERSION)


def get_file(location):
    with open(location, "r") as readf:
        contents = readf.read()
    return contents.strip()


setup(
    name="aparoid",
    author="Stefan2200",
    author_email="stefan@stefanvlems.nl",
    url="https://github.com/stefan2200/aparoid",
    description="Framework for Android application security analysis",
    version=VERSION.get("__version__", "0.0.0"),
    packages=find_packages(where=".", exclude=["tests"]),
    long_description=get_file('README.md'),
    long_description_content_type='text/markdown',
    install_requires=get_file('requirements.txt').split("\n"),
    include_package_data=True,
    package_data={"aparoid": ["*"]},
    entry_points={
        "console_scripts": [
            "aparoid=aparoid.main:start",
        ]
    },
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Topic :: Security",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Topic :: Software Development :: Disassemblers",
        "Topic :: Utilities",
    ],
)
