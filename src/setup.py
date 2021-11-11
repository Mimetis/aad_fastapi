from os import path

from setuptools import setup


def parse_requirements():
    """
    If requirements.txt file exist, parse lines and return a list
    """
    if path.exists("requirements.txt"):
        with open("requirements.txt") as reqFile:
            return list(reqFile.read().splitlines())
    else:
        return []


setup(
    name="aad",
    package_dir={"": "src"},
    packages=["aad"],
    version="0.0.1",
    long_description="**aad** helper for bearer verification with FastAPI and easier "
    "client mechanism to get a token from Azure AD",
    long_description_content_type="text/markdown",
    keywords=["python"],
    install_requires=parse_requirements(),
    classifiers=[
        "Development Status :: Beta",
        "Programming Language :: Python :: 3.8",
    ],
)
