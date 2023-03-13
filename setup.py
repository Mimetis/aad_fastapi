"""Python setup.py for aad_fastapi package"""
import io
import os

from setuptools import find_packages, setup


def read(*paths, **kwargs):
    content = ""
    with io.open(
            os.path.join(os.path.dirname(__file__), *paths),
            encoding=kwargs.get("encoding", "utf8"),
    ) as open_file:
        content = open_file.read().strip()
    return content


def read_requirements(path):
    return [
        line.strip()
        for line in read(path).split("\n")
        if not line.startswith(('"', "#", "-", "git+"))
    ]


setup(
    name="aad_fastapi",
    version=read("aad_fastapi", "VERSION"),
    description="aad_fastapi middleware backend helper for bearer verification with FastAPI and Azure AD",
    keywords=["python"],
    author="Sébastien Pertus, Dor Lugasi-Gal",
    author_email="sebastien.pertus@gmail.com, dorlugasigal@gmail.com",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    url="https://github.com/Mimetis/aad_fastapi",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    project_urls={
        "Homepage": "https://github.com/Mimetis/aad_fastapi",
        "Bug Tracker": "https://github.com/Mimetis/aad_fastapi/issues",
    },
    packages=find_packages(exclude=["tests", ".github"]),
    install_requires=read_requirements("requirements.txt"),
    extras_require={"test": read_requirements("requirements-test.txt")},
    python_requires=">=3.7",
)
