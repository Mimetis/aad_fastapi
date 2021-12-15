from setuptools import setup
import pathlib
import os


def get_description() -> str:
    dir = pathlib.Path(__file__).parent.parent.absolute()
    readme_path = os.path.join(dir, "README.md")
    with open(readme_path, "r", encoding="utf-8") as fh:
        return fh.read()


setup(
    name="aad_fastapi",
    package_dir={"": "src"},
    packages=["aad_fastapi"],
    version="1.0.0a1",
    author="Sébastien Pertus",
    license="MIT",
    author_email="sebastien.pertus@gmail.com",
    description="**aad_fastapi** middleware backend helper for bearer verification with FastAPI and Azure AD",
    long_description=get_description(),
    long_description_content_type="text/markdown",
    keywords=["python"],
    url="https://github.com/Mimetis/aad_fastapi",
    project_urls={
        "Bug Tracker": "https://github.com/Mimetis/aad_fastapi/issuers",
    },
    install_requires=[
        "Authlib==0.15.4",
        "msal==1.12.0",
        "azure-identity==1.6.0",
        "azure-keyvault==4.1.0",
        "azure-keyvault-certificates==4.2.1",
        "fastapi==0.68.1",
        "aiohttp==3.7.4.post0",
    ],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
)
