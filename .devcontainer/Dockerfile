# [Choice] Ubuntu version (use hirsuite or bionic on local arm64/Apple Silicon): hirsute, focal, bionic
ARG VARIANT=focal
FROM mcr.microsoft.com/vscode/devcontainers/base:${VARIANT}

# replace vscode user 
ARG USERNAME=alex
ARG VSC_CODE_NAME=vscode
RUN usermod -m -d /home/$USERNAME $VSC_CODE_NAME
RUN groupmod -n $USERNAME $VSC_CODE_NAME
RUN usermod -l $USERNAME $VSC_CODE_NAME

# Finish setting up $USERNAME (sudo, no password etc ...)
RUN echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# Install some basics packages
RUN apt-get update && \ 
    apt-get upgrade -y && \
    apt-get install -y sudo git curl wget make procps python3-pip unzip pandoc jq black

# Install Azure CLI
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Python things: update pip, install az-cli
RUN python3 -m pip install pip --upgrade

# Install required librairies
COPY ./requirements.txt /home/$USERNAME/

RUN pip install -r /home/$USERNAME/requirements.txt