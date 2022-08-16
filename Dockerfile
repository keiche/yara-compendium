FROM ubuntu:20.04

WORKDIR /app

ENV YARA_VERSION="3.9.0-1"

# Dependencies
RUN apt update -y && \
    apt install git python3 python3-pip python3-yara libyara3 yara=${YARA_VERSION} -y && \
    pip3 install --upgrade pip build setuptools

# Install app
COPY pyproject.toml README.md LICENSE  ./
ADD etc ./etc
ADD compendium ./compendium
RUN git config --global --add safe.directory '*' && \
    pip3 install .

ENTRYPOINT ["yara-compendium"]
