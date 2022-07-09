FROM ubuntu:22.04

WORKDIR /app

ENV PATH="/root/.poetry/bin:${PATH}"
ENV YARA_VERSION="4.1.3-1build1"

COPY yara_compendium.py pyproject.toml README.md LICENSE  ./
ADD etc ./etc

RUN apt update -y && apt upgrade -y && \
    apt install curl gcc git make python3 python3-dev python3-distutils yara=${YARA_VERSION} -y && \
    curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3 - && \
    poetry update && \
    poetry install

ENTRYPOINT ["poetry", "run", "yara_compendium"]
CMD ["--help"]