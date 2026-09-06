FROM python:3.11-slim

WORKDIR /app

RUN pip install poetry

COPY pyproject.toml poetry.lock ./

RUN poetry config virtualenvs.create false \
    && poetry install --no-root --only main

COPY . .

RUN poetry install --only main

ENTRYPOINT ["osint"]