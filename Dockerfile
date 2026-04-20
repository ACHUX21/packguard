FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE run.py ./
COPY src ./src
COPY config ./config
COPY data ./data
COPY examples ./examples

RUN python -m pip install --upgrade pip && \
    pip install .[yaml]

ENTRYPOINT ["packguard"]
CMD ["doctor"]
