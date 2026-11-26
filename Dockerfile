# Multi-stage runtime image: build/install dependencies separately, and do not
# ship pytest or the development toolchain in the application image.
FROM python:3.11-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /opt/venv

WORKDIR /build
COPY requirements.txt requirements-postgres.txt requirements-portal.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-postgres.txt -r requirements-portal.txt

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --disabled-password --gecos "" paari

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY app/ ./app/
COPY alembic/ ./alembic/
COPY alembic.ini ./
COPY schemas/ ./schemas/
COPY sdk/ ./sdk/
COPY web/ ./web/
COPY README.md ./

RUN mkdir -p /app/secrets /app/data \
    && chown -R paari:paari /app/secrets /app/data
USER paari

EXPOSE 8000

# Migrations are a one-off deployment job, never an API replica startup task.
# The sandbox may use a local signer; production must provision a managed KMS/HSM.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
