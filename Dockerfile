# syntax=docker/dockerfile:1

FROM python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534 AS base
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.lock ./requirements.lock
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

# --- target: the single-worker player-facing container -----------------------
FROM base AS target
COPY app ./app
RUN useradd -m -u 10001 appuser && mkdir -p /data && chown -R appuser:appuser /data
USER appuser
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

# --- tooling: tests / reference solution / grader / calibration --------------
FROM base AS tooling
COPY requirements-tooling.lock ./requirements-tooling.lock
RUN pip install --no-cache-dir --require-hashes -r requirements-tooling.lock
COPY app ./app
COPY evaluation ./evaluation
COPY tests ./tests
COPY PLAYER.md ./PLAYER.md
CMD ["python", "-m", "pytest", "tests/", "-q"]
