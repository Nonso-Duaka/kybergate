# Build stage: compile the Kyber reference code and prove it is correct.
FROM python:3.13-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc make libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY . .
RUN make clean all && python -m kybergate.kat && python -m pytest -q --ignore=tests/test_interop.py

# Runtime stage: no compiler, no test tools.
FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -m kg && mkdir instance && chown kg instance
COPY --from=build /src/kybergate ./kybergate
USER kg
ENV COOKIE_SECURE=1 KYBERGATE_DB=/app/instance/kybergate.db
EXPOSE 8000
# Handshake keys live in SQLite, so several workers are safe.
CMD ["sh", "-c", "uvicorn kybergate.web.asgi:app --host 0.0.0.0 --port ${PORT:-8000} --workers 2 --proxy-headers"]
