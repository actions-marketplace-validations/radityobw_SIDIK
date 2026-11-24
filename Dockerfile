FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/radityobw/SIDIK" \
      org.opencontainers.image.title="SIDIK" \
      org.opencontainers.image.description="Lightweight Offline Python SAST & Multi-Manifest OSV SCA Security Analyzer" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY sidik ./sidik

RUN pip install --no-cache-dir . \
    && adduser --disabled-password --gecos "" sidik

WORKDIR /workspace
USER sidik

ENTRYPOINT ["sidik"]
CMD ["--help"]
