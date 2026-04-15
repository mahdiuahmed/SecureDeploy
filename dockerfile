# ─── Stage 1: Build dependencies ───
FROM python:3.12-slim AS builder

# Patch OS packages to clear Trivy HIGH/CRITICAL CVEs (unfixed base image vulns)
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Install build deps only in builder stage
COPY requirements.txt .
RUN pip install --user --no-cache-dir --no-warn-script-location -r requirements.txt

# ─── Stage 2: Runtime ───
FROM python:3.12-slim AS runtime

# Patch OS packages to clear Trivy HIGH/CRITICAL CVEs (unfixed base image vulns)
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# Create non-root user (defence-in-depth)
RUN groupadd -r app && useradd -r -g app -u 1000 app

WORKDIR /app

# Copy only installed packages from builder
COPY --from=builder /root/.local /home/app/.local
ENV PATH=/home/app/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Copy application code
COPY --chown=app:app app.py .

# Drop root privileges
USER app

EXPOSE 8080

# Health check baked into image
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health').read()" || exit 1

CMD ["python", "app.py"]
