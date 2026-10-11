# Multi-stage Dockerfile for Sentinel
# Stage 1: Build Frontend Assets
FROM node:20-alpine AS frontend-builder
WORKDIR /build

# Enable pnpm via corepack
RUN corepack enable && corepack prepare pnpm@latest --activate

# Install frontend dependencies
COPY frontend/package.json frontend/pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile || pnpm install

# Copy frontend source and build
COPY frontend/ ./
ENV VITE_API_BASE_URL=/
RUN pnpm build

# Stage 2: Python Backend Runtime
FROM python:3.12-slim
WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Install python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application directories
COPY backend /app/backend
COPY seed /app/seed
COPY scripts /app/scripts
COPY docs /app/docs

# Copy built frontend SPA assets from stage 1
COPY --from=frontend-builder /build/dist /app/frontend/dist

# Create storage directories
RUN mkdir -p /app/data /app/reports

EXPOSE 8000

CMD ["sh", "-c", "python -m seed.seed --if-empty && uvicorn backend.app.main:app --host 0.0.0.0 --port 8000"]
