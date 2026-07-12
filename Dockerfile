# Stage 1: Build Vue frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --network-timeout=120000 || npm ci --registry=https://registry.npmmirror.com --network-timeout=120000
COPY frontend/index.html frontend/vite.config.js frontend/jsconfig.json ./
COPY frontend/src/ src/
COPY frontend/public/ public/
RUN npm run build

# Stage 2: Python runtime with Playwright
FROM python:3.12-slim-bookworm

# ── 清华镜像加速 apt ──
RUN sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources \
    && sed -i 's|security.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources

# System deps for Playwright Chromium + CJK fonts
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxrandr2 libgbm1 \
    libpango-1.0-0 libcairo2 libasound2 libxdamage1 \
    libxfixes3 libxshmfence1 libx11-xcb1 \
    fonts-noto-cjk \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# ── Create non-root user ──────────────────────────────────────
RUN useradd --system --uid 10001 --create-home appuser

WORKDIR /app

# Python dependencies (清华镜像)
COPY requirements.txt .
RUN pip install --no-cache-dir \
    -i https://pypi.tuna.tsinghua.edu.cn/simple \
    --trusted-host pypi.tuna.tsinghua.edu.cn \
    -r requirements.txt \
    && PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers \
       PLAYWRIGHT_DOWNLOAD_HOST=https://npmmirror.com/mirrors/playwright/ \
       playwright install chromium \
    && chown -R appuser:appuser /opt/playwright-browsers

# Application source
COPY extract.py export.py scheduler.py ./
COPY common/ common/
COPY extractor/ extractor/
COPY backend/ backend/
COPY docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh

# Built frontend from stage 1
COPY --from=frontend-builder /app/frontend/dist frontend/dist

# Create data directories with correct ownership
RUN mkdir -p /app/data/auth /app/data/database /app/data/browser_profile \
    /app/data/media /app/data/exports /app/data/logs \
    && chown -R appuser:appuser /app

# Switch to non-root
USER appuser

# Environment defaults
ENV APP_ENV=production \
    MODE=all \
    HEADLESS=true \
    SCRAPER_INCREMENTAL=true \
    SCRAPER_FILTER="" \
    SCRAPER_SCHEDULE="" \
    COOKIE_SECURE=false \
    PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers \
    PYTHONUNBUFFERED=1

EXPOSE 8000

ENTRYPOINT ["bash", "docker-entrypoint.sh"]
