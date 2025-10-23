FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Setup py4web apps folder with built-in apps
RUN py4web setup apps --yes

ENV DATABASE_URL="sqlite://manager.db" \
    REDIS_HOST="redis" \
    REDIS_PORT="6379" \
    REDIS_PASSWORD="" \
    REDIS_DB="0" \
    SESSION_SECRET="" \
    PY4WEB_APPS="/app"

EXPOSE 8000

CMD ["python", "simple_app.py"]