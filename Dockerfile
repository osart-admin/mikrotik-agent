FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates iputils-ping \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app

# Last, so a new version per build does not invalidate the pip layer.
ARG APP_VERSION=unknown
ARG APP_BUILT=
ENV APP_VERSION=$APP_VERSION APP_BUILT=$APP_BUILT

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
