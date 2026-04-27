FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DASHBOARD_HOST=0.0.0.0 \
    DASHBOARD_PORT=5000

# Install dependencies first (layer-cached unless requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code, modules, dashboard, and default config
COPY log_simulator.py .
COPY modules/ ./modules/
COPY dashboard/ ./dashboard/
COPY config.json .

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/', timeout=3).status==200 else 1)" || exit 1

CMD ["python", "-u", "dashboard/app.py"]
