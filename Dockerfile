FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer-cached unless requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and default config
COPY log_simulator.py .
COPY modules/ ./modules/
COPY config.json .

CMD ["python", "-u", "log_simulator.py"]
