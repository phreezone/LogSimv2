FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer-cached unless requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY log_simulator.py .
COPY modules/ ./modules/

# config.json and .env are mounted at runtime — not baked into the image
CMD ["python", "-u", "log_simulator.py"]
