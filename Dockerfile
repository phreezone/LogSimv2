FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer-cached unless requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code and default config. log_simulator.py imports integrations/
# (native/Cribl transports) at startup, and starts dashboard/app.py (the web UI and
# the API the MCP server drives).
COPY log_simulator.py config.json ./
COPY modules/ ./modules/
COPY integrations/ ./integrations/
COPY dashboard/ ./dashboard/

# Dashboard / API. It binds 0.0.0.0 (DASHBOARD_HOST) so the published port works.
ENV DASHBOARD_PORT=5000
EXPOSE 5000

# With a console (docker run -it / compose attach) the interactive menu runs; without
# one LogSim runs headless and is driven from the dashboard.
CMD ["python", "-u", "log_simulator.py"]
