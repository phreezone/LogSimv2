# Extensibility: Adding a New Module

Adding a new log source is simple:

1. Create a new file (e.g., my_new_firewall.py) in the modules/ directory.
2. At the top of the file, define the module's "contract":
   ```python
   NAME = "My New Firewall"
   DESCRIPTION = "Simulates my new firewall logs."
   XSIAM_VENDOR = "MyVendor"
   XSIAM_PRODUCT = "MyProduct"
   CONFIG_KEY = "my_new_firewall_config"  # Must match a key in config.json
   ```

3. Create the main generate_log function with the standard signature:
   ```python
   def generate_log(config, scenario=None, threat_level="Realistic", benign_only=False):
       if benign_only:
           # return generate_benign_log(config)
           pass

       if scenario:
           # return generate_scenario_log(config, scenario)
           pass

       # ... logic to generate a random benign or threat log ...
       log_string = "my log line"
       return log_string
   ```

4. Add a new section to `config.json` for your module's non-secret settings (hostname, port, event mix, simulated environment data):
   ```json
   "my_new_firewall_config": {
     "transport": "syslog",
     "syslog_port": 1520,
     "hostname": "MY-FW-01"
   }
   ```

   If your module requires transport credentials or API keys (e.g., an HTTP Collector URL and key), add those to `.env` and reference them via `http_collectors` in `config.json` — never put secrets directly in `config.json`. See [Configuration](configuration.md#b-transport-configuration) for the full `http_collectors` schema.

5. Run log_simulator.py. Your new module will automatically appear in the list.
