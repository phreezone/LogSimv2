"""Cloud account / project ids: the .env values that replace PLACEHOLDER_* in config.json.

config.json carries PLACEHOLDER_AWS_ACCOUNT_ID, PLACEHOLDER_GCP_PROJECT_ID and
PLACEHOLDER_GCP_PROJECT_NUMBER inside account ids, ARNs, service-account emails and
resource paths. log_simulator.py and dashboard/app.py replace them in the raw config
text before parsing, from the matching .env variable.

Two things used to go wrong:

* The lookup was case-sensitive. Windows environment names are not, so a .env line
  `aws_account_id=...` worked there, but under Docker/Linux `os.getenv("AWS_ACCOUNT_ID")`
  missed it and the placeholder stayed literal.
* With the variable unset (the normal case for someone without native AWS/GCP, whose
  events go out through the Cribl fallback), every CloudTrail record carried the text
  PLACEHOLDER_AWS_ACCOUNT_ID as its accountId and inside every ARN.

`env_get` finds a variable under any letter case, and an unset id now falls back to a
fixed, well-formed fake value (12-digit account / project number, valid project id), so
the logs look real and stay stable from run to run. The fallbacks are never treated as
a configured cloud: `is_fallback` lets transport keep S3 / Pub/Sub "not configured".
"""
from __future__ import annotations

import os
from typing import Callable, Dict, Optional

# placeholder in config.json -> (.env variable, fallback when unset)
PLACEHOLDERS: Dict[str, tuple] = {
    "PLACEHOLDER_AWS_ACCOUNT_ID":     ("AWS_ACCOUNT_ID",     "418263950174"),
    "PLACEHOLDER_GCP_PROJECT_ID":     ("GCP_PROJECT_ID",     "examplecorp-sim-prod"),
    "PLACEHOLDER_GCP_PROJECT_NUMBER": ("GCP_PROJECT_NUMBER", "583920174625"),
}

FALLBACK_VALUES = frozenset(fb for _, fb in PLACEHOLDERS.values())


def env_get(name: str, default: str = "") -> str:
    """os.getenv(name), but also matching the name in any letter case.

    Exact match first; otherwise the first non-empty variable whose name equals `name`
    ignoring case (a .env written as `aws_account_id=` under Docker/Linux)."""
    v = os.environ.get(name)
    if v and v.strip():
        return v.strip()
    want = name.lower()
    for k, v in os.environ.items():
        if k.lower() == want and v and v.strip():
            return v.strip()
    return default


def resolve() -> Dict[str, tuple]:
    """{placeholder: (value, from_env)} for every placeholder."""
    out = {}
    for ph, (var, fallback) in PLACEHOLDERS.items():
        val = env_get(var)
        out[ph] = (val, True) if val else (fallback, False)
    return out


def aws_account_id(default: Optional[str] = None) -> str:
    """AWS_ACCOUNT_ID from the environment (any case), else the fallback (or `default`)."""
    var, fallback = PLACEHOLDERS["PLACEHOLDER_AWS_ACCOUNT_ID"]
    return env_get(var) or (default if default is not None else fallback)


def substitute(config_str: str, warn: Optional[Callable[[str], None]] = None) -> str:
    """Replace every PLACEHOLDER_* in raw config text; `warn` is told about fallbacks."""
    for ph, (val, from_env) in resolve().items():
        if ph not in config_str:
            continue
        config_str = config_str.replace(ph, val)
        if not from_env and warn:
            warn(f"--- NOTE: {PLACEHOLDERS[ph][0]} not set in .env; {ph} values use "
                 f"the stand-in '{val}'. ---")
    return config_str


def is_fallback(value) -> bool:
    """True for a stand-in id, which must not count as a configured AWS/GCP target."""
    return isinstance(value, str) and value.strip() in FALLBACK_VALUES
