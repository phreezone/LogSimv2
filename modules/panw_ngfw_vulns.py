"""Palo Alto Networks NGFW — Vulnerabilities (on-demand, one entry per signature).

A thin companion to `panw_ngfw`: it carries NO background traffic. Its only job is to list every
tenant-confirmed vulnerability signature the PAN NGFW generator knows as its own entry in the
dashboard's Fire Individual Threat dropdown (and in the MCP `fire_event` tool and the CLI
specific-threat menu), so one exact signature can be fired ad hoc and the native PAN NGFW alert
named `<Name>(<ID>)` can be looked for.

  * One entry per signature, `vuln_<id>`; the dropdown groups it under the alert it targets, which
    is the tenant's own alert name, `Name(ID)`.
  * The logs are exactly what `panw_ngfw` builds for that signature: an internet attacker
    (`untrust -> dmz`) trips the signature against a DMZ server with the signature's own action,
    App-ID, port and request path, threat log only, `threat_id` sent as `Name(ID)`.
  * Transport, destination and zone model are `panw_ngfw`'s: the module shares its
    `panw_ngfw_config` block (syslog host/port, `zones`, DMZ servers), so nothing new to configure.
  * In a long-running session it generates nothing (returns None). The same signatures already
    ride the grouped events of the Palo Alto Networks NGFW module; this module exists for
    on-demand use only.

The hand-curated vulnerability signatures that have their own dedicated events in the NGFW module
(Log4j, Dnsmasq, IAX2, the PHP/Moxa/TRENDnet exploits, the scanner and RPC detections) are not
repeated here; only the tenant-confirmed catalogue is.
"""
import re

try:
    from modules import panw_ngfw as _panw
except ImportError:  # run from inside modules/
    import panw_ngfw as _panw

NAME = "Palo Alto Networks NGFW Vulnerabilities"
DESCRIPTION = ("On-demand only: one entry per tenant-confirmed PAN NGFW vulnerability signature, fired "
               "as a threat log from an internet attacker to a DMZ server (alert named Name(ID)). "
               "Generates nothing in a long-running session.")
XSIAM_PARSER = _panw.XSIAM_PARSER
CONFIG_KEY = _panw.CONFIG_KEY      # shares panw_ngfw_config: transport, syslog host, zones, DMZ servers

last_threat_event_time = 0


def _build():
    """[{event, id, key, name, severity, category}] for every vulnerability-subtype tenant signature,
    ordered by name then ID."""
    rows = []
    for t in _panw._TENANT_SIGS:
        sid, name, severity, category, subtype = t[0], t[1], t[2], t[3], t[4]
        if subtype != "vulnerability":
            continue
        rows.append({"event": f"vuln_{sid}", "id": sid, "key": f"t{sid}", "name": name,
                     "severity": severity, "category": category})
    rows.sort(key=lambda r: (r["name"].lower(), r["id"]))
    return rows


_SIGNATURES = _build()
_BY_EVENT = {r["event"]: r for r in _SIGNATURES}
# threat_catalog.canonical_name() maps these spellings to the entry key (upper-cased lookup), so the
# MCP fire_event tool and the dashboard accept a bare signature ID ("97710") or "t97710" as well.
_RENAMED_THREATS = {**{str(r["id"]): r["event"] for r in _SIGNATURES},
                    **{f"T{r['id']}": r["event"] for r in _SIGNATURES}}


def _alert_name(row):
    return f"{row['name']}({row['id']})"


def get_threat_names():
    return [r["event"] for r in _SIGNATURES]


def get_threat_info():
    """Per-signature metadata for the on-demand listing. Every entry is analytic (a native PAN NGFW
    alert is the point); weight 0 because nothing here runs in the background."""
    return [{"event": r["event"], "display_name": _alert_name(r), "analytic": True,
             "xsiam_alert": _alert_name(r), "weight": 0, "severity": r["severity"],
             "category": r["category"]} for r in _SIGNATURES]


def _resolve(name):
    """`vuln_<id>`, `<id>` or `t<id>` (any case) -> its signature row, else None."""
    m = re.fullmatch(r"(?:vuln_|t)?(\d+)", str(name or "").strip().lower())
    return _BY_EVENT.get(f"vuln_{m.group(1)}") if m else None


def generate_log(config, scenario=None, threat_level="Realistic", benign_only=False,
                 context=None, scenario_event=None):
    """Fire the named signature and return (logs, event). With no event (the background loop) there
    is nothing to generate."""
    row = _resolve(scenario_event)
    if row is None:
        return None
    return _panw.tenant_sig_event(config, row["key"]), row["event"]
