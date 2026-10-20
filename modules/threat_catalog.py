"""Which threats can be fired on demand, and the XSIAM analytic each one targets.

Every module keeps generating ALL of its threats during long-running sessions; that is
what gives XSIAM a realistic mix. On-demand firing (the dashboard's Fire Individual
Threat panel, the MCP fire_event tool, the CLI "specific threat" menu) is narrower: it
offers only threats built to trigger a native XSIAM analytics alert (XDR Analytics or
Analytics BIOC), because firing anything else on demand gives the operator nothing to
look for.

A module declares its mapping in one of two ways:

  get_threat_info()   list of {"event", "analytic", "xsiam_alert", ...} — the firewall
                      modules, whose threat tables already carry these fields
  ANALYTIC_ALERTS     {threat_key: "alert name"} — every other module; a threat absent
                      from the dict is background-only

A module with neither (or an empty ANALYTIC_ALERTS) offers nothing on demand. Proofpoint,
Infoblox and Apache httpd are in that position: Cortex publishes no analytics for those
data sources, and none has ever fired from them in the tenant — their alerts come from
correlation rules and threat intel.

Alert names are the ones the tenant actually raises where that has been observed (the
tenant often fires a named variation, e.g. "Suspicious port scan" for Port Scan), and
the published Cortex name otherwise.
"""

_NON_ANALYTIC_PREFIX = "[Non-Analytic] "


def analytic_threats(module):
    """[{"event": key, "alert": name}, ...] for the module's on-demand threats,
    in the module's own threat order."""
    info_fn = getattr(module, "get_threat_info", None)
    if callable(info_fn):
        return [{"event": i["event"], "alert": i["xsiam_alert"]}
                for i in info_fn() if i.get("analytic") and i.get("xsiam_alert")]
    table = getattr(module, "ANALYTIC_ALERTS", None) or {}
    names_fn = getattr(module, "get_threat_names", None)
    names = names_fn() if callable(names_fn) else list(table)
    return [{"event": n, "alert": table[n]} for n in names if n in table]


def canonical_name(module, name):
    """Map a legacy threat name to its current key: strips the retired
    '[Non-Analytic] ' display prefix and applies a module's rename table."""
    if not name:
        return name
    if name.lower().startswith(_NON_ANALYTIC_PREFIX.lower()):
        name = name[len(_NON_ANALYTIC_PREFIX):]
    renamed = getattr(module, "_RENAMED_THREATS", None) or {}
    new = renamed.get(name.upper())
    if new:
        return new.lower() if name == name.lower() else new
    return name


def resolve_on_demand(module, name):
    """(event_key, alert) if `name` may be fired on demand, else None. `event_key` is
    the module's own spelling, ready to pass as scenario_event. Matching is
    case-insensitive (modules differ: aws uses UPPER keys, okta lower)."""
    want = (canonical_name(module, name) or "").lower()
    for t in analytic_threats(module):
        if t["event"].lower() == want:
            return t["event"], t["alert"]
    return None
