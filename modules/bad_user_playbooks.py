"""Bad User use-case playbooks: a story told in order instead of a random mix.

Without a playbook, Bad User drives every module on its own clock and fires a random
allowed threat from each. The case is wide but has no narrative: an AWS snapshot, a
Windows lockout and a Zscaler DLP hit arrive unrelated and in any order.

A playbook is one use case as an ordered list of steps. Each step names a module and one of
its threats and says how long after the previous step it happens. Every step runs as the
target, through the same path the random mix uses (the target's focus user, the
`bad_user_policy` allow-list and the record filter), so the user, the computer's internal IP
and the office egress IP stay the same all the way through. The module workers still send
the target's benign traffic underneath; with a playbook running they fire no random threats.

Timing. Each step's `gap` is a nominal (min, max) in seconds after the previous step. The
run's duration decides the pace: the whole playbook is stretched or squeezed to finish at
about 85% of the duration (see `plan`), so a 15-minute run and a 60-minute run tell the same
story at different speeds. After the last step the module workers carry on with benign
traffic until the duration ends.

A step is skipped, with the reason shown, when its module is not running for this target (not
selected, AWS without an `aws_iam_user`, Windows on a Mac or Linux computer) or its threat is
not available. Steps are skipped instead of failing the run, and a skipped step adds no gap.

Some generators pick an outside operator a share of the time (ESXi `guest_ops_exec` does 40%
of the time) and the record filter drops those records, so the runner tries a step up to
RETRIES times before it records "no output".

Adding a playbook: add an entry to PLAYBOOKS, then run

    python -m modules.bad_user_playbooks

which checks every step against the modules' real threat names and the Bad User allow-list.
"""

import random

# Pace limits for `plan`: the playbook is scaled to fit the run, within these bounds.
FIT_FRACTION = 0.85
SCALE_MIN = 0.05
SCALE_MAX = 3.0
MIN_GAP_S = 2.0
RETRIES = 5            # tries per step before it is recorded as "no output"

TACTICS = (
    "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
)


def _s(module, threat, tactic, label, gap):
    """One step: `module` fires `threat` about `gap` seconds after the previous step."""
    return {"module": module, "threat": threat, "tactic": tactic, "label": label,
            "gap": (float(gap[0]), float(gap[1]))}


PLAYBOOKS = {
    "phish_to_exfil": {
        "name": "Phishing click to data theft",
        "summary": "The user's workstation is compromised through a phishing link: command and "
                   "control, credential theft, movement to a coworker's machine, then a large "
                   "upload out.",
        "steps": [
            _s("Proofpoint Email Gateway", "click_permitted", "Initial Access",
               "Clicks a phishing link that the email gateway lets through", (5, 15)),
            _s("Zscaler Web Gateway", "sandbox_threat", "Execution",
               "Downloads a payload that the web gateway sandbox flags", (20, 60)),
            _s("Infoblox NIOS", "C2_BEACON", "Command and Control",
               "Host starts beaconing to a command-and-control domain over DNS", (30, 90)),
            _s("Palo Alto Networks NGFW", "recurring_rare_domain", "Command and Control",
               "Repeated connections to a rare domain", (20, 60)),
            _s("Windows Event Log", "lsass_handle_access", "Credential Access",
               "A process opens a handle to LSASS to read credentials", (60, 180)),
            _s("Windows Event Log", "share_enumeration", "Discovery",
               "Lists the SMB shares of other hosts", (60, 150)),
            _s("Windows Event Log", "psexec_lateral", "Lateral Movement",
               "PsExec to a coworker's machine", (60, 180)),
            _s("Zscaler Web Gateway", "data_exfil", "Exfiltration",
               "Large upload to external storage through the web gateway", (90, 240)),
            _s("Palo Alto Networks NGFW", "large_upload_https", "Exfiltration",
               "The same upload seen as a large HTTPS session on the firewall", (20, 60)),
            _s("Cisco Firepower", "large_file_upload", "Exfiltration",
               "...and on a second firewall", (10, 30)),
        ],
    },
    "insider_data_theft": {
        "name": "Insider data theft",
        "summary": "An employee finds, collects and sends out data they can reach: SharePoint "
                   "and OneDrive discovery, bulk download, external sharing and mail, a bulk S3 "
                   "read, an upload to a personal cloud app, then deleting files.",
        "steps": [
            _s("Office 365 SharePoint Online", "sharepoint_enumeration", "Discovery",
               "Browses SharePoint sites they do not normally use", (10, 30)),
            _s("Office 365 SharePoint Online", "onedrive_enumeration", "Discovery",
               "Browses other people's OneDrive", (20, 60)),
            _s("Office 365 SharePoint Online", "mass_download", "Collection",
               "Downloads a large number of files", (60, 180)),
            _s("Office 365 SharePoint Online", "external_sharing", "Exfiltration",
               "Shares files with an external address", (60, 150)),
            _s("Office 365 DLP", "dlp_sensitive_external", "Exfiltration",
               "Data loss prevention flags sensitive content sent outside", (10, 30)),
            _s("Office 365 Exchange Online", "sensitive_mail_external", "Exfiltration",
               "Emails sensitive content to an outside recipient", (60, 150)),
            _s("aws", "S3_READ_EXFIL_CHAIN", "Collection",
               "Reads a large set of S3 objects", (90, 240)),
            _s("Zscaler Web Gateway", "cloud_app_threat", "Exfiltration",
               "Uploads to a personal cloud storage app", (60, 180)),
            _s("Fortinet FortiGate", "large_upload", "Exfiltration",
               "Large upload seen on the firewall", (10, 30)),
            _s("Office 365 SharePoint Online", "mass_file_deletion", "Defense Evasion",
               "Deletes files to cover their tracks", (120, 300)),
        ],
    },
    "cloud_admin_abuse": {
        "name": "Cloud privilege escalation and persistence",
        "summary": "The user's own cloud account is turned into an administrator across Entra, "
                   "Azure, AWS and GCP: enumerate, escalate, add backdoor credentials, then "
                   "switch the audit logs off.",
        "steps": [
            _s("Azure AD Sign-ins", "powershell_signin", "Initial Access",
               "Signs in with PowerShell instead of a browser", (5, 15)),
            _s("Azure AD Sign-ins", "graph_enumeration", "Discovery",
               "Enumerates the directory through Microsoft Graph", (30, 90)),
            _s("Azure AD Audit", "admin_role_add", "Privilege Escalation",
               "Adds an administrator role", (60, 150)),
            _s("Azure AD Audit", "app_credential_added", "Persistence",
               "Adds a credential to an application", (60, 150)),
            _s("Azure Activity", "wip_role_assignment", "Privilege Escalation",
               "Assigns a powerful role on a subscription", (60, 150)),
            _s("Azure Activity", "wip_keyvault_secret_dump", "Credential Access",
               "Reads every secret in a Key Vault", (60, 150)),
            _s("aws", "IAM_RECON_LIST", "Discovery",
               "Lists IAM users, roles and policies", (60, 150)),
            _s("aws", "ATTACH_ADMIN_POLICY", "Privilege Escalation",
               "Attaches AdministratorAccess", (30, 90)),
            _s("aws", "CREATE_ACCESS_KEY", "Persistence",
               "Creates a new access key", (30, 90)),
            _s("Google Cloud Compute", "IAM_RECON_TESTPERMISSIONS", "Discovery",
               "Probes which permissions the account holds", (60, 150)),
            _s("Google Cloud Compute", "IAM_PRIVILEGE_ESCALATION", "Privilege Escalation",
               "Grants itself an owner role", (30, 90)),
            _s("Google Cloud Compute", "CREATE_SA_KEY", "Persistence",
               "Creates a service account key", (30, 90)),
            _s("Azure Activity", "wip_diagnostic_settings_delete", "Defense Evasion",
               "Deletes Azure diagnostic settings", (90, 240)),
            _s("aws", "STOP_CLOUDTRAIL", "Defense Evasion",
               "Stops CloudTrail logging", (10, 30)),
            _s("Google Cloud Compute", "DISABLE_AUDIT_LOGGING", "Defense Evasion",
               "Disables GCP audit logging", (10, 30)),
        ],
    },
    "ransomware_precursor": {
        "name": "Ransomware precursor",
        "summary": "From the user's machine: discovery, credential theft, spreading with PsExec "
                   "and scheduled tasks, SMB movement, preparing the hypervisor, destroying "
                   "backups, then mass file changes.",
        "steps": [
            _s("Windows Event Log", "share_enumeration", "Discovery",
               "Lists the SMB shares of other hosts", (10, 30)),
            _s("Windows Event Log", "lsass_handle_access", "Credential Access",
               "A process opens a handle to LSASS", (40, 100)),
            _s("Windows Event Log", "psexec_lateral", "Lateral Movement",
               "PsExec to a coworker's machine", (40, 100)),
            _s("Windows Event Log", "remote_scheduled_task", "Execution",
               "Creates a scheduled task on a remote host", (30, 90)),
            _s("Windows Event Log", "malicious_service_install", "Persistence",
               "Installs a service from a user-writable path", (30, 90)),
            _s("Fortinet FortiGate", "smb_new_host_lateral", "Lateral Movement",
               "SMB to a host this machine never talks to", (20, 60)),
            _s("Cisco ASA Firewall", "smb_rare_file_transfer", "Lateral Movement",
               "Unusual SMB file transfer", (20, 60)),
            _s("VMware ESXi", "guest_ops_exec", "Execution",
               "Runs programs inside guest machines from the hypervisor", (60, 150)),
            _s("VMware ESXi", "vm_disk_attach", "Collection",
               "Attaches another VM's disk to read it directly", (30, 90)),
            _s("aws", "BACKUP_VAULT_DELETED", "Impact",
               "Deletes a backup vault", (60, 150)),
            _s("aws", "EBS_SNAPSHOT_DELETION", "Impact",
               "Deletes EBS snapshots", (20, 60)),
            _s("Office 365 SharePoint Online", "mass_file_editing", "Impact",
               "Mass modification of files (encryption)", (60, 150)),
            _s("aws", "S3_RANSOMWARE_ENCRYPT", "Impact",
               "Re-encrypts S3 objects", (30, 90)),
        ],
    },
    "mailbox_takeover": {
        "name": "Mailbox takeover and mail forwarding",
        "summary": "The user's mailbox is set up to leak and hide mail: a new device, a new MFA "
                   "method, forwarding and hiding rules, delegated access, then sensitive mail "
                   "and files shared outside.",
        "steps": [
            _s("Azure AD Sign-ins", "new_device_signin", "Initial Access",
               "Signs in from a device not seen before", (5, 15)),
            _s("Azure AD Audit", "auth_method_added", "Persistence",
               "Registers a new MFA method", (30, 90)),
            _s("Office 365 Exchange Online", "inbox_forwarding_rule", "Collection",
               "Creates an inbox rule that forwards mail out", (30, 90)),
            _s("Office 365 Exchange Online", "email_hiding_rule", "Defense Evasion",
               "Creates a rule that hides incoming mail", (30, 90)),
            _s("Office 365 Exchange Online", "mailbox_delegation", "Collection",
               "Grants another account access to the mailbox", (60, 150)),
            _s("Office 365 Exchange Online", "send_as_permission", "Collection",
               "Grants Send As permission", (30, 90)),
            _s("Office 365 Exchange Online", "sensitive_mail_external", "Exfiltration",
               "Emails sensitive content to an outside recipient", (60, 150)),
            _s("Office 365 SharePoint Online", "anonymous_link", "Exfiltration",
               "Creates an anyone-with-the-link share", (60, 150)),
            _s("Office 365 Exchange Online", "exchange_audit_log_disabled", "Defense Evasion",
               "Turns off mailbox audit logging", (30, 90)),
        ],
    },
    "recon_and_discovery": {
        "name": "Reconnaissance from the workstation",
        "summary": "Someone learning the environment from the user's machine: LDAP and SMB "
                   "discovery, Kerberos attacks, a port sweep, then directory and cloud "
                   "enumeration.",
        "steps": [
            _s("Palo Alto Networks NGFW", "ldap_recon", "Discovery",
               "Queries the directory over LDAP", (5, 15)),
            _s("Check Point Firewall", "smb_share_enumeration", "Discovery",
               "Enumerates SMB shares across hosts", (20, 60)),
            _s("Windows Event Log", "share_enumeration", "Discovery",
               "Lists the SMB shares of other hosts", (20, 60)),
            _s("Windows Event Log", "as_rep_roasting", "Credential Access",
               "Requests AS-REP hashes for accounts without pre-auth", (30, 90)),
            _s("Windows Event Log", "multiple_service_tickets", "Credential Access",
               "Requests many service tickets (Kerberoasting)", (30, 90)),
            _s("Fortinet FortiGate", "port_sweep", "Discovery",
               "Sweeps ports across the internal network", (30, 90)),
            _s("Azure AD Sign-ins", "graph_enumeration", "Discovery",
               "Enumerates the directory through Microsoft Graph", (40, 100)),
            _s("Okta SSO", "admin_role_enumeration", "Discovery",
               "Lists the Okta administrator roles", (30, 90)),
            _s("aws", "IAM_RECON_LIST", "Discovery",
               "Lists IAM users, roles and policies", (30, 90)),
            _s("aws", "ORGANIZATIONS_RECON", "Discovery",
               "Lists the AWS organization", (30, 90)),
            _s("Google Cloud Compute", "IAM_RECON_TESTPERMISSIONS", "Discovery",
               "Probes which GCP permissions the account holds", (30, 90)),
            _s("Azure Activity", "wip_multi_region_enumeration", "Discovery",
               "Enumerates resources across Azure regions", (30, 90)),
        ],
    },
    "endpoint_beaconing": {
        "name": "Infected endpoint: beaconing and tunneling",
        "summary": "Network-only story that works for any operating system: DNS and web "
                   "beaconing, fast-flux and tunneling, an SSH tunnel and Tor from the machine, "
                   "then a miner.",
        "steps": [
            _s("Infoblox NIOS", "C2_BEACON", "Command and Control",
               "Beacons to a command-and-control domain over DNS", (5, 15)),
            _s("Infoblox NIOS", "FAST_FLUX_DNS", "Command and Control",
               "Resolves a fast-flux domain", (30, 90)),
            _s("Zscaler Web Gateway", "web_c2_beacon", "Command and Control",
               "Regular web beacon through the gateway", (30, 90)),
            _s("Cisco ASA Firewall", "dns_c2_beacon", "Command and Control",
               "DNS beaconing seen on the firewall", (20, 60)),
            _s("Infoblox NIOS", "DNS_TUNNEL", "Command and Control",
               "Data tunneled inside DNS queries", (30, 90)),
            _s("Fortinet FortiGate", "ddns_connection", "Command and Control",
               "Connects to a dynamic-DNS host", (30, 90)),
            _s("Zscaler Web Gateway", "reverse_ssh_tunnel", "Command and Control",
               "Opens a reverse SSH tunnel", (30, 90)),
            _s("Cisco Firepower", "ssh_over_https", "Command and Control",
               "SSH hidden on the HTTPS port", (30, 90)),
            _s("Check Point Firewall", "dns_tunneling", "Exfiltration",
               "DNS tunneling seen on the firewall", (30, 90)),
            _s("Zscaler Web Gateway", "tor_connection", "Command and Control",
               "Connects to the Tor network", (30, 90)),
            _s("Cisco ASA Firewall", "cryptomining", "Impact",
               "Crypto-mining traffic", (60, 150)),
        ],
    },
}


# ── Views ────────────────────────────────────────────────────────────────────

def nominal_seconds(steps):
    """Length of `steps` at nominal pace: the sum of the gap midpoints."""
    return sum((s["gap"][0] + s["gap"][1]) / 2.0 for s in steps)


def get(key):
    """The playbook for `key`, or None."""
    return PLAYBOOKS.get(key)


def describe(key):
    """JSON-ready description of one playbook (the picker and the API)."""
    pb = PLAYBOOKS[key]
    return {
        "key": key,
        "name": pb["name"],
        "summary": pb["summary"],
        "nominal_minutes": round(nominal_seconds(pb["steps"]) / 60.0, 1),
        "modules": sorted({s["module"] for s in pb["steps"]}),
        "steps": [{"index": i + 1, "module": s["module"], "threat": s["threat"],
                   "tactic": s["tactic"], "label": s["label"]}
                  for i, s in enumerate(pb["steps"])],
    }


def list_playbooks():
    """Every playbook, in definition order."""
    return [describe(k) for k in PLAYBOOKS]


# ── Planning ─────────────────────────────────────────────────────────────────

def plan(key, duration_seconds, availability, rng=None):
    """Lay the playbook `key` out on a run of `duration_seconds`.

    `availability(module_name, threat)` returns None when the step can run, else the reason
    it cannot (shown on the step). Skipped steps add no gap: the pace is fitted to the steps
    that run.

    Returns {"scale", "span_seconds", "steps"}; each step is {index, module, threat, tactic,
    label, state, offset_s, note}. `offset_s` is seconds after the run starts (None for a
    skipped step) and state is "pending" or "skipped".
    """
    rng = rng or random
    pb = PLAYBOOKS[key]
    rows = []
    for i, s in enumerate(pb["steps"]):
        why = availability(s["module"], s["threat"])
        rows.append({"index": i + 1, "module": s["module"], "threat": s["threat"],
                     "tactic": s["tactic"], "label": s["label"],
                     "state": "pending" if why is None else "skipped",
                     "offset_s": None, "note": why, "_gap": s["gap"]})
    runnable = [r for r in rows if r["state"] == "pending"]
    nominal = sum((r["_gap"][0] + r["_gap"][1]) / 2.0 for r in runnable)
    scale = 1.0
    if nominal > 0:
        scale = max(SCALE_MIN, min(SCALE_MAX, FIT_FRACTION * float(duration_seconds) / nominal))
    t = 0.0
    for r in runnable:
        t += max(MIN_GAP_S, rng.uniform(*r["_gap"]) * scale)
        r["offset_s"] = t
    # The per-step floor can push a long playbook past a short run (15 steps in one minute).
    # The story must finish inside the run, so squeeze the offsets back into the budget.
    budget = FIT_FRACTION * float(duration_seconds)
    if runnable and t > budget:
        squeeze = budget / t
        for r in runnable:
            r["offset_s"] *= squeeze
        scale *= squeeze
        t = budget
    for r in runnable:
        r["offset_s"] = round(r["offset_s"], 1)
    for r in rows:
        del r["_gap"]
    return {"scale": round(scale, 3), "span_seconds": round(t, 1), "steps": rows}


# ── Self-check ───────────────────────────────────────────────────────────────

def validate(modules_by_name):
    """Problems with the playbook definitions, against the real modules.

    `modules_by_name` maps module NAME to the loaded module. A step must name a module that
    exists and one of its threats that Bad User may fire (bad_user_policy.allowed_threats),
    tactics must be known, and gaps must be sane. Returns a list of strings (empty = fine).
    """
    try:
        from modules import bad_user_policy as policy
    except ImportError:                       # pragma: no cover - script-style import
        import bad_user_policy as policy
    problems = []
    for key, pb in PLAYBOOKS.items():
        if not pb.get("steps"):
            problems.append(f"{key}: no steps")
        for i, s in enumerate(pb["steps"], 1):
            where = f"{key} step {i} ({s['module']} / {s['threat']})"
            mod = modules_by_name.get(s["module"])
            if mod is None:
                problems.append(f"{where}: no such module")
            elif s["threat"] not in policy.allowed_threats(mod):
                problems.append(f"{where}: not a threat Bad User may fire in that module")
            if s["tactic"] not in TACTICS:
                problems.append(f"{where}: unknown tactic {s['tactic']!r}")
            lo, hi = s["gap"]
            if not (0 < lo <= hi):
                problems.append(f"{where}: bad gap {s['gap']}")
    return problems


def _load_modules():                           # pragma: no cover - exercised by the CLI
    import importlib
    import pkgutil
    import modules as pkg
    found = {}
    for info in pkgutil.iter_modules(pkg.__path__):
        try:
            mod = importlib.import_module(f"modules.{info.name}")
        except Exception:
            continue
        if hasattr(mod, "NAME") and hasattr(mod, "generate_log"):
            found[mod.NAME] = mod
    return found


if __name__ == "__main__":                     # pragma: no cover
    import sys
    problems = validate(_load_modules())
    for p in problems:
        print("PROBLEM:", p)
    total = sum(len(pb["steps"]) for pb in PLAYBOOKS.values())
    print(f"{len(PLAYBOOKS)} playbooks, {total} steps, {len(problems)} problem(s)")
    sys.exit(1 if problems else 0)
