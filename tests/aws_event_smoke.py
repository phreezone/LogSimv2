"""Structural smoke test for every AWS CloudTrail generator.

Validates each generator's output against the CloudTrail rules that XSIAM's AWS
parser actually depends on. Written after 2026-08-02, when two defects that
field-level review had missed were found the hard way:

  * `MAKE_S3_PUBLIC` emitted PutBucketPolicy, a form the built-in BIOC ignores.
  * 15 identity-pool entries used `type: "Role"`, which CloudTrail never emits
    at top level — XSIAM could not resolve the identity, silently excluding
    ~10% of AWS events from every identity-based cloud analytic.

Both produced perfectly plausible-looking JSON. These checks encode the rules
that would have caught the second class locally.

IMPORTANT SCOPE LIMIT: this proves events are *well-formed*, NOT that any
detector fires. Both S3-public variants normalised identically in XSIAM yet
only one alerted — the discriminator survived only in the original API name.
Detector alignment can only be proven by firing at a tenant and reading back a
fired alert. See tests/aws_detector_sweep.py for that half.

usage:  python tests/aws_event_smoke.py [iterations]
exit 0 = clean, 1 = violations found
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

from modules import aws  # noqa: E402

# Valid top-level userIdentity.type values per the CloudTrail record contents
# reference. "Role" is deliberately ABSENT — it is only ever legal nested in
# sessionContext.sessionIssuer.type.
VALID_IDENTITY_TYPES = {
    "Root", "IAMUser", "AssumedRole", "FederatedUser", "Directory",
    "AWSAccount", "AWSService", "IdentityCenterUser", "Unknown",
    "SAMLUser", "WebIdentityUser",
}

# Identities backed by temporary STS credentials: ARN must be sts, key ASIA.
TEMP_CRED_TYPES = {"AssumedRole", "FederatedUser", "SAMLUser", "WebIdentityUser"}

REQUIRED_FIELDS = ("eventVersion", "eventTime", "eventSource", "eventName",
                   "awsRegion", "userIdentity", "eventID", "eventType",
                   "recipientAccountId")

TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ACCOUNT_RE = re.compile(r"^\d{12}$")


def check_event(ev, gen_name):
    """Return a list of violation strings for one CloudTrail event."""
    v = []

    def bad(msg):
        v.append(f"{gen_name}: {msg}")

    if not isinstance(ev, dict):
        return [f"{gen_name}: event is {type(ev).__name__}, expected dict"]

    for f in REQUIRED_FIELDS:
        if f not in ev or ev[f] in (None, ""):
            bad(f"missing required field {f}")

    if "eventTime" in ev and not TIME_RE.match(str(ev.get("eventTime", ""))):
        bad(f"eventTime not ISO8601 Z: {ev.get('eventTime')!r}")

    acct = str(ev.get("recipientAccountId", ""))
    if acct and not ACCOUNT_RE.match(acct):
        bad(f"recipientAccountId not 12 digits: {acct!r}")

    # Unsubstituted config placeholders leak as literal text into ARNs.
    blob = json.dumps(ev, default=str)
    if "PLACEHOLDER_" in blob:
        bad("contains unsubstituted PLACEHOLDER_* value")

    ui = ev.get("userIdentity") or {}
    itype = ui.get("type")

    if itype not in VALID_IDENTITY_TYPES:
        bad(f"invalid top-level userIdentity.type {itype!r} "
            f"(XSIAM cannot resolve the identity; 'Role' belongs only in sessionIssuer)")

    arn = ui.get("arn") or ""
    if itype in TEMP_CRED_TYPES and arn:
        if ":iam::" in arn:
            bad(f"temporary-credential identity uses an iam:: ARN: {arn}")
        if itype == "AssumedRole" and "assumed-role/" not in arn:
            bad(f"AssumedRole arn missing assumed-role/ segment: {arn}")
    if itype == "IAMUser" and arn and ":sts::" in arn:
        bad(f"IAMUser uses an sts:: ARN: {arn}")

    # accessKeyId prefix must match credential class. ConsoleLogin has none.
    akid = ui.get("accessKeyId")
    if akid:
        if itype in TEMP_CRED_TYPES and not akid.startswith("ASIA"):
            bad(f"temporary credentials should use an ASIA key, got {akid[:4]}")
        if itype in ("IAMUser", "Root") and not akid.startswith("AKIA"):
            bad(f"long-term credentials should use an AKIA key, got {akid[:4]}")
    if ev.get("eventName") == "ConsoleLogin" and akid:
        bad("ConsoleLogin should not carry accessKeyId")

    # AssumedRole is the one type that must NOT carry a top-level userName — the
    # role name belongs in sessionIssuer. IAMUser/Root carry it normally, and so
    # do SAMLUser / WebIdentityUser / FederatedUser (the federated subject name).
    if "userName" in ui and itype == "AssumedRole":
        bad("top-level userName present on AssumedRole (role name belongs in sessionIssuer)")

    # AssumedRole must carry a sessionIssuer, and that is where Role is legal.
    if itype == "AssumedRole":
        sc = ui.get("sessionContext") or {}
        issuer = sc.get("sessionIssuer") or {}
        if not issuer:
            bad("AssumedRole missing sessionContext.sessionIssuer")
        else:
            if issuer.get("type") != "Role":
                bad(f"sessionIssuer.type should be 'Role', got {issuer.get('type')!r}")
            if ":role/" not in (issuer.get("arn") or ""):
                bad(f"sessionIssuer.arn should be a role ARN: {issuer.get('arn')!r}")

    for r in (ev.get("resources") or []):
        if isinstance(r, dict) and r.get("ARN") and not str(r["ARN"]).startswith("arn:aws:"):
            bad(f"resource ARN malformed: {r['ARN']!r}")

    return v


def load_config():
    cs = open("config.json", encoding="utf-8").read()
    for ph, envvar in (("PLACEHOLDER_GCP_PROJECT_ID", "GCP_PROJECT_ID"),
                       ("PLACEHOLDER_GCP_PROJECT_NUMBER", "GCP_PROJECT_NUMBER"),
                       ("PLACEHOLDER_AWS_ACCOUNT_ID", "AWS_ACCOUNT_ID")):
        val = os.getenv(envvar, "")
        if not val:
            print(f"WARNING: {envvar} unset — placeholder check will misfire")
        cs = cs.replace(ph, val)
    return json.loads(cs)


def collect_generators():
    """Every distinct generator reachable ambiently or by name."""
    gens = {}
    for fn in list(aws.BENIGN_SCENARIOS) + list(aws.THREAT_SCENARIOS):
        gens[fn.__name__] = fn
    for name, fn in aws.SCENARIO_FUNCTIONS.items():
        gens[fn.__name__] = fn
    return dict(sorted(gens.items()))


def main():
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 25
    config = load_config()
    gens = collect_generators()

    print(f"AWS event smoke test — {len(gens)} generators x {iterations} iterations\n")

    violations = defaultdict(list)
    errors = {}
    identity_types = defaultdict(int)
    event_names = defaultdict(int)
    total_events = 0

    for name, fn in gens.items():
        for _ in range(iterations):
            try:
                out = fn(config, context=None)
            except Exception as e:  # a generator that throws is a hard failure
                errors[name] = repr(e)[:200]
                break
            events = out if isinstance(out, list) else [out]
            for ev in events:
                if isinstance(ev, (bytes, bytearray, str)):
                    continue  # already-serialised payloads aren't inspectable here
                total_events += 1
                identity_types[(ev.get("userIdentity") or {}).get("type")] += 1
                event_names[ev.get("eventName")] += 1
                for msg in check_event(ev, name):
                    violations[name].append(msg)

    print(f"generators : {len(gens)}")
    print(f"events     : {total_events}")
    print(f"raised     : {len(errors)}")
    print(f"violating  : {len(violations)}\n")

    print("--- identity types produced ---")
    for t, n in sorted(identity_types.items(), key=lambda x: -x[1]):
        flag = "" if t in VALID_IDENTITY_TYPES else "   <-- INVALID"
        print(f"  {n:6}  {t}{flag}")

    if errors:
        print("\n--- generators that raised ---")
        for n, e in errors.items():
            print(f"  {n}: {e}")

    if violations:
        print("\n--- violations (deduplicated) ---")
        for n, msgs in sorted(violations.items()):
            uniq = sorted(set(msgs))
            print(f"\n  {n}  ({len(msgs)} total, {len(uniq)} distinct)")
            for m in uniq[:6]:
                print(f"      {m.split(': ', 1)[1]}")

    print(f"\n--- distinct eventNames: {len(event_names)} ---")
    ok = not violations and not errors
    print("\nRESULT:", "CLEAN" if ok else "FAILURES FOUND")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
