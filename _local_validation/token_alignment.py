"""Guard the cross-plane token/ticket SEMANTICS for the hybrid campaign and Kerberos scenarios.

field_check.py already validates Windows event FIELD SHAPE against Microsoft docs. This test guards
how the two planes represent their (different) token systems, so a hybrid on-prem->cloud chain stays
realistic and fireable:
  - on-prem = Kerberos ticket metadata (4768 TGT / 4769 TGS): valid encryption types, krbtgt RID 502,
    and -- critically -- a Kerberoast TGS must target a USER service account (ServiceName NOT ending
    in "$"), or XSIAM's Kerberoasting rule discards it.
  - cloud = OAuth: a token-THEFT sign-in must present a replayed Primary Refresh Token
    (incomingTokenType = primaryRefreshToken), non-interactive, AzureAD issuer.
  - the two planes link by IDENTITY (same username), never by one token crossing over.

Run:  python _local_validation/token_alignment.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import session_utils as su                       # noqa: E402
from modules import azuread_threat_sequences as seq           # noqa: E402

CFG = json.load(open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                  "config.json"), encoding="utf-8"))

# Valid Kerberos TicketEncryptionType values a DC logs (plus 0xFFFFFFFF on failure).
_VALID_ENC = {"0x1", "0x01", "0x3", "0x03", "0x11", "0x12", "0x17", "0x18", "0xFFFFFFFF"}
_WEAK_ENC = {"0x17", "0x18", "0x1", "0x01", "0x3", "0x03"}   # RC4 / DES (roastable)
# Entra incomingTokenType enum.
_VALID_TOKEN_TYPES = {"none", "primaryRefreshToken", "saml2", "remoteDesktopToken", "unknownFutureValue"}
_FAILS = []


def check(cond, msg):
    print(("  OK  " if cond else " FAIL ") + msg)
    if not cond:
        _FAILS.append(msg)


def _win(t, eid):
    return [r for s, _i, r in t if s == seq.WIN_SRC and r.get("event_id") == eid]


def _cloud_signins(t):
    return [r for s, _i, r in t if s == seq.AAD_SRC and "userPrincipalName" in r]


def test_hybrid_token_alignment():
    print("[hybrid on-prem/cloud token alignment]")
    sc = su.build_session_context(CFG)
    ctx = {"session_context": sc}
    # run several times (random user/SPN each build) so the invariants hold for all draws
    seen_identity_join = False
    for _ in range(40):
        t = seq.build("hybrid_onprem_cloud", CFG, ctx)

        for tgt in _win(t, "4768"):
            ed = tgt["event_data"]
            check(ed["ServiceName"] == "krbtgt", "4768 TGT service is krbtgt")
            check(ed["ServiceSid"].endswith("-502"), "4768 krbtgt SID RID == 502")
            check(ed["TicketEncryptionType"] in _VALID_ENC, f"4768 enc type valid ({ed['TicketEncryptionType']})")

        for tgs in _win(t, "4769"):
            ed = tgs["event_data"]
            check(not ed["ServiceName"].endswith("$"),
                  f"4769 Kerberoast target is a USER account, not machine ({ed['ServiceName']})")
            check(ed["TicketEncryptionType"] in _WEAK_ENC,
                  f"4769 roast ticket is weakly encrypted ({ed['TicketEncryptionType']})")
            check("@" in ed["TargetUserName"], "4769 TargetUserName is user@REALM form")

        signins = _cloud_signins(t)
        check(bool(signins), "hybrid emits a cloud sign-in")
        for s in signins:
            check(s["incomingTokenType"] == "primaryRefreshToken",
                  "cloud token-theft presents a replayed PRT (incomingTokenType=primaryRefreshToken)")
            check(s["isInteractive"] is False, "cloud token replay is non-interactive")
            check(s["incomingTokenType"] in _VALID_TOKEN_TYPES, "cloud incomingTokenType is a valid enum value")
            check(s["tokenIssuerType"] == "AzureAD", "cloud token issuer is AzureAD")

        # identity join: the on-prem actor and the cloud principal are the SAME username
        win_users = {ed["event_data"]["TargetUserName"].split("@")[0].lower()
                     for ed in _win(t, "4768")}
        cloud_users = {s["userPrincipalName"].split("@")[0].lower() for s in signins}
        if win_users and cloud_users:
            check(win_users == cloud_users, f"on-prem and cloud are the same identity ({win_users} == {cloud_users})")
            seen_identity_join = True
    check(seen_identity_join, "exercised the on-prem<->cloud identity join at least once")


def test_kerberoast_scenario_targets_user_accounts():
    print("[kerberoasting generator targets user service accounts]")
    # Every SPN in the roastable inventory must resolve to a user account (never a computer account).
    import modules.windows_events as win
    bad = [spn for spn in win._KERBEROAST_SPNS
           if win._SPN_TO_SERVICE_ACCOUNT.get(spn, "").endswith("$") or not win._SPN_TO_SERVICE_ACCOUNT.get(spn)]
    check(not bad, f"all {len(win._KERBEROAST_SPNS)} roastable SPNs map to a user service account ({bad[:3]})")


if __name__ == "__main__":
    test_hybrid_token_alignment()
    test_kerberoast_scenario_targets_user_accounts()
    print()
    if _FAILS:
        print(f"FAILED ({len(_FAILS)}):")
        for f in dict.fromkeys(_FAILS):
            print("  - " + f)
        sys.exit(1)
    print("ALL TOKEN-ALIGNMENT GUARDS PASSED")
