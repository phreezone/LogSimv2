# Proofpoint Email Gateway

**Dataset:** `proofpoint_tap_raw`
**Transport:** HTTP Collector (5 per-app collectors defined in `config.json`)
**Format:** Proofpoint TAP SIEM API JSON (Admin SDK Reports API Activity resource)

Simulates Proofpoint Targeted Attack Protection (TAP) email security events. The module generates JSON matching the official Proofpoint TAP SIEM API schema exactly, including the four `_log_type` values that match XSIAM alert rules. The `ProofpointTAPModelingRules_1_3.xif` XIF rule maps JSON fields to XDM.

### Log Types

| `_log_type` | Description |
|---|---|
| `message-delivered` | Email delivered to mailbox — benign or BEC (no URL/attachment payload) |
| `message-blocked` | Email quarantined by TAP — phishing, malware, spam, macro |
| `click-blocked` | User clicked a TAP-rewritten URL; TAP blocked the destination at click time |
| `click-permitted` | User clicked URL; TAP allowed it — retroactively flagged as threat |

### XDM Field Mappings (ProofpointTAPModelingRules_1_3.xif)

| JSON Field | XDM Field |
|---|---|
| `fromAddress` | `xdm.email.sender` |
| `recipient` | `xdm.email.recipients` |
| `ccAddresses` | `xdm.email.cc` |
| `subject` | `xdm.email.subject` |
| `messageID` | `xdm.email.message_id` |
| `GUID` | `xdm.event.id` / `xdm.alert.original_alert_id` |
| `sender` | `xdm.email.return_path` |
| `messageParts` (array) | `xdm.email.attachment.filename` / `md5` / `sha256` |
| `threatsInfoMap` | `xdm.alert.description` / `threatType` / `threatID` |
| `senderIP` | `xdm.intermediate.host.ipv4_addresses` |
| `clickIP` | `xdm.source.host.ipv4_addresses` |
| `userAgent` | `xdm.source.user_agent` |
| `url` | `xdm.target.url` |
| `messageTime` | `xdm.email.delivery_timestamp` |

### Hunt-Relevant Extra Fields

These top-level fields are not mapped by the XIF but are preserved in the raw dataset for custom detection rules:

| Field | Notes |
|---|---|
| `classification` | `PHISHING`, `MALWARE`, `SPAM`, `IMPOSTOR` |
| `threatID` | SHA256 hash of the threat artifact |
| `threatURL` | Link to Proofpoint Threat Insight portal |
| `threatStatus` | `active` for all simulated threats |
| `clickTime` | When the user clicked (click events only) |
| `clickIP` | Internal workstation IP where click originated |
| `impostorScore` | 0–100; high (>75) = BEC indicator |
| `phishScore` | 0–100; TAP phishing confidence |
| `malwareScore` | 0–100; TAP malware confidence |
| `spamScore` | 0–100; TAP spam confidence |
| `campaignId` | Links events in the same attack campaign |
| `headerFrom` | Display name + address (may differ from `fromAddress` in spoofed emails) |
| `replyToAddress` | Array; reply-to misdirection is a key BEC/phishing signal |
| `modulesRun` | TAP modules that processed the message: `spam`, `urldefense`, `pdr`, `sandbox`, `impostor`, `qr-scanner` |
| `completelyRewritten` | `true` if all URLs in the message were rewritten by URL Defense |

### Message Structure

All `message-*` events follow the TAP SIEM API schema:

- `fromAddress`: **array** `["sender@domain.com"]`
- `replyToAddress`: **array** (empty `[]` or `["reply@domain.com"]`)
- `policyRoutes`: always starts with `"default_inbound"`; threat events targeting executives or finance add a second route (`"executives"`, `"finance"`, `"hr"`, etc.)
- `messageParts`: array of body/attachment objects; each part has `filename`, `contentType`, `md5`, `sha256`, `sandboxStatus` (`null`=not submitted, `"CLEAN"`, `"MALICIOUS"`, `"UNKNOWN"`)
- `threatsInfoMap`: array of threat objects with `classification`, `threat`, `threatId`, `threatStatus`, `threatType`, `campaignId`, `threatTime`, `threatUrl`

Click events (`click-blocked`, `click-permitted`) use a **different schema**: `recipient` is a string (not array), top-level `campaignId`/`threatID`/`threatTime`, no `messageParts` or `threatsInfoMap`.

---

## Benign Events

| Event Type | Description | Key Fields |
|---|---|---|
| `message-delivered` | Standard business email successfully delivered to mailbox. Subject from a pool of 18 realistic business templates. Sender from well-known SaaS domains (microsoft.com, google.com, salesforce.com, etc.). 50% chance of a benign attachment (PDF, DOCX, XLSX, PPTX, image). 30% chance of CC recipients. Low scores indicate clean email. | `_log_type=message-delivered`, `phishScore=0–15`, `spamScore=0–25`, `malwareScore=0`, `modulesRun=["spam","urldefense"]`, `quarantineFolder=null`, `quarantineRule=null`, `completelyRewritten=false`; attachments have `sandboxStatus="CLEAN"` (documents) or `null` (images) |

---

## Threat Events

Threat events are selected by weighted random choice from `_THREAT_WEIGHTS`. Multi-event generators (`spam_campaign`, `phishing_campaign`) return a Python list of JSON strings. All other generators return a single JSON string.

| Threat Key | Log Type | Category | Description | Key Fields | Weight |
|---|---|---|---|---|---|
| `phishing_url` | `message-blocked` | URL Phishing | Inbound phishing email with a malicious URL. URL rewritten by TAP URL Defense (`completelyRewritten=true`). Suspicious reply-to address as secondary signal. Quarantined in "Phish" folder. | `phishScore=80–100`, `spamScore=40–80`, `quarantineFolder=Phish`, `quarantineRule=module.urldefense.phish`, `modulesRun=["spam","urldefense","pdr"]`, `classification=PHISHING`, `threatType=URL`, `url=malicious_url`, `replyToAddress=[attacker_reply@gmail.com]`, `completelyRewritten=true` | 20 |
| `malware_attachment` | `message-blocked` | Malware | Email with a malicious attachment (Emotet, QakBot, AsyncRAT, IcedID, AgentTesla, Dridex, PDFExploit). Sandbox detonation verdict: `sandboxStatus=MALICIOUS`. Quarantined in "Malware" folder. | `malwareScore=90–100`, `phishScore=20–60`, `quarantineFolder=Malware`, `quarantineRule=module.sandbox.threat`, `modulesRun=["spam","urldefense","pdr","sandbox"]`, `classification=MALWARE`, `threatType=ATTACHMENT`, attachment `sandboxStatus=MALICIOUS`, SHA256 as `threatID` | 18 |
| `credential_phishing` | `message-blocked` | Credential Harvesting | High-confidence credential harvesting. Subjects reference M365, VPN re-auth, account lockout. URL leads to a fake login page. Maximum `phishScore`. 1–5 recipients targeted. | `phishScore=90–100`, `spamScore=50–85`, `quarantineFolder=Phish`, `quarantineRule=module.urldefense.phish`, `classification=PHISHING`, `threatType=URL`, `completelyRewritten=true`, `url=fake_login_url`, `policyRoutes=["default_inbound", "privileged_users"/"executives"/etc.]` | 15 |
| `bec_impostor` | `message-delivered` | Business Email Compromise | CEO/CFO impersonation using a lookalike domain (e.g., `examplecorp.net` instead of `examplecorp.com`). **Delivered to mailbox** — no URL or attachment payload to block. Detection signal: high `impostorScore` + `replyToAddress` differs from `fromAddress` (reply-to redirects to a personal Gmail). | `_log_type=message-delivered`, `impostorScore=75–100`, `phishScore=20–55`, `malwareScore=0`, `modulesRun=["spam","urldefense","impostor"]`, `classification=IMPOSTOR`, `replyToAddress=["ceo-NNN@gmail.com"]`, sender `fromAddress=exec@lookalike-domain`, no `threatsInfoMap` | 12 |
| `spam_campaign` | `message-blocked` | Spam | High-volume spam burst: 5–18 messages from the same `senderIP` to different internal recipients. Standard XSIAM alert: same `senderIP` count ≥ 5 in 1 hour. Returns list. | `_log_type=message-blocked` (each), `spamScore=85–100`, `phishScore=10–40`, `quarantineFolder=Spam`, `quarantineRule=module.spam.bulk`, `classification=SPAM`, same `sender` and `senderIP` across all events | 10 |
| `click_blocked` | `click-blocked` | URL Defense Block | User clicked a TAP-rewritten URL; TAP URL Defense blocked navigation to the malicious destination in real time. High-confidence indicator. `clickIP` is the user's internal workstation IP (usable for cross-source correlation with Zscaler/Firepower). | `_log_type=click-blocked`, `clickIP=user_workstation_ip`, `userAgent=browser_ua`, `url=malicious_url`, `classification=PHISHING`, `phishScore=80–100`, `modulesRun=["urldefense"]`, `recipient=email_string` (not array), `threatStatus=active` | 10 |
| `malicious_macro` | `message-blocked` | Macro Malware | Macro-enabled Office document (`.xlsm`, `.doc`, `.xlsb`, `.docm`) detected by sandbox detonation. Sandbox opens document and observes macro execution behavior before delivering verdict. | `malwareScore=85–100`, `quarantineFolder=Malware`, `quarantineRule=module.sandbox.threat`, `modulesRun=["spam","urldefense","pdr","sandbox"]`, `classification=MALWARE`, `threatType=ATTACHMENT`, attachment `contentType=application/vnd.ms-excel.sheet.macroEnabled.12` or `application/msword`, `sandboxStatus=MALICIOUS` | 8 |
| `phishing_campaign` | `message-blocked` | Phishing Campaign | Coordinated campaign: same attacker (`senderIP`, `subject`, `threatID`) sending to 4–10 different internal recipients. All messages blocked by URL Defense. Returns list. Shared `threatID` enables campaign correlation. | `_log_type=message-blocked` (each), same `sender`/`senderIP`/`subject` across events, `phishScore=80–100`, `classification=PHISHING`, same `threatID` and `campaignId`, `completelyRewritten=true` | 7 |
| `click_permitted` | `click-permitted` | URL Allowed (Retroactive) | User clicked a URL that TAP allowed at click time — later identified as a threat. **The user successfully reached the phishing page.** Critical signal for incident response. `clickTime` is back-dated (30 min – 1 hour ago). Correlate `clickIP` with Zscaler proxy and then Okta for credential theft confirmation. | `_log_type=click-permitted`, `clickIP=user_workstation_ip`, `clickTime=past_timestamp`, `threatStatus=active`, `phishScore=60–90`, `recipient=email_string`, `modulesRun=["urldefense"]` | 5 |
| `qr_code_phishing` | `message-blocked` | QR Code Phishing | QR code embedded in a PNG attachment (`AuthCode.png`). URL is inside the image — cannot be rewritten by URL Defense (`completelyRewritten=false`). Detected by the `qr-scanner` module. Common bypass technique for URL rewriting solutions. | `_log_type=message-blocked`, `quarantineFolder=Phish`, `quarantineRule=module.qr.phish`, `modulesRun=["spam","urldefense","pdr","qr-scanner"]`, `completelyRewritten=false`, attachment `contentType=image/png`, `classification=PHISHING`, `phishScore=70–95` | 3 |
| `callback_phishing` | `message-blocked` | Callback / TOAD | Telephone-oriented attack delivery (TOAD). Message body contains a phone number to call — no URL or attachment. Blocked by spam module (not URL Defense). No `threatsInfoMap` or `threatID`. Hunt: `message-blocked` where `spamScore > 70 AND phishScore > 50 AND threatsInfoMap` is empty. | `_log_type=message-blocked`, `phishScore=50–80`, `spamScore=75–100`, `quarantineFolder=Spam`, `quarantineRule=module.spam.callback`, `modulesRun=["spam","urldefense"]`, `classification=PHISHING`, no `threatsInfoMap`, subjects reference Norton/McAfee/IRS/Geek Squad auto-renewal with phone numbers | 2 |

### Scenario Events

The Proofpoint module supports coordinated kill-chain scenario injection via the `scenario_event` parameter:

| `scenario_event` value | Mapped To | Description |
|---|---|---|
| `CLICK_BLOCKED` | `_generate_click_blocked` | Kill chain step: victim clicks a phishing link in a delivered email. Generates a `click-blocked` event for the specified user, using that user's session IP as `clickIP`. |
| `CLICK_PERMITTED` | `_generate_click_permitted` | Kill chain step: victim successfully reaches a phishing page before TAP flags the URL. Generates a `click-permitted` event with a back-dated `clickTime`. |
