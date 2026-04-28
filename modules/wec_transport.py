# modules/wec_transport.py
# WS-Management client for pushing Windows Event XML to a WEC endpoint.
#
# This module is a TRANSPORT helper — it does NOT define a NAME attribute,
# so load_modules() and _load_modules() will skip it (same pattern as
# session_utils.py).
#
# Protocol: Source-initiated WEF subscription over HTTPS with mutual TLS.
#   1. Enumerate  — discover subscription UUID and delivery parameters
#   2. Events     — POST batches of Windows Event XML (CDATA-wrapped)
#   3. Heartbeat  — keepalive when idle
#   4. Ack        — collector acknowledges receipt
#
# Requires: requests-pkcs12, lxml, cryptography

import logging
import threading
import time
import uuid
import xml.etree.ElementTree as _stdlib_ET

import requests
from requests_pkcs12 import Pkcs12Adapter

try:
    from lxml import etree as _etree
    _HAS_LXML = True
except ImportError:
    _HAS_LXML = False

log = logging.getLogger("logsim.wec")

# ── SOAP namespace map ─────────────────────────────────────────────────────
NSMAP = {
    "s":    "http://www.w3.org/2003/05/soap-envelope",
    "a":    "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "n":    "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
    "w":    "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
    "p":    "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd",
    "e":    "http://schemas.xmlsoap.org/ws/2004/08/eventing",
    "b":    "http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd",
    "m":    "http://schemas.microsoft.com/wbem/wsman/1/machineid",
    "auth": "http://schemas.microsoft.com/wbem/wsman/1/authentication",
}

# ── SOAP action URIs ───────────────────────────────────────────────────────
ACTION_ENUMERATE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
ACTION_ENUMERATE_RESP = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse"
ACTION_EVENTS = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Events"
ACTION_HEARTBEAT = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Heartbeat"
ACTION_ACK = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Ack"

RESOURCE_URI_ENUMERATE = "http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription"
RESOURCE_URI_EVENTLOG = "http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog"
ACTION_EVENT_SINGLE = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Event"
ANONYMOUS = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"

# ── SOAP envelope templates ───────────────────────────────────────────────
# Using string templates for the fixed SOAP structure — lxml handles
# namespace prefixes perfectly, but the variable parts (events in CDATA)
# are simpler to inject via string formatting.

_ENUMERATE_TEMPLATE = (
    '<s:Envelope'
    ' xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
    ' xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
    ' xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"'
    ' xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"'
    ' xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"'
    ' xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd">'
    '<s:Header>'
    '<a:To>{to}</a:To>'
    '<w:ResourceURI s:mustUnderstand="true">{resource_uri}</w:ResourceURI>'
    '<m:MachineID xmlns:m="http://schemas.microsoft.com/wbem/wsman/1/machineid"'
    ' s:mustUnderstand="false">{machine_id}</m:MachineID>'
    '<a:ReplyTo>'
    '<a:Address s:mustUnderstand="true">{anonymous}</a:Address>'
    '</a:ReplyTo>'
    '<a:Action s:mustUnderstand="true">{action}</a:Action>'
    '<w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>'
    '<a:MessageID>uuid:{message_id}</a:MessageID>'
    '<w:Locale xml:lang="en-US" s:mustUnderstand="false" />'
    '<p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />'
    '<p:SessionId s:mustUnderstand="false">uuid:{session_id}</p:SessionId>'
    '<p:OperationID s:mustUnderstand="false">uuid:{operation_id}</p:OperationID>'
    '<p:SequenceId s:mustUnderstand="false">{sequence_id}</p:SequenceId>'
    '<w:OperationTimeout>PT60.000S</w:OperationTimeout>'
    '</s:Header>'
    '<s:Body>'
    '<n:Enumerate>'
    '<w:OptimizeEnumeration/>'
    '<w:MaxElements>32000</w:MaxElements>'
    '</n:Enumerate>'
    '</s:Body>'
    '</s:Envelope>'
)

_EVENTS_TEMPLATE = (
    '<s:Envelope'
    ' xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
    ' xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
    ' xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing"'
    ' xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"'
    ' xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">'
    '<s:Header>'
    '<a:To>{to}</a:To>'
    '<m:MachineID xmlns:m="http://schemas.microsoft.com/wbem/wsman/1/machineid"'
    ' s:mustUnderstand="false">{machine_id}</m:MachineID>'
    '<a:ReplyTo>'
    '<a:Address s:mustUnderstand="true">{anonymous}</a:Address>'
    '</a:ReplyTo>'
    '<a:Action s:mustUnderstand="true">{action}</a:Action>'
    '<w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>'
    '<a:MessageID>uuid:{message_id}</a:MessageID>'
    '<w:Locale xml:lang="en-US" s:mustUnderstand="false" />'
    '<p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />'
    '<p:SessionId s:mustUnderstand="false">uuid:{session_id}</p:SessionId>'
    '<p:OperationID s:mustUnderstand="false">uuid:{operation_id}</p:OperationID>'
    '<p:SequenceId s:mustUnderstand="false">{sequence_id}</p:SequenceId>'
    '<w:OperationTimeout>PT60.000S</w:OperationTimeout>'
    '<e:Identifier xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing">'
    '{identifier}</e:Identifier>'
    '<w:Bookmark>{bookmark_xml}</w:Bookmark>'
    '<w:AckRequested/>'
    '</s:Header>'
    '<s:Body>'
    '<w:Events>{events_wrapped}</w:Events>'
    '</s:Body>'
    '</s:Envelope>'
)

_HEARTBEAT_TEMPLATE = (
    '<s:Envelope'
    ' xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
    ' xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
    ' xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing"'
    ' xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"'
    ' xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">'
    '<s:Header>'
    '<a:To>{to}</a:To>'
    '<m:MachineID xmlns:m="http://schemas.microsoft.com/wbem/wsman/1/machineid"'
    ' s:mustUnderstand="false">{machine_id}</m:MachineID>'
    '<a:ReplyTo>'
    '<a:Address s:mustUnderstand="true">{anonymous}</a:Address>'
    '</a:ReplyTo>'
    '<a:Action s:mustUnderstand="true">{action}</a:Action>'
    '<w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>'
    '<a:MessageID>uuid:{message_id}</a:MessageID>'
    '<w:Locale xml:lang="en-US" s:mustUnderstand="false" />'
    '<p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />'
    '<p:SessionId s:mustUnderstand="false">uuid:{session_id}</p:SessionId>'
    '<p:OperationID s:mustUnderstand="false">uuid:{operation_id}</p:OperationID>'
    '<p:SequenceId s:mustUnderstand="false">{sequence_id}</p:SequenceId>'
    '<w:OperationTimeout>PT60.000S</w:OperationTimeout>'
    '<e:Identifier xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing">'
    '{identifier}</e:Identifier>'
    '<w:AckRequested/>'
    '</s:Header>'
    '<s:Body>'
    '<w:Events></w:Events>'
    '</s:Body>'
    '</s:Envelope>'
)


def _uuid_upper():
    """Generate an uppercase UUID string (MS convention)."""
    return str(uuid.uuid4()).upper()


def _xml_escape_cdata(text):
    """Escape ]]> inside text so CDATA wrapping is safe."""
    return text.replace("]]>", "]]]]><![CDATA[>")


class WecTransportError(Exception):
    """Raised when WEC transport encounters a protocol-level error."""


class WecClient:
    """WS-Management client that pushes Windows Event XML to a WEC endpoint.

    Usage:
        client = WecClient(broker_url, pfx_path, pfx_password)
        client.enumerate()           # discover subscription
        client.deliver_events([...]) # send event batch
        client.heartbeat()           # keepalive
        client.close()               # cleanup
    """

    def __init__(self, broker_url, pfx_path, pfx_password,
                 machine_id="logsim.examplecorp.local",
                 verify_ssl=False):
        if not broker_url:
            raise WecTransportError("WEC_BROKER_URL is required")
        if not pfx_path:
            raise WecTransportError("WEC_PFX_PATH is required")

        self.broker_url = broker_url.rstrip("/")
        self.machine_id = machine_id
        self._pfx_path = pfx_path
        self._pfx_password = pfx_password
        self._verify_ssl = verify_ssl

        # Session with mutual TLS via PFX cert
        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._session.mount("https://", Pkcs12Adapter(
            pkcs12_filename=pfx_path,
            pkcs12_password=pfx_password,
        ))

        # Subscription state (populated by enumerate())
        self.subscription_id = None
        self.subscription_version = None
        self.delivery_url = None
        self.identifier = None  # e:Identifier from ReferenceProperties
        self.heartbeat_interval_ms = 900_000  # default 15 min
        self.bookmark = None

        # Per-connection state
        self._session_id = _uuid_upper()
        self._sequence_id = 0
        self._seq_lock = threading.Lock()
        self._last_record_id = 0

        # Heartbeat thread
        self._heartbeat_thread = None
        self._heartbeat_stop = threading.Event()
        self._last_delivery_time = 0.0

        log.info("WecClient initialized: broker=%s machine_id=%s",
                 self.broker_url, self.machine_id)

    def _next_sequence(self):
        with self._seq_lock:
            self._sequence_id += 1
            return self._sequence_id

    def _send_soap(self, url, envelope_str):
        """Encode as UTF-16LE with BOM and POST to the WEC endpoint."""
        body = b"\xff\xfe" + envelope_str.encode("utf-16-le")
        headers = {
            "Content-Type": "application/soap+xml;charset=UTF-16",
            "User-Agent": "Microsoft WinRM Client",
            "Connection": "Keep-Alive",
        }
        resp = self._session.post(url, data=body, headers=headers, timeout=30)

        if resp.status_code not in (200, 202):
            log.error("WEC POST %s returned %d: %s",
                      url, resp.status_code, resp.text[:500])
            raise WecTransportError(
                f"WEC endpoint returned HTTP {resp.status_code}")

        # Response may be UTF-16LE (with BOM) or UTF-8
        raw = resp.content
        if raw[:2] == b"\xff\xfe":
            return raw[2:].decode("utf-16-le", errors="replace")
        if raw[:3] == b"\xef\xbb\xbf":
            return raw[3:].decode("utf-8", errors="replace")
        try:
            return raw.decode("utf-16-le", errors="replace")
        except Exception:
            return raw.decode("utf-8", errors="replace")

    # ── Enumerate ──────────────────────────────────────────────────────────

    def enumerate(self):
        """POST Enumerate to discover subscription UUID and delivery URL.

        Must be called once before deliver_events() or heartbeat().
        Returns the subscription_id (UUID string).
        """
        enumerate_url = f"{self.broker_url}/SubscriptionManager/WEC"
        msg_id = _uuid_upper()
        op_id = _uuid_upper()
        seq = self._next_sequence()

        envelope = _ENUMERATE_TEMPLATE.format(
            to=enumerate_url,
            resource_uri=RESOURCE_URI_ENUMERATE,
            anonymous=ANONYMOUS,
            action=ACTION_ENUMERATE,
            message_id=msg_id,
            machine_id=self.machine_id,
            session_id=self._session_id,
            operation_id=op_id,
            sequence_id=seq,
        )

        log.info("WEC Enumerate -> %s", enumerate_url)
        try:
            resp_xml = self._send_soap(enumerate_url, envelope)
        except requests.exceptions.ConnectionError as exc:
            raise WecTransportError(
                "Could not connect to Broker VM WEC. "
                "Check URL, cert, and that WEC is activated in XSIAM console. "
                f"Error: {exc}"
            ) from exc

        self._parse_enumerate_response(resp_xml)
        log.info("WEC subscription discovered: id=%s version=%s delivery=%s",
                 self.subscription_id, self.subscription_version,
                 self.delivery_url)
        return self.subscription_id

    def _parse_enumerate_response(self, resp_xml):
        """Extract subscription ID, version, and delivery URL from response."""
        try:
            if _HAS_LXML:
                root = _etree.fromstring(resp_xml.encode("utf-8")
                                         if isinstance(resp_xml, str)
                                         else resp_xml)
            else:
                root = _stdlib_ET.fromstring(resp_xml)
        except Exception as exc:
            log.error("Failed to parse Enumerate response: %s\n%s",
                      exc, resp_xml[:1000])
            raise WecTransportError(
                f"Failed to parse Enumerate response: {exc}") from exc

        NS_E = "{http://schemas.xmlsoap.org/ws/2004/08/eventing}"
        NS_A = "{http://schemas.xmlsoap.org/ws/2004/08/addressing}"
        NS_W = "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}"

        # Primary: delivery URL is in e:NotifyTo/a:Address inside e:Delivery
        delivery_url = None
        for notify in root.iter(f"{NS_E}NotifyTo"):
            addr_el = notify.find(f"{NS_A}Address")
            if addr_el is not None and addr_el.text:
                text = addr_el.text.strip()
                if "subscription" in text.lower():
                    delivery_url = text
                    break

        # Fallback: e:EndTo/a:Address
        if not delivery_url:
            for endto in root.iter(f"{NS_E}EndTo"):
                addr_el = endto.find(f"{NS_A}Address")
                if addr_el is not None and addr_el.text:
                    text = addr_el.text.strip()
                    if "subscription" in text.lower():
                        delivery_url = text
                        break

        # Last resort: any a:Address containing "subscription"
        if not delivery_url:
            for addr_el in root.iter(f"{NS_A}Address"):
                text = (addr_el.text or "").strip()
                if text and "subscription" in text.lower():
                    delivery_url = text
                    break

        if not delivery_url:
            log.error("No delivery URL found in Enumerate response:\n%s",
                      resp_xml[:2000])
            raise WecTransportError(
                "No subscription delivery URL in Enumerate response. "
                "Check that a WEC subscription is configured in XSIAM.")

        self.delivery_url = delivery_url

        # Extract subscription UUID from URL
        # Format: .../WEC/{uuid}/{version}  or  .../subscriptions/{uuid}/{version}
        parts = delivery_url.rstrip("/").split("/")
        if len(parts) >= 2:
            self.subscription_version = parts[-1]
            self.subscription_id = parts[-2]
        else:
            self.subscription_id = parts[-1]
            self.subscription_version = "1"

        # Extract e:Identifier from ReferenceProperties (echoed in event delivery)
        for ident_el in root.iter(f"{NS_E}Identifier"):
            if ident_el.text:
                self.identifier = ident_el.text.strip()
                break

        # Extract heartbeat interval if present (format: PT3600.000S or ms int)
        for hb_el in root.iter(f"{NS_W}Heartbeats"):
            hb_text = (hb_el.text or "").strip()
            try:
                if hb_text.startswith("PT") and hb_text.endswith("S"):
                    secs = float(hb_text[2:-1])
                    self.heartbeat_interval_ms = int(secs * 1000)
                else:
                    self.heartbeat_interval_ms = int(hb_text)
            except (TypeError, ValueError):
                pass

        # Extract bookmark if present (w:Bookmark element from subscription)
        for bm_el in root.iter(f"{NS_W}Bookmark"):
            if _HAS_LXML:
                bm_xml = _etree.tostring(bm_el, encoding="unicode")
            else:
                bm_xml = _stdlib_ET.tostring(bm_el, encoding="unicode")
            self.bookmark = bm_xml

    # ── Bookmark ──────────────────────────────────────────────────────────

    def _build_bookmark_xml(self, events_xml):
        """Build a bookmark XML fragment from the last event's RecordId."""
        last_record_id = None
        for xml_str in reversed(events_xml):
            idx = xml_str.find("<EventRecordID>")
            if idx >= 0:
                end = xml_str.find("</EventRecordID>", idx)
                if end >= 0:
                    last_record_id = xml_str[idx + 15:end]
                    break
        if last_record_id:
            try:
                self._last_record_id = int(last_record_id)
            except ValueError:
                pass
        rid = self._last_record_id or 1
        return (
            f'<BookmarkList>'
            f'<Bookmark Channel="Security" RecordId="{rid}" IsCurrent="true"/>'
            f'</BookmarkList>'
        )

    # ── Events delivery ────────────────────────────────────────────────────

    def deliver_events(self, events_xml, source_host=None):
        """POST a batch of Windows Event XML strings to the WEC endpoint.

        Args:
            events_xml: list of XML strings (each a complete <Event> element)
            source_host: optional per-batch MachineID override
        """
        if not self.delivery_url:
            raise WecTransportError(
                "No delivery URL — call enumerate() first")
        if not events_xml:
            return

        msg_id = _uuid_upper()
        op_id = _uuid_upper()
        seq = self._next_sequence()
        machine = source_host or self.machine_id

        # Wrap each event in <w:Event Action="..."><![CDATA[...]]></w:Event>
        event_parts = []
        for xml_str in events_xml:
            safe = _xml_escape_cdata(xml_str)
            event_parts.append(
                f'<w:Event Action="{ACTION_EVENT_SINGLE}">'
                f'<![CDATA[{safe}]]>'
                f'</w:Event>'
            )
        events_wrapped = "".join(event_parts)

        bookmark_xml = self._build_bookmark_xml(events_xml)

        envelope = _EVENTS_TEMPLATE.format(
            to=self.delivery_url,
            anonymous=ANONYMOUS,
            action=ACTION_EVENTS,
            message_id=msg_id,
            machine_id=machine,
            session_id=self._session_id,
            operation_id=op_id,
            sequence_id=seq,
            identifier=self.identifier or self.subscription_id,
            bookmark_xml=bookmark_xml,
            events_wrapped=events_wrapped,
        )

        resp_xml = self._send_soap(self.delivery_url, envelope)
        self._last_delivery_time = time.time()

        log.debug("WEC delivered %d events (seq=%d)", len(events_xml), seq)
        return resp_xml

    # ── Heartbeat ──────────────────────────────────────────────────────────

    def heartbeat(self):
        """Send a heartbeat (empty body) to keep the subscription alive."""
        if not self.delivery_url:
            raise WecTransportError(
                "No delivery URL — call enumerate() first")

        msg_id = _uuid_upper()
        op_id = _uuid_upper()
        seq = self._next_sequence()

        envelope = _HEARTBEAT_TEMPLATE.format(
            to=self.delivery_url,
            anonymous=ANONYMOUS,
            action=ACTION_HEARTBEAT,
            message_id=msg_id,
            machine_id=self.machine_id,
            session_id=self._session_id,
            operation_id=op_id,
            sequence_id=seq,
            identifier=self.identifier or self.subscription_id,
        )

        resp_xml = self._send_soap(self.delivery_url, envelope)
        log.debug("WEC heartbeat sent (seq=%d)", seq)
        return resp_xml

    # ── Background heartbeat thread ────────────────────────────────────────

    def start_heartbeat_thread(self, interval_s=None):
        """Spawn a daemon thread that sends heartbeats when idle.

        The heartbeat resets whenever deliver_events() is called.
        """
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return

        if interval_s is None:
            interval_s = self.heartbeat_interval_ms / 1000.0

        self._heartbeat_stop.clear()

        def _heartbeat_loop():
            while not self._heartbeat_stop.is_set():
                self._heartbeat_stop.wait(timeout=interval_s)
                if self._heartbeat_stop.is_set():
                    break
                elapsed = time.time() - self._last_delivery_time
                if elapsed >= interval_s:
                    try:
                        self.heartbeat()
                    except Exception as exc:
                        log.warning("Heartbeat failed: %s", exc)

        self._heartbeat_thread = threading.Thread(
            target=_heartbeat_loop,
            daemon=True,
            name="logsim-wec-heartbeat",
        )
        self._heartbeat_thread.start()
        log.info("WEC heartbeat thread started (interval=%ds)", interval_s)

    # ── Cleanup ────────────────────────────────────────────────────────────

    def close(self):
        """Stop heartbeat thread and close the HTTP session."""
        self._heartbeat_stop.set()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5)
        self._session.close()
        log.info("WecClient closed")
