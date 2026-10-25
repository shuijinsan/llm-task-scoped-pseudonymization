import json
import re
import hmac
import hashlib
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter

class Pseudonymizer:
    """
    A linkability-aware pseudonymizer for security logs.
    Supports: raw, redaction, global_hmac, scoped_hmac, and task_scoped.
    """
    IPV4_RE = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
    EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
    USER_RE = re.compile(r'(?i)(\buser(?:name)?\s*[=:]\s*<?)([^\s<>,;]+)')
    SOURCE_RE = re.compile(r'Source:([^\s]+)')

    def __init__(self, mode="raw", secret_key=None, window_size_sec=1800, hostnames=(), task_id="task_01"):
        valid_modes = ("raw", "redaction", "global_hmac", "scoped_hmac", "task_scoped")
        if mode not in valid_modes:
            raise ValueError(f"Unknown mode: {mode}")
        if window_size_sec <= 0:
            raise ValueError("Invalid window size")
        if mode.endswith("hmac") or mode == "task_scoped":
            if not isinstance(secret_key, bytes) or len(secret_key) < 16:
                raise ValueError("Missing or invalid HMAC key")

        self.mode = mode
        self.key = secret_key
        self.window_size = window_size_sec
        self.task_id = task_id

        hosts = sorted({h.strip().lower() for h in hostnames if isinstance(h, str) and h.strip()}, key=len, reverse=True)
        self.host_re = None
        if hosts:
            pattern = r'(?<![A-Za-z0-9_.-])(?:' + "|".join(map(re.escape, hosts)) + r')(?![A-Za-z0-9_.-])'
            self.host_re = re.compile(pattern, re.I)

    @staticmethod
    def _get_epoch(timestamp_str):
        dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError("Timestamp must include timezone")
        return dt.astimezone(timezone.utc).timestamp()

    def _token(self, entity_type, value, timestamp_str):
        if self.mode == "raw":
            return value
        if self.mode == "redaction":
            return f"[{entity_type}]"

        if entity_type == "IP":
            value = ipaddress.ip_address(value).compressed
        elif entity_type in ("HOST", "EMAIL", "SOURCE"):
            value = value.casefold()

        bucket = None
        if self.mode == "scoped_hmac":
            epoch = self._get_epoch(timestamp_str)
            bucket = int(epoch // self.window_size)
        elif self.mode == "task_scoped":
            bucket = self.task_id

        message = json.dumps(
            ["v1", entity_type, bucket, value],
            separators=(",", ":"),
            ensure_ascii=False
        ).encode("utf-8")
        
        digest = hmac.new(self.key, message, hashlib.sha256).hexdigest()[:32]
        return f"{entity_type}_{digest}"

    def mask_text(self, text, timestamp_str):
        if self.mode == "raw":
            return text

        text = self.EMAIL_RE.sub(lambda m: self._token("EMAIL", m.group(), timestamp_str), text)
        text = self.SOURCE_RE.sub(lambda m: "Source:" + self._token("SOURCE", m.group(1), timestamp_str), text)

        def replace_ip(match):
            value = match.group()
            try:
                ipaddress.IPv4Address(value)
            except ipaddress.AddressValueError:
                return value
            return self._token("IP", value, timestamp_str)

        text = self.IPV4_RE.sub(replace_ip, text)

        if self.host_re is not None:
            text = self.host_re.sub(lambda m: self._token("HOST", m.group(), timestamp_str), text)

        text = self.USER_RE.sub(lambda m: m.group(1) + self._token("USER", m.group(2), timestamp_str), text)
        return text


def extract_logs():
    """
    Extracts Wazuh and AMiner logs from the AIT-ADS dataset.
    """
    start_ts = 1642993260.0
    end_ts = 1642999093.0
    logs = []
    errors = 0

    with open("data/ait_ads/russellmitchell_wazuh.json", "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                ts = data.get("@timestamp", "")
                if not ts: continue
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                epoch = dt.timestamp()
                
                if start_ts <= epoch <= end_ts:
                    ip = data.get("agent", {}).get("ip", "")
                    desc = data.get("rule", {}).get("description", "")
                    hostname = data.get("predecoder", {}).get("hostname", "")
                    raw_log = data.get("full_log", "")
                    log_text = f"[{ts}] IP:{ip} Host:{hostname} Event:{desc} Log:{raw_log}"
                    logs.append({
                        "timestamp": ts,
                        "epoch": epoch,
                        "source": "wazuh",
                        "hostname": hostname,
                        "asset_id": ip,
                        "text": log_text
                    })
            except Exception:
                errors += 1

    with open("data/ait_ads/russellmitchell_aminer.json", "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                ts_list = data.get("LogData", {}).get("Timestamps", [])
                if not ts_list: continue
                epoch = ts_list[0]
                
                if start_ts <= epoch <= end_ts:
                    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
                    ts = dt.isoformat()
                    raw_log = data.get("LogData", {}).get("RawLogData", [""])[0]
                    aminer_id = data.get("AMiner", {}).get("ID", "")
                    log_text = f"[{ts}] Source:{aminer_id} Audit:{raw_log}"
                    logs.append({
                        "timestamp": ts,
                        "epoch": epoch,
                        "source": "aminer",
                        "hostname": "",
                        "asset_id": aminer_id,
                        "text": log_text
                    })
            except Exception:
                errors += 1

    logs.sort(key=lambda x: x["epoch"])
    return logs, errors

if __name__ == "__main__":
    print("Starting data audit...")
    secret_key = Path(".secrets/hmac.key").read_bytes()
    logs, errors = extract_logs()
    print(f"Total alerts extracted: {len(logs)}")
