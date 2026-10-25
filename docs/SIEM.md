# SENTINEL — SIEM / centralized logging

## Enable

Edit `~/.sentinel/config.json`:

```json
"alerting": {
  "siem": {
    "enabled": true,
    "format": "json",
    "min_severity": "LOW",
    "syslog": {
      "enabled": true,
      "host": "siem.example.local",
      "port": 514,
      "protocol": "udp"
    },
    "splunk_hec": {
      "enabled": false,
      "url": "https://splunk.example:8088/services/collector",
      "token": "YOUR-HEC-TOKEN",
      "index": "security",
      "verify_tls": true
    },
    "webhook": {
      "enabled": false,
      "url": "https://siem.example/hooks/sentinel"
    },
    "ship_file": {
      "enabled": true,
      "path": ""
    }
  }
}
```

`format`: `json` (default) or `cef` (for syslog CEF parsers).

## Commands

```bash
python3 sentinel.py siem status
python3 sentinel.py siem test
python3 sentinel.py siem cef-sample
```

## Ship file

When SIEM is enabled, events also append to:

`~/.sentinel/data/siem_ship.jsonl`

Point Filebeat / Elastic Agent / Wazuh agent at that path for air-gapped or buffered delivery.

## Safety

- Disabled by default
- No credentials logged
- TLS verify on by default for HEC/webhook
