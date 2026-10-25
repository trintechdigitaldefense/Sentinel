# SENTINEL — Host go-live (operational setup)

One command to prepare a **new host** before pilot/field-soak.

```bash
cd Sentinel
python3 setup.py
python3 sentinel.py go-live
python3 sentinel.py go-live --service   # also try always-on service
```

## What it does

| Step | Action |
|------|--------|
| directories | `~/.sentinel` data dirs, permissions |
| **Alert channel** | Enables local SIEM ship file; reports WhatsApp/email/Splunk |
| **Persistence baseline** | Creates persistence baseline |
| **SUID baseline** | Creates SUID inventory baseline |
| **FIM baseline** | Builds file integrity baseline |
| **Canaries** | Deploys deception / canary files |
| **Heartbeat** | Writes first heartbeat |
| **Service** | Optional with `--service` |

Report: `~/.sentinel/data/go_live_report.json`

## Then

```bash
python3 sentinel.py pilot
python3 sentinel.py field-soak --confirm
python3 sentinel.py dashboard-url
```

## Remote alerts

`go-live` always turns on the **local ship file**. For WhatsApp or Splunk:

```bash
# Splunk
python3 sentinel.py siem splunk-configure --url https://SPLUNK:8088 --token TOKEN --index security

# WhatsApp — set in ~/.sentinel/config.json under alerting.whatsapp
```

## Sales / runbook

Day-0 step 2–7 on the one-page runbook can be replaced by:

`python3 sentinel.py go-live --service`
