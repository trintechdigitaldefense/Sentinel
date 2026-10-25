# SENTINEL → Splunk (HEC)

## 1. Splunk side

1. Settings → Data Inputs → **HTTP Event Collector** → New Token  
2. Enable token, note the **token value**  
3. Default index e.g. `security` or `main`  
4. HEC port usually **8088** (TLS)

## 2. Sentinel configure

```bash
python3 sentinel.py siem splunk-configure \
  --url https://YOUR_SPLUNK:8088 \
  --token YOUR_HEC_TOKEN \
  --index security
```

Or from environment:

```bash
export SPLUNK_HEC_URL=https://YOUR_SPLUNK:8088
export SPLUNK_HEC_TOKEN=YOUR_HEC_TOKEN
export SPLUNK_HEC_INDEX=security
python3 sentinel.py siem splunk env
```

Self-signed cert lab:

```bash
python3 sentinel.py siem splunk-configure --url https://splunk:8088 --token XXX --index main --no-verify
```

## 3. Test

```bash
python3 sentinel.py siem splunk health
python3 sentinel.py siem test
```

## 4. Search in Splunk

```
sourcetype=sentinel:alert
source=sentinel
```

```
index=security sourcetype=sentinel:alert title=REVERSE_SHELL
```

## 5. Flush local buffer

If events were only written to the ship file:

```bash
python3 sentinel.py siem splunk flush
```

## Config keys

`~/.sentinel/config.json` → `alerting.siem.splunk_hec`:

| Key | Meaning |
|-----|---------|
| enabled | true |
| url | `https://host:8088` (collector path auto-added) |
| token | HEC token |
| index | optional index name |
| source | default `sentinel` |
| sourcetype | default `sentinel:alert` |
| verify_tls | default true |

All Sentinel alerts (hunt, critical, SSH blocks, etc.) fan out to HEC when SIEM + splunk_hec are enabled.
