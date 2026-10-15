# SENTINEL on Unraid

1. Install Docker support (default on Unraid).
2. Prefer `docker compose` from this repo, or add a custom template:

- Repository: build from GitHub or push your own image
- Port: `8792` (dashboard)
- Volume: map `/mnt/user/appdata/sentinel` → `/data`
- Extra Parameters: `--cap-drop ALL --security-opt no-new-privileges`
- Only add `NET_RAW` if you need LAN discovery inside the container and understand the risk

3. First run:

```bash
docker compose run --rm sentinel python3 setup.py
docker compose up -d
```

4. Open `http://TOWER:8792` and change the default dashboard password immediately.
