# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Field evidence pack for pilots and client handoff.

Collects local artifacts + multi-host agent snapshots + field-soak report
into a hashed zip suitable for TrinTech pilot delivery (not full legal CoC).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import socket
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("sentinel.field_evidence")


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def collect(
    hours: int = 24,
    include_soak: bool = True,
    include_multi_host: bool = True,
    out_dir: Optional[Path] = None,
    run_soak: bool = False,
    soak_confirm: bool = False,
) -> dict[str, Any]:
    """Build field evidence directory + zip + MANIFEST with SHA-256."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    work = Path(out_dir) if out_dir else (_data() / f"field_evidence_{stamp}")
    work.mkdir(parents=True, exist_ok=True)

    files_meta = []
    data = _data()

    # Optional soak first so report is fresh
    soak_result = None
    if run_soak:
        try:
            from modules.field_soak import run_field_soak
            soak_result = run_field_soak(confirm=soak_confirm, run_sim=soak_confirm)
            (work / "field_soak_inline.json").write_text(json.dumps(soak_result, indent=2, default=str))
            files_meta.append({"name": "field_soak_inline.json", "source": "generated"})
        except Exception as e:
            log.warning("soak: %s", e)
            (work / "field_soak_error.json").write_text(json.dumps({"error": str(e)}))
            files_meta.append({"name": "field_soak_error.json", "source": "error"})

    copy_names = [
        "alerts.log",
        "heartbeat.json",
        "devices.json",
        "fleet_devices.json",
        "remote_agents.json",
        "field_soak_report.json",
        "go_live_report.json",
        "ssh_last_scan.json",
        "iptables_blocklist.json",
        "behavioral_baseline.json",
        "self_integrity.json",
    ]
    for name in copy_names:
        src = data / name
        if src.exists() and src.is_file():
            dest = work / name
            try:
                shutil.copy2(src, dest)
                files_meta.append({"name": name, "source": str(src), "sha256": _sha256(dest)})
            except Exception as e:
                log.debug("copy %s: %s", name, e)

    # integrity baseline if present
    fim = data / "integrity_baseline" / "integrity_baseline.json"
    if fim.exists():
        dest = work / "integrity_baseline.json"
        shutil.copy2(fim, dest)
        files_meta.append({"name": "integrity_baseline.json", "source": str(fim), "sha256": _sha256(dest)})

    # multi-host snapshot
    mh = None
    if include_multi_host:
        try:
            from modules.multi_host import status as mh_status
            mh = mh_status()
            (work / "multi_host_status.json").write_text(json.dumps(mh, indent=2, default=str))
            files_meta.append({"name": "multi_host_status.json", "source": "generated", "sha256": _sha256(work / "multi_host_status.json")})
        except Exception as e:
            (work / "multi_host_status.json").write_text(json.dumps({"error": str(e)}))
            files_meta.append({"name": "multi_host_status.json", "source": "error"})

        # copy central agent reports if any
        try:
            from modules.central_agent import agents_dir
            ad = agents_dir()
            if ad.exists():
                dest_dir = work / "agent_reports"
                dest_dir.mkdir(exist_ok=True)
                n = 0
                for p in sorted(ad.glob("*.json"))[:50]:
                    shutil.copy2(p, dest_dir / p.name)
                    files_meta.append({"name": f"agent_reports/{p.name}", "sha256": _sha256(dest_dir / p.name)})
                    n += 1
                (work / "agent_reports_count.txt").write_text(str(n))
        except Exception as e:
            log.debug("agent reports: %s", e)

    # doctor snapshot (best-effort)
    try:
        from modules.doctor import run_doctor
        # may print — capture via status dict if available
        pass
    except Exception:
        pass

    try:
        from modules.phase5 import heartbeat_status
        hb = heartbeat_status()
        (work / "heartbeat_status.json").write_text(json.dumps(hb, indent=2, default=str))
        files_meta.append({"name": "heartbeat_status.json", "sha256": _sha256(work / "heartbeat_status.json")})
    except Exception as e:
        log.debug("hb: %s", e)

    meta = {
        "product": "Sentinel",
        "org": "TrinTech Digital Defense",
        "purpose": "Field pilot evidence pack",
        "created": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "hours_window_note": hours,
        "files": files_meta,
        "multi_host_ready": bool((mh or {}).get("multi_host_ready")) if mh else False,
        "disclaimer": (
            "Local SHA-256 integrity only — not a full legal chain of custody. "
            "Suitable for pilot delivery and internal review."
        ),
        "include_soak": include_soak,
        "soak_result_ok": (soak_result or {}).get("ok") if soak_result else None,
    }
    manifest = work / "MANIFEST.json"
    manifest.write_text(json.dumps(meta, indent=2, default=str))
    files_meta.append({"name": "MANIFEST.json", "sha256": _sha256(manifest)})

    # rewrite manifest with final hashes
    meta["files"] = files_meta
    manifest.write_text(json.dumps(meta, indent=2, default=str))

    zpath = work.with_suffix(".zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in work.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(work).as_posix())

    pack_hash = _sha256(zpath)
    (work / "PACK.sha256").write_text(f"{pack_hash}  {zpath.name}\n")

    return {
        "ok": True,
        "folder": str(work),
        "zip": str(zpath),
        "sha256": pack_hash,
        "file_count": len(files_meta),
        "multi_host_ready": meta.get("multi_host_ready"),
        "disclaimer": meta["disclaimer"],
    }
