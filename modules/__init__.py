# Sentinel extension modules — TrinTech Digital Defense
try:
    from .phase1 import (
        quiet_should_emit, auto_quarantine, embed_canary_beacon,
        handle_canary_beacon, client_onboard, phase1_self_check,
        tls_agent_headers, CRITICAL_ALERTS,
    )
except ImportError:
    from phase1 import (
        quiet_should_emit, auto_quarantine, embed_canary_beacon,
        handle_canary_beacon, client_onboard, phase1_self_check,
        tls_agent_headers, CRITICAL_ALERTS,
    )

try:
    from .phase2 import (
        mirage_deploy, score_interaction, process_canary_scan,
        timeline_record, timeline_report, adaptive_decoy_set,
        phase2_self_check, top_scores, generate_decoy_content,
    )
except ImportError:
    try:
        from phase2 import (
            mirage_deploy, score_interaction, process_canary_scan,
            timeline_record, timeline_report, adaptive_decoy_set,
            phase2_self_check, top_scores, generate_decoy_content,
        )
    except ImportError:
        pass

__all__ = [
    "quiet_should_emit", "auto_quarantine", "embed_canary_beacon",
    "handle_canary_beacon", "client_onboard", "phase1_self_check",
    "tls_agent_headers", "CRITICAL_ALERTS",
    "mirage_deploy", "score_interaction", "process_canary_scan",
    "timeline_record", "timeline_report", "adaptive_decoy_set",
    "phase2_self_check", "top_scores", "generate_decoy_content",
]
