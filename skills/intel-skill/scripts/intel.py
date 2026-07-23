"""Intel Skill — IOC reputation & enrichment.

Shim layer for backward compatibility.
All logic has been moved to the new modular architecture:
  _utils.py         — cache, embeddings, validation
  osint_gatherer.py — external API calls
  data_enrichment.py — local context (DNS, RDAP, heuristics)
  threat_scoring.py  — risk scoring math
  intel_facade.py   — command orchestration & rendering
"""

from __future__ import annotations

# ── Re-export infrastructure for downstream imports ──
from _utils import (
    _DOMAIN_RE,
    _HASH_RE,
    _IPV4_RE,
    _IPV6_RE,
    cache_get,
    cache_set,
    cosine_similarity,
    embed_texts,
    is_private_ip,
    looks_like_domain,
    looks_like_hash,
    looks_like_ip,
)
from data_enrichment import (
    dns_lookup,
    hebrew_phishing_detection,
    is_high_risk_country,
    is_known_good_asn,
    israeli_domain_monitoring,
    rdap,
    reverse_dns,
)

# ── Re-export new public API from facade ──
from intel_facade import (
    cmd_attack,
    cmd_cert_il,
    cmd_cluster,
    cmd_dns,
    cmd_feeds,
    cmd_domain,
    cmd_hash,
    cmd_ip,
    cmd_israeli_monitor,
    cmd_sweep,
    cmd_whois,
    main,
)
from osint_gatherer import (
    abuseipdb,
    cert_il_feed,
    ipapi_co,
    maltiverse_hash,
    maltiverse_ip,
    shodan,
    virustotal,
)
from threat_scoring import (
    score_domain,
    score_hash,
    score_ip,
    score_with_israeli_factors,
    verdict_emoji,
)

# ── Backward-compat aliases (old private names → new public names) ──
_abuseipdb = abuseipdb
_maltiverse_ip = maltiverse_ip
_virustotal = virustotal
_score_ip = score_ip

__all__ = [
    # CLI / facade
    "main",
    "cmd_ip",
    "cmd_domain",
    "cmd_hash",
    "cmd_sweep",
    "cmd_dns",
    "cmd_whois",
    "cmd_israeli_monitor",
    "cmd_cert_il",
    "cmd_cluster",
    "cmd_attack",
    "cmd_feeds",
    # Backward-compat aliases
    "_abuseipdb",
    "_maltiverse_ip",
    "_virustotal",
    "_score_ip",
    # Infra exports
    "_IPV4_RE",
    "_IPV6_RE",
    "_DOMAIN_RE",
    "_HASH_RE",
    "cache_get",
    "cache_set",
    "embed_texts",
    "cosine_similarity",
    "is_private_ip",
    "looks_like_ip",
    "looks_like_domain",
    "looks_like_hash",
    # OSINT
    "abuseipdb",
    "maltiverse_ip",
    "maltiverse_hash",
    "virustotal",
    "shodan",
    "ipapi_co",
    "cert_il_feed",
    # Enrichment
    "dns_lookup",
    "rdap",
    "reverse_dns",
    "hebrew_phishing_detection",
    "israeli_domain_monitoring",
    "is_high_risk_country",
    "is_known_good_asn",
    # Scoring
    "score_ip",
    "score_domain",
    "score_hash",
    "score_with_israeli_factors",
    "verdict_emoji",
]

if __name__ == "__main__":
    raise SystemExit(main())
