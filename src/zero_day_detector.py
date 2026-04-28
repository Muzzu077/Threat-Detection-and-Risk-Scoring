"""
TrustFlow — Zero-Day Detection via Unsupervised Clustering

Concept
-------
Known attack types (sql_injection, xss, etc.) are caught by the supervised
classifier. A *zero-day* is by definition a pattern the supervised model has
never seen — so it lives in the residual space of "normal" events that
nonetheless look anomalous on unsupervised features.

Pipeline
--------
1. Fetch recent events the supervised classifier labelled "normal".
2. Vectorise each event into a small feature space (numeric stats from
   action/resource/risk/time).
3. Run DBSCAN to find dense clusters; treat noise points (label=-1) as
   isolated outliers and dense small clusters as candidate zero-day attack
   patterns.
4. Rank clusters by a novelty score: (cluster_size * mean_risk * unique_resources).

We use sklearn's DBSCAN — HDBSCAN is in requirements as a future upgrade for
variable-density clusters but we keep DBSCAN here so the module works even if
HDBSCAN compilation fails on the host.
"""
import math
from collections import Counter
from datetime import datetime

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler


# ── Feature extraction ───────────────────────────────────────────────────────

def _vectorise_event(e) -> list:
    """Convert a LogEvent ORM row into a small numeric feature vector."""
    risk = float(e.risk_score or 0)
    anomaly = float(e.anomaly_score or 0)
    ti = float(e.threat_intel_score or 0)
    hour = e.timestamp.hour if e.timestamp else 0

    action = (e.action or "").upper()
    method_score = {"GET": 1, "POST": 2, "PUT": 3, "DELETE": 4, "PATCH": 5}.get(action, 0)
    status_failure = 1 if (e.status or "").lower() in ("failure", "error", "fail", "denied") else 0

    resource = (e.resource or "")
    resource_len = len(resource)
    has_query = 1 if "?" in resource else 0
    has_special = 1 if any(c in resource for c in "<>'\"`;|&") else 0
    path_depth = resource.count("/")

    return [
        risk, anomaly, ti, hour,
        method_score, status_failure,
        resource_len, has_query, has_special, path_depth,
    ]


def cluster_zero_day_events(events: list,
                            eps: float = 0.9, min_samples: int = 3) -> dict:
    """
    Cluster events to surface candidate zero-day patterns.

    Args:
        events: list of LogEvent ORM rows (already filtered by tenant)
        eps:    DBSCAN epsilon (smaller → tighter clusters)
        min_samples: minimum points to form a cluster

    Returns:
        {
          clusters: [{cluster_id, size, novelty_score, common_resource,
                      mean_risk, sample_event_ids}],
          isolated_outliers: int,
          total_analysed: int,
        }
    """
    if not events:
        return {"clusters": [], "isolated_outliers": 0, "total_analysed": 0}

    # Focus on events the supervised classifier marked "normal" or "unknown" —
    # known attacks are already handled. We *also* require risk > 25 to skip
    # truly benign traffic; this is the residual band where zero-days hide.
    candidates = [e for e in events
                  if (e.attack_type or "normal") in ("normal", "unknown")
                  and (e.risk_score or 0) > 25]

    if len(candidates) < min_samples:
        return {"clusters": [], "isolated_outliers": 0, "total_analysed": len(candidates)}

    X = np.array([_vectorise_event(e) for e in candidates], dtype=float)
    X_scaled = StandardScaler().fit_transform(X)

    db = DBSCAN(eps=eps, min_samples=min_samples).fit(X_scaled)
    labels = db.labels_

    isolated = int((labels == -1).sum())

    clusters_out = []
    for cid in set(labels):
        if cid == -1:
            continue  # noise
        members = [candidates[i] for i, lab in enumerate(labels) if lab == cid]
        risks = [m.risk_score or 0 for m in members]
        resources = [m.resource or "" for m in members]
        ips = [m.ip or "" for m in members]
        users = [m.user or "" for m in members]

        common_resource = Counter(resources).most_common(1)[0][0] if resources else ""
        unique_resources = len(set(resources))

        # Novelty score — bigger, riskier, more diverse clusters rank higher
        novelty = round(
            len(members) * (sum(risks) / len(risks)) * math.log(1 + unique_resources),
            2,
        )

        clusters_out.append({
            "cluster_id": int(cid),
            "size": len(members),
            "novelty_score": novelty,
            "mean_risk": round(sum(risks) / len(risks), 1),
            "max_risk": round(max(risks), 1),
            "common_resource": common_resource[:120],
            "unique_resources": unique_resources,
            "unique_ips": len(set(ips)),
            "unique_users": len(set(users)),
            "sample_event_ids": [m.id for m in members[:5]],
            "first_seen": min((m.timestamp for m in members if m.timestamp), default=None),
            "last_seen":  max((m.timestamp for m in members if m.timestamp), default=None),
        })

    # Rank: highest novelty first
    clusters_out.sort(key=lambda c: c["novelty_score"], reverse=True)

    # Stringify timestamps (the iso step has to come last so dict keys above stay clean)
    for c in clusters_out:
        if c["first_seen"]: c["first_seen"] = c["first_seen"].isoformat()
        if c["last_seen"]:  c["last_seen"]  = c["last_seen"].isoformat()

    return {
        "clusters": clusters_out,
        "isolated_outliers": isolated,
        "total_analysed": len(candidates),
        "computed_at": datetime.utcnow().isoformat(),
    }
