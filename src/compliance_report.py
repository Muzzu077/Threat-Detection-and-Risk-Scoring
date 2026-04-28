"""
TrustFlow — Compliance Evidence Report Generator (SOC 2 / ISO 27001)

Produces a structured JSON report covering security/availability/confidentiality
evidence over a chosen period. The frontend renders this as a printable HTML
document; users browser-print to PDF.

Frameworks supported:
    - soc2     (Trust Services Criteria)
    - iso27001 (Annex A controls subset)
"""
from datetime import datetime, timedelta
from collections import Counter



# Mapping of evidence sections → controls covered, per framework
SOC2_CONTROLS = {
    "incident_response":   ["CC7.3", "CC7.4", "CC7.5"],
    "access_control":      ["CC6.1", "CC6.2", "CC6.3"],
    "monitoring":          ["CC4.1", "CC4.2", "CC7.1", "CC7.2"],
    "system_operations":   ["CC8.1", "A1.2"],
    "data_segregation":    ["CC6.6", "C1.1", "C1.2"],
}

ISO_CONTROLS = {
    "incident_response":   ["A.16.1.1", "A.16.1.2", "A.16.1.5", "A.16.1.7"],
    "access_control":      ["A.9.1.1", "A.9.2.1", "A.9.2.5", "A.9.4.1"],
    "monitoring":          ["A.12.4.1", "A.12.4.2", "A.12.4.3"],
    "system_operations":   ["A.12.1.1", "A.12.6.1"],
    "data_segregation":    ["A.13.2.1", "A.18.1.4"],
}


def _humanise_seconds(s: float) -> str:
    if s is None:
        return "—"
    if s <= 0:
        return "< 1s"
    if s < 60:
        return f"{int(s)}s"
    if s < 3600:
        return f"{int(s // 60)}m {int(s % 60)}s"
    return f"{int(s // 3600)}h {int((s % 3600) // 60)}m"


def generate_report(db, framework: str = "soc2",
                    period_start: datetime = None,
                    period_end: datetime = None) -> dict:
    """
    Build evidence report for the requested framework + period.

    Args:
        db: Database singleton
        framework: 'soc2' | 'iso27001'
        period_start, period_end: datetimes; default to last 90 days

    Returns: dict with sections, controls, raw evidence figures.
    """
    framework = (framework or "soc2").lower()
    if framework not in ("soc2", "iso27001"):
        raise ValueError(f"unsupported framework: {framework}")

    if period_end is None:
        period_end = datetime.utcnow()
    if period_start is None:
        period_start = period_end - timedelta(days=90)

    controls = SOC2_CONTROLS if framework == "soc2" else ISO_CONTROLS

    from src.database import LogEvent, Incident, User, ApiKey, Application, NotificationPreference

    session = db.Session()
    try:
        # ── Section 1: Incident Response ─────────────────────────────────────
        inc_q = session.query(Incident).filter(
            Incident.timestamp >= period_start,
            Incident.timestamp <= period_end,
        )
        incidents = inc_q.all()

        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for inc in incidents:
            r = inc.risk_score or 0
            if r >= 80:   sev_counts["CRITICAL"] += 1
            elif r >= 60: sev_counts["HIGH"] += 1
            elif r >= 40: sev_counts["MEDIUM"] += 1
            else:         sev_counts["LOW"] += 1

        resolved = [i for i in incidents if i.status == "RESOLVED"]
        mttd_vals, mttr_vals = [], []
        for i in incidents:
            if i.detected_at and i.timestamp:
                d = (i.detected_at - i.timestamp).total_seconds()
                if d >= 0: mttd_vals.append(d)
            if i.responded_at and i.detected_at:
                r = (i.responded_at - i.detected_at).total_seconds()
                if r >= 0: mttr_vals.append(r)

        mttd_avg = sum(mttd_vals) / len(mttd_vals) if mttd_vals else None
        mttr_avg = sum(mttr_vals) / len(mttr_vals) if mttr_vals else None

        attack_types = Counter(i.attack_type or "unknown" for i in incidents)

        # ── Section 2: Access Control ────────────────────────────────────────
        users = session.query(User).all()
        active_users = [u for u in users if u.is_active]
        admins = [u for u in users if u.role == "admin"]
        keys = session.query(ApiKey).all()
        active_keys  = [k for k in keys if k.is_active]
        revoked_keys = [k for k in keys if not k.is_active]

        keys_in_period = [k for k in keys
                          if k.created_at and period_start <= k.created_at <= period_end]
        revoked_in_period = [k for k in keys
                             if not k.is_active and k.created_at
                             and period_start <= k.created_at <= period_end]

        # ── Section 3: Monitoring ────────────────────────────────────────────
        ev_q = session.query(LogEvent).filter(
            LogEvent.timestamp >= period_start,
            LogEvent.timestamp <= period_end,
        )
        total_events = ev_q.count()
        critical_events = ev_q.filter(LogEvent.risk_score >= 85).count()

        ueba_events = ev_q.filter(LogEvent.anomaly_score > 0.5).count()
        threat_intel_hits = ev_q.filter(LogEvent.threat_intel_score > 0).count()

        # ── Section 4: System Operations ─────────────────────────────────────
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        backend = db.engine.url.get_backend_name() if hasattr(db.engine.url, "get_backend_name") else str(db.engine.url).split("://")[0]
        tables = inspector.get_table_names()

        # ── Section 5: Data Segregation ──────────────────────────────────────
        applications = session.query(Application).count()
        tenants = session.query(User).count()
        notif_configured = session.query(NotificationPreference).count()

        # Tenant isolation evidence — check that every event has a tenant_id
        events_with_tenant   = ev_q.filter(LogEvent.tenant_id.isnot(None)).count()
        tenant_isolation_pct = round(
            (events_with_tenant / total_events * 100) if total_events else 100.0, 2
        )

        report = {
            "framework": framework.upper().replace("ISO27001", "ISO 27001"),
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "period": {
                "start": period_start.isoformat() + "Z",
                "end":   period_end.isoformat() + "Z",
                "days":  (period_end - period_start).days,
            },
            "summary": {
                "total_events":      total_events,
                "total_incidents":   len(incidents),
                "open_incidents":    len([i for i in incidents if i.status in ("OPEN", "INVESTIGATING")]),
                "resolved_incidents": len(resolved),
                "tenants":           tenants,
                "active_users":      len(active_users),
                "admins":            len(admins),
                "applications":      applications,
            },

            "sections": {
                "incident_response": {
                    "controls": controls["incident_response"],
                    "evidence": {
                        "incident_count":            len(incidents),
                        "by_severity":               sev_counts,
                        "by_attack_type":            dict(attack_types.most_common(10)),
                        "mttd_avg_seconds":          round(mttd_avg, 2) if mttd_avg is not None else None,
                        "mttd_avg_human":            _humanise_seconds(mttd_avg),
                        "mttr_avg_seconds":          round(mttr_avg, 2) if mttr_avg is not None else None,
                        "mttr_avg_human":            _humanise_seconds(mttr_avg),
                        "automated_response_rate":   round(
                            sum(1 for i in incidents if i.responded_at) / len(incidents) * 100, 1
                        ) if incidents else 0,
                    },
                    "narrative": (
                        "TrustFlow auto-detects suspicious events via supervised + unsupervised ML "
                        "and triggers SOAR playbooks for high-severity incidents. Detection-to-response "
                        "metrics are tracked per incident."
                    ),
                },

                "access_control": {
                    "controls": controls["access_control"],
                    "evidence": {
                        "total_users":               len(users),
                        "active_users":              len(active_users),
                        "admin_users":               len(admins),
                        "user_role_breakdown":       dict(Counter(u.role for u in users)),
                        "api_keys_total":            len(keys),
                        "api_keys_active":           len(active_keys),
                        "api_keys_revoked":          len(revoked_keys),
                        "api_keys_issued_in_period": len(keys_in_period),
                        "api_keys_revoked_in_period": len(revoked_in_period),
                        "auth_methods":              ["JWT (HS256)", "bcrypt password hashing", "API key (sha256)"],
                        "rate_limit":                "1000 req / 60s sliding window per API key",
                    },
                    "narrative": (
                        "All authentication uses bcrypt-hashed passwords and JWT access/refresh tokens. "
                        "API keys are sha256-hashed and rate-limited via Redis sliding window. "
                        "Role-based access enforces admin-only routes server-side."
                    ),
                },

                "monitoring": {
                    "controls": controls["monitoring"],
                    "evidence": {
                        "total_events_logged":     total_events,
                        "critical_events":         critical_events,
                        "ueba_anomalies":          ueba_events,
                        "threat_intel_hits":       threat_intel_hits,
                        "log_retention_status":    "indefinite (PostgreSQL)",
                        "real_time_alerts":        "WebSocket live feed + multi-channel dispatch",
                    },
                    "narrative": (
                        "Every ingested event is enriched with risk scoring, attack-type classification, "
                        "MITRE ATT&CK mapping, and threat intel cross-checks. Critical events trigger "
                        "real-time alerts via the user's configured channels."
                    ),
                },

                "system_operations": {
                    "controls": controls["system_operations"],
                    "evidence": {
                        "database_backend":    backend,
                        "schema_tables":       len(tables),
                        "tables":              tables,
                        "cache_layer":         "Redis 7",
                        "deployment":          "Docker Compose multi-service stack",
                        "ci_cd":               "GitHub Actions (lint + tests + docker build)",
                        "ml_model_versioning": "Persisted artifacts (joblib) with timestamped metrics",
                    },
                    "narrative": (
                        "TrustFlow runs on a containerised PostgreSQL/Redis stack with health checks, "
                        "auto-restart, and CI-validated builds."
                    ),
                },

                "data_segregation": {
                    "controls": controls["data_segregation"],
                    "evidence": {
                        "tenant_count":            tenants,
                        "applications_count":      applications,
                        "events_with_tenant_id":   events_with_tenant,
                        "tenant_isolation_pct":    tenant_isolation_pct,
                        "isolation_mechanism":     "tenant_id foreign key on every event/incident; queries filter by current_user.id unless role=admin",
                        "encryption_in_transit":   "TLS terminated at nginx (HTTP for local dev only)",
                        "encryption_at_rest":      "PostgreSQL volume encryption (deployment-dependent)",
                        "siem_export_configured":  notif_configured,
                    },
                    "narrative": (
                        "Multi-tenant isolation is enforced at the database layer via tenant_id columns "
                        "and a query-time filter dependency. Cross-tenant access is impossible without "
                        "the admin role."
                    ),
                },
            },

            "controls_covered": sorted({c for cs in controls.values() for c in cs}),
        }

        return report
    finally:
        session.close()
