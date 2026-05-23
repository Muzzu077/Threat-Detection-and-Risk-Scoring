from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey, Index, text
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime
import os

Base = declarative_base()


# ─── Auth Models ─────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    display_name = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    role = Column(String, default="user")  # "user" | "admin"

    api_keys = relationship("ApiKey", back_populates="owner")


class ApiKey(Base):
    __tablename__ = 'api_keys'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    application_id = Column(Integer, ForeignKey('applications.id'), nullable=True, index=True)
    name = Column(String, default="Default")
    prefix = Column(String, nullable=False)
    key_hash = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)

    owner = relationship("User", back_populates="api_keys")
    application = relationship("Application", back_populates="api_keys")


class Application(Base):
    """A tenant-owned application that ingests events into TrustFlow."""
    __tablename__ = 'applications'

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    name = Column(String, nullable=False)
    slug = Column(String, nullable=False, index=True)
    description = Column(Text, default="")
    environment = Column(String, default="production")  # production | staging | development
    status = Column(String, default="active")  # active | paused | archived
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    api_keys = relationship("ApiKey", back_populates="application")


class RefreshToken(Base):
    __tablename__ = 'refresh_tokens'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    token_hash = Column(String, unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    revoked = Column(Boolean, default=False)


class Playbook(Base):
    """User-defined SOAR playbook: trigger + ordered list of steps."""
    __tablename__ = 'playbooks'

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, default="")
    enabled = Column(Boolean, default=True)

    # Trigger
    trigger_attack_types = Column(Text, default="")  # comma-separated
    trigger_min_risk     = Column(Float, default=70.0)
    trigger_application_id = Column(Integer, ForeignKey('applications.id'), nullable=True)

    # Steps — JSON array of {type, params}
    steps = Column(Text, default="[]")

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class NotificationPreference(Base):
    """Per-tenant alert routing — where a user's threats get sent."""
    __tablename__ = 'notification_preferences'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), unique=True, nullable=False, index=True)

    # Channel destinations
    telegram_chat_id  = Column(String, default="")
    whatsapp_number   = Column(String, default="")  # E.164 format e.g. +14155552671
    email_address     = Column(String, default="")

    # Channel toggles
    enable_telegram   = Column(Boolean, default=False)
    enable_whatsapp   = Column(Boolean, default=False)
    enable_email      = Column(Boolean, default=False)

    # Filters
    min_severity      = Column(String, default="HIGH")  # CRITICAL | HIGH | MEDIUM | LOW

    # SIEM export (Phase 3)
    siem_type         = Column(String, default="")  # "splunk" | "elastic" | "datadog" | "webhook" | ""
    siem_url          = Column(String, default="")
    siem_token        = Column(String, default="")
    siem_index        = Column(String, default="trustflow")  # Splunk index / Elastic index name
    enable_siem       = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ─── Core Models ─────────────────────────────────────────────────────────────

class LogEvent(Base):
    __tablename__ = 'log_events'
    __table_args__ = (
        Index('idx_log_events_tenant_app_timestamp', 'tenant_id', 'application_id', text('timestamp DESC')),
    )

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user = Column(String)
    role = Column(String)
    ip = Column(String)
    action = Column(String)
    status = Column(String)
    resource = Column(String)

    # Risk Data
    anomaly_score = Column(Float)
    risk_score = Column(Float)
    time_risk = Column(Float)
    role_risk = Column(Float)
    resource_risk = Column(Float)
    explanation = Column(Text)

    # ML Engine
    attack_type = Column(String, default="unknown")
    ml_confidence = Column(Float, default=0.0)

    # Threat Intelligence
    country = Column(String, default="UNKNOWN")
    threat_intel_score = Column(Float, default=0.0)
    threat_intel_reason = Column(Text, default="")

    # SOAR
    response_actions = Column(Text, default="")

    # Multi-tenant
    tenant_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    application_id = Column(Integer, ForeignKey('applications.id'), nullable=True, index=True)

class Incident(Base):
    __tablename__ = 'incidents'

    id = Column(Integer, primary_key=True)
    log_event_id = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="OPEN")
    owner = Column(String, default="Unassigned")
    note = Column(Text, default="")
    risk_score = Column(Float)
    user = Column(String)
    action = Column(String)
    response_actions = Column(Text, default="")
    attack_type = Column(String, default="unknown")
    detected_at = Column(DateTime, default=datetime.utcnow)
    responded_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    # Multi-tenant
    tenant_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    application_id = Column(Integer, ForeignKey('applications.id'), nullable=True, index=True)

class AttackChain(Base):
    """Groups related high-risk events into kill chains."""
    __tablename__ = 'attack_chains'

    id = Column(Integer, primary_key=True)
    chain_id = Column(String, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    max_risk = Column(Float)
    severity = Column(String)
    involved_ips = Column(Text, default="")
    involved_users = Column(Text, default="")
    event_ids = Column(Text, default="")
    start_time = Column(DateTime)
    end_time = Column(DateTime)

    # Multi-tenant
    tenant_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)


class Database:
    def __init__(self):
        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            raise RuntimeError(
                "DATABASE_URL is not set. TrustFlow requires PostgreSQL — "
                "set DATABASE_URL=postgresql://user:pass@host:5432/dbname"
            )
        if not db_url.startswith(("postgresql://", "postgresql+psycopg2://")):
            raise RuntimeError(
                f"DATABASE_URL must point to PostgreSQL (got: {db_url.split('://')[0]}://...). "
                "SQLite is no longer supported."
            )
        self.engine = create_engine(db_url, echo=False, pool_pre_ping=True)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self._migrate_tenant_columns()

    def _migrate_tenant_columns(self):
        from sqlalchemy import text, inspect
        inspector = inspect(self.engine)
        migrations = [
            ("log_events", "tenant_id", "INTEGER"),
            ("incidents", "tenant_id", "INTEGER"),
            ("attack_chains", "tenant_id", "INTEGER"),
            ("log_events", "application_id", "INTEGER"),
            ("incidents", "application_id", "INTEGER"),
            ("api_keys", "application_id", "INTEGER"),
            ("notification_preferences", "siem_type",   "VARCHAR"),
            ("notification_preferences", "siem_url",    "VARCHAR"),
            ("notification_preferences", "siem_token",  "VARCHAR"),
            ("notification_preferences", "siem_index",  "VARCHAR"),
            ("notification_preferences", "enable_siem", "BOOLEAN"),
        ]
        with self.engine.connect() as conn:
            for table, column, col_type in migrations:
                if table in inspector.get_table_names():
                    existing_cols = [c["name"] for c in inspector.get_columns(table)]
                    if column not in existing_cols:
                        try:
                            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
                            conn.commit()
                        except Exception:
                            pass
        # Backfill: ensure every tenant with API keys / events has at least
        # one Application, and orphan rows get assigned to it.
        self._backfill_default_applications()

    def _backfill_default_applications(self):
        from sqlalchemy import text
        session = self.Session()
        try:
            # Find tenant_ids that have data but no Application
            tenant_ids = set()
            for row in session.execute(text("SELECT DISTINCT user_id FROM api_keys")).fetchall():
                if row[0] is not None:
                    tenant_ids.add(row[0])
            for row in session.execute(text("SELECT DISTINCT tenant_id FROM log_events WHERE tenant_id IS NOT NULL")).fetchall():
                if row[0] is not None:
                    tenant_ids.add(row[0])

            for tid in tenant_ids:
                existing = session.query(Application).filter(Application.tenant_id == tid).first()
                if existing:
                    default_app = existing
                else:
                    default_app = Application(
                        tenant_id=tid,
                        name="Default Application",
                        slug=f"default-{tid}",
                        description="Auto-created application for legacy data.",
                        environment="production",
                        status="active",
                    )
                    session.add(default_app)
                    session.flush()
                # Backfill orphan keys / events / incidents for this tenant
                session.execute(
                    text("UPDATE api_keys SET application_id = :aid WHERE user_id = :tid AND application_id IS NULL"),
                    {"aid": default_app.id, "tid": tid},
                )
                session.execute(
                    text("UPDATE log_events SET application_id = :aid WHERE tenant_id = :tid AND application_id IS NULL"),
                    {"aid": default_app.id, "tid": tid},
                )
                session.execute(
                    text("UPDATE incidents SET application_id = :aid WHERE tenant_id = :tid AND application_id IS NULL"),
                    {"aid": default_app.id, "tid": tid},
                )
            session.commit()
        except Exception as e:
            print(f"Backfill applications failed: {e}")
            session.rollback()
        finally:
            session.close()

    def get_session(self):
        return self.Session()

    def _apply_tenant_filter(self, query, model, tenant_id, user_role=None):
        """Apply tenant scoping. Admins see all data, users see only their own."""
        if user_role == "admin" or tenant_id is None:
            return query
        return query.filter(model.tenant_id == tenant_id)

    def insert_event(self, event_dict):
        session = self.Session()
        try:
            event = LogEvent(**event_dict)
            session.add(event)
            session.flush()

            incident_id = None
            if event_dict.get('risk_score', 0) > 80:
                incident = Incident(
                    log_event_id=event.id,
                    risk_score=event_dict['risk_score'],
                    user=event_dict.get('user', ''),
                    action=event_dict.get('action', ''),
                    timestamp=event.timestamp,
                    attack_type=event_dict.get('attack_type', 'unknown'),
                    detected_at=datetime.utcnow(),
                    tenant_id=event_dict.get('tenant_id'),
                    application_id=event_dict.get('application_id'),
                )
                session.add(incident)
                session.flush()
                incident_id = incident.id

            session.commit()
            return event.id, incident_id
        except Exception as e:
            print(f"Error inserting event: {e}")
            session.rollback()
            return None, None
        finally:
            session.close()

    def fetch_all_events(self, limit=500, tenant_id=None, user_role=None):
        session = self.Session()
        try:
            query = session.query(LogEvent)
            query = self._apply_tenant_filter(query, LogEvent, tenant_id, user_role)
            return query.order_by(LogEvent.timestamp.desc()).limit(limit).all()
        finally:
            session.close()

    def fetch_events_paginated(self, page=1, limit=50, min_risk=0, tenant_id=None, user_role=None):
        session = self.Session()
        try:
            query = session.query(LogEvent)
            query = self._apply_tenant_filter(query, LogEvent, tenant_id, user_role)
            if min_risk > 0:
                query = query.filter(LogEvent.risk_score >= min_risk)
            total = query.count()
            events = query.order_by(LogEvent.timestamp.desc()).offset((page - 1) * limit).limit(limit).all()
            return events, total
        finally:
            session.close()

    def fetch_incidents(self, status=None, tenant_id=None, user_role=None):
        session = self.Session()
        try:
            q = session.query(Incident)
            q = self._apply_tenant_filter(q, Incident, tenant_id, user_role)
            if status:
                q = q.filter(Incident.status == status)
            return q.order_by(Incident.timestamp.desc()).all()
        finally:
            session.close()

    def update_incident_status(self, incident_id, new_status, owner=None, tenant_id=None, user_role=None):
        session = self.Session()
        try:
            q = session.query(Incident).filter(Incident.id == incident_id)
            q = self._apply_tenant_filter(q, Incident, tenant_id, user_role)
            inc = q.first()
            if inc:
                inc.status = new_status
                if owner:
                    inc.owner = owner
                if new_status == "RESOLVED":
                    inc.resolved_at = datetime.utcnow()
                session.commit()
        finally:
            session.close()

    def update_incident_note(self, incident_id, note, tenant_id=None, user_role=None):
        session = self.Session()
        try:
            q = session.query(Incident).filter(Incident.id == incident_id)
            q = self._apply_tenant_filter(q, Incident, tenant_id, user_role)
            inc = q.first()
            if inc:
                inc.note = note
                session.commit()
        finally:
            session.close()

    def update_incident_response(self, incident_id, response_json: str,
                                 tenant_id=None, user_role=None):
        session = self.Session()
        try:
            q = session.query(Incident).filter(Incident.id == incident_id)
            q = self._apply_tenant_filter(q, Incident, tenant_id, user_role)
            inc = q.first()
            if inc:
                inc.response_actions = response_json
                inc.responded_at = datetime.utcnow()
                session.commit()
        finally:
            session.close()

    def get_incident_details(self, incident_id, tenant_id=None, user_role=None):
        session = self.Session()
        try:
            q = session.query(Incident).filter(Incident.id == incident_id)
            q = self._apply_tenant_filter(q, Incident, tenant_id, user_role)
            incident = q.first()
            if incident:
                log_event = session.query(LogEvent).filter(LogEvent.id == incident.log_event_id).first()
                return incident, log_event
            return None, None
        finally:
            session.close()

    def get_stats(self, tenant_id=None, user_role=None):
        session = self.Session()
        try:
            from sqlalchemy import func

            eq = session.query(LogEvent)
            eq = self._apply_tenant_filter(eq, LogEvent, tenant_id, user_role)

            iq = session.query(Incident)
            iq = self._apply_tenant_filter(iq, Incident, tenant_id, user_role)

            total_events = eq.count()
            open_incidents = iq.filter(Incident.status.in_(["OPEN", "INVESTIGATING"])).count()
            critical_events = eq.filter(LogEvent.risk_score >= 85).count()
            high_events = eq.filter(LogEvent.risk_score >= 61, LogEvent.risk_score < 85).count()

            avg_risk_result = session.query(func.avg(LogEvent.risk_score))
            avg_risk_result = self._apply_tenant_filter(avg_risk_result, LogEvent, tenant_id, user_role).scalar()
            avg_risk = round(float(avg_risk_result or 0), 1)

            resolved_q = iq.filter(Incident.status == "RESOLVED")

            return {
                "total_events": total_events,
                "open_incidents": open_incidents,
                "critical_events": critical_events,
                "high_events": high_events,
                "avg_risk": avg_risk,
                "resolved_incidents": resolved_q.count()
            }
        finally:
            session.close()

    def get_mttd_mttr_stats(self, tenant_id=None, user_role=None):
        from datetime import timedelta
        session = self.Session()
        try:
            base_q = session.query(Incident)
            base_q = self._apply_tenant_filter(base_q, Incident, tenant_id, user_role)

            incidents_with_detect = base_q.filter(
                Incident.detected_at.isnot(None),
                Incident.timestamp.isnot(None)
            ).all()

            mttd_values = []
            for inc in incidents_with_detect:
                if inc.detected_at and inc.timestamp:
                    diff = (inc.detected_at - inc.timestamp).total_seconds()
                    if diff >= 0:
                        mttd_values.append(diff)

            mttd_avg = round(sum(mttd_values) / len(mttd_values), 2) if mttd_values else 0

            incidents_with_response = [i for i in incidents_with_detect if i.responded_at]

            mttr_values = []
            for inc in incidents_with_response:
                if inc.responded_at and inc.detected_at:
                    diff = (inc.responded_at - inc.detected_at).total_seconds()
                    if diff >= 0:
                        mttr_values.append(diff)

            mttr_avg = round(sum(mttr_values) / len(mttr_values), 2) if mttr_values else 0

            incidents_resolved = [i for i in incidents_with_detect if i.resolved_at]

            resolution_values = []
            for inc in incidents_resolved:
                if inc.resolved_at and inc.detected_at:
                    diff = (inc.resolved_at - inc.detected_at).total_seconds()
                    if diff >= 0:
                        resolution_values.append(diff)

            resolution_avg = round(sum(resolution_values) / len(resolution_values), 2) if resolution_values else 0

            now = datetime.utcnow()
            mttd_trend = []
            mttr_trend = []
            for days_ago in range(6, -1, -1):
                day_start = (now - timedelta(days=days_ago)).replace(hour=0, minute=0, second=0, microsecond=0)
                day_end = day_start + timedelta(days=1)
                date_str = day_start.strftime("%Y-%m-%d")

                day_incidents = [inc for inc in incidents_with_detect
                                 if inc.detected_at and day_start <= inc.detected_at < day_end]
                day_mttd = []
                for inc in day_incidents:
                    if inc.timestamp:
                        diff = (inc.detected_at - inc.timestamp).total_seconds()
                        if diff >= 0:
                            day_mttd.append(diff)
                mttd_trend.append({
                    "date": date_str,
                    "mttd_seconds": round(sum(day_mttd) / len(day_mttd), 2) if day_mttd else 0
                })

                day_resp = [inc for inc in incidents_with_response
                            if inc.responded_at and day_start <= inc.responded_at < day_end]
                day_mttr = []
                for inc in day_resp:
                    if inc.detected_at:
                        diff = (inc.responded_at - inc.detected_at).total_seconds()
                        if diff >= 0:
                            day_mttr.append(diff)
                mttr_trend.append({
                    "date": date_str,
                    "mttr_seconds": round(sum(day_mttr) / len(day_mttr), 2) if day_mttr else 0
                })

            return {
                "mttd_avg_seconds": mttd_avg,
                "mttr_avg_seconds": mttr_avg,
                "resolution_avg_seconds": resolution_avg,
                "mttd_trend": mttd_trend,
                "mttr_trend": mttr_trend,
                "total_incidents_analyzed": len(incidents_with_detect),
                "incidents_with_response": len(incidents_with_response),
                "incidents_resolved": len(incidents_resolved),
            }
        finally:
            session.close()

    def get_recent_events_for_graph(self, limit=200, tenant_id=None, user_role=None):
        session = self.Session()
        try:
            query = session.query(LogEvent).filter(LogEvent.risk_score >= 50)
            query = self._apply_tenant_filter(query, LogEvent, tenant_id, user_role)
            return query.order_by(LogEvent.timestamp.desc()).limit(limit).all()
        finally:
            session.close()

    def save_attack_chain(self, chain: dict):
        import json as _json
        session = self.Session()
        try:
            existing = session.query(AttackChain).filter(AttackChain.chain_id == chain["chain_id"]).first()
            if existing:
                return

            from datetime import datetime as dt
            ac = AttackChain(
                chain_id=chain["chain_id"],
                max_risk=chain.get("max_risk", 0),
                severity=chain.get("severity", "low"),
                involved_ips=", ".join(chain.get("involved_ips", [])),
                involved_users=", ".join(chain.get("involved_users", [])),
                event_ids=_json.dumps([e.get("id", 0) for e in chain.get("events", [])]),
                start_time=dt.fromisoformat(chain["start_time"]) if chain.get("start_time") else None,
                end_time=dt.fromisoformat(chain["end_time"]) if chain.get("end_time") else None,
                tenant_id=chain.get("tenant_id"),
            )
            session.add(ac)
            session.commit()
        except Exception as e:
            print(f"Error saving attack chain: {e}")
            session.rollback()
        finally:
            session.close()

    # ─── User Management ─────────────────────────────────────────────────────

    def create_user(self, email: str, password_hash: str, display_name: str = "", role: str = "user"):
        session = self.Session()
        try:
            user = User(
                email=email,
                password_hash=password_hash,
                display_name=display_name,
                role=role,
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            session.expunge(user)
            return user
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def get_user_by_email(self, email: str):
        session = self.Session()
        try:
            user = session.query(User).filter(User.email == email).first()
            if user:
                session.expunge(user)
            return user
        finally:
            session.close()

    def get_user_by_id(self, user_id: int):
        session = self.Session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if user:
                session.expunge(user)
            return user
        finally:
            session.close()

    # ─── Application Management ──────────────────────────────────────────────

    def list_applications(self, tenant_id=None, user_role=None):
        session = self.Session()
        try:
            q = session.query(Application)
            if user_role != "admin" and tenant_id is not None:
                q = q.filter(Application.tenant_id == tenant_id)
            apps = q.order_by(Application.created_at.desc()).all()
            for a in apps:
                session.expunge(a)
            return apps
        finally:
            session.close()

    def get_application(self, app_id: int, tenant_id=None, user_role=None):
        session = self.Session()
        try:
            q = session.query(Application).filter(Application.id == app_id)
            if user_role != "admin" and tenant_id is not None:
                q = q.filter(Application.tenant_id == tenant_id)
            app = q.first()
            if app:
                session.expunge(app)
            return app
        finally:
            session.close()

    def create_application(self, tenant_id: int, name: str, slug: str,
                           description: str = "", environment: str = "production"):
        session = self.Session()
        try:
            app = Application(
                tenant_id=tenant_id,
                name=name,
                slug=slug,
                description=description,
                environment=environment,
                status="active",
            )
            session.add(app)
            session.commit()
            session.refresh(app)
            session.expunge(app)
            return app
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def update_application(self, app_id: int, tenant_id: int, user_role: str, **fields):
        session = self.Session()
        try:
            q = session.query(Application).filter(Application.id == app_id)
            if user_role != "admin":
                q = q.filter(Application.tenant_id == tenant_id)
            app = q.first()
            if not app:
                return None
            for k, v in fields.items():
                if v is not None and hasattr(app, k):
                    setattr(app, k, v)
            session.commit()
            session.refresh(app)
            session.expunge(app)
            return app
        finally:
            session.close()

    def delete_application(self, app_id: int, tenant_id: int, user_role: str):
        """Soft delete — mark as archived. Keeps event history intact."""
        return self.update_application(app_id, tenant_id, user_role, status="archived")

    # ─── Custom Playbooks ────────────────────────────────────────────────────

    def list_playbooks(self, tenant_id: int):
        session = self.Session()
        try:
            pbs = session.query(Playbook).filter(Playbook.tenant_id == tenant_id) \
                .order_by(Playbook.created_at.desc()).all()
            for p in pbs:
                session.expunge(p)
            return pbs
        finally:
            session.close()

    def get_playbook(self, playbook_id: int, tenant_id: int):
        session = self.Session()
        try:
            p = session.query(Playbook).filter(
                Playbook.id == playbook_id,
                Playbook.tenant_id == tenant_id,
            ).first()
            if p:
                session.expunge(p)
            return p
        finally:
            session.close()

    def create_playbook(self, tenant_id: int, **fields):
        session = self.Session()
        try:
            pb = Playbook(tenant_id=tenant_id, **fields)
            session.add(pb)
            session.commit()
            session.refresh(pb)
            session.expunge(pb)
            return pb
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def update_playbook(self, playbook_id: int, tenant_id: int, **fields):
        session = self.Session()
        try:
            pb = session.query(Playbook).filter(
                Playbook.id == playbook_id, Playbook.tenant_id == tenant_id,
            ).first()
            if not pb:
                return None
            for k, v in fields.items():
                if v is not None and hasattr(pb, k):
                    setattr(pb, k, v)
            session.commit()
            session.refresh(pb)
            session.expunge(pb)
            return pb
        finally:
            session.close()

    def delete_playbook(self, playbook_id: int, tenant_id: int) -> bool:
        session = self.Session()
        try:
            pb = session.query(Playbook).filter(
                Playbook.id == playbook_id, Playbook.tenant_id == tenant_id,
            ).first()
            if not pb:
                return False
            session.delete(pb)
            session.commit()
            return True
        finally:
            session.close()

    # ─── Notification Preferences ────────────────────────────────────────────

    def get_notification_preferences(self, user_id: int):
        session = self.Session()
        try:
            pref = session.query(NotificationPreference).filter(
                NotificationPreference.user_id == user_id
            ).first()
            if pref:
                session.expunge(pref)
            return pref
        finally:
            session.close()

    def upsert_notification_preferences(self, user_id: int, **fields):
        session = self.Session()
        try:
            pref = session.query(NotificationPreference).filter(
                NotificationPreference.user_id == user_id
            ).first()
            if pref is None:
                pref = NotificationPreference(user_id=user_id)
                session.add(pref)
            for k, v in fields.items():
                if v is not None and hasattr(pref, k):
                    setattr(pref, k, v)
            session.commit()
            session.refresh(pref)
            session.expunge(pref)
            return pref
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_application_stats(self, app_id: int, tenant_id=None, user_role=None):
        from sqlalchemy import func
        session = self.Session()
        try:
            eq = session.query(LogEvent).filter(LogEvent.application_id == app_id)
            iq = session.query(Incident).filter(Incident.application_id == app_id)
            if user_role != "admin" and tenant_id is not None:
                eq = eq.filter(LogEvent.tenant_id == tenant_id)
                iq = iq.filter(Incident.tenant_id == tenant_id)

            total_events = eq.count()
            avg_q = session.query(func.avg(LogEvent.risk_score)).filter(
                LogEvent.application_id == app_id
            )
            if user_role != "admin" and tenant_id is not None:
                avg_q = avg_q.filter(LogEvent.tenant_id == tenant_id)
            avg_risk = avg_q.scalar()
            last_event = eq.order_by(LogEvent.timestamp.desc()).first()
            critical = eq.filter(LogEvent.risk_score >= 85).count()
            open_incidents = iq.filter(Incident.status.in_(["OPEN", "INVESTIGATING"])).count()

            return {
                "application_id": app_id,
                "total_events": total_events,
                "avg_risk": round(float(avg_risk or 0), 1),
                "critical_events": critical,
                "open_incidents": open_incidents,
                "last_event_at": last_event.timestamp.isoformat() if last_event and last_event.timestamp else None,
            }
        finally:
            session.close()


# Lazy singleton — defers DATABASE_URL check until first access so importing
# this module (e.g. in tests that patch `db`) doesn't require a live database.
_db_instance = None


def _get_db() -> "Database":
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance


class _DBProxy:
    def __getattr__(self, name):
        return getattr(_get_db(), name)


db = _DBProxy()
