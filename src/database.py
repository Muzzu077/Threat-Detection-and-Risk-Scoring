from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey
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
    name = Column(String, default="Default")
    prefix = Column(String, nullable=False)
    key_hash = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)

    owner = relationship("User", back_populates="api_keys")


class RefreshToken(Base):
    __tablename__ = 'refresh_tokens'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    token_hash = Column(String, unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    revoked = Column(Boolean, default=False)


# ─── Core Models ─────────────────────────────────────────────────────────────

class LogEvent(Base):
    __tablename__ = 'log_events'

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

    def update_incident_note(self, incident_id, note):
        session = self.Session()
        try:
            inc = session.query(Incident).filter(Incident.id == incident_id).first()
            if inc:
                inc.note = note
                session.commit()
        finally:
            session.close()

    def update_incident_response(self, incident_id, response_json: str):
        session = self.Session()
        try:
            inc = session.query(Incident).filter(Incident.id == incident_id).first()
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
