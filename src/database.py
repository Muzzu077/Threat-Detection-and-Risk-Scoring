from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import os

Base = declarative_base()

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

    # NEW: ML Engine
    attack_type = Column(String, default="unknown")
    ml_confidence = Column(Float, default=0.0)

    # NEW: Threat Intelligence
    country = Column(String, default="UNKNOWN")
    threat_intel_score = Column(Float, default=0.0)
    threat_intel_reason = Column(Text, default="")

    # NEW: SOAR
    response_actions = Column(Text, default="")  # JSON string

class Incident(Base):
    __tablename__ = 'incidents'

    id = Column(Integer, primary_key=True)
    log_event_id = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="OPEN")  # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    owner = Column(String, default="Unassigned")
    note = Column(Text, default="")
    risk_score = Column(Float)
    user = Column(String)
    action = Column(String)
    # NEW: SOAR response summary
    response_actions = Column(Text, default="")
    # NEW: Attack type from ML engine
    attack_type = Column(String, default="unknown")

class AttackChain(Base):
    """Groups related high-risk events into kill chains."""
    __tablename__ = 'attack_chains'

    id = Column(Integer, primary_key=True)
    chain_id = Column(String, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    max_risk = Column(Float)
    severity = Column(String)
    involved_ips = Column(Text, default="")    # comma-separated
    involved_users = Column(Text, default="")  # comma-separated
    event_ids = Column(Text, default="")       # comma-separated JSON
    start_time = Column(DateTime)
    end_time = Column(DateTime)


class Database:
    def __init__(self):
        # Support PostgreSQL via DATABASE_URL, fall back to SQLite
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            self.engine = create_engine(db_url, echo=False)
            print(f"🐘 Connected to PostgreSQL database.")
        else:
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            db_path = os.path.join(project_root, 'security_events.db')
            self.engine = create_engine(f'sqlite:///{db_path}', echo=False)

        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def get_session(self):
        return self.Session()

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
                    attack_type=event_dict.get('attack_type', 'unknown')
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

    def fetch_all_events(self, limit=500):
        session = self.Session()
        try:
            return session.query(LogEvent).order_by(LogEvent.timestamp.desc()).limit(limit).all()
        finally:
            session.close()

    def fetch_events_paginated(self, page=1, limit=50, min_risk=0):
        session = self.Session()
        try:
            query = session.query(LogEvent)
            if min_risk > 0:
                query = query.filter(LogEvent.risk_score >= min_risk)
            total = query.count()
            events = query.order_by(LogEvent.timestamp.desc()).offset((page - 1) * limit).limit(limit).all()
            return events, total
        finally:
            session.close()

    def fetch_incidents(self, status=None):
        session = self.Session()
        try:
            q = session.query(Incident)
            if status:
                q = q.filter(Incident.status == status)
            return q.order_by(Incident.timestamp.desc()).all()
        finally:
            session.close()

    def update_incident_status(self, incident_id, new_status, owner=None):
        session = self.Session()
        try:
            inc = session.query(Incident).filter(Incident.id == incident_id).first()
            if inc:
                inc.status = new_status
                if owner:
                    inc.owner = owner
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
        """Store SOAR response actions on the incident."""
        session = self.Session()
        try:
            inc = session.query(Incident).filter(Incident.id == incident_id).first()
            if inc:
                inc.response_actions = response_json
                session.commit()
        finally:
            session.close()

    def get_incident_details(self, incident_id):
        session = self.Session()
        try:
            incident = session.query(Incident).filter(Incident.id == incident_id).first()
            if incident:
                log_event = session.query(LogEvent).filter(LogEvent.id == incident.log_event_id).first()
                return incident, log_event
            return None, None
        finally:
            session.close()

    def get_stats(self):
        """Return aggregate KPIs."""
        session = self.Session()
        try:
            total_events = session.query(LogEvent).count()
            open_incidents = session.query(Incident).filter(
                Incident.status.in_(["OPEN", "INVESTIGATING"])
            ).count()
            critical_events = session.query(LogEvent).filter(LogEvent.risk_score >= 85).count()
            high_events = session.query(LogEvent).filter(
                LogEvent.risk_score >= 61, LogEvent.risk_score < 85
            ).count()

            # Average risk
            from sqlalchemy import func
            avg_risk_result = session.query(func.avg(LogEvent.risk_score)).scalar()
            avg_risk = round(float(avg_risk_result or 0), 1)

            return {
                "total_events": total_events,
                "open_incidents": open_incidents,
                "critical_events": critical_events,
                "high_events": high_events,
                "avg_risk": avg_risk,
                "resolved_incidents": session.query(Incident).filter(Incident.status == "RESOLVED").count()
            }
        finally:
            session.close()

    def get_recent_events_for_graph(self, limit=200):
        """Fetch recent high-risk events for attack graph."""
        session = self.Session()
        try:
            return session.query(LogEvent).filter(
                LogEvent.risk_score >= 50
            ).order_by(LogEvent.timestamp.desc()).limit(limit).all()
        finally:
            session.close()

    def save_attack_chain(self, chain: dict):
        """Persist an attack chain to the DB."""
        import json as _json
        session = self.Session()
        try:
            existing = session.query(AttackChain).filter(AttackChain.chain_id == chain["chain_id"]).first()
            if existing:
                return  # Already saved

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
            )
            session.add(ac)
            session.commit()
        except Exception as e:
            print(f"Error saving attack chain: {e}")
            session.rollback()
        finally:
            session.close()


# Singleton
db = Database()
