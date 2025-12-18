from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
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

class Incident(Base):
    __tablename__ = 'incidents'

    id = Column(Integer, primary_key=True)
    log_event_id = Column(Integer) # Linked to LogEvent
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="OPEN") # OPEN, INVESTIGATING, RESOLVED
    owner = Column(String, default="Unassigned")
    note = Column(Text, default="")
    risk_score = Column(Float)
    user = Column(String)
    action = Column(String)


class Database:
    def __init__(self, db_path='security_events.db'):
        # Use sqlite
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
            session.flush() # Get ID before commit
            
            # Auto-Incident Logic
            incident_id = None
            if event_dict['risk_score'] > 80: # Critical Threshold
                # Check if recent open ticket exists for this user? For MVP, just create new.
                incident = Incident(
                    log_event_id=event.id,
                    risk_score=event_dict['risk_score'],
                    user=event_dict['user'],
                    action=event_dict['action'],
                    timestamp=event.timestamp
                )
                session.add(incident)
                session.flush()
                incident_id = incident.id
                
            session.commit()
            return event.id, incident_id
        except Exception as e:
            print(f"Error inserting event: {e}")
            session.rollback()
            return None
        finally:
            session.close()

    def fetch_all_events(self):
        session = self.Session()
        try:
            events = session.query(LogEvent).order_by(LogEvent.timestamp.desc()).all()
            return events
        finally:
            session.close()
            
    def fetch_incidents(self):
        session = self.Session()
        try:
            return session.query(Incident).order_by(Incident.timestamp.desc()).all()
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


# Singleton for easy access
db = Database()
