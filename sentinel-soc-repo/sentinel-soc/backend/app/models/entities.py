"""SQLAlchemy ORM declarative models for PostgreSQL & Alembic migration compatibility."""
# Designed and Developed by Wasif Karim — SENTINEL SOC
try:
    from sqlalchemy import Column, Integer, String, Text, Float, Boolean, ForeignKey
    from sqlalchemy.orm import declarative_base
    Base = declarative_base()
except ImportError:
    Base = object

class EventModel:
    """Normalized Security Event entity specification."""
    __tablename__ = "events"
