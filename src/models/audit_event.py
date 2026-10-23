"""
Modèles d'événements de sécurité et d'audit des accès biométriques.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class AccessRequestMetadata(BaseModel):
    user_id: str
    user_role: str
    target_athlete_id: str
    client_ip: str
    latitude: float
    longitude: float
    timestamp: float
    requested_scope: str


class AnomalyAuditAlert(BaseModel):
    alert_id: str
    user_id: str
    user_role: str
    target_athlete_id: str
    risk_score: float
    is_blocked: bool
    reasons: List[str]
    timestamp: float
    ip: str
