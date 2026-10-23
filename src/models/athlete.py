"""
Modèles liés aux athlètes et à leur statut de consentement RGPD.
"""

from typing import Dict, Optional
from pydantic import BaseModel, Field


class BiometricConsentMatrix(BaseModel):
    """Matrice granulaire de consentement RGPD (Article 7 & 9)."""
    consent_gps: bool = Field(default=False, description="Autorise le suivi de géolocalisation pour performance")
    consent_heart_rate: bool = Field(default=False, description="Autorise la captation de fréquence cardiaque et HRV")
    consent_performance_metrics: bool = Field(default=False, description="Autorise les métriques de puissance et cadence")
    consent_medical_vitals: bool = Field(default=False, description="Autorise l'accès aux marqueurs physiologiques approfondis (lactate, glycémie)")


class AthleteRegistration(BaseModel):
    athlete_id: str = Field(..., examples=["ATH-007"])
    full_name: str = Field(..., examples=["Kylian Mbappé"])
    sport: str = Field(..., examples=["Football"])
    team: str = Field(..., examples=["Équipe de France"])
    consent: BiometricConsentMatrix = Field(default_factory=BiometricConsentMatrix)


class AthleteProfile(BaseModel):
    athlete_id: str
    sport: str
    team: str
    consent: BiometricConsentMatrix
    created_at: float
