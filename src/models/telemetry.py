"""
Modèles de flux télémétriques et biométriques des athlètes.
"""

from typing import Optional
from pydantic import BaseModel, Field


class RawBiometricTelemetry(BaseModel):
    """Données biométriques brutes collectées sur le capteur/montre connectée."""
    athlete_id: str = Field(..., examples=["ATH-007"])
    timestamp: float = Field(..., description="Horodatage Unix en secondes")
    latitude: Optional[float] = Field(None, examples=[48.8566], description="Latitude GPS")
    longitude: Optional[float] = Field(None, examples=[2.3522], description="Longitude GPS")
    heart_rate_bpm: Optional[int] = Field(None, examples=[165], description="Fréquence cardiaque en BPM")
    hrv_ms: Optional[float] = Field(None, examples=[48.5], description="Variabilité de fréquence cardiaque (RMSSD)")
    power_watts: Optional[float] = Field(None, examples=[320.0], description="Puissance en watts")
    cadence_rpm: Optional[int] = Field(None, examples=[88], description="Cadence en RPM")
    lactate_mmol_l: Optional[float] = Field(None, examples=[3.8], description="Concentration en lactate")


class IngestTelemetryRequest(BaseModel):
    """Payload d'ingestion sécurisée avec signature HMAC."""
    telemetry: RawBiometricTelemetry
    signature_hmac: str = Field(..., description="Signature HMAC-SHA256 du payload JSON")


class ObfuscatedGPS(BaseModel):
    latitude_obfuscated: float
    longitude_obfuscated: float
    precision_radius_meters: float


class DecryptedBiometricView(BaseModel):
    """Vue filtrée et démasquée selon les consentements et permissions."""
    athlete_id: str
    timestamp: float
    gps: Optional[ObfuscatedGPS] = None
    heart_rate_bpm: Optional[int] = None
    hrv_ms: Optional[float] = None
    power_watts: Optional[float] = None
    cadence_rpm: Optional[int] = None
    lactate_mmol_l: Optional[float] = None
