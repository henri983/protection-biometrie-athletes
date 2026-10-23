"""
Gestion de la configuration et des variables d'environnement.
"""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "Protection Biométrie Athlètes API"
    APP_ENV: str = "development"
    LOG_LEVEL: str = "INFO"

    # Clé maître de chiffrement (256-bit AES-GCM en hexadécimal)
    BIOMETRIC_MASTER_KEY_HEX: str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    # Clé de signature HMAC d'intégrité de la télémétrie
    HMAC_TELEMETRY_KEY_HEX: str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

    # Paramètres de détection d'anomalies IA
    MAX_PLAUSIBLE_SPEED_KMH: float = 900.0
    AI_ANOMALY_THRESHOLD: float = 0.75

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
