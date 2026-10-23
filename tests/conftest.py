"""
Fixtures pytest pour les tests de protection des données biométriques.
"""

import pytest
import pytest_asyncio
import httpx
from fastapi import FastAPI

from src.config import Settings
from src.main import create_app
from src.security.crypto import BiometricCryptoEngine
from src.security.gps_obfuscator import GPSPrivacyGuard
from src.security.consent_manager import ConsentManager
from src.ai.anomaly_detector import BiometricAccessAnomalyEngine
from src.ai.impossible_travel import ImpossibleTravelDetector


@pytest.fixture
def test_settings() -> Settings:
    return Settings(
        APP_ENV="test",
        LOG_LEVEL="DEBUG",
        BIOMETRIC_MASTER_KEY_HEX="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        HMAC_TELEMETRY_KEY_HEX="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        MAX_PLAUSIBLE_SPEED_KMH=900.0,
        AI_ANOMALY_THRESHOLD=0.75,
    )


@pytest.fixture
def crypto_engine(test_settings: Settings) -> BiometricCryptoEngine:
    return BiometricCryptoEngine(
        master_key_hex=test_settings.BIOMETRIC_MASTER_KEY_HEX,
        hmac_key_hex=test_settings.HMAC_TELEMETRY_KEY_HEX,
    )


@pytest.fixture
def gps_guard() -> GPSPrivacyGuard:
    return GPSPrivacyGuard()


@pytest.fixture
def consent_mgr() -> ConsentManager:
    return ConsentManager()


@pytest.fixture
def travel_detector() -> ImpossibleTravelDetector:
    return ImpossibleTravelDetector(max_speed_kmh=900.0)


@pytest.fixture
def anomaly_engine() -> BiometricAccessAnomalyEngine:
    return BiometricAccessAnomalyEngine(risk_threshold=0.75, max_speed_kmh=900.0)


@pytest.fixture
def test_app(test_settings: Settings) -> FastAPI:
    return create_app(settings=test_settings)


@pytest_asyncio.fixture
async def async_client(test_app: FastAPI):
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
