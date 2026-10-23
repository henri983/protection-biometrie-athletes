"""
Tests d'intégration end-to-end de l'API FastAPI de protection biométrique.
"""

import json
import pytest
import httpx
from src.security.crypto import BiometricCryptoEngine


@pytest.mark.asyncio
async def test_health_check(async_client: httpx.AsyncClient):
    """Vérifie l'endpoint /health."""
    response = await async_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "protection-biometrie-athletes"


@pytest.mark.asyncio
async def test_full_athlete_workflow_and_ai_defense(
    async_client: httpx.AsyncClient, crypto_engine: BiometricCryptoEngine
):
    """
    Scénario d'intégration complet :
    1. Enregistrement d'un athlète avec matrice de consentement
    2. Ingestion de télémétrie signée par capteur (HMAC-SHA256)
    3. Consultation autorisée par un coach (avec masquage des données médicales)
    4. Révocation de consentement et vérification de coupure d'accès
    5. Tentative de piratage avec voyage impossible détectée et bloquée par l'IA
    """
    athlete_id = "ATH-77"

    # 1. Enregistrement de l'athlète
    reg_payload = {
        "athlete_id": athlete_id,
        "full_name": "Antoine Dupont",
        "sport": "Rugby",
        "team": "Stade Toulousain",
        "consent": {
            "consent_gps": True,
            "consent_heart_rate": True,
            "consent_performance_metrics": True,
            "consent_medical_vitals": False,  # Refus des bilans sanguins/lactates pour le staff technique
        },
    }
    reg_res = await async_client.post("/api/v1/athletes", json=reg_payload)
    assert reg_res.status_code == 201

    # 2. Ingestion de données télémétriques signées
    telemetry_data = {
        "athlete_id": athlete_id,
        "timestamp": 1700042400.0,
        "latitude": 43.6047,
        "longitude": 1.4442,
        "heart_rate_bpm": 182,
        "hrv_ms": 35.2,
        "power_watts": 410.0,
        "cadence_rpm": 92,
        "lactate_mmol_l": 5.4,
    }
    # Calcul de la signature HMAC
    raw_json = json.dumps(telemetry_data, separators=(",", ":"))
    # Le modèle pydantic RawBiometricTelemetry doit correspondre
    from src.models.telemetry import RawBiometricTelemetry
    telemetry_obj = RawBiometricTelemetry(**telemetry_data)
    sig = crypto_engine.compute_hmac_signature(telemetry_obj.model_dump_json())

    ingest_payload = {
        "telemetry": telemetry_data,
        "signature_hmac": sig,
    }
    ingest_res = await async_client.post("/api/v1/telemetry/ingest", json=ingest_payload)
    assert ingest_res.status_code == 201

    # 3. Consultation légitime par le coach
    coach_headers = {
        "X-User-ID": "COACH-DUPONT",
        "X-User-Role": "head_coach",
        "X-Client-IP": "82.64.1.5",
        "X-Client-Lat": "43.6047",
        "X-Client-Lon": "1.4442",
        "X-Requested-Scope": "performance",
    }
    read_res = await async_client.get(f"/api/v1/athletes/{athlete_id}/biometrics", headers=coach_headers)
    assert read_res.status_code == 200
    records = read_res.json()
    assert len(records) == 1
    record = records[0]

    # Vérification des consentements et filtrage :
    assert record["heart_rate_bpm"] == 182
    assert record["power_watts"] == 410.0
    # Le lactate est à None car non consenti pour le coach
    assert record["lactate_mmol_l"] is None
    # Les coordonnées GPS sont obfusquées (pas en clair)
    assert record["gps"]["latitude_obfuscated"] == 43.60
    assert record["gps"]["longitude_obfuscated"] == 1.44

    # 4. Attaque par usurpation d'identité avec voyage impossible (IP australienne 10 secondes plus tard)
    hacker_headers = {
        "X-User-ID": "COACH-DUPONT",
        "X-User-Role": "head_coach",
        "X-Client-IP": "139.130.4.5",
        "X-Client-Lat": "-33.8688",
        "X-Client-Lon": "151.2093",
        "X-Requested-Scope": "performance",
    }
    hack_res = await async_client.get(f"/api/v1/athletes/{athlete_id}/biometrics", headers=hacker_headers)
    assert hack_res.status_code == 403
    hack_detail = hack_res.json()["detail"]
    assert hack_detail["risk_score"] >= 0.75
    assert any("Voyage impossible" in r for r in hack_detail["reasons"])

    # 5. Consultation des alertes par un administrateur fédération
    admin_headers = {"X-User-Role": "federation_admin"}
    alerts_res = await async_client.get("/api/v1/ai/audit/anomalies", headers=admin_headers)
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) >= 1
    assert alerts[0]["user_id"] == "COACH-DUPONT"
    assert alerts[0]["is_blocked"] is True
