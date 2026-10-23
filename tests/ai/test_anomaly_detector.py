"""
Tests du moteur IA d'évaluation et de détection des accès anormaux.
"""

import pytest
from src.ai.anomaly_detector import BiometricAccessAnomalyEngine
from src.models.audit_event import AccessRequestMetadata


@pytest.mark.ai
def test_normal_access_low_risk(anomaly_engine: BiometricAccessAnomalyEngine):
    """Accès normal diurne avec faible fréquence : score de risque très bas, accès autorisé."""
    meta = AccessRequestMetadata(
        user_id="COACH-01",
        user_role="head_coach",
        target_athlete_id="ATH-01",
        client_ip="82.64.1.1",
        latitude=48.8566,
        longitude=2.3522,
        timestamp=1700042400.0,  # 10h00 GMT
        requested_scope="performance",
    )

    risk_score, should_block, reasons = anomaly_engine.evaluate_access(meta)
    assert risk_score < 0.3
    assert should_block is False
    assert len(reasons) == 0


@pytest.mark.ai
def test_rate_burst_anomaly_detection(anomaly_engine: BiometricAccessAnomalyEngine):
    """Envoi répété de > 15 requêtes en moins d'une minute : déclenchement d'une alerte d'exfiltration."""
    user_id = "SCRAPER-BOT"
    base_time = 1700042400.0

    for i in range(16):
        meta = AccessRequestMetadata(
            user_id=user_id,
            user_role="performance_analyst",
            target_athlete_id="ATH-01",
            client_ip="100.1.2.3",
            latitude=48.8566,
            longitude=2.3522,
            timestamp=base_time + (i * 2),  # Espacées de 2 secondes
            requested_scope="performance",
        )
        risk_score, should_block, reasons = anomaly_engine.evaluate_access(meta)

    # La 16ème requête doit détecter le scraping
    assert any("anormalement élevé" in r for r in reasons)
    assert risk_score >= 0.5


@pytest.mark.ai
def test_impossible_travel_triggers_blocking_alert(anomaly_engine: BiometricAccessAnomalyEngine):
    """Le cumul d'un voyage impossible déclenche un blocage immédiat (risk >= 0.75)."""
    user_id = "SUSPICIOUS-USER"
    t0 = 1700042400.0

    # Connexion à Londres
    meta1 = AccessRequestMetadata(
        user_id=user_id,
        user_role="head_coach",
        target_athlete_id="ATH-01",
        client_ip="151.101.1.1",
        latitude=51.5074,
        longitude=-0.1278,
        timestamp=t0,
        requested_scope="performance",
    )
    anomaly_engine.evaluate_access(meta1)

    # Connexion à Sydney 5 minutes plus tard
    meta2 = AccessRequestMetadata(
        user_id=user_id,
        user_role="head_coach",
        target_athlete_id="ATH-01",
        client_ip="139.130.4.5",
        latitude=-33.8688,
        longitude=151.2093,
        timestamp=t0 + 300.0,
        requested_scope="performance",
    )
    risk_score, should_block, reasons = anomaly_engine.evaluate_access(meta2)

    assert should_block is True
    assert risk_score >= 0.75
    assert len(anomaly_engine.recorded_alerts) >= 1
    assert anomaly_engine.recorded_alerts[-1].user_id == user_id
