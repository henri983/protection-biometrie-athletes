"""
Tests du détecteur IA de Voyage Géographiquement Impossible (Impossible Travel).
"""

import pytest
from src.ai.impossible_travel import ImpossibleTravelDetector


@pytest.mark.ai
def test_normal_movement_within_speed_limits(travel_detector: ImpossibleTravelDetector):
    """Déplacement plausible (Paris vers Lyon en 2 heures de TGV ~ 230 km/h)."""
    user_id = "COACH-01"
    paris_lat, paris_lon = 48.8566, 2.3522
    lyon_lat, lyon_lon = 45.7640, 4.8357

    t0 = 1700000000.0
    t1 = t0 + 7200.0  # 2 heures plus tard

    # Première requête à Paris
    is_imp1, _, _ = travel_detector.evaluate_travel(user_id, paris_lat, paris_lon, t0, "192.168.1.10")
    assert is_imp1 is False

    # Seconde requête à Lyon 2h plus tard
    is_imp2, speed, reason = travel_detector.evaluate_travel(user_id, lyon_lat, lyon_lon, t1, "192.168.2.20")
    assert is_imp2 is False
    assert speed < 250.0
    assert reason is None


@pytest.mark.ai
def test_impossible_travel_triggers_anomaly(travel_detector: ImpossibleTravelDetector):
    """Accès depuis Paris puis Tokyo 15 minutes plus tard (> 9000 km en 900s = ~38 000 km/h)."""
    user_id = "COACH-02"
    paris_lat, paris_lon = 48.8566, 2.3522
    tokyo_lat, tokyo_lon = 35.6762, 139.6503

    t0 = 1700000000.0
    t1 = t0 + 900.0  # 15 minutes plus tard

    # 1. Connexion depuis Paris
    travel_detector.evaluate_travel(user_id, paris_lat, paris_lon, t0, "82.64.10.1")

    # 2. Connexion depuis Tokyo 15 minutes après
    is_impossible, speed, reason = travel_detector.evaluate_travel(user_id, tokyo_lat, tokyo_lon, t1, "133.242.1.1")

    assert is_impossible is True
    assert speed > 900.0
    assert "Voyage impossible" in reason
