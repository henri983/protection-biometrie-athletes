"""
Tests unitaires de l'obfuscateur GPS et du respect de la vie privée spatiale.
"""

import pytest
from src.security.gps_obfuscator import GPSPrivacyGuard


@pytest.mark.unit
def test_haversine_distance_calculation(gps_guard: GPSPrivacyGuard):
    """Vérifie le calcul de distance entre la Tour Eiffel et l'Arc de Triomphe (~1.6 km)."""
    eiffel_lat, eiffel_lon = 48.8584, 2.2945
    arc_lat, arc_lon = 48.8738, 2.2950

    distance_km = gps_guard.haversine_distance_km(eiffel_lat, eiffel_lon, arc_lat, arc_lon)
    assert 1.4 < distance_km < 1.9


@pytest.mark.unit
def test_sanctuary_detection(gps_guard: GPSPrivacyGuard):
    """Vérifie la détection d'une zone sanctuaire (domicile privé de l'athlète)."""
    home_lat, home_lon = 43.6047, 1.4442  # Toulouse

    # Point à 50 mètres du domicile
    inside_lat, inside_lon = 43.6050, 1.4445
    assert gps_guard.is_in_private_sanctuary(inside_lat, inside_lon, home_lat, home_lon, sanctuary_radius_meters=300.0) is True

    # Point à 3 km du domicile
    outside_lat, outside_lon = 43.6300, 1.4600
    assert gps_guard.is_in_private_sanctuary(outside_lat, outside_lon, home_lat, home_lon, sanctuary_radius_meters=300.0) is False


@pytest.mark.unit
def test_gps_grid_obfuscation_precision(gps_guard: GPSPrivacyGuard):
    """Vérifie que l'obfuscation tronque les coordonnées pour protéger l'adresse exacte."""
    precise_lat = 48.858370123
    precise_lon = 2.294481345

    obfuscated = gps_guard.obfuscate_coordinates(precise_lat, precise_lon, precision_decimals=2)
    assert obfuscated is not None
    assert obfuscated.latitude_obfuscated == 48.85
    assert obfuscated.longitude_obfuscated == 2.29
    assert obfuscated.precision_radius_meters > 0
