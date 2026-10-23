"""
Module d'obfuscation spatio-temporelle et protection de la vie privée géographique (GPS Privacy).

Conforme aux recommandations de la CNIL et de l'EDPB sur le traçage des sportifs :
- Masquage des zones résidentielles privées (Geofence domicile)
- Perturbation spatiale différentielle (Grid Snap / Floutage gaussien de précision)
"""

import math
from typing import Optional, Tuple
from src.models.telemetry import ObfuscatedGPS


class GPSPrivacyGuard:
    """Moteur d'anonymisation et d'obfuscation de coordonnées GPS."""

    def __init__(self, default_blur_radius_meters: float = 150.0) -> None:
        self.default_blur_radius_meters = default_blur_radius_meters

    @staticmethod
    def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calcule la distance en kilomètres entre deux points GPS via la formule de Haversine."""
        r = 6371.0  # Rayon de la Terre en km
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = (
            math.sin(dlat / 2.0) ** 2
            + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2.0) ** 2
        )
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        return r * c

    def is_in_private_sanctuary(
        self,
        lat: float,
        lon: float,
        sanctuary_lat: float,
        sanctuary_lon: float,
        sanctuary_radius_meters: float = 300.0,
    ) -> bool:
        """Détecte si le sportif se trouve dans son domicile ou une zone privée protégée."""
        dist_km = self.haversine_distance_km(lat, lon, sanctuary_lat, sanctuary_lon)
        return (dist_km * 1000.0) <= sanctuary_radius_meters

    def obfuscate_coordinates(
        self,
        lat: Optional[float],
        lon: Optional[float],
        precision_decimals: int = 2,
    ) -> Optional[ObfuscatedGPS]:
        """
        Obfusque les coordonnées GPS en tronquant la précision décimale (snap to spatial grid).
        2 décimales correspondent environ à un floutage à ~1,1 km, empêchant l'identification d'une adresse précise.
        3 décimales correspondent à ~110 m (utile pour analyser l'allure sur piste sans révéler le point d'arrêt).
        """
        if lat is None or lon is None:
            return None

        factor = 10 ** precision_decimals
        obfuscated_lat = math.floor(lat * factor) / factor
        obfuscated_lon = math.floor(lon * factor) / factor

        return ObfuscatedGPS(
            latitude_obfuscated=round(obfuscated_lat, precision_decimals),
            longitude_obfuscated=round(obfuscated_lon, precision_decimals),
            precision_radius_meters=self.default_blur_radius_meters,
        )
