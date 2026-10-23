"""
Détection IA d'accès géographique impossible (Impossible Travel Detector).

Calcule la vitesse de déplacement physique requise entre deux requêtes successives
d'un même compte utilisateur à partir de leurs coordonnées GPS / IP.
Si la vitesse requise dépasse la vitesse commerciale plausible (ex: 900 km/h),
une alerte de compromission de compte (vol de session / VPN frauduleux) est levée.
"""

from typing import Dict, Optional, Tuple
from src.security.gps_obfuscator import GPSPrivacyGuard


class ImpossibleTravelDetector:
    """Moteur de détection de vélocité anormale d'accès."""

    def __init__(self, max_speed_kmh: float = 900.0) -> None:
        self.max_speed_kmh = max_speed_kmh
        # Historique par utilisateur : user_id -> (lat, lon, timestamp, ip)
        self._user_last_location: Dict[str, Tuple[float, float, float, str]] = {}

    def evaluate_travel(
        self,
        user_id: str,
        current_lat: float,
        current_lon: float,
        current_time: float,
        current_ip: str,
    ) -> Tuple[bool, float, Optional[str]]:
        """
        Évalue la cohérence spatio-temporelle de la requête.
        Retourne (is_impossible, calculated_speed_kmh, reason).
        """
        last_record = self._user_last_location.get(user_id)

        # Première connexion enregistrée pour cet utilisateur
        if not last_record:
            self._user_last_location[user_id] = (current_lat, current_lon, current_time, current_ip)
            return False, 0.0, None

        prev_lat, prev_lon, prev_time, prev_ip = last_record
        time_delta_seconds = current_time - prev_time

        # Même IP et horodatage très proche ou identique : pas de voyage
        if current_ip == prev_ip:
            self._user_last_location[user_id] = (current_lat, current_lon, current_time, current_ip)
            return False, 0.0, None

        if time_delta_seconds <= 0:
            # Requêtes simultanées depuis deux localisations différentes
            return True, float("inf"), "Accès simultanés détectés depuis des coordonnées géographiques distinctes."

        distance_km = GPSPrivacyGuard.haversine_distance_km(prev_lat, prev_lon, current_lat, current_lon)
        hours = time_delta_seconds / 3600.0
        calculated_speed_kmh = distance_km / hours

        if calculated_speed_kmh > self.max_speed_kmh:
            reason = (
                f"Voyage impossible détecté : distance de {distance_km:.1f} km parcourue en "
                f"{time_delta_seconds:.0f}s (vitesse théorique requise : {calculated_speed_kmh:.0f} km/h > max {self.max_speed_kmh} km/h). "
                f"IP précédente: {prev_ip}, Nouvelle IP: {current_ip}."
            )
            # Ne met pas à jour la position légitime pour éviter l'empoisonnement d'état
            return True, calculated_speed_kmh, reason

        # Mise à jour de la position légitime
        self._user_last_location[user_id] = (current_lat, current_lon, current_time, current_ip)
        return False, calculated_speed_kmh, None
