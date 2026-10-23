"""
Moteur IA d'évaluation et de détection des accès anormaux (Access Anomaly Engine).

Combine analyse comportementale, vélocité géographique, horaires d'activité et
fréquence des requêtes pour attribuer un score de risque temps réel (0.0 à 1.0).
"""

import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from src.ai.impossible_travel import ImpossibleTravelDetector
from src.models.audit_event import AccessRequestMetadata, AnomalyAuditAlert


class BiometricAccessAnomalyEngine:
    """Moteur d'inférence de risque et détection de comportements d'accès suspects."""

    def __init__(self, risk_threshold: float = 0.75, max_speed_kmh: float = 900.0) -> None:
        self.risk_threshold = risk_threshold
        self.travel_detector = ImpossibleTravelDetector(max_speed_kmh=max_speed_kmh)
        # Historique glissant des horodatages de requêtes par user_id
        self._user_request_timestamps: Dict[str, List[float]] = defaultdict(list)
        # Historique des alertes levées
        self.recorded_alerts: List[AnomalyAuditAlert] = []

    def evaluate_access(self, meta: AccessRequestMetadata) -> Tuple[float, bool, List[str]]:
        """
        Analyse une requête d'accès biométrique et calcule le score de risque global.
        Retourne : (risk_score, should_block, list_of_reasons).
        """
        reasons: List[str] = []
        risk_components: List[float] = []

        # 1. Analyse de vélocité physique (Voyage Impossible)
        is_impossible, speed, travel_reason = self.travel_detector.evaluate_travel(
            user_id=meta.user_id,
            current_lat=meta.latitude,
            current_lon=meta.longitude,
            current_time=meta.timestamp,
            current_ip=meta.client_ip,
        )
        if is_impossible and travel_reason:
            reasons.append(travel_reason)
            risk_components.append(0.85)  # Risque critique immédiat

        # 2. Détection de rafale / Scraping massif (> 15 requêtes / minute)
        timestamps = self._user_request_timestamps[meta.user_id]
        one_min_ago = meta.timestamp - 60.0
        # Purger les horodatages de plus d'une minute
        valid_timestamps = [t for t in timestamps if t >= one_min_ago]
        valid_timestamps.append(meta.timestamp)
        self._user_request_timestamps[meta.user_id] = valid_timestamps

        req_count_1m = len(valid_timestamps)
        if req_count_1m > 15:
            reasons.append(f"Volume de requêtes anormalement élevé ({req_count_1m} requêtes/min).")
            risk_components.append(0.60)

        # 3. Accès en horaires nocturnes anormaux (entre 01h00 et 05h00 du matin)
        # Calcul de l'heure locale approximative basée sur la longitude (15 deg = 1h)
        utc_hour = time.gmtime(meta.timestamp).tm_hour
        estimated_local_hour = int((utc_hour + (meta.longitude / 15.0)) % 24)

        # Les coachs ou analystes n'ont pas de motif d'entraînement au milieu de la nuit
        if meta.user_role in ["head_coach", "performance_analyst"]:
            if 1 <= estimated_local_hour <= 4:
                reasons.append(f"Accès inhabituel hors heures d'entraînement ({estimated_local_hour:02d}h locales).")
                risk_components.append(0.40)

        # 4. Agrégation du score de risque (0.0 à 1.0)
        if not risk_components:
            risk_score = 0.05  # Bruit de fond normal
        else:
            # Combinaison probabiliste indépendante : 1 - prod(1 - r_i)
            prod = 1.0
            for r in risk_components:
                prod *= (1.0 - r)
            risk_score = round(1.0 - prod, 3)

        should_block = risk_score >= self.risk_threshold

        if should_block:
            alert = AnomalyAuditAlert(
                alert_id=f"ALT-{len(self.recorded_alerts) + 1:04d}",
                user_id=meta.user_id,
                user_role=meta.user_role,
                target_athlete_id=meta.target_athlete_id,
                risk_score=risk_score,
                is_blocked=should_block,
                reasons=reasons,
                timestamp=meta.timestamp,
                ip=meta.client_ip,
            )
            self.recorded_alerts.append(alert)

        return risk_score, should_block, reasons
