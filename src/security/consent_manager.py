"""
Gestionnaire granulaire de consentement RGPD (Articles 7 & 9).
Permet aux athlètes d'accorder, restreindre et révoquer instantanément l'accès
à leurs données biométriques et de géolocalisation.
"""

from typing import Dict, Optional
from src.models.athlete import BiometricConsentMatrix


class ConsentManager:
    """Contrôleur de conformité des consentements biométriques."""

    def __init__(self) -> None:
        # Stockage en mémoire : athlete_id -> BiometricConsentMatrix
        self._consent_store: Dict[str, BiometricConsentMatrix] = {}

    def set_consent(self, athlete_id: str, matrix: BiometricConsentMatrix) -> None:
        """Définit ou met à jour le consentement explicite de l'athlète."""
        self._consent_store[athlete_id] = matrix

    def get_consent(self, athlete_id: str) -> BiometricConsentMatrix:
        """Récupère le statut actuel du consentement (ou refuse tout par défaut)."""
        return self._consent_store.get(athlete_id, BiometricConsentMatrix())

    def revoke_all_consent(self, athlete_id: str) -> None:
        """Révocation immédiate de l'ensemble des consentements (Droit de retrait RGPD)."""
        self._consent_store[athlete_id] = BiometricConsentMatrix(
            consent_gps=False,
            consent_heart_rate=False,
            consent_performance_metrics=False,
            consent_medical_vitals=False,
        )

    def is_scope_allowed(self, athlete_id: str, scope: str) -> bool:
        """Vérifie si un scope spécifique de données biométriques est autorisé par l'athlète."""
        consent = self.get_consent(athlete_id)

        scope_mapping = {
            "gps": consent.consent_gps,
            "heart_rate": consent.consent_heart_rate,
            "performance": consent.consent_performance_metrics,
            "medical_vitals": consent.consent_medical_vitals,
        }
        return scope_mapping.get(scope.lower(), False)
