"""
Contrôle d'accès basé sur les rôles et attributs (RBAC / ABAC) pour les données sportives.
"""

from enum import Enum
from typing import Dict, Set


class AthleteDataRole(str, Enum):
    ATHLETE = "athlete"
    HEAD_COACH = "head_coach"
    TEAM_PHYSICIAN = "team_physician"
    PERFORMANCE_ANALYST = "performance_analyst"
    DOPING_CONTROLLER = "doping_controller"
    FEDERATION_ADMIN = "federation_admin"


class BiometricPermission(str, Enum):
    READ_OWN_DATA = "read_own_data"
    MANAGE_CONSENT = "manage_consent"
    READ_PERFORMANCE_METRICS = "read_performance_metrics"
    READ_OBFUSCATED_GPS = "read_obfuscated_gps"
    READ_CARDIO_STREAM = "read_cardio_stream"
    READ_MEDICAL_VITALS = "read_medical_vitals"
    AUDIT_ANOMALIES = "audit_anomalies"


ROLE_PERMISSIONS: Dict[AthleteDataRole, Set[BiometricPermission]] = {
    AthleteDataRole.ATHLETE: {
        BiometricPermission.READ_OWN_DATA,
        BiometricPermission.MANAGE_CONSENT,
        BiometricPermission.READ_PERFORMANCE_METRICS,
        BiometricPermission.READ_OBFUSCATED_GPS,
        BiometricPermission.READ_CARDIO_STREAM,
        BiometricPermission.READ_MEDICAL_VITALS,
    },
    AthleteDataRole.HEAD_COACH: {
        BiometricPermission.READ_PERFORMANCE_METRICS,
        BiometricPermission.READ_CARDIO_STREAM,
        BiometricPermission.READ_OBFUSCATED_GPS,
        # Interdit formellement : READ_MEDICAL_VITALS (secret médical)
    },
    AthleteDataRole.TEAM_PHYSICIAN: {
        BiometricPermission.READ_CARDIO_STREAM,
        BiometricPermission.READ_MEDICAL_VITALS,
        BiometricPermission.READ_PERFORMANCE_METRICS,
    },
    AthleteDataRole.PERFORMANCE_ANALYST: {
        BiometricPermission.READ_PERFORMANCE_METRICS,
        BiometricPermission.READ_OBFUSCATED_GPS,
    },
    AthleteDataRole.DOPING_CONTROLLER: {
        BiometricPermission.READ_MEDICAL_VITALS,
    },
    AthleteDataRole.FEDERATION_ADMIN: {
        BiometricPermission.AUDIT_ANOMALIES,
    },
}


class AccessPolicyGuard:
    """Vérification formelle des autorisations."""

    @staticmethod
    def has_permission(role: AthleteDataRole, perm: BiometricPermission) -> bool:
        perms = ROLE_PERMISSIONS.get(role, set())
        return perm in perms
