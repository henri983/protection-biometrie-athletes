"""
Tests unitaires des politiques de sécurité RBAC / ABAC.
"""

import pytest
from src.security.rbac import AccessPolicyGuard, AthleteDataRole, BiometricPermission


@pytest.mark.unit
def test_coach_cannot_read_medical_vitals():
    """Le coach ne peut pas accéder aux bilans médicaux protégés par le secret médical."""
    assert AccessPolicyGuard.has_permission(AthleteDataRole.HEAD_COACH, BiometricPermission.READ_PERFORMANCE_METRICS) is True
    assert AccessPolicyGuard.has_permission(AthleteDataRole.HEAD_COACH, BiometricPermission.READ_CARDIO_STREAM) is True
    assert AccessPolicyGuard.has_permission(AthleteDataRole.HEAD_COACH, BiometricPermission.READ_MEDICAL_VITALS) is False


@pytest.mark.unit
def test_physician_access():
    """Le médecin d'équipe a accès aux biométries médicales et cardio."""
    assert AccessPolicyGuard.has_permission(AthleteDataRole.TEAM_PHYSICIAN, BiometricPermission.READ_MEDICAL_VITALS) is True
    assert AccessPolicyGuard.has_permission(AthleteDataRole.TEAM_PHYSICIAN, BiometricPermission.READ_CARDIO_STREAM) is True


@pytest.mark.unit
def test_federation_admin_audit_permission():
    """L'administrateur fédération peut auditer les anomalies mais pas lire les flux sans motif."""
    assert AccessPolicyGuard.has_permission(AthleteDataRole.FEDERATION_ADMIN, BiometricPermission.AUDIT_ANOMALIES) is True
    assert AccessPolicyGuard.has_permission(AthleteDataRole.FEDERATION_ADMIN, BiometricPermission.READ_MEDICAL_VITALS) is False
