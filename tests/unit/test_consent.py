"""
Tests unitaires de la gestion du consentement granulaire RGPD (Articles 7 & 9).
"""

import pytest
from src.models.athlete import BiometricConsentMatrix
from src.security.consent_manager import ConsentManager


@pytest.mark.unit
def test_consent_default_denial(consent_mgr: ConsentManager):
    """Par défaut, sans consentement explicite, tout accès est refusé (Privacy by Default)."""
    assert consent_mgr.is_scope_allowed("ATH-UNKNOWN", "gps") is False
    assert consent_mgr.is_scope_allowed("ATH-UNKNOWN", "heart_rate") is False
    assert consent_mgr.is_scope_allowed("ATH-UNKNOWN", "performance") is False
    assert consent_mgr.is_scope_allowed("ATH-UNKNOWN", "medical_vitals") is False


@pytest.mark.unit
def test_granular_consent_scoping(consent_mgr: ConsentManager):
    """L'athlète peut consentir au cardio et aux performances tout en refusant le GPS et les analyses médicales."""
    matrix = BiometricConsentMatrix(
        consent_gps=False,
        consent_heart_rate=True,
        consent_performance_metrics=True,
        consent_medical_vitals=False,
    )
    consent_mgr.set_consent("ATH-10", matrix)

    assert consent_mgr.is_scope_allowed("ATH-10", "heart_rate") is True
    assert consent_mgr.is_scope_allowed("ATH-10", "performance") is True
    assert consent_mgr.is_scope_allowed("ATH-10", "gps") is False
    assert consent_mgr.is_scope_allowed("ATH-10", "medical_vitals") is False


@pytest.mark.unit
def test_instantaneous_revocation(consent_mgr: ConsentManager):
    """Le retrait du consentement coupe immédiatement les autorisations d'accès."""
    matrix = BiometricConsentMatrix(
        consent_gps=True,
        consent_heart_rate=True,
        consent_performance_metrics=True,
        consent_medical_vitals=True,
    )
    consent_mgr.set_consent("ATH-10", matrix)
    assert consent_mgr.is_scope_allowed("ATH-10", "gps") is True

    # Révocation
    consent_mgr.revoke_all_consent("ATH-10")
    assert consent_mgr.is_scope_allowed("ATH-10", "gps") is False
    assert consent_mgr.is_scope_allowed("ATH-10", "heart_rate") is False
