"""
Tests unitaires du moteur cryptographique (AES-256-GCM + HMAC-SHA256).
"""

import pytest
from src.security.crypto import BiometricCryptoEngine


@pytest.mark.unit
def test_aes_gcm_encrypt_decrypt_roundtrip(crypto_engine: BiometricCryptoEngine):
    """Vérifie le cycle complet de chiffrement et déchiffrement authentifié."""
    athlete_id = "ATH-001"
    raw_vitals = {
        "heart_rate_bpm": 172,
        "hrv_ms": 52.4,
        "lactate_mmol_l": 4.2,
        "latitude": 48.8584,
        "longitude": 2.2945,
    }

    encrypted_bytes = crypto_engine.encrypt_biometrics(raw_vitals, athlete_id)
    assert isinstance(encrypted_bytes, bytes)
    assert len(encrypted_bytes) > 28

    decrypted = crypto_engine.decrypt_biometrics(encrypted_bytes, athlete_id)
    assert decrypted["heart_rate_bpm"] == 172
    assert decrypted["hrv_ms"] == 52.4
    assert decrypted["lactate_mmol_l"] == 4.2


@pytest.mark.unit
def test_wrong_athlete_aad_rejected(crypto_engine: BiometricCryptoEngine):
    """Tenter de déchiffrer avec un athlete_id différent doit échouer grâce à l'AAD (Authenticated Additional Data)."""
    raw_vitals = {"heart_rate_bpm": 150}
    encrypted = crypto_engine.encrypt_biometrics(raw_vitals, "ATH-001")

    with pytest.raises(Exception):
        crypto_engine.decrypt_biometrics(encrypted, "ATH-OTHER")


@pytest.mark.unit
def test_tampered_ciphertext_rejected(crypto_engine: BiometricCryptoEngine):
    """Toute altération d'un octet de ciphertext lève une exception d'intégrité."""
    raw_vitals = {"heart_rate_bpm": 150}
    encrypted = crypto_engine.encrypt_biometrics(raw_vitals, "ATH-001")

    # Altération d'un octet
    tampered = bytearray(encrypted)
    tampered[-1] ^= 0xFF

    with pytest.raises(Exception):
        crypto_engine.decrypt_biometrics(bytes(tampered), "ATH-001")


@pytest.mark.unit
def test_hmac_signature_validation(crypto_engine: BiometricCryptoEngine):
    """Vérifie la validité des signatures HMAC-SHA256 pour les transmissions edge."""
    payload = '{"athlete_id": "ATH-001", "heart_rate": 160}'
    sig = crypto_engine.compute_hmac_signature(payload)

    assert crypto_engine.verify_hmac_signature(payload, sig) is True
    assert crypto_engine.verify_hmac_signature(payload + " ", sig) is False
