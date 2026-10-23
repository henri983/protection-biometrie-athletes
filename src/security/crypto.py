"""
Moteur cryptographique pour les données biométriques des athlètes.
Chiffrement symétrique authentifié AES-256-GCM et signatures télémétriques HMAC-SHA256.
"""

import hmac
import hashlib
import json
import os
from typing import Any, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class BiometricCryptoEngine:
    """Moteur de chiffrement AES-256-GCM et vérification HMAC."""

    def __init__(self, master_key_hex: str, hmac_key_hex: str) -> None:
        self.master_key = bytes.fromhex(master_key_hex)
        if len(self.master_key) != 32:
            raise ValueError("La clé principale AES-256 doit faire exactement 32 octets (64 hex).")
        self.hmac_key = bytes.fromhex(hmac_key_hex)
        self.aesgcm = AESGCM(self.master_key)

    def encrypt_biometrics(self, data: Dict[str, Any], athlete_id: str) -> bytes:
        """
        Chiffre le dictionnaire biométrique en AES-256-GCM.
        Le nonce de 12 octets est préfixé au ciphertext.
        L'athlete_id est fourni en données associées authentifiées (AAD).
        """
        nonce = os.urandom(12)
        plaintext = json.dumps(data, sort_keys=True).encode("utf-8")
        aad = athlete_id.encode("utf-8")

        ciphertext = self.aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ciphertext

    def decrypt_biometrics(self, encrypted_payload: bytes, athlete_id: str) -> Dict[str, Any]:
        """
        Déchiffre le payload chiffré et valide le tag d'authentification GCM et l'AAD.
        """
        if len(encrypted_payload) < 28:  # 12 nonce + 16 tag minimum
            raise ValueError("Payload chiffré corrompu ou trop court.")

        nonce = encrypted_payload[:12]
        ciphertext = encrypted_payload[12:]
        aad = athlete_id.encode("utf-8")

        plaintext = self.aesgcm.decrypt(nonce, ciphertext, aad)
        return json.loads(plaintext.decode("utf-8"))

    def compute_hmac_signature(self, message: str) -> str:
        """Génère la signature HMAC-SHA256 d'un message."""
        return hmac.new(self.hmac_key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_hmac_signature(self, message: str, signature: str) -> bool:
        """Vérifie la signature HMAC-SHA256 en temps constant."""
        expected = self.compute_hmac_signature(message)
        return hmac.compare_digest(expected, signature)
