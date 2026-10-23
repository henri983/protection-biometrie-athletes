"""
Application FastAPI - Plateforme de Sécurisation des Données Biométriques des Athlètes
avec Détection IA des Accès Anormaux.
"""

import time
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Header, status
from pydantic import BaseModel, Field

from src.ai.anomaly_detector import BiometricAccessAnomalyEngine
from src.config import Settings, get_settings
from src.models.athlete import AthleteProfile, AthleteRegistration, BiometricConsentMatrix
from src.models.audit_event import AccessRequestMetadata, AnomalyAuditAlert
from src.models.telemetry import (
    DecryptedBiometricView,
    IngestTelemetryRequest,
    RawBiometricTelemetry,
)
from src.security.consent_manager import ConsentManager
from src.security.crypto import BiometricCryptoEngine
from src.security.gps_obfuscator import GPSPrivacyGuard
from src.security.rbac import AccessPolicyGuard, AthleteDataRole, BiometricPermission


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    current_settings = settings or get_settings()

    app = FastAPI(
        title="Protection des Données Biométriques des Athlètes",
        description="Cadre de sécurité Zero-Trust, chiffrement AES-256-GCM, conformité RGPD Art. 9 et Détection IA des Accès Anormaux",
        version="1.0.0",
    )

    # Composants de sécurité et IA
    crypto = BiometricCryptoEngine(
        master_key_hex=current_settings.BIOMETRIC_MASTER_KEY_HEX,
        hmac_key_hex=current_settings.HMAC_TELEMETRY_KEY_HEX,
    )
    gps_guard = GPSPrivacyGuard()
    consent_mgr = ConsentManager()
    anomaly_engine = BiometricAccessAnomalyEngine(
        risk_threshold=current_settings.AI_ANOMALY_THRESHOLD,
        max_speed_kmh=current_settings.MAX_PLAUSIBLE_SPEED_KMH,
    )

    # Persistance en mémoire simulant le stockage sécurisé
    athletes_db: Dict[str, AthleteProfile] = {}
    encrypted_telemetry_db: Dict[str, List[bytes]] = {}

    @app.get("/health", tags=["Monitoring"])
    async def health() -> dict:
        return {
            "status": "healthy",
            "service": "protection-biometrie-athletes",
            "total_athletes": len(athletes_db),
            "ai_alerts_count": len(anomaly_engine.recorded_alerts),
        }

    @app.post(
        "/api/v1/athletes",
        status_code=status.HTTP_201_CREATED,
        tags=["Enregistrement & Consentement"],
    )
    async def register_athlete(payload: AthleteRegistration) -> dict:
        """Enregistre un athlète avec sa matrice initiale de consentement RGPD (Art. 7)."""
        if payload.athlete_id in athletes_db:
            raise HTTPException(status_code=400, detail="Athlète déjà enregistré.")

        profile = AthleteProfile(
            athlete_id=payload.athlete_id,
            sport=payload.sport,
            team=payload.team,
            consent=payload.consent,
            created_at=time.time(),
        )
        athletes_db[payload.athlete_id] = profile
        consent_mgr.set_consent(payload.athlete_id, payload.consent)
        encrypted_telemetry_db[payload.athlete_id] = []

        return {
            "message": "Athlète enregistré avec succès et consentement consigné.",
            "athlete_id": payload.athlete_id,
            "consent": payload.consent.model_dump(),
        }

    @app.put("/api/v1/athletes/{athlete_id}/consent", tags=["Enregistrement & Consentement"])
    async def update_consent(athlete_id: str, consent: BiometricConsentMatrix) -> dict:
        """Met à jour le consentement granulaire de l'athlète."""
        if athlete_id not in athletes_db:
            raise HTTPException(status_code=404, detail="Athlète introuvable.")

        athletes_db[athlete_id].consent = consent
        consent_mgr.set_consent(athlete_id, consent)
        return {"message": "Consentement mis à jour.", "consent": consent.model_dump()}

    @app.delete("/api/v1/athletes/{athlete_id}/consent", tags=["Enregistrement & Consentement"])
    async def revoke_consent(athlete_id: str) -> dict:
        """Révocation immédiate de tout consentement (Droit de retrait RGPD)."""
        if athlete_id not in athletes_db:
            raise HTTPException(status_code=404, detail="Athlète introuvable.")

        consent_mgr.revoke_all_consent(athlete_id)
        athletes_db[athlete_id].consent = consent_mgr.get_consent(athlete_id)
        return {"message": "Tous les consentements ont été révoqués immédiatement."}

    @app.post("/api/v1/telemetry/ingest", status_code=status.HTTP_201_CREATED, tags=["Télémétrie Sécurisée"])
    async def ingest_telemetry(payload: IngestTelemetryRequest) -> dict:
        """Ingère un flux de données télémétriques après vérification de signature HMAC et chiffrement AES-256-GCM."""
        telemetry_dict = payload.telemetry.model_dump()
        telemetry_json = payload.telemetry.model_dump_json()

        # Vérification d'intégrité de bout en bout
        if not crypto.verify_hmac_signature(telemetry_json, payload.signature_hmac):
            raise HTTPException(status_code=401, detail="Signature HMAC invalide : flux altéré ou clé erronée.")

        # Chiffrement AES-256-GCM avec AAD
        encrypted_bytes = crypto.encrypt_biometrics(telemetry_dict, payload.telemetry.athlete_id)

        if payload.telemetry.athlete_id not in encrypted_telemetry_db:
            encrypted_telemetry_db[payload.telemetry.athlete_id] = []
        encrypted_telemetry_db[payload.telemetry.athlete_id].append(encrypted_bytes)

        return {
            "message": "Données biométriques chiffrées et stockées avec succès.",
            "records_stored": len(encrypted_telemetry_db[payload.telemetry.athlete_id]),
        }

    @app.get(
        "/api/v1/athletes/{athlete_id}/biometrics",
        response_model=List[DecryptedBiometricView],
        tags=["Consultation & IA"],
    )
    async def get_athlete_biometrics(
        athlete_id: str,
        x_user_id: str = Header(..., alias="X-User-ID"),
        x_user_role: str = Header(..., alias="X-User-Role"),
        x_client_ip: str = Header("127.0.0.1", alias="X-Client-IP"),
        x_client_lat: float = Header(48.8566, alias="X-Client-Lat"),
        x_client_lon: float = Header(2.3522, alias="X-Client-Lon"),
        x_requested_scope: str = Header("performance", alias="X-Requested-Scope"),
    ) -> List[DecryptedBiometricView]:
        """
        Consulte les données biométriques après évaluation du risque par l'IA,
        vérification RBAC/ABAC et application des consentements et de l'obfuscation GPS.
        """
        try:
            role = AthleteDataRole(x_user_role.lower())
        except ValueError:
            raise HTTPException(status_code=403, detail="Rôle utilisateur non valide.")

        # 1. Évaluation IA de détection d'accès anormal
        access_meta = AccessRequestMetadata(
            user_id=x_user_id,
            user_role=role.value,
            target_athlete_id=athlete_id,
            client_ip=x_client_ip,
            latitude=x_client_lat,
            longitude=x_client_lon,
            timestamp=time.time(),
            requested_scope=x_requested_scope,
        )

        risk_score, should_block, reasons = anomaly_engine.evaluate_access(access_meta)
        if should_block:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Accès bloqué par le système IA de détection d'anomalies.",
                    "risk_score": risk_score,
                    "reasons": reasons,
                },
            )

        # 2. Vérification RBAC
        if role == AthleteDataRole.ATHLETE and x_user_id != athlete_id:
            raise HTTPException(status_code=403, detail="Un athlète ne peut consulter que ses propres données.")

        records = encrypted_telemetry_db.get(athlete_id, [])
        consent = consent_mgr.get_consent(athlete_id)

        results: List[DecryptedBiometricView] = []
        for enc in records:
            decrypted = crypto.decrypt_biometrics(enc, athlete_id)

            # Application du consentement et des permissions par canal de données
            obfuscated_gps = None
            if consent.consent_gps and AccessPolicyGuard.has_permission(role, BiometricPermission.READ_OBFUSCATED_GPS):
                obfuscated_gps = gps_guard.obfuscate_coordinates(
                    decrypted.get("latitude"), decrypted.get("longitude")
                )

            view = DecryptedBiometricView(
                athlete_id=athlete_id,
                timestamp=decrypted["timestamp"],
                gps=obfuscated_gps,
                heart_rate_bpm=decrypted.get("heart_rate_bpm") if (consent.consent_heart_rate and AccessPolicyGuard.has_permission(role, BiometricPermission.READ_CARDIO_STREAM)) else None,
                hrv_ms=decrypted.get("hrv_ms") if (consent.consent_heart_rate and AccessPolicyGuard.has_permission(role, BiometricPermission.READ_CARDIO_STREAM)) else None,
                power_watts=decrypted.get("power_watts") if (consent.consent_performance_metrics and AccessPolicyGuard.has_permission(role, BiometricPermission.READ_PERFORMANCE_METRICS)) else None,
                cadence_rpm=decrypted.get("cadence_rpm") if (consent.consent_performance_metrics and AccessPolicyGuard.has_permission(role, BiometricPermission.READ_PERFORMANCE_METRICS)) else None,
                lactate_mmol_l=decrypted.get("lactate_mmol_l") if (consent.consent_medical_vitals and AccessPolicyGuard.has_permission(role, BiometricPermission.READ_MEDICAL_VITALS)) else None,
            )
            results.append(view)

        return results

    @app.get("/api/v1/ai/audit/anomalies", response_model=List[AnomalyAuditAlert], tags=["Consultation & IA"])
    async def get_anomalies(
        x_user_role: str = Header(..., alias="X-User-Role"),
    ) -> List[AnomalyAuditAlert]:
        """Consulte les alertes d'accès anormaux enregistrées par l'IA (Réservé aux administrateurs)."""
        try:
            role = AthleteDataRole(x_user_role.lower())
        except ValueError:
            raise HTTPException(status_code=403, detail="Rôle invalide.")

        if not AccessPolicyGuard.has_permission(role, BiometricPermission.AUDIT_ANOMALIES):
            raise HTTPException(status_code=403, detail="Accès refusé aux alertes d'audit.")

        return anomaly_engine.recorded_alerts

    return app


app = create_app()
