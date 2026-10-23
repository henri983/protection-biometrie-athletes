# Changelog

Toutes les modifications notables apportées à ce projet sont consignées dans ce fichier.
Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/) et adhère au [Versionnage Sémantique (SemVer)](https://semver.org/).

## [1.0.0] - 2026-10-23

### Ajouts Initiaux (v1.0.0 Release)
- **Moteur Cryptographique Biométrique :**
  - Chiffrement symétrique authentifié AES-256-GCM avec AAD lié à l'athlète.
  - Signature et vérification d'intégrité télémétrique HMAC-SHA256 en temps constant.
- **Protection Spatiale & Géolocalisation (GPS Privacy) :**
  - Floutage différentiel de coordonnées par grille spatiale.
  - Détection automatique et exclusion des périmètres sanctuaires résidentiels.
- **Gouvernance RGPD & Consentement :**
  - Matrice granulaire de consentement par canal de données (Articles 7 & 9 RGPD).
  - Révocation instantanée à la volée.
  - Ségrégation des rôles RBAC/ABAC stricte (Athlète, Coach, Médecin, Analyste, Fédéral).
- **Variante Intelligence Artificielle :**
  - Détection de voyage physiquement impossible (formule de Haversine & seuil de vélocité à 900 km/h).
  - Détection d'exfiltration en rafale / scraping massif (> 15 req/min).
  - Détection d'accès nocturnes hors calendrier d'entraînement.
  - Calcul unifié du score de risque et blocage immédiat à >= 0.75.
- **Assurance Qualité & Pipeline CI/CD :**
  - Suite de 20 tests automatisés avec 100% de réussite.
  - Workflow GitHub Actions pour analyse statique de sécurité (Bandit) et tests continus.
