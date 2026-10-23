# Politique de Sécurité & Modèle de Menace - Données Biométriques des Athlètes

## 1. Modèle de Menace (Threat Model)

| Vecteur d'Attaque | Risque Métier | Contre-Mesure Implémentée |
|---|---|---|
| **Usurpation de Compte & Vol de Session** | Exfiltration de données physiologiques par un concurrent | Détection IA de Voyage Impossible : verrouillage immédiat si la vélocité dépasse 900 km/h. |
| **Piratage du flux Télémétrique (Man-In-The-Middle)** | Falsification des données d'effort ou de santé | Signatures HMAC-SHA256 validées en temps constant sur chaque trame edge. |
| **Traçage Malveillant du Domicile (Stalking)** | Atteinte à la sécurité physique et à la vie privée de l'athlète | Obfuscation GPS différentielle + détection de périmètre sanctuaire. |
| **Violation du Secret Médical par le Staff Technique** | Chantage, non-sélection abusive basée sur un paramètre biologique | Isolation RBAC stricte : seul le `TEAM_PHYSICIAN` accède aux données médicales (lactates/bilans). |
| **Aspiration Massive (Data Scraping)** | Revente illicite des performances sportives | Détection de burst temps réel bloquant les utilisateurs à plus de 15 req/min. |

## 2. Procédure de Signalement & Divulgation Responsable

Toute anomalie ou vulnérabilité de sécurité peut être signalée de manière confidentielle à :
- **Contact Sécurité :** `henrinyame2001@gmail.com`
- **Délai d'intervention :** Sous 24 heures ouvrées.
