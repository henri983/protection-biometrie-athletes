# Conformité RGPD & Données Biométriques des Sportifs

## 1. Cadre Juridique Européen

Les données de santé et les données biométriques collectées sur les sportifs relèvent de l'**Article 9 du RGPD** (« Traitement portant sur des catégories particulières de données »).

- **Article 9.2 (a) :** Consentement explicite de la personne concernée pour une ou plusieurs finalités spécifiques.
- **Article 7 :** Conditions applicables au consentement : liberté du consentement, granularité et droit de révocation sans pénalité sportive ou contractuelle.
- **Article 25 :** Protection des données dès la conception (Privacy by Design & by Default) : désactivation automatique de tous les canaux non explicitement activés.

## 2. Matrice de Consentement Granulaire (Article 7)

L'athlète dispose d'une interface lui permettant de paramétrer indépendamment :
1. **`consent_gps` :** Localisation géographique pour analyse du dénivelé et de la vitesse de course.
2. **`consent_heart_rate` :** Fréquence cardiaque moyenne, maximale et variabilité HRV.
3. **`consent_performance_metrics` :** Puissance (Watts), cadence de pédalage ou de foulée.
4. **`consent_medical_vitals` :** Analyses biologiques approfondies (lactatémie, hématocrite, saturation O2).

## 3. Droit de Retrait Instantané

Conformément à l'article 7.3 du RGPD, l'appel à l'endpoint :
`DELETE /api/v1/athletes/{id}/consent`
révoque en temps réel et sans latence l'intégralité des flux biométriques et bloque toute nouvelle consultation.
