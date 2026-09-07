# CYBER SENTINEL — Détection des menaces SSH et supervision de la sécurité

Cyber Sentinel est un système léger de supervision de sécurité de type SOC, accompagné d'un moteur d'analyse permettant d'examiner les journaux d'authentification Linux/SSH (`auth.log`), de détecter les attaques par force brute à l'aide d'un algorithme à fenêtre glissante, de calculer dynamiquement le niveau de risque associé à chaque adresse IP et de présenter les résultats dans un tableau de bord interactif en mode sombre.

---

## Fonctionnalités

- **Analyse des journaux d'authentification SSH** : extrait les événements de connexion réussie, échouée et les tentatives utilisant des utilisateurs invalides, avec les informations relatives au port et à l'adresse IP.

- **Stockage SQLite idempotent** : garantit l'absence de doublons dans les logs et les alertes lors des exécutions répétées du programme.

- **Moteur de calcul du risque** : évalue le niveau de menace d'une adresse IP selon le nombre de tentatives de connexion échouées. Les niveaux sont : LOW, MEDIUM, HIGH et CRITICAL.

- **Détection des attaques par force brute avec fenêtre glissante** : analyse des fenêtres temporelles de 5 minutes afin d'identifier les adresses IP ayant effectué au moins 5 tentatives de connexion échouées.

- **Tableau de bord interactif de supervision** : interface de type SOC développée avec Streamlit et Plotly, permettant de visualiser l'état de sécurité du système.

- **Investigation des adresses IP** : permet de sélectionner une adresse IP afin d'obtenir une analyse détaillée de son activité et de consulter sa chronologie.

- **Explorateur de logs** : tableau structuré permettant de filtrer les événements selon plusieurs critères, notamment l'adresse IP, le nom d'utilisateur et le statut de connexion.

- **Suite de tests unitaires** : tests réalisés avec Pytest pour vérifier l'analyse des logs, le calcul du risque, la détection des attaques par force brute et l'idempotence de la base de données.

---

## Architecture

```text
auth.log
   |
   v
Analyseur de logs (parser.py)
   |
   v
Base de données SQLite (security_logs.db)
   |
   v
Statistiques par IP (statistics.py)
   |
   v
Détection de force brute (detector.py)
   |
   v
Calcul du risque (risk_scoring.py)
   |
   v
Alertes de sécurité (alerts.py)
   |
   v
Tableau de bord Cyber Sentinel (dashboard/app.py)