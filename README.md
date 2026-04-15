# -Mini-Playbook-SQL-S-curit-SOC
Playbook SQL pour SOC

Ce document présente un ensemble de requêtes SQL types utilisées par les analystes de sécurité dans un Security Operations Center (SOC). Elles permettent d’investiguer des scénarios courants tels que les tentatives de brute force, les comptes dormants, les escalades de privilèges et les connexions suspectes.

1. Tentatives de connexion échouées (Brute Force)

SELECT username, ip_address, COUNT(*) AS failed_attempts
FROM auth_logs
WHERE status = 'FAILED'
GROUP BY username, ip_address
HAVING COUNT(*) > 10
ORDER BY failed_attempts DESC;

Objectif : Détecter les comptes ciblés par des attaques par force brute.

2. Comptes dormants (Inactifs depuis 90 jours)

SELECT username, MAX(timestamp) AS last_login
FROM auth_logs
WHERE status = 'SUCCESS'
GROUP BY username
HAVING MAX(timestamp) < NOW() - INTERVAL '90 days';

Objectif : Identifier les comptes inactifs depuis plus de 90 jours.

3. Escalade de privilèges suspecte

SELECT username, timestamp, action
FROM privilege_changes
WHERE action = 'GRANT_ADMIN'
  AND timestamp > NOW() - INTERVAL '7 days';

Objectif : Lister les utilisateurs ayant reçu des privilèges administratifs récemment.

4. Connexions depuis des IP inhabituelles

SELECT username, ip_address, COUNT(*) AS login_count
FROM auth_logs
WHERE status = 'SUCCESS'
GROUP BY username, ip_address
HAVING COUNT(*) < 3
ORDER BY login_count ASC;

Objectif : Détecter des connexions réussies depuis des IP rarement utilisées par l’utilisateur.

5. Corrélation échecs → succès

SELECT a.username, a.ip_address, a.timestamp, a.status
FROM auth_logs a
JOIN (
    SELECT ip_address
    FROM auth_logs
    WHERE status = 'FAILED'
    GROUP BY ip_address
    HAVING COUNT(*) > 5
) b ON a.ip_address = b.ip_address
ORDER BY a.timestamp;

Objectif : Vérifier si une IP ayant échoué plusieurs fois finit par réussir une connexion.

🎯 Utilisation pratique

Intégrer ces requêtes dans des dashboards SIEM (Splunk, QRadar, Sentinel).

Documenter les résultats dans des rapports d’incident ou d’audit.

Ajouter ce playbook dans un portfolio GitHub pour démontrer la capacité à appliquer SQL aux scénarios de sécurité réels.

✅ Conclusion

Ce playbook SQL illustre la valeur de SQL comme outil d’investigation en sécurité. Il peut être enrichi avec d’autres scénarios (ex. détection de beaconing, analyse de DNS, suivi des sessions VPN) pour renforcer les capacités d’un SOC.
