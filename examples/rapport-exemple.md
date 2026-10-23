# Rapport de priorisation des vulnérabilités

20 vulnérabilités analysées sur 12 machines (2 lignes informatives ignorées, 1 doublon(s) fusionné(s)).
Catalogue CISA KEV : version demo, 5 entrées.

## Synthèse

| Priorité | Délai de correction | Nombre |
|---|---|---|
| P1 | 48 heures | 4 |
| P2 | 7 jours | 3 |
| P3 | 30 jours | 6 |
| P4 | 90 jours | 7 |

7 vulnérabilité(s) sont connues comme exploitées activement (catalogue KEV).

## Ce que la priorisation change par rapport au CVSS seul

- **2** vulnérabilité(s) de gravité CVSS élevée (7 ou plus) ne sont pas urgentes (P3 ou P4), car le bien est peu critique, non exposé ou en environnement de test.
- **0** vulnérabilité(s) de gravité CVSS modérée (moins de 7) deviennent urgentes (P1 ou P2), car elles sont activement exploitées ou touchent un bien exposé et critique.
  - Moins urgent : Default credentials on the printer web interface sur imprimante-rdc (CVSS 9.5*, score 50.5, P3)
  - Moins urgent : Unsupported Windows Operating System sur srv-test-app-03 (CVSS 10.0, score 43.0, P3)

## Les 10 vulnérabilités à traiter en premier

| Prio | Score | Machine | Vulnérabilité | CVE | CVSS | KEV | Exposition |
|---|---|---|---|---|---|---|---|
| P1 | 99.0 | srv-web-vitrine | Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell) | CVE-2021-44228 | 10.0 | Oui | internet |
| P1 | 81.0 | srv-ad-01 | Windows Print Spooler Remote Code Execution (PrintNigh… | CVE-2021-34527 | 8.8 | Oui | interne |
| P1 | 80.0 | wks-compta-07 | Microsoft Outlook Elevation of Privilege | CVE-2023-23397 | 9.8 | Oui | interne |
| P1 | 80.0 | 10.20.7.99 | Microsoft Outlook Elevation of Privilege | CVE-2023-23397 | 9.8 | Oui | interne |
| P2 | 74.5 | srv-fichiers-02 | MS17-010: Security Update for SMB Server (EternalBlue) | CVE-2017-0144 | 8.1 | Oui | interne |
| P2 | 73.0 | srv-test-app-03 | Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell) | CVE-2021-44228 | 10.0 | Oui | interne |
| P2 | 70.0 | srv-recette-db-01 | Remote Desktop Services Remote Code Execution (BlueKee… | CVE-2019-0708 | 9.8 | Oui | interne |
| P3 | 54.5 | srv-paiement-01 | TLS Version 1.0 Protocol Detection | - | 6.5 | Non | internet |
| P3 | 51.5 | srv-web-vitrine | TLS Version 1.0 Protocol Detection | - | 6.5 | Non | internet |
| P3 | 50.5 | imprimante-rdc | Default credentials on the printer web interface | - | 9.5* | Non | interne |

\* CVSS estimé d'après le niveau de risque du scanner (aucun score fourni).

## Machines les plus exposées

| Machine | Nom | P1 | P2 | Score max | Vulnérabilités |
|---|---|---|---|---|---|
| 10.20.2.20 | srv-web-vitrine | 1 | 0 | 99.0 | 4 |
| 10.20.3.10 | srv-ad-01 | 1 | 0 | 81.0 | 2 |
| 10.20.5.37 | wks-compta-07 | 1 | 0 | 80.0 | 2 |
| 10.20.7.99 | 10.20.7.99 | 1 | 0 | 80.0 | 1 |
| 10.20.3.25 | srv-fichiers-02 | 0 | 1 | 74.5 | 2 |
| 10.30.1.15 | srv-test-app-03 | 0 | 1 | 73.0 | 2 |
| 10.30.1.30 | srv-recette-db-01 | 0 | 1 | 70.0 | 1 |
| 10.20.1.10 | srv-paiement-01 | 0 | 0 | 54.5 | 1 |
| 10.20.9.5 | imprimante-rdc | 0 | 0 | 50.5 | 1 |
| 10.20.3.40 | srv-sauvegarde-01 | 0 | 0 | 35.5 | 2 |

## Gains rapides : un correctif, plusieurs vulnérabilités

| Correctif | Vulnérabilités | Machines |
|---|---|---|
| Enforce message signing in the host's configuration. | 6 | 6 |
| Upgrade to Apache Log4j 2.17.1 or later, or remove the JndiLookup class from the classpat… | 2 | 2 |
| Apply the Microsoft Outlook security updates. | 2 | 2 |
| Enable support for TLS 1.2 and 1.3, and disable TLS 1.0. | 2 | 2 |

## Machines absentes de l'inventaire

Ces machines ont été notées avec des valeurs par défaut (importance 3/5, interne, production). Elles méritent d'être inventoriées : un actif inconnu est déjà un risque.

- 10.20.7.99

## Détail des vulnérabilités P1

### srv-web-vitrine : Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell)

- +50.0 : gravité CVSS 10.0
- +25 : CVE-2021-44228 figure au catalogue CISA des vulnérabilités exploitées
- +5 : utilisation connue dans des campagnes de rançongiciels
- +9 : importance du bien = 4/5
- +10 : accessible depuis Internet
- **Total : 99.0/100, à corriger sous 48 heures**

Solution proposée par le scanner : Upgrade to Apache Log4j 2.17.1 or later, or remove the JndiLookup class from the classpath.

### srv-ad-01 : Windows Print Spooler Remote Code Execution (PrintNightmare)

- +44.0 : gravité CVSS 8.8
- +25 : CVE-2021-34527 figure au catalogue CISA des vulnérabilités exploitées
- +12 : importance du bien = 5/5
- **Total : 81.0/100, à corriger sous 48 heures**

Solution proposée par le scanner : Apply the Microsoft updates and disable the Print Spooler service on servers that do not need it.

### wks-compta-07 : Microsoft Outlook Elevation of Privilege

- +49.0 : gravité CVSS 9.8
- +25 : CVE-2023-23397 figure au catalogue CISA des vulnérabilités exploitées
- +6 : importance du bien = 3/5
- **Total : 80.0/100, à corriger sous 48 heures**

Solution proposée par le scanner : Apply the Microsoft Outlook security updates.

### 10.20.7.99 : Microsoft Outlook Elevation of Privilege

- +49.0 : gravité CVSS 9.8
- +25 : CVE-2023-23397 figure au catalogue CISA des vulnérabilités exploitées
- +6 : importance du bien = 3/5 (actif non inventorié, valeur par défaut)
- **Total : 80.0/100, à corriger sous 48 heures**

Solution proposée par le scanner : Apply the Microsoft Outlook security updates.
