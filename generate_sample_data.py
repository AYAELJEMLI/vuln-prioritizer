"""
generate_sample_data.py
Génère des données 100 % FICTIVES pour tester l'outil :
  samples/scan_nessus.csv   export de scanner (colonnes de type Nessus)
  samples/assets.csv        inventaire des machines d'une banque fictive
  samples/kev_extrait.json  EXTRAIT DE DÉMONSTRATION du catalogue CISA KEV (pas le catalogue officiel)

Usage : python generate_sample_data.py
"""

import csv
import json
import os

os.makedirs("samples", exist_ok=True)

ACTIFS = [  # host, ip, nom, criticite, exposition, environnement
    ("srv-paiement-01", "10.20.1.10", "srv-paiement-01", "critique", "internet", "prod"),
    ("srv-web-vitrine", "10.20.2.20", "srv-web-vitrine", "haute", "internet", "prod"),
    ("srv-ad-01", "10.20.3.10", "srv-ad-01", "critique", "interne", "prod"),
    ("srv-fichiers-02", "10.20.3.25", "srv-fichiers-02", "haute", "interne", "prod"),
    ("srv-sauvegarde-01", "10.20.3.40", "srv-sauvegarde-01", "haute", "interne", "prod"),
    ("srv-rh-01", "10.20.4.12", "srv-rh-01", "haute", "interne", "prod"),
    ("wks-compta-07", "10.20.5.37", "wks-compta-07", "moyenne", "interne", "prod"),
    ("wks-support-14", "10.20.5.52", "wks-support-14", "moyenne", "interne", "prod"),
    ("srv-test-app-03", "10.30.1.15", "srv-test-app-03", "basse", "interne", "test"),
    ("srv-recette-db-01", "10.30.1.30", "srv-recette-db-01", "moyenne", "interne", "recette"),
    ("imprimante-rdc", "10.20.9.5", "imprimante-rdc", "basse", "interne", "prod"),
]

LOG4J = "Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell)"
LOG4J_FIX = "Upgrade to Apache Log4j 2.17.1 or later, or remove the JndiLookup class from the classpath."
SMB = "SMB Signing not required"
SMB_FIX = "Enforce message signing in the host's configuration."

SCAN = [  # plugin, cve, cvss, risque, hote, port, nom, solution
    ("DEMO-001", "CVE-2021-44228", "10.0", "Critical", "10.20.2.20", "8080", LOG4J, LOG4J_FIX),
    ("DEMO-001", "CVE-2021-44228", "10.0", "Critical", "10.20.2.20", "8080", LOG4J, LOG4J_FIX),  # doublon volontaire
    ("DEMO-001", "CVE-2021-44228", "10.0", "Critical", "10.30.1.15", "8080", LOG4J, LOG4J_FIX),
    ("DEMO-002", "CVE-2017-0144", "8.1", "High", "10.20.3.25", "445", "MS17-010: Security Update for SMB Server (EternalBlue)",
     "Apply the Microsoft security updates for SMBv1 or disable SMBv1."),
    ("DEMO-003", "CVE-2021-34527", "8.8", "High", "10.20.3.10", "445", "Windows Print Spooler Remote Code Execution (PrintNightmare)",
     "Apply the Microsoft updates and disable the Print Spooler service on servers that do not need it."),
    ("DEMO-004", "CVE-2019-0708", "9.8", "Critical", "10.30.1.30", "3389", "Remote Desktop Services Remote Code Execution (BlueKeep)",
     "Apply the Microsoft security updates for Remote Desktop Services and enable Network Level Authentication."),
    ("DEMO-005", "CVE-2023-23397", "9.8", "Critical", "10.20.5.37", "445", "Microsoft Outlook Elevation of Privilege",
     "Apply the Microsoft Outlook security updates."),
    ("DEMO-005", "CVE-2023-23397", "9.8", "Critical", "10.20.7.99", "445", "Microsoft Outlook Elevation of Privilege",
     "Apply the Microsoft Outlook security updates."),
    ("DEMO-006", "", "10.0", "Critical", "10.30.1.15", "445", "Unsupported Windows Operating System",
     "Upgrade to a version of Windows that is currently supported."),
    ("DEMO-007", "", "", "Critical", "10.20.9.5", "80", "Default credentials on the printer web interface",
     "Change the default administrator password."),
    ("DEMO-008", "", "", "Medium", "10.20.2.20", "443", "SSL Certificate Expiry", "Renew the SSL certificate."),
    ("DEMO-009", "", "6.5", "Medium", "10.20.2.20", "443", "TLS Version 1.0 Protocol Detection",
     "Enable support for TLS 1.2 and 1.3, and disable TLS 1.0."),
    ("DEMO-009", "", "6.5", "Medium", "10.20.1.10", "443", "TLS Version 1.0 Protocol Detection",
     "Enable support for TLS 1.2 and 1.3, and disable TLS 1.0."),
    ("DEMO-010", "", "5.3", "Medium", "10.20.3.10", "445", SMB, SMB_FIX),
    ("DEMO-010", "", "5.3", "Medium", "10.20.3.25", "445", SMB, SMB_FIX),
    ("DEMO-010", "", "5.3", "Medium", "10.20.4.12", "445", SMB, SMB_FIX),
    ("DEMO-010", "", "5.3", "Medium", "10.20.3.40", "445", SMB, SMB_FIX),
    ("DEMO-010", "", "5.3", "Medium", "10.20.5.37", "445", SMB, SMB_FIX),
    ("DEMO-010", "", "5.3", "Medium", "10.20.5.52", "445", SMB, SMB_FIX),
    ("DEMO-011", "", "2.6", "Low", "10.20.3.40", "22", "SSH Weak Algorithms Supported",
     "Consult the product documentation to disable the weak algorithms."),
    ("DEMO-012", "", "5.3", "Medium", "10.20.2.20", "80", "HTTP TRACE / TRACK Methods Allowed", "Disable these methods."),
    ("DEMO-099", "", "", "None", "10.20.2.20", "0", "Nessus Scan Information", ""),  # informatif : ignoré
    ("DEMO-098", "", "", "None", "10.20.3.10", "0", "OS Identification", ""),  # informatif : ignoré
]

KEV = {
    "title": "EXTRAIT DE DÉMONSTRATION du catalogue CISA KEV : ce n'est PAS le catalogue officiel",
    "catalogVersion": "demo",
    "dateReleased": "demo",
    "count": 5,
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
         "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
         "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2023-23397", "vendorProject": "Microsoft", "product": "Outlook",
         "vulnerabilityName": "Microsoft Outlook Elevation of Privilege Vulnerability",
         "dueDate": "2023-04-04", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2017-0144", "vendorProject": "Microsoft", "product": "SMBv1",
         "vulnerabilityName": "Microsoft SMBv1 Remote Code Execution Vulnerability"},
        {"cveID": "CVE-2021-34527", "vendorProject": "Microsoft", "product": "Windows Print Spooler",
         "vulnerabilityName": "Microsoft Windows Print Spooler Remote Code Execution Vulnerability"},
        {"cveID": "CVE-2019-0708", "vendorProject": "Microsoft", "product": "Remote Desktop Services",
         "vulnerabilityName": "Microsoft Remote Desktop Services Remote Code Execution Vulnerability"},
    ],
}


def main():
    with open("samples/assets.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["host", "ip", "nom", "criticite", "exposition", "environnement"])
        w.writerows(ACTIFS)
    with open("samples/scan_nessus.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Plugin ID", "CVE", "CVSS v3.0 Base Score", "Risk", "Host", "Port", "Name", "Solution"])
        w.writerows(SCAN)
    with open("samples/kev_extrait.json", "w", encoding="utf-8") as f:
        json.dump(KEV, f, ensure_ascii=False, indent=2)
    print(f"{len(SCAN)} lignes de scan, {len(ACTIFS)} actifs, {len(KEV['vulnerabilities'])} entrées KEV (extrait de démo)")


if __name__ == "__main__":
    main()
