"""Lecture des trois sources : export du scanner (CSV type Nessus), inventaire des actifs, catalogue KEV."""

import csv
import json
import re
import urllib.request

RE_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
URL_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Noms de colonnes acceptés (en minuscules). Le premier trouvé est utilisé.
ALIAS_SCAN = {
    "hote": ["host", "ip address", "ip", "hostname", "asset", "hôte"],
    "cve": ["cve", "cves"],
    "cvss": ["cvss v3.1 base score", "cvss v3.0 base score", "cvss v3 base score", "cvss",
             "cvss v2.0 base score", "cvss base score"],
    "risque": ["risk", "severity", "risque", "sévérité"],
    "nom": ["name", "plugin name", "title", "nom"],
    "port": ["port"],
    "solution": ["solution", "remediation", "remédiation"],
    "plugin": ["plugin id", "id"],
}
ALIAS_ACTIFS = {
    "hote": ["host", "hote", "hôte", "hostname", "machine"],
    "ip": ["ip", "adresse ip", "ip address"],
    "nom": ["nom", "name", "description"],
    "criticite": ["criticite", "criticité", "criticality"],
    "exposition": ["exposition", "exposure"],
    "environnement": ["environnement", "environment", "env"],
}

RISQUE_VERS_CVSS = {"critical": 9.5, "critique": 9.5, "high": 7.5, "haut": 7.5, "élevé": 7.5, "eleve": 7.5,
                    "medium": 5.0, "moyen": 5.0, "low": 2.5, "faible": 2.5}
INFORMATIF = {"none", "info", "informational", "information", "aucun", ""}

CRITICITE = {"critique": 5, "critical": 5, "haute": 4, "high": 4, "moyenne": 3, "medium": 3,
             "basse": 2, "low": 2, "faible": 2, "minimale": 1, "minimal": 1}


def _norm(texte):
    return re.sub(r"\s+", " ", (texte or "").strip().lower())


def _lire_csv(chemin):
    """Lit un CSV (virgule, point-virgule ou tabulation, avec ou sans BOM). Retourne (colonnes, lignes)."""
    with open(chemin, encoding="utf-8-sig", newline="") as f:
        premiere = f.readline()
        f.seek(0)
        sep = max([",", ";", "\t"], key=premiere.count)
        lecteur = csv.DictReader(f, delimiter=sep)
        colonnes = [_norm(c) for c in (lecteur.fieldnames or [])]
        lignes = [{_norm(k): (v or "").strip() for k, v in l.items() if k} for l in lecteur]
    return colonnes, lignes


def _trouver(colonnes, alias):
    return next((a for a in alias if a in colonnes), None)


def _nombre(valeur):
    try:
        return float(str(valeur).replace(",", ".").strip())
    except ValueError:
        return None


def charger_scan(chemin):
    """Retourne (vulnérabilités, stats). Ignore les lignes informatives et fusionne les doublons."""
    colonnes, lignes = _lire_csv(chemin)
    col = {cle: _trouver(colonnes, alias) for cle, alias in ALIAS_SCAN.items()}
    if not col["hote"] or not col["nom"]:
        raise ValueError("Colonnes introuvables : il faut au moins un nom d'hôte (Host) et un nom de "
                         f"vulnérabilité (Name). Colonnes lues : {', '.join(colonnes)}")

    cvss_cols = [a for a in ALIAS_SCAN["cvss"] if a in colonnes]
    trouvees, vus = [], set()
    stats = {"lignes": len(lignes), "informatives_ignorees": 0, "doublons": 0}
    for l in lignes:
        risque = _norm(l.get(col["risque"], "")) if col["risque"] else ""
        if col["risque"] and risque in INFORMATIF:
            stats["informatives_ignorees"] += 1
            continue
        cves = sorted({c.upper() for c in RE_CVE.findall(l.get(col["cve"], ""))}) if col["cve"] else []
        cvss = next((n for n in (_nombre(l.get(c, "")) for c in cvss_cols) if n is not None), None)
        v = {
            "hote": l[col["hote"]],
            "port": l.get(col["port"], "") if col["port"] else "",
            "plugin": l.get(col["plugin"], "") if col["plugin"] else "",
            "nom": l[col["nom"]],
            "cves": cves,
            "cvss": cvss,
            "risque": risque,
            "solution": l.get(col["solution"], "") if col["solution"] else "",
        }
        cle = (v["hote"].lower(), v["port"], v["plugin"] or v["nom"], tuple(cves))
        if cle in vus:
            stats["doublons"] += 1
            continue
        vus.add(cle)
        trouvees.append(v)
    return trouvees, stats


def _criticite(valeur):
    v = _norm(valeur)
    if v in CRITICITE:
        return CRITICITE[v]
    try:
        n = int(v)
    except ValueError:
        raise ValueError(f"criticité invalide : {valeur!r} (attendu : 1 à 5, ou critique/haute/moyenne/basse)")
    if not 1 <= n <= 5:
        raise ValueError(f"criticité hors limites : {valeur!r} (attendu : 1 à 5)")
    return n


def charger_actifs(chemin):
    """Retourne un dictionnaire {hôte ou IP en minuscules : actif}."""
    colonnes, lignes = _lire_csv(chemin)
    col = {cle: _trouver(colonnes, alias) for cle, alias in ALIAS_ACTIFS.items()}
    if not col["hote"] or not col["criticite"]:
        raise ValueError("Inventaire : colonnes 'host' et 'criticite' obligatoires. "
                         f"Colonnes lues : {', '.join(colonnes)}")
    actifs = {}
    for l in lignes:
        expo = _norm(l.get(col["exposition"], "")) if col["exposition"] else "interne"
        env = _norm(l.get(col["environnement"], "")) if col["environnement"] else "prod"
        actif = {
            "hote": l[col["hote"]],
            "nom": l.get(col["nom"], "") if col["nom"] else "",
            "criticite": _criticite(l[col["criticite"]]),
            "exposition": "internet" if any(m in expo for m in ("internet", "public", "dmz")) else "interne",
            "environnement": "test" if any(m in env for m in ("test", "dev", "recette", "qa")) else "prod",
            "inventorie": True,
        }
        actifs[l[col["hote"]].lower()] = actif
        if col["ip"] and l.get(col["ip"]):
            actifs[l[col["ip"]].lower()] = actif
    return actifs


def charger_kev(chemin):
    """Lit le catalogue CISA KEV (JSON). Retourne ({CVE : entrée}, métadonnées)."""
    with open(chemin, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("Fichier KEV invalide : champ 'vulnerabilities' absent.")
    kev = {v["cveID"].upper(): v for v in data["vulnerabilities"] if "cveID" in v}
    meta = {"version": data.get("catalogVersion", "?"), "date": data.get("dateReleased", "?"), "nombre": len(kev)}
    return kev, meta


def telecharger_kev(destination, url=URL_KEV, delai=30):
    """Télécharge le catalogue, vérifie qu'il est exploitable, puis l'écrit. Lève ValueError sinon."""
    with urllib.request.urlopen(url, timeout=delai) as r:
        contenu = r.read()
    try:
        data = json.loads(contenu)
    except json.JSONDecodeError:
        raise ValueError("Le contenu téléchargé n'est pas du JSON.")
    if not isinstance(data.get("vulnerabilities"), list) or not data["vulnerabilities"]:
        raise ValueError("Le contenu téléchargé n'est pas un catalogue KEV valide.")
    with open(destination, "wb") as f:
        f.write(contenu)
    return len(data["vulnerabilities"])
