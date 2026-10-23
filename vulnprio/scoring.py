"""
Score de risque explicable (0 à 100). Chaque point est justifié dans les « raisons » du résultat.

  + gravité technique  : CVSS x 5                              (0 à 50)
  + exploitation active: faille présente dans le catalogue CISA KEV            +25
                         avec usage connu par des rançongiciels                  +5
  + importance du bien : (criticité - 1) x 3                   (0 à 12)
  + exposition         : accessible depuis Internet                          +10
  - environnement      : test / recette                                      -10

C'est une heuristique pédagogique : les poids sont des choix, pas un standard.
"""

from .loaders import RISQUE_VERS_CVSS as RISQUE_PAR_DEFAUT

PRIORITES = [(80, "P1", "48 heures"), (60, "P2", "7 jours"), (40, "P3", "30 jours"), (0, "P4", "90 jours")]
ACTIF_INCONNU = {"hote": "", "nom": "", "criticite": 3, "exposition": "interne",
                 "environnement": "prod", "inventorie": False}


def evaluer(vuln, actif, kev):
    """Retourne un dictionnaire : score, priorite, delai, raisons, kev, ransomware, cvss, cvss_estime."""
    actif = actif or ACTIF_INCONNU
    raisons = []

    cvss, estime = vuln["cvss"], False
    if cvss is None:
        cvss, estime = RISQUE_PAR_DEFAUT.get(vuln["risque"], 2.5), True
    points = cvss * 5
    if estime:
        raisons.append(f"+{points:.1f} : gravité estimée à {cvss} d'après le niveau « {vuln['risque']} » (aucun score CVSS fourni)")
    else:
        raisons.append(f"+{points:.1f} : gravité CVSS {cvss}")

    entrees = [kev[c] for c in vuln["cves"] if c in kev]
    ransomware = any(e.get("knownRansomwareCampaignUse") == "Known" for e in entrees)
    if entrees:
        points += 25
        raisons.append(f"+25 : {entrees[0]['cveID']} figure au catalogue CISA des vulnérabilités exploitées")
        if ransomware:
            points += 5
            raisons.append("+5 : utilisation connue dans des campagnes de rançongiciels")

    bonus = (actif["criticite"] - 1) * 3
    points += bonus
    raisons.append(f"+{bonus} : importance du bien = {actif['criticite']}/5"
                   + ("" if actif["inventorie"] else " (actif non inventorié, valeur par défaut)"))
    if actif["exposition"] == "internet":
        points += 10
        raisons.append("+10 : accessible depuis Internet")
    if actif["environnement"] == "test":
        points -= 10
        raisons.append("-10 : environnement de test")

    score = round(max(0.0, min(100.0, points)), 1)
    for seuil, code, delai in PRIORITES:
        if score >= seuil:
            return {"score": score, "priorite": code, "delai": delai, "raisons": raisons,
                    "kev": bool(entrees), "ransomware": ransomware, "cvss": cvss, "cvss_estime": estime}

