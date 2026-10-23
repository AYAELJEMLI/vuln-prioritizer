"""Construction des résultats, du rapport Markdown et de l'export CSV."""

import csv
import re
from collections import defaultdict

from .scoring import ACTIF_INCONNU, evaluer

ORDRE = ["P1", "P2", "P3", "P4"]


def analyser(vulns, actifs, kev):
    """Associe chaque vulnérabilité à son actif et à son score. Retourne la liste triée (plus grave d'abord)."""
    resultats = []
    for v in vulns:
        actif = actifs.get(v["hote"].lower())
        if actif is None:
            actif = dict(ACTIF_INCONNU, hote=v["hote"])
        e = evaluer(v, actif, kev)
        resultats.append({**v, "actif": actif, **e})
    resultats.sort(key=lambda r: (-r["score"], r["hote"], r["nom"]))
    return resultats


def _cell(texte, n=70):
    texte = re.sub(r"\s+", " ", str(texte or "")).replace("|", "/").strip()
    return texte if len(texte) <= n else texte[: n - 1] + "…"


def _nom_hote(r):
    return r["actif"]["nom"] or r["hote"]


def comparaison_cvss(resultats):
    """Ce que la priorisation change par rapport à un tri sur le CVSS seul."""
    retrogradees = [r for r in resultats if r["cvss"] >= 7 and r["priorite"] in ("P3", "P4")]
    promues = [r for r in resultats if r["cvss"] < 7 and r["priorite"] in ("P1", "P2")]
    return retrogradees, promues


def gains_rapides(resultats, n=5):
    """Regroupe par correctif : une même solution peut régler plusieurs vulnérabilités."""
    groupes = defaultdict(list)
    for r in resultats:
        cle = re.sub(r"\s+", " ", r["solution"].lower()).strip()[:160]
        if cle:
            groupes[cle].append(r)
    classes = sorted(groupes.values(), key=lambda g: (-len(g), -sum(x["score"] for x in g)))
    return [(g[0]["solution"], len(g), len({x["hote"] for x in g})) for g in classes[:n] if len(g) > 1]


def classement_machines(resultats, n=10):
    par_hote = defaultdict(list)
    for r in resultats:
        par_hote[r["hote"]].append(r)
    lignes = []
    for hote, liste in par_hote.items():
        lignes.append((hote, _nom_hote(liste[0]), sum(x["priorite"] == "P1" for x in liste),
                       sum(x["priorite"] == "P2" for x in liste), max(x["score"] for x in liste), len(liste)))
    return sorted(lignes, key=lambda x: (-x[2], -x[3], -x[4]))[:n]


def rapport_markdown(resultats, stats, meta_kev=None, top=10):
    comptes = {p: sum(r["priorite"] == p for r in resultats) for p in ORDRE}
    kev_n = sum(r["kev"] for r in resultats)
    inconnus = sorted({r["hote"] for r in resultats if not r["actif"]["inventorie"]})
    retro, promues = comparaison_cvss(resultats)

    out = ["# Rapport de priorisation des vulnérabilités", ""]
    out.append(f"{len(resultats)} vulnérabilités analysées sur {len({r['hote'] for r in resultats})} machines "
               f"({stats['informatives_ignorees']} lignes informatives ignorées, {stats['doublons']} doublon(s) fusionné(s)).")
    if meta_kev:
        out.append(f"Catalogue CISA KEV : version {meta_kev['version']}, {meta_kev['nombre']} entrées.")
    else:
        out.append("**Aucun catalogue KEV fourni : le critère « exploitée activement » n'a pas été pris en compte.**")
    out += ["", "## Synthèse", "", "| Priorité | Délai de correction | Nombre |", "|---|---|---|"]
    delais = {"P1": "48 heures", "P2": "7 jours", "P3": "30 jours", "P4": "90 jours"}
    out += [f"| {p} | {delais[p]} | {comptes[p]} |" for p in ORDRE]
    out += ["", f"{kev_n} vulnérabilité(s) sont connues comme exploitées activement (catalogue KEV)."]

    out += ["", "## Ce que la priorisation change par rapport au CVSS seul", ""]
    out.append(f"- **{len(retro)}** vulnérabilité(s) de gravité CVSS élevée (7 ou plus) ne sont pas urgentes (P3 ou P4), "
               "car le bien est peu critique, non exposé ou en environnement de test.")
    out.append(f"- **{len(promues)}** vulnérabilité(s) de gravité CVSS modérée (moins de 7) deviennent urgentes (P1 ou P2), "
               "car elles sont activement exploitées ou touchent un bien exposé et critique.")
    for r in retro[:3]:
        out.append(f"  - Moins urgent : {_cell(r['nom'], 50)} sur {_nom_hote(r)} (CVSS {r['cvss']}{'*' if r['cvss_estime'] else ''}, score {r['score']}, {r['priorite']})")
    for r in promues[:3]:
        out.append(f"  - Plus urgent : {_cell(r['nom'], 50)} sur {_nom_hote(r)} (CVSS {r['cvss']}{'*' if r['cvss_estime'] else ''}, score {r['score']}, {r['priorite']})")

    out += ["", f"## Les {min(top, len(resultats))} vulnérabilités à traiter en premier", "",
            "| Prio | Score | Machine | Vulnérabilité | CVE | CVSS | KEV | Exposition |", "|---|---|---|---|---|---|---|---|"]
    for r in resultats[:top]:
        out.append(f"| {r['priorite']} | {r['score']} | {_cell(_nom_hote(r), 24)} | {_cell(r['nom'], 55)} | "
                   f"{', '.join(r['cves']) or '-'} | {r['cvss']}{'*' if r['cvss_estime'] else ''} | "
                   f"{'Oui' if r['kev'] else 'Non'} | {r['actif']['exposition']} |")
    if any(r["cvss_estime"] for r in resultats[:top]):
        out += ["", "\\* CVSS estimé d'après le niveau de risque du scanner (aucun score fourni)."]

    machines = classement_machines(resultats)
    out += ["", "## Machines les plus exposées", "", "| Machine | Nom | P1 | P2 | Score max | Vulnérabilités |", "|---|---|---|---|---|---|"]
    out += [f"| {h} | {_cell(n, 24)} | {a} | {b} | {c} | {d} |" for h, n, a, b, c, d in machines]

    gains = gains_rapides(resultats)
    if gains:
        out += ["", "## Gains rapides : un correctif, plusieurs vulnérabilités", "", "| Correctif | Vulnérabilités | Machines |", "|---|---|---|"]
        out += [f"| {_cell(s, 90)} | {n} | {m} |" for s, n, m in gains]

    if inconnus:
        out += ["", "## Machines absentes de l'inventaire", "",
                "Ces machines ont été notées avec des valeurs par défaut (importance 3/5, interne, production). "
                "Elles méritent d'être inventoriées : un actif inconnu est déjà un risque.", ""]
        out += [f"- {h}" for h in inconnus]

    p1 = [r for r in resultats if r["priorite"] == "P1"]
    if p1:
        out += ["", "## Détail des vulnérabilités P1", ""]
        for r in p1:
            out += [f"### {_nom_hote(r)} : {_cell(r['nom'], 90)}", ""]
            out += [f"- {x}" for x in r["raisons"]]
            out += [f"- **Total : {r['score']}/100, à corriger sous {r['delai']}**", ""]
            if r["solution"]:
                out += [f"Solution proposée par le scanner : {_cell(r['solution'], 200)}", ""]
    return "\n".join(out).rstrip() + "\n"


def ecrire_csv(resultats, chemin, sep=";"):
    entetes = ["priorite", "score", "delai", "hote", "nom_actif", "port", "vulnerabilite", "cve", "cvss",
               "cvss_estime", "kev", "ransomware", "exposition", "criticite", "environnement", "solution"]
    with open(chemin, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=sep)
        w.writerow(entetes)
        for r in resultats:
            w.writerow([r["priorite"], r["score"], r["delai"], r["hote"], r["actif"]["nom"], r["port"], r["nom"],
                        " ".join(r["cves"]), r["cvss"], "oui" if r["cvss_estime"] else "non",
                        "oui" if r["kev"] else "non", "oui" if r["ransomware"] else "non",
                        r["actif"]["exposition"], r["actif"]["criticite"], r["actif"]["environnement"], r["solution"]])
