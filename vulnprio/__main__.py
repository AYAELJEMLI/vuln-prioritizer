import argparse
import os
import sys

from .loaders import charger_actifs, charger_kev, charger_scan, telecharger_kev, URL_KEV
from .report import analyser, ecrire_csv, rapport_markdown


def main(argv=None):
    p = argparse.ArgumentParser(prog="vulnprio", description="Priorisation des vulnérabilités selon le risque réel")
    p.add_argument("scan", help="export CSV du scanner de vulnérabilités (format Nessus)")
    p.add_argument("--actifs", help="inventaire des machines (CSV : host, criticite, exposition, environnement)")
    p.add_argument("--kev", help="catalogue CISA KEV au format JSON")
    p.add_argument("--update-kev", metavar="FICHIER", help="télécharge le catalogue KEV dans ce fichier puis l'utilise")
    p.add_argument("--kev-url", default=URL_KEV)
    p.add_argument("--sortie-md", default="rapport.md")
    p.add_argument("--sortie-csv", default="priorisation.csv")
    p.add_argument("--top", type=int, default=10, help="nombre de lignes du classement (défaut 10)")
    a = p.parse_args(argv)

    try:
        if a.update_kev:
            n = telecharger_kev(a.update_kev, a.kev_url)
            print(f"Catalogue KEV téléchargé : {n} entrées -> {a.update_kev}")
            a.kev = a.update_kev
        vulns, stats = charger_scan(a.scan)
        actifs = charger_actifs(a.actifs) if a.actifs else {}
        kev, meta = charger_kev(a.kev) if a.kev else ({}, None)
    except FileNotFoundError as e:
        print(f"Fichier introuvable : {e.filename}", file=sys.stderr)
        return 1
    except (ValueError, OSError) as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 1

    if not a.actifs:
        print("Attention : pas d'inventaire (--actifs). Toutes les machines sont notées avec des valeurs par défaut.", file=sys.stderr)
    if not a.kev:
        print("Attention : pas de catalogue KEV (--kev). Le critère « exploitée activement » est ignoré.", file=sys.stderr)
    if not vulns:
        print("Aucune vulnérabilité exploitable dans ce fichier.", file=sys.stderr)
        return 1

    resultats = analyser(vulns, actifs, kev)
    for chemin in (a.sortie_md, a.sortie_csv):
        if os.path.dirname(chemin):
            os.makedirs(os.path.dirname(chemin), exist_ok=True)
    with open(a.sortie_md, "w", encoding="utf-8") as f:
        f.write(rapport_markdown(resultats, stats, meta, a.top))
    ecrire_csv(resultats, a.sortie_csv)

    print(f"{len(resultats)} vulnérabilités analysées\n")
    print(f"{'Prio':5s}{'Score':>6s}  {'Machine':22s}{'CVSS':>5s} KEV  Vulnérabilité")
    for r in resultats[: a.top]:
        print(f"{r['priorite']:5s}{r['score']:>6}  {(r['actif']['nom'] or r['hote'])[:21]:22s}{r['cvss']:>5} "
              f"{'oui' if r['kev'] else 'non'}  {r['nom'][:45]}")
    print(f"\nRapport : {a.sortie_md}\nTableau : {a.sortie_csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
