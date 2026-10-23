import csv
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

RACINE = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, RACINE)
from vulnprio.__main__ import main
from vulnprio.loaders import charger_actifs, charger_kev, charger_scan, telecharger_kev
from vulnprio.report import analyser, comparaison_cvss, ecrire_csv, gains_rapides, rapport_markdown
from vulnprio.scoring import ACTIF_INCONNU, evaluer

S = os.path.join(RACINE, "samples")
SCAN, ACTIFS, KEV = (os.path.join(S, n) for n in ("scan_nessus.csv", "assets.csv", "kev_extrait.json"))


def ecrire(contenu, suffixe=".csv"):
    f = tempfile.NamedTemporaryFile("w", suffix=suffixe, delete=False, encoding="utf-8")
    f.write(contenu)
    f.close()
    return f.name


def vuln(**kw):
    base = {"hote": "h", "port": "", "plugin": "", "nom": "test", "cves": [], "cvss": 5.0,
            "risque": "medium", "solution": ""}
    return {**base, **kw}


def actif(**kw):
    return {**ACTIF_INCONNU, "inventorie": True, **kw}


class TestChargement(unittest.TestCase):
    def test_scan_ignore_informatif_et_fusionne_les_doublons(self):
        vulns, stats = charger_scan(SCAN)
        self.assertEqual(stats["informatives_ignorees"], 2)
        self.assertEqual(stats["doublons"], 1)
        self.assertEqual(len(vulns), stats["lignes"] - 3)

    def test_cves_multiples_virgule_decimale_et_separateur_point_virgule(self):
        chemin = ecrire("Host;Name;CVE;CVSS v3.0 Base Score;Risk\n"
                        "h1;Faille;CVE-2020-0001, cve-2020-0002;7,5;High\n")
        v, _ = charger_scan(chemin)
        self.assertEqual(v[0]["cves"], ["CVE-2020-0001", "CVE-2020-0002"])
        self.assertEqual(v[0]["cvss"], 7.5)

    def test_cvss_v3_prioritaire_sur_v2(self):
        chemin = ecrire("Host,Name,CVSS v2.0 Base Score,CVSS v3.0 Base Score,Risk\nh1,F,5.0,9.8,High\n")
        self.assertEqual(charger_scan(chemin)[0][0]["cvss"], 9.8)

    def test_colonnes_manquantes_message_clair(self):
        with self.assertRaises(ValueError) as e:
            charger_scan(ecrire("a,b\n1,2\n"))
        self.assertIn("Colonnes", str(e.exception))

    def test_actifs_criticite_texte_et_chiffre(self):
        chemin = ecrire("host,ip,criticite,exposition,environnement\nsrv1,1.1.1.1,critique,DMZ,prod\nsrv2,2.2.2.2,2,interne,recette\n")
        a = charger_actifs(chemin)
        self.assertEqual(a["srv1"]["criticite"], 5)
        self.assertEqual(a["srv1"]["exposition"], "internet")
        self.assertEqual(a["2.2.2.2"]["criticite"], 2)
        self.assertEqual(a["srv2"]["environnement"], "test")

    def test_criticite_invalide_refusee(self):
        with self.assertRaises(ValueError):
            charger_actifs(ecrire("host,criticite\nsrv1,enorme\n"))
        with self.assertRaises(ValueError):
            charger_actifs(ecrire("host,criticite\nsrv1,9\n"))

    def test_kev_charge_et_fichier_invalide_refuse(self):
        kev, meta = charger_kev(KEV)
        self.assertIn("CVE-2021-44228", kev)
        self.assertEqual(meta["nombre"], 5)
        with self.assertRaises(ValueError):
            charger_kev(ecrire('{"autre": 1}', ".json"))


class TestScoring(unittest.TestCase):
    def test_kev_ajoute_25_points(self):
        sans = evaluer(vuln(cves=["CVE-1"], cvss=8.0), actif(), {})
        avec = evaluer(vuln(cves=["CVE-1"], cvss=8.0), actif(), {"CVE-1": {"cveID": "CVE-1"}})
        self.assertEqual(round(avec["score"] - sans["score"], 1), 25.0)
        self.assertTrue(avec["kev"])

    def test_rancongiciel_ajoute_5_points_de_plus(self):
        kev = {"CVE-1": {"cveID": "CVE-1", "knownRansomwareCampaignUse": "Known"}}
        r = evaluer(vuln(cves=["CVE-1"], cvss=8.0), actif(), kev)
        self.assertTrue(r["ransomware"])
        self.assertEqual(r["score"], 8.0 * 5 + 25 + 5 + 6)

    def test_facteurs_exposition_criticite_et_test(self):
        base = evaluer(vuln(), actif(criticite=3), {})["score"]
        self.assertEqual(evaluer(vuln(), actif(criticite=3, exposition="internet"), {})["score"], base + 10)
        self.assertEqual(evaluer(vuln(), actif(criticite=5), {})["score"], base + 6)
        self.assertEqual(evaluer(vuln(), actif(criticite=3, environnement="test"), {})["score"], base - 10)

    def test_cvss_estime_depuis_le_risque(self):
        r = evaluer(vuln(cvss=None, risque="critical"), actif(), {})
        self.assertTrue(r["cvss_estime"])
        self.assertEqual(r["cvss"], 9.5)

    def test_score_borne_entre_0_et_100(self):
        kev = {"CVE-1": {"cveID": "CVE-1", "knownRansomwareCampaignUse": "Known"}}
        haut = evaluer(vuln(cves=["CVE-1"], cvss=10.0), actif(criticite=5, exposition="internet"), kev)
        bas = evaluer(vuln(cvss=0.0), actif(criticite=1, environnement="test"), {})
        self.assertEqual(haut["score"], 100.0)
        self.assertEqual(bas["score"], 0.0)

    def test_chaque_point_est_explique(self):
        r = evaluer(vuln(cves=["CVE-1"]), actif(exposition="internet"), {"CVE-1": {"cveID": "CVE-1"}})
        self.assertGreaterEqual(len(r["raisons"]), 4)


class TestAnalyseSurEchantillon(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vulns, cls.stats = charger_scan(SCAN)
        cls.kev, cls.meta = charger_kev(KEV)
        cls.res = analyser(cls.vulns, charger_actifs(ACTIFS), cls.kev)

    def test_tri_decroissant(self):
        scores = [r["score"] for r in self.res]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_log4shell_exposee_est_la_premiere_et_p1(self):
        self.assertEqual(self.res[0]["priorite"], "P1")
        self.assertEqual(self.res[0]["actif"]["nom"], "srv-web-vitrine")

    def test_la_meme_faille_pese_moins_en_environnement_de_test(self):
        log4 = [r for r in self.res if r["cves"] == ["CVE-2021-44228"]]
        prod = next(r for r in log4 if r["actif"]["environnement"] == "prod")
        test = next(r for r in log4 if r["actif"]["environnement"] == "test")
        self.assertGreater(prod["score"], test["score"])

    def test_cvss_critique_peut_etre_retrogradee(self):
        os_obsolete = next(r for r in self.res if r["nom"].startswith("Unsupported Windows"))
        self.assertEqual(os_obsolete["cvss"], 10.0)
        self.assertIn(os_obsolete["priorite"], ("P3", "P4"))
        retro, _ = comparaison_cvss(self.res)
        self.assertIn(os_obsolete, retro)

    def test_actif_non_inventorie_signale(self):
        inconnu = [r for r in self.res if r["hote"] == "10.20.7.99"]
        self.assertTrue(inconnu)
        self.assertFalse(inconnu[0]["actif"]["inventorie"])

    def test_gains_rapides_regroupe_les_correctifs_identiques(self):
        gains = gains_rapides(self.res)
        self.assertIn("message signing", gains[0][0])
        self.assertEqual(gains[0][1], 6)

    def test_rapport_contient_les_sections(self):
        md = rapport_markdown(self.res, self.stats, self.meta)
        for titre in ("## Synthèse", "## Ce que la priorisation change", "## Machines les plus exposées",
                      "## Gains rapides", "## Machines absentes de l'inventaire", "## Détail des vulnérabilités P1"):
            self.assertIn(titre, md)

    def test_rapport_sans_kev_previent_l_utilisateur(self):
        res = analyser(self.vulns, {}, {})
        self.assertIn("Aucun catalogue KEV fourni", rapport_markdown(res, self.stats, None))

    def test_export_csv(self):
        chemin = tempfile.mktemp(suffix=".csv")
        ecrire_csv(self.res, chemin)
        with open(chemin, encoding="utf-8-sig") as f:
            lignes = list(csv.DictReader(f, delimiter=";"))
        self.assertEqual(len(lignes), len(self.res))
        self.assertEqual(lignes[0]["priorite"], "P1")
        self.assertIn("score", lignes[0])


class _Serveur(BaseHTTPRequestHandler):
    corps = b"{}"

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(_Serveur.corps)

    def log_message(self, *a):
        pass


def _servir(corps):
    _Serveur.corps = corps
    s = HTTPServer(("127.0.0.1", 0), _Serveur)

    def une_requete():
        s.handle_request()
        s.server_close()

    threading.Thread(target=une_requete, daemon=True).start()
    return f"http://127.0.0.1:{s.server_port}/kev.json"


class TestTelechargementKev(unittest.TestCase):
    def test_telechargement_valide(self):
        url = _servir(json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}).encode())
        dest = tempfile.mktemp(suffix=".json")
        self.assertEqual(telecharger_kev(dest, url), 1)
        self.assertIn("CVE-2021-44228", charger_kev(dest)[0])

    def test_contenu_invalide_refuse_et_rien_ecrit(self):
        dest = tempfile.mktemp(suffix=".json")
        with self.assertRaises(ValueError):
            telecharger_kev(dest, _servir(b"<html>erreur</html>"))
        self.assertFalse(os.path.exists(dest))


class TestCommande(unittest.TestCase):
    def test_bout_en_bout(self):
        md, cs = tempfile.mktemp(suffix=".md"), tempfile.mktemp(suffix=".csv")
        code = main([SCAN, "--actifs", ACTIFS, "--kev", KEV, "--sortie-md", md, "--sortie-csv", cs])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.getsize(md) > 500 and os.path.getsize(cs) > 200)

    def test_fichier_introuvable(self):
        self.assertEqual(main(["/inexistant.csv"]), 1)


if __name__ == "__main__":
    unittest.main()
