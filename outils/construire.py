"""Construit la base de menaces Alpin Shield (développement par Fabrice M.).

Rassemble les grandes bases publiques gratuites, les ajouts manuels (dossier « ajouts ») et les contributions des
installations d'Alpin Shield, puis écrit dans « sortie/ » les fichiers publiés dans la release « base » :

  hachages-00.tsv … hachages-ff.tsv   empreintes SHA-256, rangées par leurs 2 premiers caractères
                                      (une installation ne télécharge que le morceau utile, comme une requête)
                                      colonnes : sha256  verdict(m/s/b)  nom  sources  appareils
  domaines.txt                        sites de virus et de hameçonnage (un par ligne)
  ips.txt                             serveurs pirates (centres de commande de virus)
  contributions.json                  état des signalements des installations
  index.json                          date, version, nombres et empreintes des fichiers

Verdicts : m = menace, s = suspect, b = bon (logiciel sain connu).
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
SORTIE = RACINE / "sortie"
AJOUTS = RACINE / "ajouts"
CLE = os.environ.get("ABUSECH_CLE", "").strip()
UA = {"User-Agent": "AlpinShield-base/1.0 (+https://github.com/fabrice0180-art/alpinshield-base)"}
RE_SHA = re.compile(r"^[0-9a-f]{64}$")
RE_DOMAINE = re.compile(r"^(?=.{4,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
ORDRE = {"m": 3, "s": 2, "b": 1}

# Domaines qu'on ne bloque jamais en entier (grandes plateformes, services publics, Alpin Shield lui-même) :
# leurs sous-domaines personnels (ex. pirate.pages.dev) peuvent l'être, eux-mêmes et leurs sous-domaines « système » non.
PROTEGES = {
    "google.com", "gmail.com", "youtube.com", "googleapis.com", "gstatic.com", "microsoft.com", "microsoftonline.com",
    "live.com", "office.com", "outlook.com", "windows.net", "windowsupdate.com", "apple.com", "icloud.com", "github.com",
    "githubusercontent.com", "githubassets.com", "amazon.com", "amazon.fr", "facebook.com", "whatsapp.com",
    "instagram.com", "wikipedia.org", "cloudflare.com", "abuse.ch", "mozilla.org", "gouv.fr", "service-public.fr",
    "laposte.fr", "ameli.fr", "orange.fr", "free.fr", "sfr.fr", "bouyguestelecom.fr", "paypal.com", "linkedin.com",
    "twitter.com", "x.com", "bing.com", "yahoo.com", "dropbox.com", "adobe.com", "zoom.us", "netflix.com",
}
PLATEFORMES = {  # racines d'hébergement partagé : jamais bloquées elles-mêmes, leurs sous-domaines oui
    "pages.dev", "workers.dev", "github.io", "netlify.app", "vercel.app", "firebaseapp.com", "web.app",
    "blogspot.com", "weebly.com", "wixsite.com", "sharepoint.com", "herokuapp.com", "glitch.me", "ngrok.io",
    "ngrok-free.app", "000webhostapp.com", "azurewebsites.net", "cloudfront.net", "s3.amazonaws.com", "r2.dev",
    "duckdns.org", "trycloudflare.com", "framer.app", "webflow.io", "gitbook.io", "notion.site", "repl.co",
}


def journal(*morceaux) -> None:
    print(*morceaux, flush=True)


def telecharger(url: str, delai: int = 900) -> bytes | None:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=delai) as r:
            return r.read()
    except Exception as e:  # une source indisponible ne doit jamais empêcher la construction
        journal(f"  ! source indisponible ({url.split('/')[2]}) : {str(e)[:120]}")
        return None


def dezipper(brut: bytes) -> bytes:
    if brut[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(brut)) as z:
            return z.read(z.namelist()[0])
    return brut


# ------------------------------------------------------------------ registre des empreintes
empreintes: dict[str, list] = {}   # sha256 -> [verdict, nom, set(sources), appareils]


def ajouter_empreinte(sha: str, verdict: str, nom: str, source: str, appareils: int = 0) -> None:
    sha = sha.strip().lower()
    if not RE_SHA.match(sha):
        return
    nom = re.sub(r"[\t\r\n]+", " ", (nom or "").strip())[:80]
    e = empreintes.get(sha)
    if e is None:
        empreintes[sha] = [verdict, nom, {source}, appareils]
        return
    if ORDRE[verdict] > ORDRE[e[0]] or (e[0] == "b" and verdict != "b"):
        e[0] = verdict  # une menace l'emporte toujours sur « sain »
    if not e[1] and nom:
        e[1] = nom
    e[2].add(source)
    e[3] = max(e[3], appareils)


domaines: set[str] = set()
prioritaires: set[str] = set()   # virus, hameçonnage récent, ajouts, contributions : d'abord dans la liste iPhone
ips: set[str] = set()
MAX_ESSENTIELS = 140_000         # Safari (iPhone) accepte 150 000 règles par bouclier


def proteger(hote: str) -> bool:
    """Vrai si l'hôte ne doit jamais être bloqué (grand site, plateforme d'hébergement)."""
    if hote in PLATEFORMES:
        return True
    return any(hote == p or hote.endswith("." + p) for p in PROTEGES)


def ajouter_domaine(texte: str, prioritaire: bool = True) -> None:
    h = texte.strip().lower().rstrip(".")
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0].split(":", 1)[0]
    if h.startswith("www."):
        h = h[4:]
    if RE_DOMAINE.match(h) and not proteger(h):
        domaines.add(h)
        if prioritaire:
            prioritaires.add(h)


def ajouter_domaine_secondaire(texte: str) -> None:
    ajouter_domaine(texte, prioritaire=False)


def ajouter_ip(texte: str) -> None:
    t = texte.strip().split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(t)
    except ValueError:
        return
    if ip.is_global:
        ips.add(str(ip))


# ------------------------------------------------------------------ sources
def malwarebazaar() -> None:
    if not CLE:
        journal("  ! MalwareBazaar : clé abuse.ch absente (secret ABUSECH_CLE)")
        return
    brut = telecharger(f"https://mb-api.abuse.ch/v2/files/exports/{CLE}/full.csv.zip") \
        or telecharger(f"https://mb-api.abuse.ch/v2/files/exports/{CLE}/recent.csv")
    if not brut:
        return
    texte = dezipper(brut).decode("utf-8", errors="replace")
    colonnes, avant = None, len(empreintes)
    for ligne in texte.splitlines():
        if ligne.startswith("#"):
            if "sha256" in ligne:
                colonnes = [c.strip(' "#') for c in ligne.lstrip("# ").split(",")]
            continue
        champs = next(csv.reader([ligne], skipinitialspace=True), [])
        if colonnes and "sha256_hash" in colonnes and len(champs) > colonnes.index("sha256_hash"):
            sha = champs[colonnes.index("sha256_hash")]
            nom = champs[colonnes.index("signature")] if "signature" in colonnes and len(champs) > colonnes.index("signature") else ""
        else:
            sha = next((c for c in champs if RE_SHA.match(c.strip().lower())), "")
            nom = ""
        ajouter_empreinte(sha, "m", "" if nom in ("", "n/a") else nom, "MalwareBazaar")
    journal(f"  MalwareBazaar : {len(empreintes) - avant} empreintes")


def threatfox() -> None:
    if not CLE:
        return
    brut = telecharger(f"https://threatfox-api.abuse.ch/v2/files/exports/{CLE}/full.json.zip") \
        or telecharger(f"https://threatfox-api.abuse.ch/v2/files/exports/{CLE}/recent.json")
    if not brut:
        return
    try:
        donnees = json.loads(dezipper(brut))
    except ValueError:
        journal("  ! ThreatFox : réponse illisible")
        return
    n = {"hash": 0, "domaine": 0, "ip": 0}
    for liste in donnees.values():
        for ioc in liste if isinstance(liste, list) else [liste]:
            t, v = ioc.get("ioc_type", ""), str(ioc.get("ioc_value", ""))
            if t == "sha256_hash":
                ajouter_empreinte(v, "m", ioc.get("malware_printable") or "", "ThreatFox")
                n["hash"] += 1
            elif t == "domain":
                ajouter_domaine(v)
                n["domaine"] += 1
            elif t == "ip:port":
                ajouter_ip(v)
                n["ip"] += 1
    journal(f"  ThreatFox : {n['hash']} empreintes, {n['domaine']} domaines, {n['ip']} serveurs")


def listes_texte() -> None:
    for nom, url, fonction in (
        ("Feodo Tracker (serveurs de virus bancaires)", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", ajouter_ip),
        ("SSLBL (serveurs pirates)", "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", ajouter_ip),
        ("OpenPhish (hameçonnage)", "https://openphish.com/feed.txt", ajouter_domaine),
        ("Phishing.Database (hameçonnage actif)",
         "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
         ajouter_domaine_secondaire),
    ):
        brut = telecharger(url)
        if not brut:
            continue
        avant = len(domaines) + len(ips)
        for ligne in brut.decode("utf-8", errors="replace").splitlines():
            if ligne and not ligne.startswith("#"):
                fonction(ligne.split(",")[0])
        journal(f"  {nom} : {len(domaines) + len(ips) - avant} nouveaux")


def ajouts_manuels() -> None:
    """Fichiers du dossier « ajouts » : ce que tu ajoutes toi-même (une entrée par ligne, # = commentaire)."""
    def lignes(nom):
        f = AJOUTS / nom
        return [l.strip() for l in f.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")] \
            if f.exists() else []
    for l in lignes("menaces.txt"):
        sha, _, nom = l.partition(";")
        ajouter_empreinte(sha, "m", nom or "Ajout manuel", "Alpin Shield")
    for l in lignes("sains.txt"):
        sha, _, nom = l.partition(";")
        ajouter_empreinte(sha, "b", nom or "Logiciel sain", "Alpin Shield")
    for l in lignes("domaines.txt"):
        ajouter_domaine(l)
    for l in lignes("ips.txt"):
        ajouter_ip(l)
    journal("  Ajouts manuels intégrés")


def charger_jamais_bloquer() -> None:
    f = AJOUTS / "jamais-bloquer.txt"
    if f.exists():
        for l in f.read_text(encoding="utf-8").splitlines():
            if l.strip() and not l.startswith("#"):
                PROTEGES.add(l.strip().lower())


def contributions() -> None:
    """Signalements des installations, déjà validés par integrer.py. Publiés seulement s'ils sont fiables :
    menace confirmée par une base sur l'appareil, ou même signalement venu d'au moins 2 appareils différents."""
    f = SORTIE / "contributions.json"
    if not f.exists():
        return
    etat = json.loads(f.read_text(encoding="utf-8"))
    publies = 0
    for sha, e in etat.get("empreintes", {}).items():
        appareils = len(e.get("appareils", []))
        votes = e.get("votes", {})
        if votes.get("mc"):      # menace confirmée (ClamAV, MalwareBazaar, Defender… sur l'appareil)
            ajouter_empreinte(sha, "m", e.get("nom", ""), "Alpin Shield", appareils)
        elif votes.get("m", 0) + votes.get("s", 0) >= 2:
            ajouter_empreinte(sha, "s", e.get("nom", ""), "Alpin Shield", appareils)
        elif votes.get("b", 0) >= 2 and not (votes.get("m") or votes.get("s")):
            ajouter_empreinte(sha, "b", e.get("nom", ""), "Alpin Shield", appareils)
        else:
            continue
        publies += 1
    for d in etat.get("domaines", {}):
        if len(etat["domaines"][d]) >= 2:
            ajouter_domaine(d)
    journal(f"  Contributions des installations : {publies} empreintes publiées "
            f"({len(etat.get('empreintes', {}))} signalées, {len(etat.get('appareils', []))} appareils)")


# ------------------------------------------------------------------ écriture
def ecrire() -> None:
    SORTIE.mkdir(exist_ok=True)
    morceaux: dict[str, list[str]] = {f"{i:02x}": [] for i in range(256)}
    for sha in sorted(empreintes):
        v, nom, sources, appareils = empreintes[sha]
        morceaux[sha[:2]].append(f"{sha}\t{v}\t{nom}\t{','.join(sorted(sources))}\t{appareils}")
    fichiers = {}
    for prefixe, lignes in morceaux.items():
        nom = f"hachages-{prefixe}.tsv"
        (SORTIE / nom).write_text("\n".join(lignes) + ("\n" if lignes else ""), encoding="utf-8")
    publies = sorted(d for d in domaines if not proteger(d))  # « jamais bloquer » appliqué à toutes les sources
    domaines.clear()
    domaines.update(publies)
    (SORTIE / "domaines.txt").write_text("\n".join(publies) + "\n", encoding="utf-8")
    # liste essentielle (iPhone) : prioritaires d'abord, complétée par les autres jusqu'à la limite de Safari
    prio = [d for d in publies if d in prioritaires]
    essentiels = sorted(prio[:MAX_ESSENTIELS] + [d for d in publies if d not in prioritaires][:max(0, MAX_ESSENTIELS - len(prio))])
    (SORTIE / "domaines-essentiels.txt").write_text("\n".join(essentiels) + "\n", encoding="utf-8")
    (SORTIE / "ips.txt").write_text("\n".join(sorted(ips, key=lambda x: ipaddress.ip_address(x))) + "\n", encoding="utf-8")
    for f in sorted(SORTIE.iterdir()):
        if f.name != "index.json" and f.is_file():
            fichiers[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()
    compte = {"menaces": 0, "suspects": 0, "sains": 0}
    for v, *_ in empreintes.values():
        compte[{"m": "menaces", "s": "suspects", "b": "sains"}[v]] += 1
    index = {
        "nom": "Base Alpin Shield", "version": time.strftime("%Y%m%d%H%M", time.gmtime()),
        "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "empreintes": len(empreintes), **compte, "domaines": len(domaines), "serveurs": len(ips),
        "format": 1, "morceaux": 256, "fichiers": fichiers,
    }
    (SORTIE / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    journal(f"\nBase écrite : {len(empreintes):,} empreintes ({compte['menaces']:,} menaces, {compte['sains']:,} sains), "
            f"{len(domaines):,} domaines, {len(ips):,} serveurs".replace(",", " "))


def main() -> int:
    debut = time.time()
    SORTIE.mkdir(exist_ok=True)
    journal("Construction de la base Alpin Shield")
    charger_jamais_bloquer()
    malwarebazaar()
    threatfox()
    listes_texte()
    ajouts_manuels()
    contributions()
    if len(empreintes) < 1000 and not os.environ.get("BASE_TEST"):
        journal("! Trop peu d'empreintes : sources indisponibles ? La base précédente est conservée.")
        return 1
    ecrire()
    journal(f"Terminé en {time.time() - debut:.0f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
