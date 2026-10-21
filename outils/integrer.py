"""Intègre les signalements envoyés par les installations d'Alpin Shield (tickets GitHub « contribution »).

Chaque installation envoie, au plus une fois par jour, un ticket contenant uniquement :
  - les empreintes SHA-256 des fichiers détectés (menace, suspect) ou validés sains (programmes seulement),
    avec le nom de la détection — jamais le fichier, son nom, son emplacement ni son contenu ;
  - les domaines dangereux qu'elle a bloqués ;
  - un identifiant d'appareil tiré au hasard (impossible de savoir à qui il appartient).

Sécurité : seuls les tickets créés par le propriétaire du dépôt (la clé de contribution d'Alpin Shield) sont
pris en compte, chaque champ est vérifié, et un signalement n'est publié dans la base que s'il est fiable
(voir construire.py).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

SORTIE = Path(__file__).resolve().parent.parent / "sortie"
DEPOT = os.environ.get("GITHUB_REPOSITORY", "")
PROPRIETAIRE = os.environ.get("GITHUB_REPOSITORY_OWNER", DEPOT.split("/")[0])
JETON = os.environ.get("GITHUB_TOKEN", "")
RE_SHA = re.compile(r"^[0-9a-f]{64}$")
RE_APPAREIL = re.compile(r"^[0-9a-f]{32}$")
RE_DOMAINE = re.compile(r"^(?=.{4,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
VERDICTS = {"m", "mc", "s", "b"}


def api(methode: str, chemin: str, donnees: dict | None = None):
    req = urllib.request.Request(f"https://api.github.com{chemin}", method=methode,
                                 data=json.dumps(donnees).encode() if donnees is not None else None,
                                 headers={"Authorization": f"Bearer {JETON}", "Accept": "application/vnd.github+json",
                                          "User-Agent": "AlpinShield-base", "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read() or b"null")


def lire_contribution(texte: str) -> dict | None:
    m = re.search(r"```json\s*(\{.*?\})\s*```", texte or "", re.S)
    try:
        d = json.loads(m.group(1) if m else texte)
    except (ValueError, AttributeError, TypeError):
        return None
    if not isinstance(d, dict) or not RE_APPAREIL.match(str(d.get("appareil", ""))):
        return None
    return d


def main() -> int:
    SORTIE.mkdir(exist_ok=True)
    f = SORTIE / "contributions.json"
    try:
        etat = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        etat = {}
    etat.setdefault("empreintes", {})
    etat.setdefault("domaines", {})
    etat.setdefault("appareils", [])
    if not JETON or not DEPOT:
        print("Pas de jeton GitHub : contributions non relevées.")
        f.write_text(json.dumps(etat, separators=(",", ":")), encoding="utf-8")
        return 0

    tickets, page = [], 1
    while page <= 20:
        lot = api("GET", f"/repos/{DEPOT}/issues?state=open&labels=contribution&per_page=100&page={page}")
        if not lot:
            break
        tickets += lot
        page += 1
    aujourd_hui = time.strftime("%Y-%m-%d", time.gmtime())
    acceptes = refuses = 0
    for t in tickets:
        auteur = (t.get("user") or {}).get("login", "")
        d = lire_contribution(t.get("body", "")) if auteur.lower() == PROPRIETAIRE.lower() else None
        if d is None:
            refuses += 1
        else:
            acceptes += 1
            appareil = d["appareil"]
            if appareil not in etat["appareils"]:
                etat["appareils"].append(appareil)
            for e in (d.get("empreintes") or [])[:2000]:
                if not isinstance(e, dict):
                    continue
                sha, verdict = str(e.get("sha256", "")).lower(), str(e.get("verdict", ""))
                if not RE_SHA.match(sha) or verdict not in VERDICTS:
                    continue
                nom = re.sub(r"[^\w .:/()+\-]", "", str(e.get("nom", "")))[:80]
                fiche = etat["empreintes"].setdefault(sha, {"nom": nom, "par_appareil": {}, "premier": aujourd_hui})
                if nom and not fiche.get("nom"):
                    fiche["nom"] = nom
                fiche["par_appareil"][appareil] = verdict
                fiche["dernier"] = aujourd_hui
            for dom in (d.get("domaines") or [])[:500]:
                dom = str(dom).lower().strip(".")
                if RE_DOMAINE.match(dom):
                    liste = etat["domaines"].setdefault(dom, [])
                    if appareil not in liste:
                        liste.append(appareil)
        try:  # ticket traité (accepté ou refusé) : fermé
            api("PATCH", f"/repos/{DEPOT}/issues/{t['number']}",
                {"state": "closed", "state_reason": "completed" if d else "not_planned"})
        except Exception as ex:
            print(f"  ! fermeture du ticket {t.get('number')} impossible : {ex}")

    # votes : un appareil = une voix par empreinte
    for fiche in etat["empreintes"].values():
        votes: dict[str, int] = {}
        for v in fiche.get("par_appareil", {}).values():
            votes[v] = votes.get(v, 0) + 1
        fiche["votes"] = votes
        fiche["appareils"] = list(fiche.get("par_appareil", {}))
    f.write_text(json.dumps(etat, separators=(",", ":")), encoding="utf-8")
    print(f"Contributions : {acceptes} ticket(s) intégré(s), {refuses} refusé(s) ; "
          f"{len(etat['empreintes'])} empreintes signalées par {len(etat['appareils'])} appareil(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
