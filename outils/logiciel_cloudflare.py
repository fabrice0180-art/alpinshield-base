"""Prépare la copie Cloudflare de la dernière version d'Alpin Shield (version « logiciel » du dépôt).

Cloudflare Pages refuse les fichiers de plus de 25 Mio : un fichier trop gros reste seulement sur GitHub.
La fiche version.json est réécrite pour pointer vers Cloudflare pour chaque fichier copié, GitHub sinon.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

LIMITE = 24 * 1024 * 1024
CLOUDFLARE = "https://alpinshield-base.pages.dev/logiciel/"


def main() -> int:
    dossier = Path(sys.argv[1])
    fiche = dossier / "version.json"
    if not fiche.exists():
        for f in dossier.glob("*"):
            f.unlink()
        return 0
    for f in dossier.iterdir():
        if f.is_file() and f.stat().st_size > LIMITE:
            print(f"  {f.name} : trop gros pour Cloudflare, gardé seulement sur GitHub")
            f.unlink()
    d = json.loads(fiche.read_text(encoding="utf-8"))
    for a in d.get("assets", []):
        if (dossier / a["name"]).exists():
            a["browser_download_url"] = CLOUDFLARE + a["name"]
    fiche.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Alpin Shield {d.get('version')} copié sur Cloudflare.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
