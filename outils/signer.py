"""Signe index.json (qui contient l'empreinte SHA-256 de chaque fichier de la base) avec la clé de signature de
la base (Ed25519, secret GitHub SIGNATURE_BASE). Alpin Shield vérifie cette signature avec la clé publique qu'il
contient, puis chaque fichier avec son empreinte : une base modifiée en route ou sur un serveur est refusée.

    python outils/signer.py sortie/index.json      ->  sortie/index.json.sig
"""
from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CLE_PUBLIQUE = "UI9NPpW6W4suefpAG5uZUw8zp7J9fUdCBuyumO5c5Co="   # celle intégrée à Alpin Shield


def main() -> int:
    brut = os.environ.get("SIGNATURE_BASE", "").strip().lstrip("﻿").strip()
    if not brut:
        print("Clé de signature absente (secret SIGNATURE_BASE) : la base n'est pas publiée.")
        return 1
    cle = Ed25519PrivateKey.from_private_bytes(base64.b64decode(brut))
    pub = cle.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if base64.b64encode(pub).decode() != CLE_PUBLIQUE:
        print("La clé de signature ne correspond pas à celle d'Alpin Shield : la base n'est pas publiée.")
        return 1
    f = Path(sys.argv[1])
    donnees = f.read_bytes()
    signature = cle.sign(donnees)
    cle.public_key().verify(signature, donnees)
    Path(str(f) + ".sig").write_text(base64.b64encode(signature).decode() + "\n", encoding="ascii")
    print(f"{f.name} signé.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
