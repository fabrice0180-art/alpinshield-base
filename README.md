# Base Alpin Shield

Base de menaces utilisée par **Alpin Shield** (développement par Fabrice M.) sur ordinateur (Windows, Mac, Linux)
et sur iPhone. Reconstruite automatiquement **toutes les 2 heures** par GitHub, gratuitement.

## Ce qu'elle contient

| Fichier (release « base ») | Contenu |
|---|---|
| `hachages-00.tsv` … `hachages-ff.tsv` | Empreintes SHA-256 de fichiers : menaces, suspects et logiciels sains connus, rangées par leurs 2 premiers caractères. Une installation ne télécharge que le morceau utile, comme une requête à VirusTotal. Colonnes : `sha256`, verdict (`m` menace, `s` suspect, `b` sain), nom, sources, nombre d'appareils Alpin Shield qui l'ont signalé. |
| `domaines.txt` | Sites qui diffusent des virus ou font du hameçonnage. |
| `domaines-essentiels.txt` | Les 140 000 plus importants (virus, hameçonnage récent) : bouclier Safari de l'iPhone, limité à 150 000 règles. |
| `ips.txt` | Serveurs pirates (centres de commande de virus). |
| `contributions.json` | Signalements des installations d'Alpin Shield. |
| `index.json` | Date, nombres et empreintes des fichiers. |

Adresse des fichiers : `https://github.com/fabrice0180-art/alpinshield-base/releases/download/base/<fichier>`

## Sources

- **MalwareBazaar** et **ThreatFox** (abuse.ch) : menaces confirmées, domaines et serveurs de virus.
- **Feodo Tracker** et **SSLBL** (abuse.ch) : serveurs de virus bancaires et pirates.
- **OpenPhish** (flux communautaire) et **Phishing.Database** (licence MIT) : sites de hameçonnage.
- **Installations d'Alpin Shield** : chaque appareil participant envoie, au plus une fois par jour, les empreintes des
  menaces qu'il a détectées et des programmes validés sains. Jamais de fichier, de nom de fichier, d'emplacement ni
  de contenu : seulement des empreintes, et un identifiant d'appareil tiré au hasard. Un signalement n'est publié
  que s'il est fiable : menace confirmée par une base sur l'appareil, ou signalement venu d'au moins 2 appareils.
- **Ajouts manuels** : dossier `ajouts/`.

## Ajouter des entrées soi-même

Dans le dossier `ajouts/` (une entrée par ligne, `#` pour un commentaire), puis enregistrer (« commit ») :
`menaces.txt` (`sha256;nom`), `sains.txt` (`sha256;nom`), `domaines.txt`, `ips.txt`, et `jamais-bloquer.txt`
(domaines à ne jamais bloquer, en cas de fausse alerte).
