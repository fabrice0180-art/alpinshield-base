// Guichet des signalements d'Alpin Shield (Cloudflare Pages Functions, gratuit).
// Les installations envoient ici leurs signalements, sans aucune clé. Le guichet vérifie chaque champ, ajoute
// une empreinte anonyme du réseau d'envoi (pour qu'un même réseau ne compte qu'une voix), puis dépose le tout en
// ticket « contribution » sur le dépôt GitHub de la base. La clé GitHub reste ici, en secret, jamais dans le logiciel.
const DEPOT = "fabrice0180-art/alpinshield-base";
const RE_SHA = /^[0-9a-f]{64}$/;
const RE_APPAREIL = /^[0-9a-f]{32}$/;
const RE_DOMAINE = /^(?=.{4,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/;
const VERDICTS = new Set(["m", "mc", "s", "b"]);

const repondre = (code, objet) =>
  new Response(JSON.stringify(objet), { status: code, headers: { "content-type": "application/json; charset=utf-8" } });

async function anonyme(texte) {
  const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(texte));
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

export async function onRequestPost({ request, env }) {
  const jeton = String(env.GITHUB_JETON || "").trim();
  if (!jeton) return repondre(503, { erreur: "guichet non configuré" });
  const brut = await request.text();
  if (brut.length > 400000) return repondre(413, { erreur: "envoi trop gros" });
  let d;
  try {
    d = JSON.parse(brut);
  } catch {
    return repondre(400, { erreur: "format" });
  }
  if (!d || typeof d !== "object" || !RE_APPAREIL.test(String(d.appareil || ""))) return repondre(400, { erreur: "appareil" });

  const empreintes = [];
  for (const e of (Array.isArray(d.empreintes) ? d.empreintes : []).slice(0, 2000)) {
    if (!e || typeof e !== "object") continue;
    const sha = String(e.sha256 || "").toLowerCase();
    const verdict = String(e.verdict || "");
    if (!RE_SHA.test(sha) || !VERDICTS.has(verdict)) continue;
    empreintes.push({ sha256: sha, verdict, nom: String(e.nom || "").replace(/[^\w .:/()+\-]/g, "").slice(0, 80) });
  }
  const domaines = [...new Set((Array.isArray(d.domaines) ? d.domaines : []).slice(0, 500)
    .map((x) => String(x).toLowerCase().replace(/^\.+|\.+$/g, ""))
    .filter((x) => RE_DOMAINE.test(x)))];
  if (!empreintes.length && !domaines.length) return repondre(200, { ok: true, recus: 0 });

  // empreinte anonyme du réseau : impossible d'en retrouver l'adresse, mais deux envois du même réseau se reconnaissent
  const reseau = await anonyme(jeton + "|" + (request.headers.get("CF-Connecting-IP") || ""));
  const envoi = {
    format: 1, appareil: d.appareil, reseau,
    version: String(d.version || "").replace(/[^\w.\-]/g, "").slice(0, 20), empreintes, domaines,
  };
  const r = await fetch(`https://api.github.com/repos/${DEPOT}/issues`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${jeton}`, Accept: "application/vnd.github+json",
      "User-Agent": "AlpinShield-guichet", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json",
    },
    body: JSON.stringify({
      title: `Contribution Alpin Shield ${new Date().toISOString().slice(0, 10)}`,
      body: "Signalements reçus par le guichet Cloudflare d'Alpin Shield (empreintes uniquement).\n\n```json\n" +
        JSON.stringify(envoi) + "\n```",
      labels: ["contribution"],
    }),
  });
  if (!r.ok) return repondre(502, { erreur: `dépôt refusé (${r.status})` });
  return repondre(200, { ok: true, recus: empreintes.length + domaines.length });
}

export const onRequest = () => repondre(405, { erreur: "envoi par POST uniquement" });
