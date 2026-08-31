// server.js — a minimal, rule-based reference backend.
//
// This is NOT the production SCAMCHECK detection system described in the
// product spec (no AI layer, no domain-reputation lookups, no scam
// intelligence DB). It exists so you can `npm install && npm start` and
// get the extension responding immediately while you build the real
// backend behind the same /v1/check contract.
//
// Run:
//   cd example-backend
//   npm install
//   npm start
// Then in the extension's options page, set API base URL to
// http://localhost:8787

import express from "express";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 8787;

// ---- Layer 1: text pattern rules -------------------------------------
const TEXT_RULES = [
  {
    id: "urgency",
    label: "Creates urgency",
    reason: "Urgency/manipulation",
    pattern: /\b(immediately|urgent|right away|within\s+\d+\s*(minutes|hours)|act now|expires? (today|soon)|final notice|permanently (deleted|suspended|closed))\b/i,
  },
  {
    id: "threat",
    label: "Threatens a negative consequence",
    reason: "Fear-based pressure",
    pattern: /\b(account (will be|has been) (suspended|locked|closed|deleted)|legal action|you will be (fined|charged|arrested))\b/i,
  },
  {
    id: "prize",
    label: "Unexpected prize or winnings",
    reason: "Prize/lottery lure",
    pattern: /\b(you('| ha)ve won|congratulations.*(selected|winner)|claim your (prize|reward|gift))\b/i,
  },
  {
    id: "credentials",
    label: "Requests a password or verification code",
    reason: "Credential harvesting",
    pattern: /\b(enter your password|verify your (password|pin|otp|one-time code)|send (us |me )?(the|your) code)\b/i,
  },
  {
    id: "payment",
    label: "Requests payment or gift cards",
    reason: "Payment/gift-card request",
    pattern: /\b(gift cards?|wire transfer|western union|pay(ment)? (via|through) (crypto|bitcoin)|send (money|funds|payment))\b/i,
  },
  {
    id: "impersonation",
    label: "Claims to be a bank, courier, or government agency",
    reason: "Brand/authority impersonation",
    pattern: /\b(irs|internal revenue|social security administration|paypal support|amazon support|dhl|fedex|ups delivery|your bank)\b/i,
  },
  {
    id: "job_scam",
    label: "Unusually easy job offer with upfront payment",
    reason: "Job scam pattern",
    pattern: /\b(work from home|no experience needed).{0,40}\$\d+.{0,20}(per day|per week|daily)/i,
  },
  {
    id: "romance",
    label: "Romantic urgency combined with a money request",
    reason: "Romance scam pattern",
    pattern: /\b(my love|sweetheart|darling).{0,80}(send (money|funds)|western union|gift card)/i,
  },
  {
    id: "crypto_invest",
    label: "Guaranteed investment or crypto returns",
    reason: "Investment scam pattern",
    pattern: /\b(guaranteed returns?|double your (money|bitcoin|crypto)|risk-free investment)\b/i,
  },
];

// ---- Layer 2: URL heuristics -------------------------------------------
const KNOWN_BRANDS = [
  "paypal", "amazon", "apple", "microsoft", "google", "netflix", "bankofamerica",
  "chase", "wellsfargo", "irs", "usps", "fedex", "dhl", "ups", "facebook", "instagram",
];

const SUSPICIOUS_TLDS = new Set([
  "zip", "top", "xyz", "gq", "tk", "ml", "work", "click", "country", "kim",
]);

function analyzeUrl(rawUrl) {
  const signals = [];
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return { signals: [{ label: "Not a well-formed URL", reason: "Malformed input" }], score: 1 };
  }

  const host = url.hostname.toLowerCase();
  const labels = host.split(".");
  const tld = labels[labels.length - 1];

  if (url.protocol !== "https:") {
    signals.push({ label: "Not using HTTPS", reason: "Unencrypted connection" });
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    signals.push({ label: `Uses a ".${tld}" domain often abused for scams`, reason: "Suspicious TLD" });
  }

  if (labels.length > 4) {
    signals.push({ label: "Unusually long/nested subdomain chain", reason: "Domain obfuscation" });
  }

  for (const brand of KNOWN_BRANDS) {
    const inHost = host.includes(brand);
    const isOfficial =
      host === `${brand}.com` || host.endsWith(`.${brand}.com`) || host === `www.${brand}.com`;
    if (inHost && !isOfficial) {
      signals.push({
        label: `Mentions "${brand}" but isn't ${brand}'s official domain`,
        reason: "Possible lookalike/impersonation domain",
      });
      break;
    }
  }

  if (/\d{1,3}(\.\d{1,3}){3}/.test(host)) {
    signals.push({ label: "Raw IP address instead of a domain name", reason: "Domain obfuscation" });
  }

  if (/[а-яΑ-Ωkörné]/i.test(host)) { signals.push({ label: "Domain contains non-standard characters", reason: "Possible homograph attack" }); } Select and delete it, then type this in its place: if (/[а-яА-ЯΑ-Ωα-ω]/.test(host)) { signals.push({ label: "Domain contains Cyrillic or Greek characters that can mimic Latin letters", reason: "Possible homograph attack" }); } if (host.includes("xn--")) { signals.push({ label: "Domain uses punycode encoding, sometimes used to disguise lookalike characters", reason: "Possible homograph attack" }); }

  return { signals, score: signals.length };
}

function analyzeText(text) {
  const hits = [];
  for (const rule of TEXT_RULES) {
    const match = rule.pattern.exec(text);
    if (match) {
      hits.push({
        label: rule.label,
        reason: rule.reason,
        quote: match[0].slice(0, 140),
      });
    }
  }
  return hits;
}

function scoreToRiskLevel(score) {
  if (score >= 3) return "high";
  if (score >= 1) return "suspicious";
  return "low";
}

app.get("/v1/health", (_req, res) => res.json({ ok: true }));

app.post("/v1/check", (req, res) => {
  const { type, content, pageContext } = req.body || {};

  if (!content || typeof content !== "string") {
    return res.status(400).json({ error: "content is required" });
  }

  const warningSigns = [];
  const evidence = [];
  let score = 0;

  if (type === "url" || /^https?:\/\//i.test(content)) {
    const { signals, score: urlScore } = analyzeUrl(content);
    score += urlScore;
    for (const s of signals) warningSigns.push(s.label);
  }

  // Analyze the visible text too, when present (pasted text, or the page's
  // extracted excerpt from a "Full check").
  const textToScan = [content, pageContext?.excerptText, pageContext?.title]
    .filter(Boolean)
    .join("\n");
  const textHits = analyzeText(textToScan);
  score += textHits.length;
  for (const hit of textHits) {
    warningSigns.push(hit.label);
    evidence.push({ quote: hit.quote, reason: hit.reason });
  }

  if (pageContext?.forms?.some((f) => f.hasPasswordField)) {
    warningSigns.push("Page contains a password field");
    score += 1;
  }
  if (pageContext?.forms?.some((f) => f.hasPaymentField)) {
    warningSigns.push("Page contains a payment/card field");
    score += 1;
  }

  const riskLevel = scoreToRiskLevel(score);
  const uniqueSigns = [...new Set(warningSigns)];

  const summaries = {
    low: "No strong scam indicators were found. This isn't a guarantee of safety — stay cautious with anything involving money or passwords.",
    suspicious: "A few warning signs were detected. Proceed carefully and verify independently before acting.",
    high: "Multiple strong scam indicators were detected. Treat this as likely fraudulent.",
  };

  res.json({
    riskLevel,
    summary: summaries[riskLevel],
    warningSigns: uniqueSigns,
    evidence,
    recommendedActions: {
      avoid:
        riskLevel === "low"
          ? []
          : ["Don't click links or download attachments from this", "Don't enter passwords or payment details", "Don't send money or gift cards"],
      do:
        riskLevel === "low"
          ? ["Stay cautious with any request for money, passwords, or personal details"]
          : ["Contact the organization directly through its official website or number", "Report and delete the message if it's unsolicited"],
    },
    category: null,
    confidence: null,
  });
});

app.listen(PORT, () => {
  console.log(`SCAMCHECK example backend listening on http://localhost:${PORT}`);
});
