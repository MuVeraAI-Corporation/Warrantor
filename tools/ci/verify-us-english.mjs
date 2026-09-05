/**

 * US-English gate for every public surface (X, LinkedIn, Substack, site, outreach, decks).

 *

 * House standard reversed to American English on 2026-08-21 — see ~/.claude/CLAUDE.md

 * ("American English — HARD RULE") and vj-persona-voice. This script is the enforcement.

 *

 * It exists because eyeballing demonstrably does not work: docs/content/2026-08-21-beliefs/

 * x-article/article.md shipped with 8 "authorisation" and 1 "authorized" in the same file.

 *

 * Per the standing sample-before-you-report rule, every finding prints the line it came from —

 * never a bare count.

 *

 *   node scripts/verify-us-english.mjs <file...>          # report + exit 1 on any finding

 *   node scripts/verify-us-english.mjs --fix <file...>    # rewrite outside the carve-outs

 *

 * Carve-outs (never rewritten, reported separately as SKIPPED):

 *   1. verbatim quotations   — markdown blockquote lines, and spans inside "..." / “...”

 *   2. proper nouns / titles — an entry in PROPER_NOUNS, or a Capitalised occurrence

 *   3. code                  — fenced blocks, inline `spans`, and URLs

 */

import { readFileSync, writeFileSync } from "fs";



/** British form (regex source, no anchors) -> American form. Lowercase; case is restored on output. */

const FORMS = [

  // -ise / -isation family (the big one). Handled as stems so all inflections are caught.

  ["organis", "organiz"], ["recognis", "recogniz"], ["authoris", "authoriz"],

  ["analys", "analyz"], ["prioritis", "prioritiz"], ["standardis", "standardiz"],

  ["categoris", "categoriz"], ["specialis", "specializ"], ["generalis", "generaliz"],

  ["normalis", "normaliz"], ["centralis", "centraliz"], ["formalis", "formaliz"],

  ["legitimis", "legitimiz"], ["minimis", "minimiz"], ["maximis", "maximiz"],

  ["optimis", "optimiz"], ["realis", "realiz"], ["utilis", "utiliz"],

  ["summaris", "summariz"], ["criticis", "criticiz"], ["apologis", "apologiz"],

  ["characteris", "characteriz"], ["scrutinis", "scrutiniz"], ["monetis", "monetiz"],

  ["mobilis", "mobiliz"], ["memoris", "memoriz"], ["militaris", "militariz"],

  ["sensitis", "sensitiz"], ["systematis", "systematiz"],

  // NB: advertise/exercise/revise/supervise/comprise/franchise are -ise in American English too — never add them.

  ["emphasis", "emphasiz"], ["synthesis", "synthesiz"], ["hypothesis", "hypothesiz"],

  ["harmonis", "harmoniz"], ["stabilis", "stabiliz"], ["visualis", "visualiz"],

  ["decentralis", "decentraliz"], ["personalis", "personaliz"], ["rationalis", "rationaliz"],

  ["computeris", "computeriz"], ["digitis", "digitiz"], ["itemis", "itemiz"],

  // Added 2026-08-22: "unfinalised" survived a full --fix pass on the outreach corpus (59 hits

  // across 62 files) because no "finalis" stem existed. A gate is only as good as its word list.

  ["finalis", "finaliz"], ["commercialis", "commercializ"], ["decarbonis", "decarboniz"],

  ["modernis", "moderniz"], ["nationalis", "nationaliz"], ["privatis", "privatiz"],

  ["localis", "localiz"], ["globalis", "globaliz"], ["contextualis", "contextualiz"],

  ["operationalis", "operationaliz"], ["securitis", "securitiz"], ["amortis", "amortiz"],

  ["penalis", "penaliz"], ["publicis", "publiciz"], ["colonis", "coloniz"],

  ["marginalis", "marginaliz"], ["neutralis", "neutraliz"], ["capitalis", "capitaliz"],

  ["industrialis", "industrializ"], ["institutionalis", "institutionaliz"],

  ["operationalis", "operationaliz"], ["incentivis", "incentiviz"],

  // -our

  ["behaviour", "behavior"], ["colour", "color"], ["favour", "favor"], ["honour", "honor"],

  ["labour", "labor"], ["neighbour", "neighbor"], ["rumour", "rumor"], ["endeavour", "endeavor"],

  ["flavour", "flavor"], ["harbour", "harbor"], ["humour", "humor"], ["odour", "odor"],

  ["valour", "valor"], ["vapour", "vapor"], ["armour", "armor"], ["rigour", "rigor"],

  ["vigour", "vigor"], ["splendour", "splendor"], ["saviour", "savior"], ["parlour", "parlor"],

  // -re

  ["centre", "center"], ["theatre", "theater"], ["litre", "liter"], ["metre", "meter"],

  ["fibre", "fiber"], ["calibre", "caliber"], ["sombre", "somber"], ["spectre", "specter"],

  ["manoeuvre", "maneuver"], ["lustre", "luster"], ["sceptre", "scepter"],

  // -ce / -se and one-offs

  ["licence", "license"], ["defence", "defense"], ["offence", "offense"],

  ["pretence", "pretense"], ["practise", "practice"],

  ["artefact", "artifact"], ["programme", "program"], ["judgement", "judgment"],

  ["acknowledgement", "acknowledgment"], ["ageing", "aging"], ["cheque", "check"],

  ["kerb", "curb"], ["tyre", "tire"], ["aluminium", "aluminum"], ["grey", "gray"],

  ["storey", "story"], ["whilst", "while"], ["amongst", "among"], ["towards", "toward"],

  // These are not stem+suffix ("centring" is not "centre"+"ing"), so the generic pattern cannot

  // reach them. They need their own entries.

  // Only forms the stem+suffix pattern CANNOT build ("centring" is not "centre"+"ing").

  // Do NOT add centred/practised/licenced here — joinSuffix already handles those, and a second

  // entry would queue a duplicate overlapping edit on the same span.

  ["centring", "centering"], ["manoeuvring", "maneuvering"], ["practising", "practicing"],

  // Added 2026-08-22: "afterwards" reached a PUBLISHED LinkedIn post and the gate passed it —

  // "towards" was on the list but the rest of the -wards family was not. Fix the class, not the word.

  ["afterwards", "afterward"], ["backwards", "backward"], ["forwards", "forward"],



  // Added 2026-08-23: "nought" is the British spoken form of zero and reached a video script the

  // gate had just passed. Spoken-number forms are a class the word lists never covered — a script

  // is read ALOUD, so the British/American split shows up in numerals, not only in spelling.

  ["nought", "zero"], ["noughts", "zeros"], ["maths", "math"],

  ["upwards", "upward"], ["downwards", "downward"], ["onwards", "onward"],

  ["inwards", "inward"], ["outwards", "outward"],

  ["learnt", "learned"], ["spelt", "spelled"], ["burnt", "burned"], ["dreamt", "dreamed"],

  ["leapt", "leaped"], ["spoilt", "spoiled"], ["knelt", "kneeled"],

  ["enrol", "enroll"], ["fulfil", "fulfill"], ["instalment", "installment"],

  ["skilful", "skillful"], ["wilful", "willful"], ["appal", "appall"], ["distil", "distill"],

  ["sceptic", "skeptic"], ["moustache", "mustache"], ["plough", "plow"],

  ["mould", "mold"], ["smoulder", "smolder"], ["draught", "draft"], ["gaol", "jail"],

  ["storeys", "stories"], ["speciality", "specialty"], ["orientated", "oriented"],

  ["cancelled", "canceled"], ["cancelling", "canceling"], ["labelled", "labeled"],

  ["labelling", "labeling"], ["modelled", "modeled"], ["modelling", "modeling"],

  ["travelled", "traveled"], ["travelling", "traveling"], ["traveller", "traveler"],

  ["signalled", "signaled"], ["signalling", "signaling"], ["fuelled", "fueled"],

  ["marvellous", "marvelous"], ["counsellor", "counselor"], ["jewellery", "jewelry"],

  ["defencive", "defensive"], ["offencive", "offensive"], ["analogue", "analog"],

];



/** Cited titles and registered names that keep their British spelling. Matched case-sensitively. */

const PROPER_NOUNS = [

  "World Health Organisation", "International Labour Organisation",

  "Organisation for Economic Co-operation and Development", "OECD",

  "Labour Party", "Ministry of Defence", "Serious Fraud Office",

  // Indian government bodies and programmes, official registered names.

  "Innovations for Defence Excellence", "iDEX-DIO", "Defence Innovation Organisation",

  "Defence Research and Development Organisation", "DRDO", "Ministry of Defence, India",

  "Centre for Data Ethics", "Alan Turing Institute", "Licence Agreement",

  // Cited institutions in academic references. A cited affiliation is a proper noun and
  // its registered spelling stands, exactly as a quoted title does.

  "UCL Centre for Artificial Intelligence", "Centre for Artificial Intelligence",

  "Organisation of Islamic Cooperation", "Emiratisation", "Emiratisation Policy", "Defence Science and Technology Laboratory",

  "Paris Theatre", "Egyptian Theatre", "Grauman's Egyptian Theatre",

  "Theatre Royal", "Centrepoint", "Artificial Intelligence Centre", "GenAI Centre of Excellence",

  "Barclays Technologies Centre India", "Centre of Excellence", "Innovation Centre",

  "Statistics Centre", "OctoChem Pharma and Flavours", "Finnish Defence", "Sagar Defence",

  "Indian Defence", "Sainsbury Wellcome Centre", "Dubai International Financial Centre",

  "DIFC Partner Programme", "DIFC's Partner Programme", "Global Capability Centre",

  "National Informatics Centre", "Lloyds Technology Centre", "Dubai Multi Commodities Centre",

  // Added 28 Aug 2026 from the India + GCC value book. Registered names of real

  // institutions: respelling them would rename the thing, which is the exact failure

  // the carve-out exists to prevent.

  "Qatar Shell Research and Technology Centre", "Statistics Centre - Abu Dhabi",
  "Technology Realised Value", "Max Smart Super Speciality",

  "Qatar Mobility Innovations Centre", "Emirates NBD media centre",

  // Added 25 Aug 2026, all from the Send Book volumes. Each is the REGISTERED name of a real

  // institution or a person's actual job title, so "correcting" it would rename the thing.

  // India's grid operators are literally the National / Regional / State Load Despatch Centres,

  // and an engineer who reports to one would notice the respelling immediately.

  // The legacy column name, quoted exactly as the migration script tests for it. Carved out as

  // the whole expression rather than the bare word: `organisation` on its own must keep failing

  // everywhere else, and an entry this specific cannot mask prose.

  'cols.includes("organisation")',

  "Load Despatch Centre", "load despatch centre", "Load Despatch Centres",

  "National Load Despatch Centre", "Regional Load Despatch Centre", "State Load Despatch Centre",

  "AI, Defence & Sovereign Technologies", "AI, Defence &amp; Sovereign Technologies",

  "ISB Centre for Business Innovation", "Centre for Business Innovation",

  "Centre of Data for Public Good", "Human-Centred Artificial Intelligence",

  "Dubai Exhibition Centre", "Xerox Research Centre", "The Cambridge Crystallographic Data Centre",

  "Telecommunication Engineering Centre", "Sony India Software Centre", "Societe Generale Global Solution Centre",

  "National Health Systems Resource Centre", "Senior Executive Leadership Programme", "MBZUAI Executive Programme",

  "NASSCOM Centre", "ISB Centre", "Infosys Centre",

  "WEF Centre", "Fraud Risk Surveillance Centre", "Megawatt Government Data Centre",

  "Kotak Data Centre", "University Hospital Centre", "Brencis Centre",

  "The CFO Centre", "Career Development Centre", "Airport Predictive Operation Centre",

  "Launched Airport Predictive Operation Centre", "Policy Development Programme", "Good Governance Associates Programme",

  "Leadership Development Programme", "Frontier Employee Programme", "Partner Programme",

  "Trade Licence", "Risk Function Licence",

];



const ISE_STEMS = new Set(FORMS.filter(([b]) => b.endsWith("is")).map(([b]) => b));



/** Build a matcher: -is stems take a suffix, plain words match whole. */

function pattern(brit) {

  return ISE_STEMS.has(brit)

    ? new RegExp(

        // Adverbial and nominal tails matter. An earlier suffix list stopped at "able", so

        // "recognisably" slipped through and reached a PUBLISHED X Article on 2026-08-21 — caught

        // only by scanning the live page, not the source. Longest alternatives come first so the

        // alternation cannot settle for a shorter tail and leave a British ending attached.

        `\\b([A-Za-z]*?)(${brit})(ationally|abilities|ability|ational|ations|ation|ingly|edly|ably|able|ing|ers|er|es|ed|e)\\b`,

        "gi"

      )

    : new RegExp(`\\b(${brit})(s|es|d|ed|ing)?\\b`, "gi");

}



/**

 * Join the American stem to the matched suffix.

 *

 * Added 2026-08-22 after this gate wrote "centerd" into 56 files (131 tokens; 49 of them from an

 * earlier run, 82 from this one). The naive `amer + suffix` is wrong whenever the British stem ends

 * in -e but the American one does not: centre + d gave "centerd" rather than "centered".

 * "programme" is worse than that — English keeps the doubled m, so "programmed" and "programming"

 * are ALREADY American and must not be touched at all.

 */

const KEEPS_ITS_INFLECTION = new Set(["programme"]);

function joinSuffix(brit, amer, suffix) {

  if (!suffix) return amer;

  if (KEEPS_ITS_INFLECTION.has(brit.toLowerCase()) && /^(d|ed|ing)$/i.test(suffix)) return null; // leave alone

  if (/^d$/i.test(suffix) && !/e$/i.test(amer)) return amer + "ed";

  return amer + suffix;

}



/** Restore the casing of the original token onto the replacement. */

function matchCase(src, out) {

  if (src === src.toUpperCase() && src.length > 1) return out.toUpperCase();

  if (src[0] === src[0].toUpperCase()) return out[0].toUpperCase() + out.slice(1);

  return out;

}



/**

 * Mask the three carve-outs so findings inside them are never counted or rewritten.

 * Replaces each protected span with same-length filler, preserving every offset.

 */

// quotesAreDelimiters is TRUE for code/markup, where a straight quote opens a string literal

// or a JSX attribute rather than a quotation. Masking those hid the ENTIRE site copy from

// the gate on 2026-08-22: capabilities/page.tsx kept lede="...agent programmes" through a

// full --fix that still reported PASS. Worse, the mask ran on per-line quote PARITY, so the

// same word was corrected in one clause and skipped in the next.

function maskCarveOuts(text, quotesAreDelimiters = false) {

  let masked = text;

  const blank = (m) => " ".repeat(m.length);

  masked = masked.replace(/```[\s\S]*?```/g, blank);          // fenced code

  masked = masked.replace(/`[^`\n]*`/g, blank);               // inline code

  masked = masked.replace(/https?:\/\/\S+/g, blank);          // URLs

  masked = masked.replace(/^\s*>.*$/gm, blank);               // blockquote = verbatim quote

  // Added 2026-08-22: URL SLUGS AND MODULE PATHS ARE IDENTITY, NOT PROSE.

  // vikramjha.work publishes /writing/the-licence-is-not-the-variable and /writing/who-authorised-it.

  // A --fix that "corrected" those slugs would rename live URLs and break every inbound link,

  // including the LinkedIn posts that point at them. camelCase is already safe (there is no word

  // boundary inside theLicenceIsNotTheVariable); kebab-case is NOT, so mask it explicitly.

  masked = masked.replace(/\b[a-z0-9]+(?:-[a-z0-9]+){2,}\b/g, blank);  // kebab slug (3+ segments)

  masked = masked.replace(/["'`][^"'`\n]*@\/[^"'`\n]*["'`]/g, blank); // module specifier

  if (quotesAreDelimiters) {

    // A genuine quotation inside a string literal is escaped. Protect that, not the delimiter.

    masked = masked.replace(/\\"[^"\n]{0,600}\\"/g, blank);

  } else {

    masked = masked.replace(/"[^"\n]{0,600}"/g, blank);       // prose quotation

  }

  masked = masked.replace(/“[^”\n]{0,600}”/g, blank); // curly-quoted span

  // Added 25 Aug 2026: in EMITTED HTML a quotation arrives escaped as &quot;...&quot;, so the

  // literal-quote rule above never sees it. A dossier note reading: the live hazard on any seat

  // with "Defence" in the title - which is a quoted MENTION of someone's job title - failed the

  // gate purely because the builder escaped the quotes. Same carve-out, escaped spelling.

  masked = masked.replace(/&quot;[\s\S]{0,600}?&quot;/g, blank);

  masked = masked.replace(/&#x27;[\s\S]{0,600}?&#x27;/g, blank);

  // Added 30 Aug 2026: an element marked data-verbatim holds an EXPORTED RECORD -

  // a company's registered name or a person's own job title - not our prose.

  // "Indian Institute of Gems & Jewellery" is a join key, and a seat title is what

  // that person calls themselves. Rewriting either orphans a row or misquotes a

  // human being, so both are masked rather than reported.

  masked = masked.replace(/<([a-z0-9]+)[^>]*\sdata-verbatim[^>]*>[\s\S]*?<\/\1>/gi, blank);

  // Added 25 Aug 2026 after this gate took the production lead funnel down for two days.

  //

  // SQL IS CODE, AND A COLUMN NAME IS AN IDENTIFIER. The house rule already says identifiers are

  // always American and are never rewritten - but a column called `organisation`, created in

  // Postgres long before that rule, is an identifier whose spelling is a FACT about the database,

  // not a style choice. The Americanize pass rewrote `organisation` to `organization` inside the

  // SQL in src/lib/db.ts. The live column kept its name, ensureSchema() uses CREATE TABLE IF NOT

  // EXISTS (a no-op against an existing table, and incapable of renaming), and every insert threw

  // 42703 into a bare catch that returned a silent 503. The site's primary call to action was

  // dead from ~23 Aug until it was found on 25 Aug.

  //

  // Scoped deliberately narrowly: ONLY template literals that actually contain SQL DDL/DML

  // keywords are masked. Masking every backtick literal would repeat the 22 Aug defect where an

  // over-broad quote carve-out hid the entire site copy in .tsx from this gate.

  // The bound is generous on purpose. A first attempt capped it at 4000 characters and silently

  // protected NOTHING in db.ts, whose schema literal is 4379 - the cap has to clear the largest

  // real literal or the carve-out quietly does nothing, which is the same failure shape as the

  // rule it exists to fix.

  masked = masked.replace(/`[\s\S]{0,20000}?`/g, (m) =>

    /\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE|ON\s+CONFLICT|RETURNING)\b/i.test(m)

      ? blank(m)

      : m);

  for (const noun of PROPER_NOUNS) {

    masked = masked.split(noun).join(" ".repeat(noun.length));

  }

  return masked;

}



/**

 * Importable gate. Build scripts call this on their OUTPUT so a Britishism can never reach a

 * platform even if the source markdown drifts. Returns [{token, fixed, line}], carve-outs excluded.

 */

export function findBritishisms(text, isCodeLike = false) {

  const masked = maskCarveOuts(text, isCodeLike);

  const lineOfIdx = (idx) => text.slice(0, idx).split("\n").length;

  const out = [];

  for (const [brit, amer] of FORMS) {

    for (const m of masked.matchAll(pattern(brit))) {

      const token = text.slice(m.index, m.index + m[0].length);

      const rep = ISE_STEMS.has(brit) ? m[1] + amer + m[3] : joinSuffix(brit, amer, m[2]);

      if (rep === null) continue; // already correct American inflection

      out.push({ token, fixed: matchCase(token, rep), line: lineOfIdx(m.index) });

    }

  }

  return out.sort((a, b) => a.line - b.line);

}



/** Throw with the offending rows printed — never a bare count. */

export function assertUsEnglish(text, label) {

  const found = findBritishisms(text);

  if (found.length) {

    const rows = found.map((f) => `    line ${f.line}  ${f.token} -> ${f.fixed}`).join("\n");

    throw new Error(`${label}: ${found.length} Britishism(s) survived\n${rows}`);

  }

}



const invokedDirectly =

  process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/").split("/").pop());

if (!invokedDirectly) {

  // imported as a module — skip the CLI below

} else {



const args = process.argv.slice(2);

const fix = args.includes("--fix");

const files = args.filter((a) => !a.startsWith("--"));

if (!files.length) {

  console.error("usage: node scripts/verify-us-english.mjs [--fix] <file...>");

  process.exit(2);

}



let totalFindings = 0;

let totalSkipped = 0;



for (const file of files) {

  const original = readFileSync(file, "utf8");

  // In .md/.txt a straight quote marks a quotation; in code and markup it is a delimiter.

  const isCodeLike = /\.(ts|tsx|mjs|cjs|js|jsx|json|html|htm|py|svg|xml|css)$/i.test(file);

  const masked = maskCarveOuts(original, isCodeLike);

  const lineStarts = [0];

  for (let i = 0; i < original.length; i++) if (original[i] === "\n") lineStarts.push(i + 1);

  const lineOf = (idx) => {

    let lo = 0, hi = lineStarts.length - 1;

    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid] <= idx) lo = mid; else hi = mid - 1; }

    return lo;

  };

  const lines = original.split("\n");



  const findings = [];

  const skipped = [];

  const edits = [];



  for (const [brit, amer] of FORMS) {

    const re = pattern(brit);

    // Findings come from the MASKED text so carve-outs never count...

    for (const m of masked.matchAll(re)) {

      const token = original.slice(m.index, m.index + m[0].length);

      const replacement = ISE_STEMS.has(brit)

        ? m[1] + amer + m[3]

        : joinSuffix(brit, amer, m[2]);

      if (replacement === null) continue; // "programmed"/"programming" are already American

      findings.push({ idx: m.index, token, fixed: matchCase(token, replacement), line: lineOf(m.index) });

      edits.push({ start: m.index, end: m.index + m[0].length, text: matchCase(token, replacement) });

    }

    // ...and the difference against the ORIGINAL is what the carve-outs protected.

    for (const m of original.matchAll(pattern(brit))) {

      if (masked[m.index] === " ") skipped.push({ token: m[0], line: lineOf(m.index) });

    }

  }



  findings.sort((a, b) => a.idx - b.idx);

  skipped.sort((a, b) => a.line - b.line);

  totalFindings += findings.length;

  totalSkipped += skipped.length;



  console.log(`\n${file}`);

  if (!findings.length) {

    console.log(`  PASS — 0 Britishisms outside the carve-outs`);

  } else {

    console.log(`  FAIL — ${findings.length} Britishism(s):`);

    for (const f of findings) {

      const src = (lines[f.line] || "").trim();

      console.log(`    line ${String(f.line + 1).padStart(4)}  ${f.token} -> ${f.fixed}`);

      console.log(`               ${src.length > 150 ? src.slice(0, 150) + "…" : src}`);

    }

  }

  if (skipped.length) {

    // Split 2026-08-23. A Britishism inside a HYPHENATED compound was being reported in the same

    // bucket as a source quotation, and that bucket reads as "safe to ignore". It is not: the kebab

    // mask exists to protect live URL slugs (/writing/who-authorised-it — renaming those breaks every

    // inbound link), but it cannot tell a slug from ordinary prose like "colour-coded-labels".

    // Loosening the mask risks the link breakage; burying the hit risks shipping the Britishism.

    // So neither — keep the mask, and report hyphenated hits LOUDLY and separately for a human call.

    const hyphenated = [], other = [];

    for (const s of skipped) {

      const src = lines[s.line] || "";

      const re = new RegExp(`[a-z0-9]-[a-z0-9]*${s.token}|${s.token}[a-z0-9]*-[a-z0-9]`, "i");

      (re.test(src) ? hyphenated : other).push(s);

    }

    if (other.length) {

      console.log(`  SKIPPED ${other.length} inside carve-outs (quote/proper noun/code) — review, do not auto-fix:`);

      for (const s of other) console.log(`    line ${String(s.line + 1).padStart(4)}  ${s.token}`);

    }

    if (hyphenated.length) {

      console.log(`  ⚠ HYPHENATED ${hyphenated.length} — masked as a URL slug, but MAY BE PROSE. Decide each one:`);

      for (const s of hyphenated) {

        const src = (lines[s.line] || "").trim();

        console.log(`    line ${String(s.line + 1).padStart(4)}  ${s.token}`);

        console.log(`               ${src.length > 150 ? src.slice(0, 150) + "…" : src}`);

      }

    }

  }



  if (fix && edits.length) {

    edits.sort((a, b) => b.start - a.start);

    let out = original;

    for (const e of edits) out = out.slice(0, e.start) + e.text + out.slice(e.end);

    writeFileSync(file, out, "utf8");

    console.log(`  FIXED ${edits.length} occurrence(s) written back`);

  }

}



console.log(

  `\n${files.length} file(s) · ${totalFindings} finding(s) · ${totalSkipped} protected by carve-outs`

);

if (totalFindings && !fix) process.exit(1);



} // end CLI guard

