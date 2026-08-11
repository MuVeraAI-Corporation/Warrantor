# muveraai.com namespace Worker

Serves the two things the repository's identifiers point at:

| Path | Serves | Why it must exist |
|------|--------|-------------------|
| `/go/<module>` | `go-import` meta tag | `go get muveraai.com/go/<module>` does not resolve without it |
| `/schemas/...` | protocol JSON Schemas | every generated schema stamps a `$id` under this prefix |

## The safety property

`muveraai.com` is a live production site — 30 pages, a Next.js origin, and Google
Workspace email. This Worker is attached to **two path prefixes only**, both of
which returned `404` from the origin before it existed. Every request it does not
positively recognise is passed to the origin unchanged, so a mistake here degrades
to "the site as it was" rather than to an outage.

Three independent things have to hold, and each is checked rather than assumed:

1. **Routes are narrow.** `wrangler.toml` declares `muveraai.com/go/*` and
   `muveraai.com/schemas/*`. It must never declare `muveraai.com/*`.
2. **Pass-through is the default.** Unknown module, unknown schema, non-GET
   method, or any other path → `return fetch(request)`. Seven tests assert this,
   including on `/`, `/pricing` and the Next.js chunk URLs.
3. **Email is out of reach.** Mail is an MX lookup to Google plus SMTP on :25. A
   Worker sits in neither path, and the deploy token has no `dns_records` scope,
   so it cannot alter MX or SPF even by accident.

A pre-deployment fingerprint of the site is committed here as
`pre-deploy-baseline.json` — 35 paths captured before this Worker existed: 30 live
pages with status and content hash, plus the 5 paths under `/go/` and `/schemas/`
proving they were `404`.

**Compare status codes, not content hashes.** Seven pages — `/contact`, `/trust`,
and five under `/platforms/` — are not byte-stable: three consecutive requests
with no deployment in between return three different hashes. The first
post-deploy diff flagged exactly those seven as regressions, and they were not;
`/platforms/conductor` returned its exact pre-deploy hash on a third probe. Any
hash-based check on this site produces false positives.

A content hash is only meaningful for a path proven stable first. The reliable
signal is: every previously-200 path still returns 200, and only paths under
`/go/` and `/schemas/` moved from 404 to 200.

## Why the meta tag has four fields

```html
<meta name="go-import" content="muveraai.com/go/agent-identity git https://github.com/MuVeraAI-Corporation/Warrantor go/agent-identity">
                                └── prefix ──────────────────┘     └── repo ──────────────────┘ └── subdir ──┘
```

The fourth field is a repository subdirectory, recognised since **Go 1.25**. It is
what allows a module to live at `go/agent-identity/` in this monorepo while being
imported as `muveraai.com/go/agent-identity`.

It is also load-bearing for the safety property above. From
`cmd/go/internal/vcs/vcs.go`:

```go
if mmi.Prefix != importPath {
    // ... re-fetch the prefix and require an identical tag
}
```

If the prefix were the bare domain `muveraai.com`, Go would fetch
`https://muveraai.com/?go-get=1` to verify — which would require routing this
Worker at the **homepage**. Declaring the prefix equal to the full module path
skips that check entirely, which is why `/go/*` is a sufficient route.

Consequence worth knowing: a client on Go < 1.25 running `GOPROXY=direct` will not
recognise the four-field form. The default `GOPROXY=proxy.golang.org` resolves
server-side and is unaffected, which covers essentially all consumers.

## Generated, not hand-maintained

`src/generated.ts` is produced by `scripts/generate.mjs` from the repository's
actual `go/*/go.mod` files and `specs/protocols/*.schema.json`. The generator
fails loudly if a module path is not under `muveraai.com/go/` or a schema `$id` is
not under `https://muveraai.com/schemas/`, so a namespace regression cannot reach
production silently.

Schemas are embedded as the exact bytes on disk, so a hash of the served document
equals a hash of the committed artifact.

## Commands

```bash
npm install
npm run generate    # rebuild src/generated.ts from the repo
npm run check       # regenerate and fail if the committed file is stale
npm run typecheck
npm test            # 16 tests, including the pass-through guarantees
npm run dry-run     # build without deploying
npm run deploy      # requires an authenticated wrangler session
```

## Verifying a deployment

```bash
curl -s "https://muveraai.com/go/agent-identity?go-get=1" | grep go-import
GOPROXY=direct GOFLAGS=-mod=mod go list -m muveraai.com/go/agent-identity@latest
curl -s https://muveraai.com/schemas/protocols/v1/aae.schema.json | head -3
curl -s -o /dev/null -w '%{http_code}\n' https://muveraai.com/     # must still be 200
```

## Not served, deliberately

`did:web:muveraai.com` appears in the tree as a default SBOM supplier identity. A
DID document at `/.well-known/did.json` would make it resolvable, but a DID
document asserts a public key. Publishing one with a placeholder key would create
a credential that looks authoritative and is not, so that path is left unserved
and the identifier remains illustrative until a real key exists. What making it
real would require -- key custody, rotation designed before first signature, the
/.well-known route -- is scoped in docs/cross-cutting/22-did-web-identity.md.
