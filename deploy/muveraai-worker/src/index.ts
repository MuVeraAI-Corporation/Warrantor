/**
 * muveraai.com namespace Worker.
 *
 * Serves two things and nothing else:
 *
 *   /go/<module>[/...]   Go vanity import resolution (RFC-less, see `go help importpath`)
 *   /schemas/...         the protocol JSON Schemas the $id fields point at
 *
 * DESIGN CONSTRAINT: muveraai.com is a live production site. This Worker is
 * routed only at those two path prefixes, both of which returned 404 before it
 * existed. Every request it does not positively recognise is passed through to
 * the origin unchanged, so a routing mistake degrades to "the site as it was"
 * rather than to an outage.
 *
 * WHY THE FOUR-FIELD META TAG: Go verifies a go-import tag whose prefix is
 * SHORTER than the requested import path by re-fetching the prefix and demanding
 * an identical tag (cmd/go/internal/vcs.repoRootForImportDynamic). Declaring
 * prefix == the full module path avoids that second fetch entirely -- which is
 * what keeps this Worker off `muveraai.com/`, the homepage. The trailing
 * subdirectory field, recognised since Go 1.25, is what lets a module live at
 * go/<name> in the monorepo while being imported as muveraai.com/go/<name>.
 */

import { GO_MODULES, SCHEMAS, REPO_URL, type GoModule } from './generated';

const HTML = 'text/html; charset=utf-8';
const SCHEMA_JSON = 'application/schema+json';

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** The go-import document. Kept minimal: Go parses only <head>. */
function goImportDocument(module: GoModule): string {
  const content = `${module.modulePath} git ${REPO_URL} ${module.subDir}`;
  return `<!doctype html>
<html><head>
<meta charset="utf-8">
<meta name="go-import" content="${escapeHtml(content)}">
<meta name="go-source" content="${escapeHtml(module.modulePath)} ${escapeHtml(REPO_URL)} ${escapeHtml(REPO_URL)}/tree/main/${escapeHtml(module.subDir)}{/dir} ${escapeHtml(REPO_URL)}/blob/main/${escapeHtml(module.subDir)}{/dir}/{file}#L{line}">
<meta http-equiv="refresh" content="0; url=${escapeHtml(REPO_URL)}/tree/main/${escapeHtml(module.subDir)}">
<title>${escapeHtml(module.modulePath)}</title>
</head><body>
<p>Redirecting to <a href="${escapeHtml(REPO_URL)}/tree/main/${escapeHtml(module.subDir)}">${escapeHtml(module.modulePath)}</a>.</p>
<pre>go get ${escapeHtml(module.modulePath)}</pre>
</body></html>
`;
}

function handleGo(url: URL): Response | null {
  // /go/<name> or /go/<name>/<subpackage>...
  const segments = url.pathname.split('/').filter(Boolean); // ['go', name, ...]
  const name = segments[1];
  if (name === undefined) return null;

  const module = GO_MODULES[name];
  if (module === undefined) return null; // unknown module -> let the origin 404 it

  return new Response(goImportDocument(module), {
    headers: {
      'content-type': HTML,
      // Short TTL: a wrong go-import cached for a day is a bad day.
      'cache-control': 'public, max-age=300',
    },
  });
}

function handleSchema(url: URL): Response | null {
  const key = url.pathname.slice('/schemas/'.length);
  const body = SCHEMAS[key];
  if (body === undefined) return null; // let the origin 404 it

  return new Response(body, {
    headers: {
      'content-type': SCHEMA_JSON,
      // Schemas are immutable per version -- the version is in the path.
      'cache-control': 'public, max-age=3600',
      'access-control-allow-origin': '*',
    },
  });
}

export default {
  fetch(request: Request): Response | Promise<Response> {
    const url = new URL(request.url);

    // Only GET and HEAD are ever answered locally. Anything else -- including a
    // POST that somehow matched the route -- goes to the origin untouched.
    if (request.method === 'GET' || request.method === 'HEAD') {
      if (url.pathname === '/go' || url.pathname.startsWith('/go/')) {
        const response = handleGo(url);
        if (response !== null) return response;
      }
      if (url.pathname.startsWith('/schemas/')) {
        const response = handleSchema(url);
        if (response !== null) return response;
      }
    }

    // Pass through. This is the safety property: unrecognised traffic behaves
    // exactly as it did before this Worker was deployed.
    return fetch(request);
  },
};
