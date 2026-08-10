import { describe, it, expect, vi, afterEach } from 'vitest';
import worker from './index';
import { GO_MODULES, SCHEMAS, REPO_URL } from './generated';

/**
 * The pass-through path calls global fetch. Stub it so a test failure is
 * "the Worker answered when it should have deferred", not a network call.
 */
function stubOrigin(): ReturnType<typeof vi.fn> {
  const spy = vi.fn(async () => new Response('ORIGIN', { status: 200 }));
  vi.stubGlobal('fetch', spy);
  return spy;
}

afterEach(() => vi.unstubAllGlobals());

const get = (path: string, init?: RequestInit) =>
  worker.fetch(new Request(`https://muveraai.com${path}`, init));

describe('go vanity imports', () => {
  it('serves a go-import tag for every module the repo actually declares', async () => {
    for (const [name, mod] of Object.entries(GO_MODULES)) {
      stubOrigin();
      const body = await (await get(`/go/${name}?go-get=1`)).text();
      expect(body, name).toContain(
        `<meta name="go-import" content="${mod.modulePath} git ${REPO_URL} ${mod.subDir}">`,
      );
    }
  });

  it('declares a prefix EQUAL to the module path, so Go never re-fetches the root', async () => {
    // This is the property that keeps the Worker off muveraai.com/ (the homepage).
    // cmd/go re-fetches the prefix only when prefix != importPath.
    stubOrigin();
    const body = await (await get('/go/agent-identity?go-get=1')).text();
    const content = /content="([^"]*)"/.exec(body.split('go-import')[1] ?? '')?.[1] ?? '';
    const [prefix] = content.split(' ');
    expect(prefix).toBe('muveraai.com/go/agent-identity');
  });

  it('names a subdirectory matching the real repo layout', async () => {
    for (const mod of Object.values(GO_MODULES)) {
      expect(mod.subDir).toMatch(/^go\/[a-z0-9-]+$/);
      expect(mod.modulePath).toBe(`muveraai.com/${mod.subDir}`);
    }
  });

  it('answers for subpackages, not just the module root', async () => {
    stubOrigin();
    const body = await (await get('/go/agent-identity/internal/store?go-get=1')).text();
    expect(body).toContain('go-import');
  });

  it('answers identically without ?go-get=1 (humans hit these URLs too)', async () => {
    stubOrigin();
    const body = await (await get('/go/tee-serve')).text();
    expect(body).toContain('go-import');
    expect(body).toContain('go get muveraai.com/go/tee-serve');
  });
});

describe('schemas', () => {
  it('serves every generated protocol schema at its own $id path', async () => {
    for (const key of Object.keys(SCHEMAS)) {
      stubOrigin();
      const res = await get(`/schemas/${key}`);
      expect(res.status, key).toBe(200);
      expect(res.headers.get('content-type')).toBe('application/schema+json');
      // The served bytes must equal the committed artifact, or a hash of the
      // published schema stops matching a hash of the repo.
      expect(await res.text()).toBe(SCHEMAS[key]);
    }
  });

  it('serves a body whose $id is the URL it was fetched from', async () => {
    for (const key of Object.keys(SCHEMAS)) {
      stubOrigin();
      const parsed = JSON.parse(await (await get(`/schemas/${key}`)).text()) as { $id: string };
      expect(parsed.$id).toBe(`https://muveraai.com/schemas/${key}`);
    }
  });
});

describe('pass-through is the default (the safety property)', () => {
  const untouched = [
    '/',
    '/pricing',
    '/platforms/aegis',
    '/company',
    '/blog',
    '/_next/static/chunks/1jexzsn2qdw84.js',
    '/.well-known/did.json',
  ];

  it.each(untouched)('does not answer %s locally', async (path) => {
    const origin = stubOrigin();
    expect(await (await get(path)).text()).toBe('ORIGIN');
    expect(origin).toHaveBeenCalledOnce();
  });

  it('defers unknown modules and unknown schemas to the origin', async () => {
    for (const path of ['/go/not-a-module', '/schemas/nope.json', '/schemas/']) {
      const origin = stubOrigin();
      expect(await (await get(path)).text(), path).toBe('ORIGIN');
      expect(origin).toHaveBeenCalledOnce();
    }
  });

  it('never answers a non-GET/HEAD request, even on a matching path', async () => {
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
      const origin = stubOrigin();
      const res = await get('/go/agent-identity?go-get=1', { method });
      expect(await res.text(), method).toBe('ORIGIN');
      expect(origin).toHaveBeenCalledOnce();
    }
  });
});
