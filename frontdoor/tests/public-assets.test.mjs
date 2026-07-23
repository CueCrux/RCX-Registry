// Guards the growth-item static assets — the graded deliverables that a Nuxt
// build won't catch if they're malformed (they're copied verbatim into .output).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const pub = (p) => fileURLToPath(new URL(`../public/${p}`, import.meta.url))
const read = (p) => readFileSync(pub(p), 'utf8')

test('.well-known/mcp.json is valid and points at the registry API', () => {
  const card = JSON.parse(read('.well-known/mcp.json'))
  assert.equal(card.transport.type, 'http')
  assert.equal(card.transport.url, 'https://registry.rcxprotocol.org/v0/servers')
  assert.equal(card.capabilities.registry.openapi, 'https://rcxprotocol.org/openapi.json')
  assert.equal(card.auth.publisher_writes.status, 'disabled')
  assert.equal(card.auth.publisher_writes.http_status, 404)
  assert.equal(card.receipts.format_signature, 'ed25519')
  assert.equal(card.receipts.production_signed_records, false)
  assert.equal(card.receipts.publisher_rights_records, 0)
  assert.equal(card.receipts.public_live_retrieval, false)
})

test('OpenAPI matches the fail-closed publisher surface and runtime envelope', () => {
  const spec = JSON.parse(read('openapi.json'))
  assert.equal(spec.openapi, '3.1.0')
  assert.ok(spec.paths['/v0/servers/{server_name}/versions/{version}'])
  for (const [path, method] of [
    ['/v0/publisher-rights/dns-challenge', 'post'],
    ['/v0/publisher-rights/dns-verify', 'post'],
    ['/v0/publisher-rights/github/start', 'get'],
    ['/v0/publisher-rights/github/callback', 'get'],
  ]) {
    const operation = spec.paths[path][method]
    assert.equal(operation.deprecated, true)
    assert.deepEqual(Object.keys(operation.responses), ['404'])
    assert.equal(operation.requestBody, undefined)
    assert.equal(operation.parameters, undefined)
  }
  assert.equal(spec.paths['/v0/publishers/declare'], undefined)
  assert.equal(spec.paths['/v0/publisher-rights/manual-verify'], undefined)
  assert.equal(spec.components.schemas.DnsVerifyRequest, undefined)
  assert.ok(spec.components.schemas.ServerEnvelope.properties.server)
  assert.ok(spec.components.schemas.ServerEnvelope.properties._meta)
  assert.equal(spec.components.schemas.ReceiptRef, undefined)
})

test('the catch-all is the only spec page so base-to-chapter navigation cannot reuse a page component', () => {
  const legacyWrapper = fileURLToPath(new URL('../pages/spec/v1/index.vue', import.meta.url))
  assert.equal(existsSync(legacyWrapper), false)
})

test('sitemap lists every built page', () => {
  const xml = read('sitemap.xml')
  for (const path of [
    '/',
    '/verify',
    '/spec/v1',
    '/spec/v1/01-conventions',
    '/spec/v1/02-canonical-cbor',
    '/spec/v1/03-canonical-json',
    '/spec/v1/04-hashing',
    '/spec/v1/05-receipts',
    '/spec/v1/06-merkle-and-snapshots',
    '/spec/v1/07-api-and-errors',
    '/spec/v1/vectors',
    '/subregistry',
    '/publish',
    '/badge',
    '/legal',
    '/legal/terms',
    '/legal/privacy',
  ]) {
    assert.ok(xml.includes(`<loc>https://rcxprotocol.org${path}</loc>`), `missing ${path}`)
  }
})

test('robots welcomes the named retrieval bots and references the sitemap', () => {
  const robots = read('robots.txt')
  for (const bot of ['OAI-SearchBot', 'Claude-SearchBot', 'Claude-User', 'PerplexityBot', 'Googlebot']) {
    assert.ok(robots.includes(`User-agent: ${bot}`), `missing ${bot}`)
  }
  assert.ok(robots.includes('Sitemap: https://rcxprotocol.org/sitemap.xml'))
})

test('llms.txt has the required H2 sections', () => {
  const llms = read('llms.txt')
  for (const h2 of ['## What it is', '## Protocol specification', '## API endpoints', '## Publisher verification', '## Subregistry positioning']) {
    assert.ok(llms.includes(h2), `missing ${h2}`)
  }
  assert.ok(llms.includes('310ace858172b6f4acdd982ef25c2441f20d6b7a'))
})

test('svg assets are present and non-trivial', () => {
  for (const svg of ['favicon.svg', 'badge/verified.svg']) {
    const s = read(svg)
    assert.ok(s.includes('<svg') && s.length > 120, `bad ${svg}`)
  }
})
