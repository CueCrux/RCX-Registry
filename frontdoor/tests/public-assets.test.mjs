// Guards the growth-item static assets — the graded deliverables that a Nuxt
// build won't catch if they're malformed (they're copied verbatim into .output).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const pub = (p) => fileURLToPath(new URL(`../public/${p}`, import.meta.url))
const read = (p) => readFileSync(pub(p), 'utf8')

test('.well-known/mcp.json is valid and points at the registry API', () => {
  const card = JSON.parse(read('.well-known/mcp.json'))
  assert.equal(card.transport.type, 'http')
  assert.match(card.transport.url, /^https:\/\/registry\.rcxprotocol\.org/)
  assert.equal(card.receipts.signature, 'ed25519')
})

test('sitemap lists every built page', () => {
  const xml = read('sitemap.xml')
  for (const path of ['/', '/verify', '/subregistry', '/publish', '/badge', '/legal', '/legal/terms', '/legal/privacy']) {
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
  for (const h2 of ['## What it is', '## API endpoints', '## Publisher verification', '## Subregistry positioning']) {
    assert.ok(llms.includes(h2), `missing ${h2}`)
  }
})

test('svg assets are present and non-trivial', () => {
  for (const svg of ['favicon.svg', 'badge/verified.svg']) {
    const s = read(svg)
    assert.ok(s.includes('<svg') && s.length > 120, `bad ${svg}`)
  }
})
