import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { setTimeout as delay } from 'node:timers/promises'
import { chromium } from 'playwright'

const host = '127.0.0.1'
const port = Number(process.env.RCX_FRONTDOOR_SMOKE_PORT || 4310)
const origin = `http://${host}:${port}`
const logs = []

const server = spawn(process.execPath, ['.output/server/index.mjs'], {
  env: {
    ...process.env,
    HOST: host,
    PORT: String(port),
    NITRO_HOST: host,
    NITRO_PORT: String(port),
  },
  stdio: ['ignore', 'pipe', 'pipe'],
})

for (const stream of [server.stdout, server.stderr]) {
  stream.on('data', (chunk) => logs.push(chunk.toString()))
}

async function waitUntilReady() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (server.exitCode !== null) {
      throw new Error(`frontdoor exited before readiness (${server.exitCode})\n${logs.join('')}`)
    }

    try {
      const response = await fetch(`${origin}/`)
      if (response.ok) return
    } catch {
      // The socket is expected to refuse briefly while Nitro starts.
    }

    await delay(250)
  }

  throw new Error(`frontdoor did not become ready\n${logs.join('')}`)
}

async function requireOk(path) {
  const response = await fetch(`${origin}${path}`)
  assert.equal(response.status, 200, `${path} returned ${response.status}`)
  return response
}

async function requireRedirect(path, location) {
  const response = await fetch(`${origin}${path}`, { redirect: 'manual' })
  assert.equal(response.status, 308, `${path} returned ${response.status}`)
  assert.equal(response.headers.get('location'), location)
}

async function requireNotFound(path) {
  const response = await fetch(`${origin}${path}`, { redirect: 'manual' })
  assert.equal(response.status, 404, `${path} returned ${response.status}`)
}

try {
  await waitUntilReady()

  const baselinePaths = ['/', '/verify', '/publish', '/subregistry', '/badge', '/legal']
  const specPaths = [
    '/spec/v1',
    '/spec/v1/01-conventions',
    '/spec/v1/02-canonical-cbor',
    '/spec/v1/03-canonical-json',
    '/spec/v1/04-hashing',
    '/spec/v1/05-receipts',
    '/spec/v1/06-merkle-and-snapshots',
    '/spec/v1/07-api-and-errors',
    '/spec/v1/vectors',
    '/spec/v1/01-conventions.md',
  ]

  for (const path of [...baselinePaths, ...specPaths]) {
    await requireOk(path)
  }

  const overviewHtml = await (await requireOk('/spec/v1')).text()
  assert.match(overviewHtml, /310ace858172b6f4acdd982ef25c2441f20d6b7a/)
  assert.match(overviewHtml, /href="#main-content"[^>]*>Skip to main content/)
  assert.match(overviewHtml, /href="\/spec\/v1\/01-conventions"/)
  assert.doesNotMatch(overviewHtml, /href="01-conventions\.md"/)

  const receiptsHtml = await (await requireOk('/spec/v1/05-receipts')).text()
  assert.match(receiptsHtml, /href="\/spec\/v1\/02-canonical-cbor"/)
  assert.doesNotMatch(receiptsHtml, /href="02-canonical-cbor"/)

  const publishHtml = await (await requireOk('/publish')).text()
  assert.match(publishHtml, /Both verification paths are currently disabled/)
  assert.match(publishHtml, /Declarations are intentionally closed/)
  assert.match(publishHtml, /POST \/v0\/publishers\/declare/)
  assert.match(publishHtml, /fingerprint:8f2a…c0/)
  assert.doesNotMatch(publishHtml, /rcx-registry-challenge=/)
  assert.doesNotMatch(publishHtml, /Start onboarding/)
  assert.doesNotMatch(publishHtml, /curl -X POST[^<]*\/v0\/publishers\/declare/)

  const openApi = await (await requireOk('/openapi.json')).json()
  assert.equal(openApi.paths['/v0/publishers/declare'], undefined)
  assert.equal(openApi.paths['/v0/publisher-rights/manual-verify'], undefined)
  for (const [path, method] of [
    ['/v0/publisher-rights/dns-challenge', 'post'],
    ['/v0/publisher-rights/dns-verify', 'post'],
    ['/v0/publisher-rights/github/start', 'get'],
    ['/v0/publisher-rights/github/callback', 'get'],
  ]) {
    const operation = openApi.paths[path][method]
    assert.equal(operation.deprecated, true)
    assert.deepEqual(Object.keys(operation.responses), ['404'])
  }
  assert.equal(openApi.components.schemas.DnsVerifyRequest, undefined)
  assert.ok(openApi.components.schemas.ServerEnvelope.properties.server)

  const vectorIndex = await requireOk('/spec/v1/vectors')
  assert.doesNotMatch(vectorIndex.headers.get('cache-control') ?? '', /immutable/)

  await requireRedirect('/spec/v1/readme', '/spec/v1')
  await requireRedirect('/spec/v1/vectors/readme', '/spec/v1/vectors')
  await requireRedirect('/spec/v1/vectors/README.md', '/spec/v1/vectors')
  await requireNotFound('/spec/v1/not-a-real-chapter')
  await requireNotFound('/spec/v1/reimpl/spec-v1')

  const vectorNames = [
    'canonical-cbor.json',
    'canonical-json.json',
    'chains.json',
    'hashes.json',
    'receipts.json',
    'snapshot-merkle.json',
  ]

  for (const name of vectorNames) {
    const response = await requireOk(`/spec/v1/vectors/${name}`)
    const cacheControl = response.headers.get('cache-control') ?? ''
    assert.match(cacheControl, /max-age=31536000/)
    assert.match(cacheControl, /immutable/)
    assert.equal(response.headers.get('access-control-allow-origin'), '*')
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff')

    const served = Buffer.from(await response.arrayBuffer())
    const source = await readFile(new URL(`../../spec/v1/vectors/${name}`, import.meta.url))
    assert.ok(served.equals(source), `${name} differs from repository source`)
  }

  const sitemap = await (await requireOk('/sitemap.xml')).text()
  assert.match(sitemap, /https:\/\/rcxprotocol\.org\/spec\/v1\/vectors/)

  const llms = await (await requireOk('/llms.txt')).text()
  assert.match(llms, /https:\/\/rcxprotocol\.org\/spec\/v1/)
  assert.match(llms, /all return 404 at the production edge/)

  const browser = await chromium.launch({ headless: true })
  try {
    const page = await browser.newPage()

    async function assertSpecState(path, heading, activeLabel) {
      await page.waitForFunction(
        ({ heading, canonical, activeLabel }) => {
          const currentHeading = document.querySelector('#spec-content h1')?.textContent?.trim()
          const currentCanonical = document.querySelector('link[rel="canonical"]')?.getAttribute('href')
          const currentActive = document.querySelector('nav[aria-label="Specification chapters"] [aria-current="page"]')?.textContent?.trim()
          return currentHeading === heading && currentCanonical === canonical && currentActive === activeLabel
        },
        { heading, canonical: `https://rcxprotocol.org${path}`, activeLabel },
        { timeout: 5_000 },
      )
    }

    await page.goto(`${origin}/spec/v1`)
    await assertSpecState('/spec/v1', 'RCX Protocol Specification — rcx-spec/v1', 'Overview')

    await page.getByRole('link', { name: '2. Canonical CBOR', exact: true }).click()
    await page.waitForURL('**/spec/v1/02-canonical-cbor')
    await assertSpecState('/spec/v1/02-canonical-cbor', '2. Canonical CBOR', '2. Canonical CBOR')

    await page.getByRole('link', { name: 'Conformance vectors', exact: true }).click()
    await page.waitForURL('**/spec/v1/vectors')
    await assertSpecState('/spec/v1/vectors', 'RCX Protocol Spec v1 conformance vectors', 'Conformance vectors')
  } finally {
    await browser.close()
  }
} finally {
  if (server.exitCode === null) server.kill('SIGTERM')
  await Promise.race([
    new Promise((resolve) => server.once('exit', resolve)),
    delay(5_000),
  ])
}
