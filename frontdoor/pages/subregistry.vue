<script setup lang="ts">
const api = useRuntimeConfig().public.registryApiUrl

useHead({
  title: 'Subregistry · RCX-Registry',
  meta: [
    {
      name: 'description',
      content:
        'RCX-Registry is a spec-compliant MCP subregistry: a baseline /v0 read API shape-compatible with upstream, a documented _meta.org.rcxprotocol.registry namespace, and a swappable registry URL for clients like VS Code.',
    },
  ],
})

const metaExample = `{
  "server": {
    "name": "io.example.com/my-mcp-server",
    "version": "1.4.0"
  },
  "_meta": {
    "io.modelcontextprotocol.registry/official": {
      "status": "active",
      "isLatest": true
    },
    "org.rcxprotocol.registry/publisher": {
      "publisher_rights_verified": true,
      "verification_method": "dns_txt",
      "enrichment_receipt_hash": "blake3:8802…6f11"
    }
  }
}`

const vscodePolicy = `// VS Code enterprise policy (device management)
// Repoints the whole MCP gallery at a compatible registry read API.
{
  "McpGalleryServiceUrl": "${api}"
}`

const routes = [
  { r: 'GET /v0/servers', d: 'List servers — cursor pagination, limit' },
  { r: 'GET /v0/servers/{name}/versions', d: 'List versions for a server' },
  { r: 'GET /v0/servers/{name}/versions/{version}', d: 'Fetch one version' },
]
</script>

<template>
  <div>
    <!-- hero -->
    <section class="aurora-hero">
      <div class="relative mx-auto max-w-6xl px-5 pt-16 pb-14">
        <p class="eyebrow"><span class="led" aria-hidden="true"></span> Positioning</p>
        <h1 class="display-h1 text-ink mt-5 mb-4 max-w-[17ch]">
          A drop-in <span class="grad-span">subregistry.</span>
        </h1>
        <p class="text-lg text-ink2 max-w-[64ch] mb-9">
          The MCP registry documents an open subregistry model: implement the read shape, add value
          through custom <span class="font-mono text-acc">_meta</span> fields, no approval step.
          RCX-Registry preserves that envelope and reserves an RCX metadata namespace. The live
          mirror read dataset works today. Snapshot/signing sync is degraded, and publisher
          extensions remain gated until authenticated proof, signed-artifact persistence, and
          public receipt verification ship.
        </p>
        <div class="flex flex-wrap gap-3">
          <a :href="`${api}/v0/servers?limit=5`" class="btn btn-quiet">Try /v0/servers ↗</a>
          <a href="/openapi.json" class="btn btn-quiet">OpenAPI spec ↗</a>
        </div>
      </div>
    </section>

    <!-- shape-compatible -->
    <section class="mx-auto max-w-6xl px-5 mt-20" aria-labelledby="shape-h">
      <p class="sec-label">Shape-compatible</p>
      <h2 id="shape-h" class="display-h2 text-ink mb-3">Your existing clients work unchanged</h2>
      <p class="text-ink2 max-w-[70ch] mb-7">
        The baseline read API mirrors the upstream <span class="font-mono text-acc">/v0</span>
        surface field-for-field. Anything that already speaks to the official MCP registry speaks to
        this one. Optional RCX metadata appears inside the existing envelope only when its producing
        pipeline has supplied it.
      </p>
      <div class="glass-card overflow-hidden">
        <table class="w-full text-sm">
          <tbody>
            <tr v-for="(row, i) in routes" :key="row.r" :class="{ 'border-t border-edge': i > 0 }">
              <td class="p-4 font-mono text-[12.5px] text-acc align-top whitespace-nowrap">{{ row.r }}</td>
              <td class="p-4 text-ink2">{{ row.d }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- the _meta contract -->
    <section class="mx-auto max-w-6xl px-5 mt-24" aria-labelledby="meta-h">
      <p class="sec-label">The namespace contract</p>
      <h2 id="meta-h" class="display-h2 text-ink mb-3">Everything RCX adds lives under one <span class="font-mono">_meta</span> key</h2>
      <p class="text-ink2 max-w-[70ch] mb-5">
        Subregistries extend server entries through <span class="font-mono text-acc">_meta</span>, and
        RCX keeps its entire footprint inside
        <span class="font-mono text-acc">org.rcxprotocol.registry</span>. A client that ignores it
        sees a plain upstream entry; a client that reads it can consume extensions when present.
      </p>
      <div class="max-w-2xl mb-6">
        <MonoBlock :code="metaExample" label="extension shape (when present)" />
      </div>
      <div class="grid gap-4 sm:grid-cols-2">
        <article class="glass-card p-6">
          <p class="font-mono text-[12px] text-trust mb-2">…/publisher</p>
          <p class="text-sm text-ink2">
            Publisher-declared capability metadata plus verification method and enrichment receipt
            hash. Public writes to this block are disabled until caller authentication and signing
            are complete.
          </p>
        </article>
        <article class="glass-card p-6">
          <p class="font-mono text-[12px] text-trust mb-2">…/auto</p>
          <p class="text-sm text-ink2">
            Registry-derived enrichment fields and their receipt hash. This is additive metadata;
            a mirrored entry need not carry the block.
          </p>
        </article>
      </div>
    </section>

    <!-- point a client -->
    <section class="mx-auto max-w-6xl px-5 mt-24" aria-labelledby="point-h">
      <p class="sec-label">Point a client here</p>
      <h2 id="point-h" class="display-h2 text-ink mb-3">VS Code, by policy</h2>
      <p class="text-ink2 max-w-[70ch] mb-5">
        VS Code exposes an enterprise policy,
        <span class="font-mono text-acc">McpGalleryServiceUrl</span>, that repoints its entire MCP
        gallery at any spec-compliant endpoint. Because our <span class="font-mono">/v0</span> matches
        the shape, this works today — one policy value moves a whole fleet onto a compatible read API.
      </p>
      <div class="max-w-2xl mb-4">
        <MonoBlock :code="vscodePolicy" label="VS Code policy" />
      </div>
      <p class="text-sm text-ink3 max-w-[70ch]">
        Any client that lets you configure the registry base URL points here the same way. And
        because there is a self-contained <a href="/openapi.json" class="underline">/openapi.json</a>,
        OpenAPI-to-MCP tooling can wrap the registry itself as a server — one more surface, no extra
        work from us.
      </p>
    </section>

    <!-- configured sync model -->
    <section class="mx-auto max-w-6xl px-5 mt-24" aria-labelledby="sync-h">
      <p class="sec-label">Freshness</p>
      <h2 id="sync-h" class="display-h2 text-ink mb-3">Configured sync model</h2>
      <p class="mb-7 max-w-[72ch] text-ink2">
        Production serves the mirrored dataset, but its sync attempt currently fails when Vault
        Transit returns 403. The snapshot table is empty, so there is no live signed snapshot evidence.
      </p>
      <div class="grid gap-4 sm:grid-cols-3">
        <article class="glass-card p-6">
          <h3 class="font-display font-bold text-ink mb-2">Mirror</h3>
          <p class="text-sm text-ink2">
            The configured loop is designed to walk every upstream page and mint a signed snapshot
            over the flat, sorted BLAKE3 set digest named
            <span class="font-mono">snapshot_merkle_root</span>. It is not completing in production.
          </p>
        </article>
        <article class="glass-card p-6">
          <h3 class="font-display font-bold text-ink mb-2">Soft-delete</h3>
          <p class="text-sm text-ink2">
            When a server disappears upstream it is soft-deleted with a 30-day retention window — a
            removal is recorded, never a silent gap.
          </p>
        </article>
        <article class="glass-card p-6">
          <h3 class="font-display font-bold text-ink mb-2">Enrichment</h3>
          <p class="text-sm text-ink2">
            The implementation can refresh already-seeded declarations on a 24-hour cadence, but
            no public declaration route is available and complete signed artifacts are not persisted
            or returned by the public API.
          </p>
        </article>
      </div>
    </section>

    <!-- closing -->
    <section class="mx-auto max-w-6xl px-5 mt-24 mb-24">
      <div class="glass-panel px-8 py-12 sm:px-12 text-center">
        <h2 class="display-h2 text-ink mb-4">Same servers. Same shape. Now with attributable metadata.</h2>
        <p class="text-ink2 max-w-[56ch] mx-auto mb-8">
          Repoint a client for mirror reads. Publisher verification remains closed pending trust hardening.
        </p>
        <div class="flex flex-wrap justify-center gap-3">
          <a :href="`${api}/v0/servers?limit=5`" class="btn btn-approve">Browse the API ↗</a>
          <NuxtLink to="/publish" class="btn btn-quiet">Publisher status</NuxtLink>
        </div>
      </div>
    </section>
  </div>
</template>
