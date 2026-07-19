<script setup lang="ts">
const api = useRuntimeConfig().public.registryApiUrl
const site = useRuntimeConfig().public.siteUrl

useHead({
  title: 'RCX-Registry: verifiable, MCP-compatible discovery',
  meta: [
    {
      name: 'description',
      content:
        'RCX-Registry mirrors the official MCP registry and makes its history tamper-evident: ~17,439 servers, every state change a signed CROWN receipt, publishers verified by DNS or GitHub. Shape-compatible with your existing MCP clients.',
    },
  ],
  script: [
    {
      type: 'application/ld+json',
      innerHTML: JSON.stringify({
        '@context': 'https://schema.org',
        '@type': 'Organization',
        name: 'RCX-Registry',
        url: site,
        description:
          'A verifiable, MCP-compatible subregistry that mirrors the official MCP registry and records every state change as a signed, hash-chained CROWN receipt.',
        sameAs: ['https://github.com/CueCrux/RCX-Registry'],
      }),
    },
    {
      type: 'application/ld+json',
      innerHTML: JSON.stringify({
        '@context': 'https://schema.org',
        '@type': 'DataCatalog',
        name: 'RCX-Registry',
        description:
          'A verifiable mirror of the official Model Context Protocol server registry. Baseline read API is shape-compatible with the upstream /v0 surface; every mutation is an ed25519-signed CROWN receipt.',
        url: api,
        isBasedOn: 'https://registry.modelcontextprotocol.io',
        provider: { '@type': 'Organization', name: 'RCX-Registry', url: site },
        license: 'https://www.apache.org/licenses/LICENSE-2.0',
      }),
    },
  ],
})

// Live-stats strip. SSR renders the templated baseline (~17,439, the one figure
// we're allowed to state); on the client we OPTIONALLY upgrade the mirror count
// from the registry's own API. Fails silently so the page never depends on the
// registry being reachable.
const serverCount = ref<string>('~17,439')
const live = ref(false)
onMounted(async () => {
  try {
    const res = await fetch(`${api}/v0/servers?limit=1`, { headers: { accept: 'application/json' } })
    if (!res.ok) return
    const body = await res.json()
    const n = body?.metadata?.count ?? body?.metadata?.total
    if (typeof n === 'number' && n > 0) {
      serverCount.value = n.toLocaleString('en-US')
      live.value = true
    }
  } catch {
    // registry unreachable / CORS — keep the templated baseline
  }
})

const pillars = [
  {
    title: 'Mirror',
    chip: 'GET /v0/servers',
    body:
      'A sync loop walks every page of the upstream MCP registry on a fixed cadence and canonicalises each server. The baseline read API is shape-compatible with upstream /v0, so your existing MCP clients point at it and work unchanged.',
  },
  {
    title: 'Verify',
    chip: '_rcx-registry.<domain>',
    body:
      'Publishers prove control of their namespace — DNS TXT challenge, or GitHub OAuth for io.github.* — then declare RCX capability metadata for their servers, surfaced to clients under _meta.org.rcxprotocol.registry.',
  },
  {
    title: 'Receipt',
    chip: 'crown:… · ed25519',
    body:
      'Every state change — a snapshot, an enrichment, a rights verification — is an ed25519-signed, hash-chained CROWN receipt minted via Vault Transit. The registry’s entire history is independently verifiable, not merely trusted.',
  },
]

// Real 2025–26 MCP supply-chain incidents. The "why" behind tamper-evidence.
const incidents = [
  {
    tag: 'postmark-mcp · Sept 2025',
    body:
      'An npm-published MCP server ran clean for 15 versions, then shipped an update that BCC’d every email it handled to the author’s server. ~300 organisations pulled it before disclosure. A rug-pull that per-version receipts and history diffing would have surfaced.',
  },
  {
    tag: 'CVE-2025-54136 · "MCP rug pull"',
    body:
      'A tool definition was mutated after a client had already approved it — the classic bait-and-switch. Approval at publish time says nothing about what the server does next.',
  },
  {
    tag: 'CVE-2025-6514 · mcp-remote',
    body:
      'Command injection in a connector with ~437,000 downloads. Distribution scale is exactly why a verifiable chain of custody matters: one bad version reaches a lot of machines fast.',
  },
  {
    tag: 'MCPTox · poisoned tool descriptions',
    body:
      'Adversarial instructions hidden in tool descriptions reached a 72.8% success rate against agents. What a server advertises is attacker-controlled text — it should be attributable to a verified publisher.',
  },
  {
    tag: 'Microsoft advisory · June 2026',
    body:
      'An estimated ~200,000 vulnerable MCP instances in the wild. The ecosystem grew faster than its trust story. Namespace ownership is solved; tamper-evident history is not.',
  },
]
</script>

<template>
  <div>
    <!-- ================= aurora hero ================= -->
    <section class="aurora-hero">
      <div class="relative mx-auto max-w-6xl px-5 pt-16 pb-14 sm:pt-20 sm:pb-16">
        <div class="grid items-center gap-10 lg:grid-cols-[1.08fr_0.92fr] lg:gap-8">
          <div>
            <p class="eyebrow">
              <span class="led" aria-hidden="true"></span>
              RCX-Registry · verifiable MCP subregistry
            </p>

            <h1 class="display-h1 text-ink mt-5 mb-4 max-w-[18ch]">
              Verifiable discovery <span class="grad-span">for MCP.</span>
            </h1>

            <p class="text-lg text-ink2 max-w-[60ch] mb-9">
              A tamper-evident mirror of the official MCP registry. Every server the upstream
              registry lists, plus proof: verified publishers, and a signed, hash-chained history
              you can replay yourself. Drop-in shape-compatible with the clients you already run.
            </p>

            <div class="flex flex-wrap gap-3">
              <NuxtLink to="/publish" class="btn btn-approve">Claim your namespace</NuxtLink>
              <a :href="`${api}/v0/servers?limit=5`" class="btn btn-quiet">Browse the registry API ↗</a>
            </div>
          </div>

          <!-- illustrative latest-snapshot receipt card -->
          <div class="relative mx-auto w-full max-w-md lg:max-w-none">
            <div class="glass-panel p-6 font-mono text-[12.5px] text-ink2">
              <div class="flex items-center justify-between mb-4">
                <span class="topchip"><span class="led" aria-hidden="true"></span> registry.snapshot</span>
                <span class="text-ink3">cadence · hourly</span>
              </div>
              <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2">
                <dt class="text-ink3">servers</dt>
                <dd class="text-ink">{{ serverCount }}</dd>
                <dt class="text-ink3">merkle_root</dt>
                <dd class="text-acc truncate">b3:9f4c…e21a</dd>
                <dt class="text-ink3">signer</dt>
                <dd class="text-trust truncate">vault-transit · ed25519</dd>
                <dt class="text-ink3">prev</dt>
                <dd class="text-ink2 truncate">crown:8802…6f11</dd>
              </dl>
              <p class="mt-4 pt-3 border-t border-edge" style="color: var(--ok)">
                ✓ signed · chain intact
              </p>
            </div>
            <p class="mt-2 text-[11px] text-ink3 font-mono">illustrative — shape of a snapshot receipt</p>
          </div>
        </div>
      </div>
    </section>

    <!-- ================= live-stats strip ================= -->
    <section class="mx-auto max-w-6xl px-5 mt-14">
      <div class="grid gap-4 sm:grid-cols-3">
        <div class="glass-card p-5">
          <p class="font-display text-2xl font-bold text-ink">
            {{ serverCount }}
            <span v-if="live" class="align-middle text-[11px] font-mono text-ok">· live</span>
          </p>
          <p class="text-sm text-ink2 mt-1">servers mirrored from the upstream MCP registry</p>
        </div>
        <div class="glass-card p-5">
          <p class="font-display text-2xl font-bold text-ink">every change</p>
          <p class="text-sm text-ink2 mt-1">a signed, hash-chained CROWN receipt — replayable end to end</p>
        </div>
        <div class="glass-card p-5">
          <p class="font-display text-2xl font-bold text-ink">DNS · GitHub</p>
          <p class="text-sm text-ink2 mt-1">two ways for a publisher to prove they own their namespace</p>
        </div>
      </div>
    </section>

    <!-- ================= three pillars ================= -->
    <section class="mx-auto max-w-6xl scroll-mt-24 px-5 mt-24" aria-labelledby="pillars-h">
      <p class="sec-label">How it works</p>
      <h2 id="pillars-h" class="display-h2 text-ink mb-3">Mirror. Verify. Receipt.</h2>
      <p class="text-ink2 max-w-[68ch] mb-7">
        A discovery surface existing clients can use unchanged, a way for publishers to prove who
        they are, and a signed history so nobody has to take the registry’s word for it.
      </p>
      <div class="grid gap-4 sm:grid-cols-3">
        <article v-for="p in pillars" :key="p.title" class="glass-card flex flex-col p-6">
          <span class="topchip mb-4"><span class="led" aria-hidden="true"></span>{{ p.chip }}</span>
          <h3 class="font-display font-bold text-ink text-lg mt-4 mb-2">{{ p.title }}</h3>
          <p class="text-sm text-ink2">{{ p.body }}</p>
        </article>
      </div>
    </section>

    <!-- ================= why this exists (incident-led) ================= -->
    <section class="mx-auto max-w-6xl scroll-mt-24 px-5 mt-24" aria-labelledby="why-h">
      <p class="sec-label">Why this exists</p>
      <h2 id="why-h" class="display-h2 text-ink mb-3">Namespace ownership is solved. History isn’t.</h2>
      <p class="text-ink2 max-w-[72ch] mb-8">
        MCP registries verify who a publisher is at the moment they publish. Nothing about that makes
        the registry’s <em>history</em> tamper-evident, and nothing catches a server that turns
        malicious after it was approved. The last year of incidents is that gap, over and over:
      </p>

      <ul class="grid gap-3">
        <li v-for="inc in incidents" :key="inc.tag">
          <article class="glass-card p-5">
            <p class="font-mono text-[12px] text-crit mb-2">{{ inc.tag }}</p>
            <p class="text-sm text-ink2">{{ inc.body }}</p>
          </article>
        </li>
      </ul>

      <div class="glass-panel px-6 py-6 mt-6">
        <p class="text-ink2 max-w-[74ch]">
          RCX-Registry’s job is the part the others skip: a signed, replayable chain of custody
          over the whole registry, so a rug-pull, a silent mutation, or a tampered record shows up as
          a broken chain — not a surprise in production.
          <NuxtLink to="/verify" class="text-[var(--acc)] underline">See how verification works →</NuxtLink>
        </p>
      </div>
    </section>

    <!-- ================= closing CTA ================= -->
    <section class="mx-auto max-w-6xl px-5 mt-24 mb-24" aria-labelledby="cta-h">
      <div class="glass-panel px-8 py-12 sm:px-12 text-center">
        <h2 id="cta-h" class="display-h2 text-ink mb-4">Point your clients at a registry that can prove itself.</h2>
        <p class="text-ink2 max-w-[58ch] mx-auto mb-8">
          The read API is shape-compatible with upstream, so switching is a URL change. Publishers
          claim a namespace in minutes and get a receipted history for free.
        </p>
        <div class="flex flex-wrap justify-center gap-3">
          <NuxtLink to="/subregistry" class="btn btn-approve">Point a client here</NuxtLink>
          <NuxtLink to="/publish" class="btn btn-quiet">Claim your namespace</NuxtLink>
        </div>
      </div>
    </section>
  </div>
</template>
