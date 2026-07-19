<script setup lang="ts">
const api = useRuntimeConfig().public.registryApiUrl

useHead({
  title: 'Publish · RCX-Registry',
  meta: [
    {
      name: 'description',
      content:
        'Claim your MCP namespace on RCX-Registry by DNS TXT or GitHub OAuth, then declare RCX capability metadata for your servers. Verified publishers get a receipted history and a badge.',
    },
  ],
})

const txtRecord = `_rcx-registry.example.com.  IN  TXT  "rcx-registry-challenge=8f2a…c0"`

const declareCurl = `curl -X POST '${api}/v0/publishers/declare' \\
  -H 'authorization: Bearer <publisher-passport>' \\
  -H 'content-type: application/json' \\
  -d @declaration.json`
</script>

<template>
  <div>
    <!-- hero -->
    <section class="aurora-hero">
      <div class="relative mx-auto max-w-6xl px-5 pt-16 pb-14">
        <p class="eyebrow"><span class="led" aria-hidden="true"></span> Publisher onboarding</p>
        <h1 class="display-h1 text-ink mt-5 mb-4 max-w-[16ch]">
          Claim your <span class="grad-span">namespace.</span>
        </h1>
        <p class="text-lg text-ink2 max-w-[60ch] mb-9">
          Your servers are already mirrored here. Prove you control the namespace and you can enrich
          them with RCX capability metadata, earn a receipted history, and add the verified badge to
          your README. Two ways to prove it — pick whichever fits your namespace.
        </p>
        <div class="flex flex-wrap gap-3">
          <a :href="`${api}/publish`" class="btn btn-approve">Start onboarding ↗</a>
          <NuxtLink to="/badge" class="btn btn-quiet">See the badge</NuxtLink>
        </div>
      </div>
    </section>

    <!-- two paths -->
    <section class="mx-auto max-w-6xl px-5 mt-20" aria-labelledby="paths-h">
      <p class="sec-label">Prove control</p>
      <h2 id="paths-h" class="display-h2 text-ink mb-7">Two verification paths</h2>
      <div class="grid gap-4 lg:grid-cols-2">
        <!-- DNS -->
        <article class="glass-card p-7 flex flex-col">
          <span class="topchip mb-4"><span class="led" aria-hidden="true"></span> DNS TXT</span>
          <h3 class="font-display font-bold text-ink text-lg mb-2">Domain namespaces</h3>
          <p class="text-sm text-ink2 mb-4">
            For namespaces rooted in a domain you control (for example
            <span class="font-mono text-acc">com.example.*</span>). Start a challenge, publish one TXT
            record, verify.
          </p>
          <ol class="text-sm text-ink2 space-y-2 mb-4 list-decimal pl-5">
            <li>
              <span class="font-mono text-[12.5px]">POST /v0/publisher-rights/dns-challenge</span> —
              get a one-time token.
            </li>
            <li>Publish it under <span class="font-mono text-[12.5px]">_rcx-registry.&lt;domain&gt;</span>:</li>
          </ol>
          <div class="mb-4">
            <MonoBlock :code="txtRecord" label="DNS TXT record" />
          </div>
          <p class="text-sm text-ink2 mt-auto">
            Then <span class="font-mono text-[12.5px]">POST /v0/publisher-rights/dns-verify</span> and
            the registry resolves the record and mints a rights-verification receipt.
          </p>
        </article>

        <!-- GitHub -->
        <article class="glass-card p-7 flex flex-col">
          <span class="topchip mb-4"><span class="led" aria-hidden="true"></span> GitHub OAuth</span>
          <h3 class="font-display font-bold text-ink text-lg mb-2">io.github.* namespaces</h3>
          <p class="text-sm text-ink2 mb-4">
            For servers published under a GitHub org or user
            (<span class="font-mono text-acc">io.github.you.*</span>). No DNS needed — authorise once
            and the registry maps your GitHub identity to the namespace.
          </p>
          <ol class="text-sm text-ink2 space-y-2 mb-4 list-decimal pl-5">
            <li><span class="font-mono text-[12.5px]">GET /v0/publisher-rights/github/start</span> — begin the OAuth flow.</li>
            <li>Authorise the RCX-Registry app on GitHub.</li>
            <li>The <span class="font-mono text-[12.5px]">/callback</span> confirms ownership and records a receipt.</li>
          </ol>
          <p class="text-sm text-ink3 mt-auto">
            Namespaces that fit neither path can go through operator-mediated manual review
            (<span class="font-mono text-[12.5px]">/v0/publisher-rights/manual-verify</span>).
          </p>
        </article>
      </div>
    </section>

    <!-- declare -->
    <section class="mx-auto max-w-6xl px-5 mt-24" aria-labelledby="declare-h">
      <p class="sec-label">After you’re verified</p>
      <h2 id="declare-h" class="display-h2 text-ink mb-3">Declare your capability metadata</h2>
      <p class="text-ink2 max-w-[68ch] mb-5">
        A verified publisher submits a schema-validated RCX enrichment declaration. It’s hashed,
        refreshed on a 24-hour cadence, and surfaced to clients under
        <span class="font-mono text-acc">_meta.org.rcxprotocol.registry/publisher</span> — so what
        clients see about your server comes from you, attributably, not from a scraper.
      </p>
      <div class="max-w-3xl mb-4">
        <MonoBlock :code="declareCurl" label="declare enrichment" />
      </div>
      <p class="text-sm text-ink3 max-w-[68ch]">
        Every declaration, like every rights verification, is a signed CROWN receipt — your history
        on the registry is itself verifiable. Declaration schema:
        <span class="font-mono text-acc">static.rcxprotocol.org/schemas/…/rcx-enrichment</span>.
      </p>
    </section>

    <!-- closing -->
    <section class="mx-auto max-w-6xl px-5 mt-24 mb-24">
      <div class="glass-panel px-8 py-12 sm:px-12 text-center">
        <h2 class="display-h2 text-ink mb-4">Your namespace is already mirrored. Claim it.</h2>
        <p class="text-ink2 max-w-[54ch] mx-auto mb-8">
          Onboarding runs on the registry host. Verification takes minutes; the receipted history and
          the badge are yours for free.
        </p>
        <div class="flex flex-wrap justify-center gap-3">
          <a :href="`${api}/publish`" class="btn btn-approve">Start onboarding ↗</a>
          <NuxtLink to="/verify" class="btn btn-quiet">How verification works</NuxtLink>
        </div>
      </div>
    </section>
  </div>
</template>
