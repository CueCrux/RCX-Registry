<script setup lang="ts">
const api = useRuntimeConfig().public.registryApiUrl

useHead({
  title: 'Publish · RCX-Registry',
  meta: [
    {
      name: 'description',
      content:
        'Publisher onboarding status for RCX-Registry. All public verification and declaration writes currently fail closed while proof binding, audit time, OAuth state, and signing are hardened.',
    },
  ],
})

const txtRecord = `_rcx-registry.example.com.  IN  TXT  "fingerprint:8f2a…c0"`
</script>

<template>
  <div>
    <!-- hero -->
    <section class="aurora-hero">
      <div class="relative mx-auto max-w-6xl px-5 pt-16 pb-14">
        <p class="eyebrow"><span class="led" aria-hidden="true"></span> Publisher onboarding</p>
        <h1 class="display-h1 text-ink mt-5 mb-4 max-w-[16ch]">
          Publisher onboarding is <span class="grad-span">fail-closed.</span>
        </h1>
        <p class="text-lg text-ink2 max-w-[60ch] mb-9">
          The read API remains available, but every public publisher verification and declaration
          write currently returns 404. We will reopen onboarding only after identity binding,
          server-owned audit time, OAuth state, signing, and receipt retrieval pass review.
        </p>
        <div class="flex flex-wrap gap-3">
          <a :href="`${api}/v0/servers?limit=5`" class="btn btn-approve">Browse the read API ↗</a>
          <NuxtLink to="/verify" class="btn btn-quiet">Review the evidence boundary</NuxtLink>
        </div>
      </div>
    </section>

    <!-- two paths -->
    <section class="mx-auto max-w-6xl px-5 mt-20" aria-labelledby="paths-h">
      <p class="sec-label">Designed proof paths</p>
      <h2 id="paths-h" class="display-h2 text-ink mb-3">Both verification paths are currently disabled</h2>
      <p class="mb-7 max-w-[72ch] text-ink2">
        These cards document the intended contracts, not callable production workflows. The edge
        returns 404 until the trust-model gates below are implemented and accepted.
      </p>
      <div class="grid gap-4 lg:grid-cols-2">
        <!-- DNS -->
        <article class="glass-card p-7 flex flex-col">
          <span class="topchip mb-4"><span class="led led-warn" aria-hidden="true"></span> DNS TXT · disabled</span>
          <h3 class="font-display font-bold text-ink text-lg mb-2">Domain namespaces</h3>
          <p class="text-sm text-ink2 mb-4">
            The intended route covers a server named
            <span class="font-mono text-acc">io.example.com/my-server</span>. A reviewed replacement
            must bind the passport to the domain proof instead of trusting caller-supplied identifiers.
          </p>
          <ol class="text-sm text-ink2 space-y-2 mb-4 list-decimal pl-5">
            <li>
              <span class="font-mono text-[12.5px]">POST /v0/publisher-rights/dns-challenge</span> —
              return <span class="font-mono">record_name</span> and an
              <span class="font-mono">expected_value</span> exactly equal to the supplied passport fingerprint.
            </li>
            <li>Publish it under <span class="font-mono text-[12.5px]">_rcx-registry.&lt;domain&gt;</span>:</li>
          </ol>
          <div class="mb-4">
            <MonoBlock :code="txtRecord" label="DNS TXT record" />
          </div>
          <p class="text-sm text-ink2 mt-auto">
            The replacement verify route must resolve that exact value, derive audit time on the
            server, bind the proof to an authenticated passport, and persist a retrievable signed
            artifact. The current public challenge and verify routes both return 404.
          </p>
        </article>

        <!-- GitHub -->
        <article class="glass-card p-7 flex flex-col">
          <span class="topchip mb-4"><span class="led led-warn" aria-hidden="true"></span> GitHub OAuth · disabled</span>
          <h3 class="font-display font-bold text-ink text-lg mb-2">io.github.* namespaces</h3>
          <p class="text-sm text-ink2 mb-4">
            The routes are implemented but production OAuth credentials are unset. The reviewed
            replacement must also bind state to a server-side session and prove organization
            ownership instead of treating a user login as org control.
          </p>
          <ol class="text-sm text-ink2 space-y-2 mb-4 list-decimal pl-5">
            <li>Provision and rotate a production OAuth app through the approved custody path.</li>
            <li>Bind state, redirect URI, namespace, and publisher identity on the server.</li>
            <li>Verify user or organization ownership explicitly, then use server-owned audit time.</li>
          </ol>
          <p class="text-sm text-ink3 mt-auto">
            The public start and callback routes return 404 today. Manual review is also absent
            until an authenticated, passport-attributed operator surface ships.
          </p>
        </article>
      </div>
    </section>

    <!-- declarations -->
    <section class="mx-auto max-w-6xl px-5 mt-24" aria-labelledby="declare-h">
      <p class="sec-label">Fail-closed write surface</p>
      <h2 id="declare-h" class="display-h2 text-ink mb-3">Declarations are intentionally closed</h2>
      <p class="text-ink2 max-w-[68ch] mb-5">
        <span class="font-mono text-acc">POST /v0/publishers/declare</span> is disabled at the edge
        and absent from the application router. Namespace rights alone are not caller
        authentication: accepting a passport identifier in a JSON body would let another caller
        overwrite publisher metadata.
      </p>
      <p class="text-sm text-ink3 max-w-[68ch]">
        It will reopen only after the request proves control of the verified publisher identity,
        produces a real signature through the configured signer, and has public receipt/key
        retrieval. The schema and conformance vectors remain available for implementers meanwhile.
      </p>
    </section>

    <!-- closing -->
    <section class="mx-auto max-w-6xl px-5 mt-24 mb-24">
      <div class="glass-panel px-8 py-12 sm:px-12 text-center">
        <h2 class="display-h2 text-ink mb-4">Read access is live. Publisher writes remain closed.</h2>
        <p class="text-ink2 max-w-[54ch] mx-auto mb-8">
          Existing mirror reads continue normally. Do not publish a DNS record or begin OAuth yet;
          no production onboarding route will accept it until the replacement is reviewed and deployed.
        </p>
        <div class="flex flex-wrap justify-center gap-3">
          <a :href="`${api}/v0/servers?limit=5`" class="btn btn-approve">Browse the read API ↗</a>
          <NuxtLink to="/verify" class="btn btn-quiet">How verification works</NuxtLink>
        </div>
      </div>
    </section>
  </div>
</template>
