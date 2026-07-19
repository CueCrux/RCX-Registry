<script setup lang="ts">
const api = useRuntimeConfig().public.registryApiUrl

useHead({
  title: 'Verify · RCX-Registry',
  meta: [
    {
      name: 'description',
      content:
        'How RCX-Registry proves its history: canonical hashing, a Merkle root per snapshot, ed25519 signatures via Vault Transit, and a hash-chain you can replay yourself.',
    },
  ],
})

const receiptShape = `{
  "kind": "RegistrySnapshot",
  "id": "crown:e6b1…88f2",
  "merkle_root": "b3:9f4c…e21a",
  "server_count": 17439,
  "prev": "crown:8802…6f11",
  "signer_kid": "rcx-registry-2026-04",
  "alg": "ed25519",
  "sig": "base64…"
}`

const verifyCode = `# 1. pull the mirrored set + snapshot metadata
curl -s '${api}/v0/servers?limit=100&cursor=...' > page.json

# 2. canonicalise each server envelope, BLAKE3-hash it
# 3. rebuild the Merkle root over the full set
# 4. compare it to merkle_root in the signed snapshot receipt
# 5. verify sig against the published signer key (signer_kid)
# 6. walk prev -> prev back through the chain; any break = tamper`

const steps = [
  {
    n: '01',
    title: 'Canonical form, then hash',
    body:
      'Every server envelope is serialised to a canonical CBOR/JSON form and hashed with BLAKE3. Canonicalisation means two parties that hold the same data compute the same hash — no ambiguity about whitespace or field order.',
  },
  {
    n: '02',
    title: 'A Merkle root per snapshot',
    body:
      'Each sync builds a Merkle tree over the full canonical set and signs the root. One root commits to every server in that snapshot at once: change any single entry and the root changes.',
  },
  {
    n: '03',
    title: 'Signed via Vault Transit',
    body:
      'The root is signed ed25519 with a key that never leaves Vault Transit. The signature binds the receipt id and the payload hash together, so a receipt cannot be edited in place or moved onto a different snapshot.',
  },
  {
    n: '04',
    title: 'Chained, so history is append-only',
    body:
      'Each receipt carries the id of the one before it. That turns individual signatures into a spine: to forge one record you would have to re-sign every record after it, which you cannot do without the Vault key.',
  },
]
</script>

<template>
  <div>
    <!-- hero -->
    <section class="aurora-hero">
      <div class="relative mx-auto max-w-6xl px-5 pt-16 pb-14">
        <p class="eyebrow"><span class="led" aria-hidden="true"></span> Verification model</p>
        <h1 class="display-h1 text-ink mt-5 mb-4 max-w-[15ch]">
          Don’t trust. <span class="grad-span">Verify.</span>
        </h1>
        <p class="text-lg text-ink2 max-w-[62ch] mb-9">
          A registry that asks for trust is just another database. RCX-Registry publishes the proof
          instead: signed, hash-chained receipts over the whole set, reproducible from open-source
          code and public schemas. Here is exactly what that means — and how to check it.
        </p>
        <div class="flex flex-wrap gap-3">
          <a href="https://github.com/CueCrux/RCX-Registry" class="btn btn-quiet">Read the source ↗</a>
          <NuxtLink to="/subregistry" class="btn btn-quiet">Point a client here</NuxtLink>
        </div>
      </div>
    </section>

    <!-- interactive chain -->
    <section class="mx-auto max-w-6xl px-5 mt-20" aria-labelledby="chain-h">
      <p class="sec-label">The chain, interactive</p>
      <h2 id="chain-h" class="display-h2 text-ink mb-3">One flipped byte, and the chain says so</h2>
      <p class="text-ink2 max-w-[68ch] mb-7">
        Four receipts on a sealed spine — a snapshot, a rights verification, a publisher declaration,
        another snapshot. Flip one byte and verification pinpoints the exact record that broke.
      </p>
      <DiagramReceiptChain />
    </section>

    <!-- the model -->
    <section class="mx-auto max-w-6xl px-5 mt-24" aria-labelledby="model-h">
      <p class="sec-label">The model</p>
      <h2 id="model-h" class="display-h2 text-ink mb-7">Four properties, each one checkable</h2>
      <div class="grid gap-4 sm:grid-cols-2">
        <article v-for="s in steps" :key="s.n" class="glass-card p-6">
          <p class="font-mono text-[12px] text-acc mb-2">{{ s.n }}</p>
          <h3 class="font-display font-bold text-ink text-lg mb-2">{{ s.title }}</h3>
          <p class="text-sm text-ink2">{{ s.body }}</p>
        </article>
      </div>
    </section>

    <!-- verify it yourself -->
    <section class="mx-auto max-w-6xl px-5 mt-24" aria-labelledby="diy-h">
      <p class="sec-label">Verify it yourself</p>
      <h2 id="diy-h" class="display-h2 text-ink mb-3">The shape of a snapshot receipt</h2>
      <p class="text-ink2 max-w-[68ch] mb-5">
        A snapshot receipt commits to the whole mirrored set through its Merkle root, names the
        signer, and points at the previous receipt. Nothing here is secret — that is the point.
      </p>
      <div class="max-w-2xl mb-8">
        <MonoBlock :code="receiptShape" label="snapshot receipt shape" />
      </div>

      <h3 class="display-h2 text-ink mb-3" style="font-size: clamp(22px, 2.6vw, 28px)">
        Recompute it from public data
      </h3>
      <p class="text-ink2 max-w-[68ch] mb-5">
        Because the mirror API is public and the receipt schemas are published at
        <span class="font-mono text-acc">static.rcxprotocol.org</span>, verification is reproducible.
        The steps:
      </p>
      <div class="max-w-3xl">
        <MonoBlock :code="verifyCode" label="verification steps" />
      </div>
      <p class="text-sm text-ink3 max-w-[68ch] mt-4">
        The canonicalisation, hashing, and signature-verification logic lives in the
        <span class="font-mono">rcx-registry-crown</span> crate — Apache-2.0, so you can run the same
        checks the registry runs.
      </p>
    </section>

    <!-- closing -->
    <section class="mx-auto max-w-6xl px-5 mt-24 mb-24">
      <div class="glass-panel px-8 py-12 sm:px-12 text-center">
        <h2 class="display-h2 text-ink mb-4">Verification is a feature, not a promise.</h2>
        <p class="text-ink2 max-w-[56ch] mx-auto mb-8">
          Publishers who claim a namespace get their own receipted history — and a badge that links
          straight to it.
        </p>
        <div class="flex flex-wrap justify-center gap-3">
          <NuxtLink to="/publish" class="btn btn-approve">Claim your namespace</NuxtLink>
          <NuxtLink to="/badge" class="btn btn-quiet">Get the badge</NuxtLink>
        </div>
      </div>
    </section>
  </div>
</template>
