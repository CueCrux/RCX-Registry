<script setup lang="ts">
useHead({
  title: 'Verify · RCX-Registry',
  meta: [
    {
      name: 'description',
      content:
        'How the RCX-Registry v1 signed-receipt format works: canonical encodings, a flat BLAKE3 snapshot-set digest, exact link semantics, test vectors, and current production limits.',
    },
  ],
})

const receiptShape = `{
  "event_id": "11111111111111111111111111111111",
  "snapshot_id": "22222222222222222222222222222222",
  "scraped_at": 1784761200000,
  "server_count": 17439,
  "snapshot_merkle_root": "9f4c…e21a",
  "previous_snapshot_hash": "8802…6f11",
  "upstream_registry_uri": "https://registry.modelcontextprotocol.io/v0/servers",
  "upstream_snapshot_etag": null,
  "changes": { "added": 17439, "removed": 0, "modified": 0 },
  "receipt_hash": "4b2d…54d9",
  "receipt_signature": "e646…a004",
  "signer_kid": "vault:transit:rcx-registry-signing-key-1"
}`

const verifyCode = `# Download the normative, test-only corpus
curl -fsS 'https://rcxprotocol.org/spec/v1/vectors/receipts.json' -o receipts.json
curl -fsS 'https://rcxprotocol.org/spec/v1/vectors/snapshot-merkle.json' -o snapshots.json

# 1. reproduce each canonical-CBOR receipt byte string
# 2. recompute receipt_hash after zeroing exactly:
#    receipt_hash, receipt_signature, and signer_kid
# 3. verify ed25519 over full canonical CBOR with only
#    receipt_signature zeroed, using the vector's TEST public key
# 4. reproduce the flat snapshot-set digest byte-for-byte
# 5. compare every result with the checked-in expected hex`

const steps = [
  {
    n: '01',
    title: 'The canonical form is explicit',
    body:
      'Mirrored server objects use the canonical JSON rules in Spec §3. CROWN receipts use canonical CBOR from §2. The spec pins the exact form per artifact instead of treating CBOR and JSON as interchangeable.',
  },
  {
    n: '02',
    title: 'A flat set digest per snapshot',
    body:
      'The historical field name is snapshot_merkle_root, but v1 computes one sequential BLAKE3 stream over sorted entries. It is not a Merkle tree and provides no inclusion or consistency proofs.',
  },
  {
    n: '03',
    title: 'Hash and signature preimages are pinned',
    body:
      'receipt_hash zeros three fields; the ed25519 signature then covers full canonical CBOR with only receipt_signature zeroed. The production implementation is designed to use Vault Transit; the published vectors use an obvious test-only key.',
  },
  {
    n: '04',
    title: 'Link targets differ by receipt type',
    body:
      'RegistrySnapshot.previous_snapshot_hash points to the prior snapshot set digest. EntryEnriched.supersedes_prior points to the prior enrichment receipt_hash. v1 does not define one universal receipt spine.',
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
          RCX-Registry publishes a byte-exact wire specification and conformance vectors for signed
          receipts and snapshot history. Those formats and test signatures are reproducible today;
          production currently has zero snapshots and its Vault signing attempt returns 403.
        </p>
        <div class="flex flex-wrap gap-3">
          <a href="https://github.com/CueCrux/RCX-Registry" class="btn btn-quiet">Read the source ↗</a>
          <NuxtLink to="/subregistry" class="btn btn-quiet">Point a client here</NuxtLink>
        </div>
      </div>
    </section>

    <!-- link semantics -->
    <section class="mx-auto max-w-6xl px-5 mt-20" aria-labelledby="chain-h">
      <p class="sec-label">Link semantics</p>
      <h2 id="chain-h" class="display-h2 text-ink mb-3">Two histories, two different targets</h2>
      <p class="text-ink2 max-w-[68ch] mb-7">
        The v1 wire format does not put every receipt type onto one generic chain. Verifiers must
        follow the field defined for the history they are checking.
      </p>
      <div class="grid gap-4 sm:grid-cols-2">
        <article class="glass-card p-6">
          <p class="font-mono text-[12px] text-acc mb-2">RegistrySnapshot</p>
          <h3 class="font-display font-bold text-ink text-lg mb-2">Snapshot history</h3>
          <p class="text-sm text-ink2">
            <span class="font-mono">previous_snapshot_hash</span> equals the prior snapshot's flat
            set digest, stored in <span class="font-mono">snapshot_merkle_root</span>.
          </p>
        </article>
        <article class="glass-card p-6">
          <p class="font-mono text-[12px] text-trust mb-2">EntryEnriched</p>
          <h3 class="font-display font-bold text-ink text-lg mb-2">Enrichment supersession</h3>
          <p class="text-sm text-ink2">
            <span class="font-mono">supersedes_prior</span> equals the prior enrichment receipt's
            <span class="font-mono">receipt_hash</span>.
          </p>
        </article>
      </div>
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
        These are the logical fields of a RegistrySnapshot. Byte strings are shortened hex for
        readability; the actual wire value is a canonical-CBOR map. The previous hash names the
        prior snapshot set digest, not a receipt id or receipt hash.
      </p>
      <div class="max-w-2xl mb-8">
        <MonoBlock :code="receiptShape" label="snapshot receipt shape" />
      </div>

      <h3 class="display-h2 text-ink mb-3" style="font-size: clamp(22px, 2.6vw, 28px)">
        Reproduce the normative vectors
      </h3>
      <p class="text-ink2 max-w-[68ch] mb-5">
        The published corpus freezes receipt bytes, hashes, signatures, negative cases, snapshot
        digests, and chains. An independent implementation can run these checks without reading the
        Rust reference implementation.
      </p>
      <div class="max-w-3xl">
        <MonoBlock :code="verifyCode" label="verification steps" />
      </div>
      <p class="text-sm text-ink3 max-w-[68ch] mt-4">
        The canonicalisation, hashing, and signature-verification logic lives in the
        <span class="font-mono">rcx-registry-crown</span> crate — Apache-2.0, so you can run the same
        checks the registry runs.
      </p>
      <div class="mt-6 max-w-3xl rounded-card border border-edge-strong bg-surface2 p-5">
        <p class="font-mono text-[11px] uppercase tracking-[0.14em] text-crit">Current v1 boundary</p>
        <p class="mt-2 text-sm leading-6 text-ink2">
          Production currently has no snapshot rows, and the configured sync attempt fails when
          Vault Transit returns 403. Public publisher writes are closed. The rights and enrichment
          storage paths retain deterministic BLAKE3 receipt-hash references rather than complete
          signed artifacts. The public <span class="font-mono">/v0</span> API does not expose full
          receipt bodies, and <span class="font-mono">signer_kid</span> does not resolve a production
          public key. Signing recovery, complete artifact persistence, retrieval, and authoritative
          key discovery remain M1a work.
        </p>
      </div>
    </section>

    <!-- closing -->
    <section class="mx-auto max-w-6xl px-5 mt-24 mb-24">
      <div class="glass-panel px-8 py-12 sm:px-12 text-center">
        <h2 class="display-h2 text-ink mb-4">A frozen format, with explicit boundaries.</h2>
        <p class="text-ink2 max-w-[56ch] mx-auto mb-8">
          Start with the normative specification and vectors. Production receipt retrieval, public
          key discovery, and real inclusion proofs remain visible follow-on work.
        </p>
        <div class="flex flex-wrap justify-center gap-3">
          <NuxtLink to="/spec/v1" class="btn btn-approve">Read Protocol Spec v1</NuxtLink>
          <NuxtLink to="/spec/v1/vectors" class="btn btn-quiet">Download vectors</NuxtLink>
        </div>
      </div>
    </section>
  </div>
</template>
