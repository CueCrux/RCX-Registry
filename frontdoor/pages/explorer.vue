<script setup lang="ts">
// Transparency portal. Renders the artifacts the registry publishes and, for
// every one of them, the exact command that re-verifies it without trusting
// this page.
//
// Everything here is fetched CLIENT-SIDE on purpose. This site is a static SSR
// build that must render with the registry offline (see nuxt.config.ts), so the
// registry is never fetched during build or SSR. A reader who loads this page
// while the API is down gets a page that says so, not a broken build.
//
// The page is deliberately not a verifier. It shows what was served and hands
// you the command to check it yourself — a browser tab claiming "verified" is
// exactly the trust-the-operator move RCX exists to remove.
const api = useRuntimeConfig().public.registryApiUrl

useHead({
  title: 'Explorer · RCX-Registry',
  meta: [
    {
      name: 'description',
      content:
        'Browse the RCX-Registry transparency artifacts: signed snapshot receipts, snapshot roots, entry sets and the signing key — each with the command that independently re-verifies it.',
    },
  ],
})

type Snapshot = {
  snapshot_id: string
  scraped_at: string
  server_count: number
  snapshot_root: string
  receipt_hash: string
  signer_kid: string
  receipt_cbor_hex: string
  entries_available: boolean
}

type KeyState = {
  status: 'published' | 'unsigned' | 'unavailable'
  keys: { signer_kid: string; algorithm: string; public_key_hex: string }[]
  note?: string
}

const keyState = ref<KeyState | null>(null)
const keyError = ref<string | null>(null)
const snapshots = ref<Snapshot[]>([])
const snapshotsError = ref<string | null>(null)
const loading = ref(true)
const selected = ref<Snapshot | null>(null)

// Membership lookup. The honest answer to "is my server in this snapshot" needs
// the whole entry set, because v1's root is a flat set digest with no inclusion
// proof — so this streams a large file on demand rather than on page load.
const lookupName = ref('')
const lookupState = ref<'idle' | 'loading' | 'found' | 'absent' | 'error'>('idle')
const lookupDetail = ref('')

async function load() {
  loading.value = true
  const [keys, list] = await Promise.allSettled([
    $fetch<KeyState>(`${api}/.well-known/rcx-keys.json`),
    $fetch<{ snapshots: Snapshot[] }>(`${api}/v0/snapshots?limit=20`),
  ])

  if (keys.status === 'fulfilled') keyState.value = keys.value
  // A 503 here is `unavailable`, which is a real answer rather than a failure —
  // surface the distinction instead of collapsing both into "error".
  else keyError.value = String((keys.reason as Error)?.message ?? keys.reason)

  if (list.status === 'fulfilled') {
    snapshots.value = list.value.snapshots ?? []
    selected.value = snapshots.value[0] ?? null
  } else {
    snapshotsError.value = String((list.reason as Error)?.message ?? list.reason)
  }
  loading.value = false
}

onMounted(load)

const publicKeyHex = computed(() => keyState.value?.keys?.[0]?.public_key_hex ?? '<public-key-hex>')

function short(hex: string, head = 12) {
  return hex.length > head * 2 ? `${hex.slice(0, head)}…${hex.slice(-head)}` : hex
}

function when(iso: string) {
  return new Date(iso).toISOString().replace('T', ' ').replace(/\..*/, ' UTC')
}

async function lookup() {
  const name = lookupName.value.trim()
  const snapshot = selected.value
  if (!name || !snapshot) return
  if (!snapshot.entries_available) {
    lookupState.value = 'error'
    lookupDetail.value =
      'This snapshot’s entry set has aged out of retention. Its receipt still verifies, but membership can no longer be recomputed.'
    return
  }
  lookupState.value = 'loading'
  lookupDetail.value = ''
  try {
    const entries = await $fetch<{ name: string; version: string }[]>(
      `${api}/v0/snapshots/${snapshot.snapshot_id}/entries`
    )
    const hit = entries.find((entry) => entry.name === name)
    if (hit) {
      lookupState.value = 'found'
      lookupDetail.value = `${hit.name} @ ${hit.version}`
    } else {
      lookupState.value = 'absent'
      lookupDetail.value = `${name} is not in this snapshot’s ${entries.length.toLocaleString()} entries.`
    }
  } catch (error) {
    lookupState.value = 'error'
    lookupDetail.value = String((error as Error)?.message ?? error)
  }
}

// The commands are built from what is actually on screen, so a reader can copy
// them without substituting anything — and so they cannot drift from the data.
const verifyCommands = computed(() => {
  const s = selected.value
  if (!s) return ''
  return `# 1. the receipt is genuinely signed by the registry
curl -fsS '${api}/v0/snapshots/${s.snapshot_id}' \\
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["receipt_cbor_hex"])' > receipt.hex
curl -fsS '${api}/.well-known/rcx-keys.json' \\
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["keys"][0]["public_key_hex"])' > key.hex
rcx verify receipt receipt.hex --key @key.hex

# 2. the entry set really digests to the root inside that signed receipt
curl -fsS '${api}/v0/snapshots/${s.snapshot_id}/entries' -o entries.json
rcx verify snapshot entries.json --root ${s.snapshot_root}

# 3. your server is in that set
grep -q '"name":"io.example/thing"' entries.json && echo present`
})
</script>

<template>
  <div>
    <!-- hero -->
    <section class="aurora-hero">
      <div class="relative mx-auto max-w-6xl px-5 pt-16 pb-14">
        <p class="eyebrow"><span class="led" aria-hidden="true"></span> Transparency portal</p>
        <h1 class="display-h1 text-ink mt-5 mb-4 max-w-[18ch]">
          Every artifact, and <span class="grad-span">how to check it.</span>
        </h1>
        <p class="text-lg text-ink2 max-w-[64ch] mb-4">
          Signed snapshot receipts, the roots they commit to, the entry sets those roots digest,
          and the key it all verifies under. Nothing here asks you to take our word for it: each
          view carries the command that reproduces it on your machine.
        </p>
        <p class="text-sm text-ink3 max-w-[64ch]">
          This page does not verify anything itself. A browser tab that prints “verified” is the
          trust-the-operator move RCX exists to remove — so it shows you what was served, and the
          command that checks it.
        </p>
      </div>
    </section>

    <!-- signing key -->
    <section class="mx-auto max-w-6xl px-5 mt-16" aria-labelledby="key-h">
      <p class="sec-label">Signing key</p>
      <h2 id="key-h" class="display-h2 text-ink mb-3">What receipts verify under</h2>

      <div class="glass-card p-6">
        <template v-if="keyState?.status === 'published'">
          <div v-for="key in keyState.keys" :key="key.signer_kid" class="space-y-1">
            <p class="font-mono text-sm text-acc break-all">{{ key.public_key_hex }}</p>
            <p class="text-sm text-ink3">
              {{ key.algorithm }} · <span class="font-mono">{{ key.signer_kid }}</span>
            </p>
          </div>
          <p class="text-sm text-ink3 mt-4 max-w-[70ch]">
            Match a receipt to a key on its <span class="font-mono">signer_kid</span>, never on
            position. Key history across rotations is not published yet, so a receipt signed under
            a since-rotated key will not verify against this list.
          </p>
        </template>
        <p v-else-if="keyState?.status === 'unsigned'" class="text-ink2">
          This registry publishes no signing key. Its receipts cannot be verified by a third party.
          That is a settled answer, not a temporary one.
        </p>
        <p v-else-if="keyState?.status === 'unavailable'" class="text-ink2">
          The signing key has not been read yet. This is retryable — it does <strong>not</strong>
          mean the registry is unsigned.
        </p>
        <p v-else-if="keyError" class="text-ink2">
          Could not reach the registry: <span class="font-mono text-sm">{{ keyError }}</span>
        </p>
        <p v-else class="text-ink3">Loading…</p>
      </div>
    </section>

    <!-- snapshot explorer -->
    <section class="mx-auto max-w-6xl px-5 mt-20" aria-labelledby="snap-h">
      <p class="sec-label">Snapshot explorer</p>
      <h2 id="snap-h" class="display-h2 text-ink mb-3">Signed history</h2>
      <p class="text-ink2 max-w-[70ch] mb-7">
        Every sync tick mints a snapshot receipt signed with the key above. Only snapshots whose
        signed bytes were retained appear here — a row you cannot verify would be a row that
        dead-ends.
      </p>

      <p v-if="loading" class="text-ink3">Loading…</p>
      <p v-else-if="snapshotsError" class="text-ink2">
        Could not reach the registry: <span class="font-mono text-sm">{{ snapshotsError }}</span>
      </p>
      <p v-else-if="!snapshots.length" class="text-ink2">
        No verifiable snapshots yet. Snapshots minted before signed bytes were retained are skipped
        rather than shown unverifiably.
      </p>

      <div v-else class="grid gap-6 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
        <!-- list -->
        <ol class="glass-card divide-y divide-white/5 max-h-[28rem] overflow-y-auto">
          <li v-for="snapshot in snapshots" :key="snapshot.snapshot_id">
            <button
              class="w-full text-left px-5 py-3 hover:bg-white/5 transition"
              :class="selected?.snapshot_id === snapshot.snapshot_id ? 'bg-white/5' : ''"
              @click="selected = snapshot; lookupState = 'idle'"
            >
              <span class="block font-mono text-xs text-acc">{{ short(snapshot.snapshot_root, 8) }}</span>
              <span class="block text-sm text-ink2">{{ when(snapshot.scraped_at) }}</span>
              <span class="block text-xs text-ink3">
                {{ snapshot.server_count.toLocaleString() }} servers
                <template v-if="!snapshot.entries_available"> · entries aged out</template>
              </span>
            </button>
          </li>
        </ol>

        <!-- detail -->
        <div v-if="selected" class="glass-card p-6 space-y-4">
          <dl class="space-y-3">
            <div>
              <dt class="text-xs uppercase tracking-wide text-ink3">Snapshot root</dt>
              <dd class="font-mono text-sm text-acc break-all">{{ selected.snapshot_root }}</dd>
            </div>
            <div>
              <dt class="text-xs uppercase tracking-wide text-ink3">Receipt hash</dt>
              <dd class="font-mono text-sm text-ink2 break-all">{{ selected.receipt_hash }}</dd>
            </div>
            <div class="grid sm:grid-cols-2 gap-3">
              <div>
                <dt class="text-xs uppercase tracking-wide text-ink3">Scraped at</dt>
                <dd class="text-sm text-ink2">{{ when(selected.scraped_at) }}</dd>
              </div>
              <div>
                <dt class="text-xs uppercase tracking-wide text-ink3">Servers</dt>
                <dd class="text-sm text-ink2">{{ selected.server_count.toLocaleString() }}</dd>
              </div>
            </div>
            <div>
              <dt class="text-xs uppercase tracking-wide text-ink3">Signed by</dt>
              <dd class="font-mono text-sm text-ink2 break-all">{{ selected.signer_kid }}</dd>
            </div>
            <div>
              <dt class="text-xs uppercase tracking-wide text-ink3">Entry set</dt>
              <dd class="text-sm text-ink2">
                <template v-if="selected.entries_available">
                  available — membership can be recomputed
                </template>
                <template v-else>
                  aged out of retention. The receipt still verifies; membership cannot be
                  recomputed for this snapshot.
                </template>
              </dd>
            </div>
          </dl>

          <!-- membership -->
          <div class="pt-4 border-t border-white/5">
            <label for="lookup" class="block text-xs uppercase tracking-wide text-ink3 mb-2">
              Is a server in this snapshot?
            </label>
            <div class="flex gap-2">
              <input
                id="lookup"
                v-model="lookupName"
                type="text"
                placeholder="io.github.example/server"
                class="flex-1 rounded-md bg-black/20 border border-white/10 px-3 py-2 text-sm font-mono text-ink"
                @keyup.enter="lookup"
              />
              <button class="btn btn-quiet" :disabled="lookupState === 'loading'" @click="lookup">
                {{ lookupState === 'loading' ? 'Fetching…' : 'Check' }}
              </button>
            </div>
            <p v-if="lookupState === 'loading'" class="text-xs text-ink3 mt-2">
              Downloading the full entry set — v1 has no inclusion proof, so membership means
              recomputing over every entry.
            </p>
            <p v-else-if="lookupState === 'found'" class="text-sm text-acc mt-2">
              Present: <span class="font-mono">{{ lookupDetail }}</span>
            </p>
            <p v-else-if="lookupState === 'absent'" class="text-sm text-ink2 mt-2">{{ lookupDetail }}</p>
            <p v-else-if="lookupState === 'error'" class="text-sm text-ink2 mt-2">{{ lookupDetail }}</p>
            <p class="text-xs text-ink3 mt-3">
              This check runs in your browser against bytes the registry served. It is a
              convenience, not proof — the commands below are the proof.
            </p>
          </div>
        </div>
      </div>
    </section>

    <!-- verify it yourself -->
    <section v-if="selected" class="mx-auto max-w-6xl px-5 mt-20 mb-24" aria-labelledby="verify-h">
      <p class="sec-label">Don’t trust this page</p>
      <h2 id="verify-h" class="display-h2 text-ink mb-3">Re-verify it yourself</h2>
      <p class="text-ink2 max-w-[70ch] mb-6">
        These commands are built from the snapshot selected above, so nothing needs substituting.
        <span class="font-mono">rcx</span> performs no network I/O — it checks bytes you already
        hold.
      </p>
      <MonoBlock :code="verifyCommands" label="verify this snapshot" />
      <p class="text-sm text-ink3 mt-6 max-w-[70ch]">
        What this establishes: the registry signed a snapshot with this root, and the entry set you
        were handed is exactly the set that root digests. What it does
        <strong>not</strong> establish: that the registry never rewrote its history. v1's root is a
        flat set digest, not a Merkle tree, so there are no inclusion or consistency proofs and no
        independent witness has co-signed anything. Detecting a fork needs the transparency log —
        proposed in
        <a class="underline" href="https://github.com/CueCrux/RCX-Registry/blob/main/rfcs/0001-transparency-log.md">RFC-0001</a>.
      </p>
    </section>
  </div>
</template>
