<script setup lang="ts">
// The hash chain, interactive: four receipt blocks linked by prev-hash. Flip
// one byte and watch verification pinpoint the tamper. State swap only, so
// reduced motion needs no special casing.
const BLOCKS = [
  { id: 'crown:41c7…09aa', verb: 'registry.snapshot', hash: 'b3:0a41…' },
  { id: 'crown:8802…6f11', verb: 'rights.verify.dns', hash: 'b3:77c2…' },
  { id: 'crown:c9a3…5510', verb: 'publisher.declare', hash: 'b3:e19d…' },
  { id: 'crown:e6b1…88f2', verb: 'registry.snapshot', hash: 'b3:4bf0…' },
]
const TAMPER_AT = 2

const tampered = ref(false)
</script>

<template>
  <div class="dg">
    <div class="dg-chain" role="img" :aria-label="tampered
      ? 'Sealed receipt spine with one byte flipped in the third record: verification fails at that record'
      : 'Four signed receipts on a sealed spine linked by chained segment seals, verification passing'">
      <template v-for="(b, i) in BLOCKS" :key="b.id">
        <div
          class="dg-block"
          :class="{ 'dg-block--bad': tampered && i === TAMPER_AT }"
          aria-hidden="true"
        >
          <p class="dg-block-id">{{ b.id }}</p>
          <p class="dg-block-verb">{{ b.verb }}</p>
          <p class="dg-block-sig">
            <span :class="tampered && i === TAMPER_AT ? 'dg-crit' : 'dg-ok'">
              {{ tampered && i === TAMPER_AT ? '✗ payload hash mismatch' : '✓ sig · ed25519' }}
            </span>
          </p>
        </div>
        <span
          v-if="i < BLOCKS.length - 1"
          class="dg-link"
          :class="{ 'dg-link--bad': tampered && i === TAMPER_AT - 1 }"
          aria-hidden="true"
        >
          <span class="dg-link-hash">seal {{ b.hash }}</span>
          <span class="dg-link-line"></span>
        </span>
      </template>
    </div>

    <div class="dg-verify">
      <p class="dg-verdict" :class="tampered ? 'dg-crit' : 'dg-ok'" aria-live="polite">
        <span class="dg-verdict-cmd">rcx-registry verify --chain --strict</span>
        {{ tampered ? `ok: false · first failure at receipt ${TAMPER_AT + 1} (payload hash mismatch)` : 'ok: true · 4 receipts · chain intact' }}
      </p>
      <button type="button" class="btn btn-quiet dg-btn" @click="tampered = !tampered">
        {{ tampered ? 'Restore the byte' : 'Flip one byte on disk' }}
      </button>
    </div>

    <p class="dg-caption">
      Each CROWN receipt is ed25519-signed (via Vault Transit) over both its id and the BLAKE3 hash
      of its payload, so a receipt cannot be edited in place or transplanted elsewhere; ordering is
      carried by the chained hash on the spine. Anyone can replay the registry's history from these
      receipts and detect a single flipped byte — that is what makes the registry independently
      verifiable rather than merely trusted.
    </p>
  </div>
</template>

<style scoped>
.dg {
  border: 1px solid var(--edge);
  border-radius: var(--radius);
  background: var(--surface2);
  padding: 22px;
}
.dg-chain {
  display: flex;
  align-items: stretch;
  gap: 0;
  flex-wrap: wrap;
  row-gap: 14px;
}
.dg-block {
  border: 1px solid color-mix(in srgb, var(--ok) 40%, var(--edge));
  border-radius: var(--radius-sm);
  background: var(--surface);
  padding: 10px 12px;
  min-width: 0;
  flex: 1 1 9rem;
  transition: border-color 0.2s ease;
}
.dg-block--bad {
  border-color: color-mix(in srgb, var(--crit) 65%, transparent);
}
.dg-block-id {
  font-family: var(--font-mono);
  font-size: 10.5px;
  color: var(--ink3);
}
.dg-block-verb {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--ink);
  margin: 3px 0;
}
.dg-block-sig {
  font-family: var(--font-mono);
  font-size: 10px;
}
.dg-ok {
  color: var(--ok);
}
.dg-crit {
  color: var(--crit);
}
.dg-link {
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  padding: 0 4px;
  flex: none;
  width: 5.4rem;
}
.dg-link-hash {
  font-family: var(--font-mono);
  font-size: 9px;
  color: var(--ink3);
  margin-bottom: 3px;
  white-space: nowrap;
}
.dg-link-line {
  width: 100%;
  height: 0;
  border-top: 1px solid var(--edge-strong);
  position: relative;
}
.dg-link-line::after {
  content: '';
  position: absolute;
  right: -1px;
  top: -3.5px;
  border: 3px solid transparent;
  border-left-color: var(--edge-strong);
}
.dg-link--bad .dg-link-line {
  border-top-style: dashed;
  border-top-color: var(--crit);
}
.dg-link--bad .dg-link-line::after {
  border-left-color: var(--crit);
}
.dg-link--bad .dg-link-hash {
  color: var(--crit);
}

.dg-verify {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  flex-wrap: wrap;
  margin-top: 16px;
  border: 1px solid var(--edge);
  border-radius: var(--radius-sm);
  padding: 10px 14px;
  background: var(--surface);
}
.dg-verdict {
  font-family: var(--font-mono);
  font-size: 11px;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.dg-verdict-cmd {
  color: var(--ink3);
}
.dg-btn {
  height: 34px;
  padding: 0 13px;
  font-size: 12px;
  flex: none;
}
.dg-caption {
  margin-top: 14px;
  font-size: 12.5px;
  color: var(--ink3);
  max-width: 68ch;
}

@media (max-width: 720px) {
  .dg-link {
    width: 100%;
    padding: 2px 0;
  }
  .dg-link-line {
    display: none;
  }
  .dg-block {
    flex-basis: 100%;
  }
}
@media (prefers-reduced-motion: reduce) {
  .dg-block {
    transition: none;
  }
}
</style>
