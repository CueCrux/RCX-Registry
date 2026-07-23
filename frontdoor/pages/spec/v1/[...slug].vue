<script setup lang="ts">
import specFreeze from '~/spec-v1-freeze.json'

// Route reuse must never leave a chapter rendering data fetched for the prior
// slug. Make Nuxt's current interpolated-route key behaviour explicit here.
definePageMeta({ key: route => route.path })

// The index route imports this component so both base and chapter URLs share one renderer.
const SPEC_SOURCE_COMMIT = specFreeze.sourceCommit

const chapters = [
  { slug: '', label: 'Overview' },
  { slug: '01-conventions', label: '1. Conventions' },
  { slug: '02-canonical-cbor', label: '2. Canonical CBOR' },
  { slug: '03-canonical-json', label: '3. Canonical JSON' },
  { slug: '04-hashing', label: '4. Hashing' },
  { slug: '05-receipts', label: '5. CROWN receipts' },
  { slug: '06-merkle-and-snapshots', label: '6. Snapshots' },
  { slug: '07-api-and-errors', label: '7. API and errors' },
  { slug: 'vectors', label: 'Conformance vectors' },
]

const route = useRoute()
const rawSlug = Array.isArray(route.params.slug)
  ? route.params.slug.join('/')
  : (route.params.slug ?? '').toString()
const canonicalSlug = rawSlug.replace(/\.md$/, '').replace(/\/$/, '')
const aliasTarget = canonicalSlug.toLowerCase() === 'readme'
  ? '/spec/v1'
  : canonicalSlug.toLowerCase() === 'vectors/readme'
    ? '/spec/v1/vectors'
    : undefined

if (aliasTarget) {
  await navigateTo(aliasTarget, { redirectCode: 308, replace: true })
}

const contentPath = canonicalSlug ? `/spec/v1/${canonicalSlug}` : '/spec/v1'
const sourcePath = canonicalSlug === ''
  ? '/spec/v1/readme'
  : canonicalSlug === 'vectors'
    ? '/spec/v1/vectors/readme'
    : contentPath

const { data: doc } = await useAsyncData(`spec-v1-${canonicalSlug || 'overview'}`, () =>
  queryCollection('specV1').path(sourcePath).first()
)

if (!doc.value) {
  throw createError({ statusCode: 404, statusMessage: 'Protocol specification chapter not found', fatal: true })
}

const canonicalUrl = `https://rcxprotocol.org${contentPath}`

useHead({
  title: () => `${doc.value?.title ?? 'Protocol Spec v1'} · RCX-Registry`,
  meta: [
    {
      name: 'description',
      content: () => doc.value?.description ?? 'The normative RCX Protocol Specification v1 and conformance vectors.',
    },
  ],
  link: [{ rel: 'canonical', href: canonicalUrl }],
})
</script>

<template>
  <div class="mx-auto max-w-6xl px-5 pt-10 pb-24">
    <nav aria-label="Breadcrumb" class="mb-7 flex flex-wrap items-center gap-2 text-sm text-ink3">
      <NuxtLink to="/" class="min-h-11 inline-flex items-center text-acc hover:underline">RCX-Registry</NuxtLink>
      <span aria-hidden="true">/</span>
      <NuxtLink to="/spec/v1" class="min-h-11 inline-flex items-center text-acc hover:underline">Protocol Spec v1</NuxtLink>
      <template v-if="canonicalSlug">
        <span aria-hidden="true">/</span>
        <span aria-current="page" class="text-ink2">{{ canonicalSlug }}</span>
      </template>
    </nav>

    <div class="grid gap-8 lg:grid-cols-[220px_minmax(0,1fr)] lg:gap-10">
      <aside class="lg:sticky lg:top-24 lg:self-start">
        <p class="mb-3 font-mono text-[11px] uppercase tracking-[0.16em] text-ink3">Specification</p>
        <nav aria-label="Specification chapters" class="flex flex-wrap gap-2 lg:flex-col lg:gap-1">
          <NuxtLink
            v-for="chapter in chapters"
            :key="chapter.slug"
            :to="chapter.slug ? `/spec/v1/${chapter.slug}` : '/spec/v1'"
            class="min-h-11 inline-flex items-center rounded-ctrl border px-3 py-2 text-sm transition-colors lg:w-full"
            :class="canonicalSlug === chapter.slug
              ? 'border-edge-strong bg-surface text-ink'
              : 'border-transparent text-ink2 hover:border-edge hover:bg-surface2 hover:text-ink'"
            :aria-current="canonicalSlug === chapter.slug ? 'page' : undefined"
          >
            {{ chapter.label }}
          </NuxtLink>
        </nav>
      </aside>

      <div class="min-w-0">
        <section class="mb-5 rounded-card border border-edge-strong bg-surface2 px-5 py-4" aria-label="Specification provenance">
          <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p class="font-mono text-[11px] uppercase tracking-[0.14em] text-ok">Normative v1 · frozen</p>
              <p class="mt-1 text-sm leading-6 text-ink2">
                Published directly from source commit
                <code class="break-all font-mono text-xs text-ink">{{ SPEC_SOURCE_COMMIT }}</code>.
              </p>
            </div>
            <a
              :href="`https://github.com/CueCrux/RCX-Registry/tree/${SPEC_SOURCE_COMMIT}/spec/v1`"
              class="min-h-11 shrink-0 inline-flex items-center justify-center rounded-ctrl border border-edge-strong px-4 text-sm font-medium text-ink hover:bg-surface"
            >
              Inspect source ↗
            </a>
          </div>
        </section>

        <section class="mb-5 rounded-card border border-warn/50 bg-warn/10 px-5 py-4" aria-label="Hosted runtime status">
          <p class="font-mono text-[11px] uppercase tracking-[0.14em] text-warn">Hosted runtime status</p>
          <p class="mt-2 text-sm leading-6 text-ink2">
            This frozen specification defines formats and code paths, not evidence that the hosted
            service has produced them. Production currently has zero snapshots, and snapshot signing
            is degraded because Vault Transit returns 403. The conformance vectors remain reproducible.
          </p>
        </section>

        <article id="spec-content" class="glass-card legal-prose spec-prose overflow-hidden p-6 hover:!transform-none sm:p-10">
          <ContentRenderer v-if="doc" :value="doc" />
        </article>
      </div>
    </div>
  </div>
</template>

<style scoped>
.spec-prose {
  font-size: 16px;
  line-height: 1.7;
  overflow-wrap: anywhere;
}

.spec-prose :deep(pre) {
  max-width: 100%;
  overflow-x: auto;
  border: 1px solid var(--edge);
  border-radius: var(--radius-control);
  background: var(--surface2);
  padding: 14px 16px;
  font-family: var(--font-mono);
  font-size: 13px;
  line-height: 1.65;
}

.spec-prose :deep(table) {
  display: block;
  max-width: 100%;
  overflow-x: auto;
}

@media (min-width: 1024px) {
  .spec-prose {
    max-width: 75ch;
  }
}
</style>
