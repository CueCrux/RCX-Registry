<script setup lang="ts">
const site = useRuntimeConfig().public.siteUrl

useHead({
  title: 'Badge · RCX-Registry',
  meta: [
    {
      name: 'description',
      content:
        'RCX-Registry badge guidance: the image is not proof, and publisher onboarding is currently closed, so no new verified badge claim should be made.',
    },
  ],
})

const badgeUrl = `${site}/badge/verified.svg`
const verificationUrl = `${site}/verify`

const markdownSnippet = `[![Verified on RCX-Registry](${badgeUrl})](${verificationUrl})`
const htmlSnippet = `<a href="${verificationUrl}">
  <img src="${badgeUrl}" alt="Verified on RCX-Registry" height="20">
</a>`
</script>

<template>
  <div>
    <!-- hero -->
    <section class="aurora-hero">
      <div class="relative mx-auto max-w-6xl px-5 pt-16 pb-14">
        <p class="eyebrow"><span class="led" aria-hidden="true"></span> README badge</p>
        <h1 class="display-h1 text-ink mt-5 mb-4 max-w-[16ch]">
          Link to the <span class="grad-span">proof model.</span>
        </h1>
        <p class="text-lg text-ink2 max-w-[60ch] mb-8">
          This asset is reserved for a future verified namespace. Publisher onboarding is currently
          fail-closed and production has no rights rows, so do not use the badge as a current claim.
          When verification reopens, the authoritative namespace-control record will remain
          <span class="font-mono">GET /v0/publishers/{publisher_passport}</span>. The image alone is
          not proof, and it does not imply a signed rights receipt.
        </p>
        <!-- live preview of the badge served from this site -->
        <div class="glass-panel inline-flex items-center gap-4 px-5 py-4">
          <img :src="badgeUrl" alt="Verified on RCX-Registry" height="20" class="h-5" />
          <span class="text-sm text-ink3 font-mono">/badge/verified.svg</span>
        </div>
      </div>
    </section>

    <!-- snippets -->
    <section class="mx-auto max-w-6xl px-5 mt-20" aria-labelledby="copy-h">
      <p class="sec-label">Copy &amp; paste</p>
      <h2 id="copy-h" class="display-h2 text-ink mb-3">Two snippets, one verification model</h2>
      <p class="text-ink2 max-w-[68ch] mb-7">
        These snippets link to the protocol's verification boundaries, not to a per-server evidence
        page. Public receipt retrieval and authoritative key discovery are M1a work.
      </p>

      <div class="grid gap-8 lg:grid-cols-2">
        <div>
          <p class="text-sm font-medium text-ink mb-2">Markdown</p>
          <MonoBlock :code="markdownSnippet" label="Markdown badge snippet" />
        </div>
        <div>
          <p class="text-sm font-medium text-ink mb-2">HTML</p>
          <MonoBlock :code="htmlSnippet" label="HTML badge snippet" />
        </div>
      </div>
    </section>

    <!-- why -->
    <section class="mx-auto max-w-6xl px-5 mt-24" aria-labelledby="why-h">
      <p class="sec-label">Why it’s worth it</p>
      <h2 id="why-h" class="display-h2 text-ink mb-7">A badge that actually means something</h2>
      <div class="grid gap-4 sm:grid-cols-3">
        <article class="glass-card p-6">
          <h3 class="font-display font-bold text-ink mb-2">Status lives in the API</h3>
          <p class="text-sm text-ink2">
            Publisher verification writes currently return 404. When a reviewed proof flow reopens,
            consumers must check the rights endpoint instead of trusting a copied image.
          </p>
        </article>
        <article class="glass-card p-6">
          <h3 class="font-display font-bold text-ink mb-2">It links to the model</h3>
          <p class="text-sm text-ink2">
            Clicking through explains canonical bytes, signatures, link semantics, conformance
            vectors, and the current gap before complete public live verification.
          </p>
        </article>
        <article class="glass-card p-6">
          <h3 class="font-display font-bold text-ink mb-2">It is not proof by itself</h3>
          <p class="text-sm text-ink2">
            The SVG is a public static asset and can be copied by anyone. Treat it as a navigation
            aid; rely on API metadata for actual status only after verification is reopened.
          </p>
        </article>
      </div>
    </section>

    <!-- closing -->
    <section class="mx-auto max-w-6xl px-5 mt-24 mb-24">
      <div class="glass-panel px-8 py-12 sm:px-12 text-center">
        <h2 class="display-h2 text-ink mb-4">Verification is temporarily unavailable.</h2>
        <p class="text-ink2 max-w-[52ch] mx-auto mb-8">
          Do not publish this badge as a verified claim today. Review the closure and evidence
          boundary while the replacement publisher-proof flow is designed and accepted.
        </p>
        <div class="flex flex-wrap justify-center gap-3">
          <NuxtLink to="/publish" class="btn btn-approve">Publisher status</NuxtLink>
          <NuxtLink to="/verify" class="btn btn-quiet">How verification works</NuxtLink>
        </div>
      </div>
    </section>
  </div>
</template>
