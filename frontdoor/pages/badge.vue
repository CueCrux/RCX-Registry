<script setup lang="ts">
const api = useRuntimeConfig().public.registryApiUrl
const site = useRuntimeConfig().public.siteUrl

useHead({
  title: 'Badge · RCX-Registry',
  meta: [
    {
      name: 'description',
      content:
        'Add a "verified on RCX-Registry" badge to your README. Copy the Markdown or HTML snippet — it links straight to your server’s signed history on the registry.',
    },
  ],
})

const badgeUrl = `${site}/badge/verified.svg`
const historyUrl = `${api}/servers/<your-namespace>`

const markdownSnippet = `[![Verified on RCX-Registry](${badgeUrl})](${historyUrl})`
const htmlSnippet = `<a href="${historyUrl}">
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
          Wear the <span class="grad-span">receipt.</span>
        </h1>
        <p class="text-lg text-ink2 max-w-[60ch] mb-8">
          Once your namespace is verified, drop this badge in your README. It links straight to your
          server’s signed history on RCX-Registry — a trust signal for your users and a backlink to
          the proof.
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
      <h2 id="copy-h" class="display-h2 text-ink mb-3">Two snippets, one placeholder</h2>
      <p class="text-ink2 max-w-[68ch] mb-7">
        Swap <span class="font-mono text-acc">&lt;your-namespace&gt;</span> for your server’s
        canonical name (for example <span class="font-mono">com.example/my-mcp-server</span>). The
        link resolves to that server’s signed-history page on the registry.
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
          <h3 class="font-display font-bold text-ink mb-2">It’s earned</h3>
          <p class="text-sm text-ink2">
            The badge only makes sense after you’ve proven namespace control by DNS or GitHub. It
            isn’t a decoration — it’s backed by a rights-verification receipt.
          </p>
        </article>
        <article class="glass-card p-6">
          <h3 class="font-display font-bold text-ink mb-2">It links to proof</h3>
          <p class="text-sm text-ink2">
            Clicking through lands on your server’s signed history — snapshots, declarations,
            verifications — that anyone can replay. Not a logo that links to a marketing page.
          </p>
        </article>
        <article class="glass-card p-6">
          <h3 class="font-display font-bold text-ink mb-2">It compounds</h3>
          <p class="text-sm text-ink2">
            Every badge is a backlink and a trust signal. Users see it, other publishers see it, and
            answer engines index it. Verification becomes visible where developers already look.
          </p>
        </article>
      </div>
    </section>

    <!-- closing -->
    <section class="mx-auto max-w-6xl px-5 mt-24 mb-24">
      <div class="glass-panel px-8 py-12 sm:px-12 text-center">
        <h2 class="display-h2 text-ink mb-4">Not verified yet?</h2>
        <p class="text-ink2 max-w-[52ch] mx-auto mb-8">
          Claim your namespace first — DNS TXT or GitHub OAuth, minutes either way — and the badge is
          yours.
        </p>
        <div class="flex flex-wrap justify-center gap-3">
          <NuxtLink to="/publish" class="btn btn-approve">Claim your namespace</NuxtLink>
          <NuxtLink to="/verify" class="btn btn-quiet">How verification works</NuxtLink>
        </div>
      </div>
    </section>
  </div>
</template>
