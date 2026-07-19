<script setup lang="ts">
useHead({
  title: 'Legal · RCX-Registry',
  meta: [
    {
      name: 'description',
      content: 'Terms of use and privacy notice for RCX-Registry.',
    },
  ],
})

const legalDocs = [
  { slug: 'terms', label: 'Terms', description: 'Terms of use, disclaimers, and the no-warranty basis of the service.' },
  { slug: 'privacy', label: 'Privacy', description: 'What the registry collects, why, and how little of it is personal.' },
]
</script>

<template>
  <div class="mx-auto max-w-4xl px-5 pt-14 pb-24">
    <p class="eyebrow">
      <span class="led" aria-hidden="true"></span>
      Legal centre
    </p>
    <h1 class="display-h1 text-ink mt-5 mb-4 max-w-[14ch]">The paperwork.</h1>
    <p class="text-lg text-ink2 max-w-[58ch] mb-10">
      RCX-Registry is an open-source project (Apache-2.0). These are the terms it’s offered under and
      how it handles data.
    </p>

    <div class="grid gap-4 sm:grid-cols-2">
      <article v-for="doc in legalDocs" :key="doc.slug" class="glass-card p-6 flex flex-col">
        <h2 class="font-display font-bold text-ink text-lg mb-2">{{ doc.label }}</h2>
        <p class="text-sm text-ink2 mb-5 flex-1">{{ doc.description }}</p>
        <NuxtLink :to="`/legal/${doc.slug}`" class="btn btn-quiet self-start h-10">
          Read {{ doc.label.toLowerCase() }}
        </NuxtLink>
      </article>
    </div>
  </div>
</template>
