<script setup lang="ts">
const route = useRoute()
const slug = route.params.slug as string

const { data: doc } = await useAsyncData(`legal-${slug}`, () =>
  queryCollection('content').path(`/legal/${slug}`).first()
)

if (!doc.value) {
  throw createError({ statusCode: 404, statusMessage: 'Legal document not found', fatal: true })
}

useHead({
  title: () => `${doc.value?.title ?? 'Legal'} · RCX-Registry`,
  meta: [{ name: 'description', content: () => doc.value?.description ?? '' }],
})
</script>

<template>
  <div class="mx-auto max-w-3xl px-5 pt-14 pb-24">
    <NuxtLink to="/legal" class="text-sm text-acc hover:underline">&larr; Back to legal centre</NuxtLink>

    <article class="glass-card p-7 sm:p-10 mt-6 legal-prose hover:!transform-none">
      <ContentRenderer v-if="doc" :value="doc" />
    </article>
  </div>
</template>
