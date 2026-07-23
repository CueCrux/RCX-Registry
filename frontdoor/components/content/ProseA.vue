<script setup lang="ts">
const props = defineProps<{
  href?: string
  target?: string
}>()

const route = useRoute()

const resolvedHref = computed(() => {
  const href = props.href ?? ''
  const hasScheme = /^[a-z][a-z\d+.-]*:/i.test(href)

  if (href.startsWith('//') || (hasScheme && !/^(?:https?:|mailto:)/i.test(href))) {
    return ''
  }

  if (!route.path.startsWith('/spec/v1') || /^(?:https?:|mailto:|\/|#|\?)/i.test(href)) {
    return href
  }

  const hashIndex = href.indexOf('#')
  const path = hashIndex === -1 ? href : href.slice(0, hashIndex)
  const fragment = hashIndex === -1 ? '' : href.slice(hashIndex)

  const normalizedPath = path
    .replace(/^\.\//, '')
    .replace(/\.md$/, '')
    .replace(/\/$/, '')

  return normalizedPath ? `/spec/v1/${normalizedPath}${fragment}` : fragment
})
</script>

<template>
  <span v-if="!resolvedHref"><slot /></span>
  <NuxtLink v-else :href="resolvedHref" :target="props.target">
    <slot />
  </NuxtLink>
</template>
