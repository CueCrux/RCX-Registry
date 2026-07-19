<script setup lang="ts">
const props = defineProps<{
  code: string
  label: string
}>()

const copied = ref(false)
let timer: ReturnType<typeof setTimeout> | undefined

async function copy() {
  try {
    await navigator.clipboard.writeText(props.code)
    copied.value = true
    if (timer) clearTimeout(timer)
    timer = setTimeout(() => {
      copied.value = false
    }, 1800)
  } catch {
    // clipboard unavailable (permissions/http); leave the text selectable
  }
}

onBeforeUnmount(() => {
  if (timer) clearTimeout(timer)
})
</script>

<template>
  <div class="mono-block" tabindex="0">
    <code>{{ code }}</code>
    <button
      type="button"
      class="copy-btn"
      :class="{ copied }"
      :aria-label="`Copy ${label} to clipboard`"
      @click="copy"
    >
      {{ copied ? 'Copied' : 'Copy' }}
    </button>
  </div>
</template>
