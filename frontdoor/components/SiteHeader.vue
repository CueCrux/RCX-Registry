<script setup lang="ts">
const mobileOpen = ref(false)
const route = useRoute()
const api = useRuntimeConfig().public.registryApiUrl

const links = [
  { to: '/verify', label: 'Verify' },
  { to: '/publish', label: 'Publish' },
  { to: '/subregistry', label: 'Subregistry' },
  { to: '/badge', label: 'Badge' },
]

watch(
  () => route.path,
  () => {
    mobileOpen.value = false
  }
)
</script>

<template>
  <header
    class="fixed top-0 inset-x-0 z-50 border-b border-edge"
    style="background: var(--panel-bg); backdrop-filter: blur(var(--blur)); -webkit-backdrop-filter: blur(var(--blur))"
  >
    <nav class="relative mx-auto max-w-6xl flex items-center justify-between px-5 h-[68px]" aria-label="Main">
      <!-- brand: theme-adaptive inline mark (verified block) + wordmark -->
      <NuxtLink to="/" class="flex items-center gap-3">
        <svg viewBox="0 0 32 32" class="h-8 w-8 shrink-0" aria-hidden="true">
          <rect x="2.5" y="2.5" width="27" height="27" rx="8" fill="var(--surface)" stroke="var(--edge-strong)" />
          <path d="M6.5 12.5 v-2 a4 4 0 0 1 4 -4 h2" fill="none" stroke="var(--acc)" stroke-width="2" stroke-linecap="round" />
          <path d="M25.5 19.5 v2 a4 4 0 0 1 -4 4 h-2" fill="none" stroke="var(--trust)" stroke-width="2" stroke-linecap="round" />
          <path d="M11 16.4 l3.2 3.1 l6.8 -7.4" fill="none" stroke="var(--ok)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
        <span class="font-display text-xl font-bold tracking-tight text-ink">RCX-Registry</span>
      </NuxtLink>

      <!-- centered nav pill (desktop) -->
      <div class="nav-pill-wrap hidden lg:flex" aria-hidden="false">
        <div class="nav-pill">
          <NuxtLink
            v-for="link in links"
            :key="link.to"
            :to="link.to"
            class="nav-pill-item"
            :class="{ 'nav-pill-item--on': route.path.startsWith(link.to) }"
          >
            {{ link.label }}
          </NuxtLink>
        </div>
      </div>

      <div class="flex items-center gap-2">
        <a
          :href="api"
          class="hidden lg:inline-flex px-3.5 h-11 items-center rounded-ctrl text-sm font-medium text-ink2 hover:text-ink hover:bg-surface transition-colors"
        >
          Registry API ↗
        </a>
        <ClientOnly>
          <ThemeToggle />
          <template #fallback>
            <span class="inline-block h-11 w-11" aria-hidden="true" />
          </template>
        </ClientOnly>

        <!-- mobile menu button -->
        <button
          type="button"
          class="lg:hidden inline-flex items-center justify-center h-11 w-11 rounded-ctrl border border-edge-strong text-ink2 hover:text-ink"
          :aria-expanded="mobileOpen"
          aria-controls="mobile-nav"
          aria-label="Toggle navigation menu"
          @click="mobileOpen = !mobileOpen"
        >
          <svg v-if="!mobileOpen" class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <path d="M3 6h18M3 12h18M3 18h18" />
          </svg>
          <svg v-else class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <path d="M6 6l12 12M18 6L6 18" />
          </svg>
        </button>
      </div>
    </nav>

    <!-- mobile nav -->
    <div v-if="mobileOpen" id="mobile-nav" class="lg:hidden border-t border-edge px-5 py-3 flex flex-col gap-1">
      <NuxtLink
        v-for="link in links"
        :key="link.to"
        :to="link.to"
        class="h-11 inline-flex items-center px-3 rounded-ctrl text-sm font-medium text-ink2 hover:text-ink hover:bg-surface"
        :class="{ 'text-ink bg-surface': route.path.startsWith(link.to) }"
      >
        {{ link.label }}
      </NuxtLink>
      <a
        :href="api"
        class="h-11 inline-flex items-center px-3 rounded-ctrl text-sm font-medium text-ink2 hover:text-ink hover:bg-surface"
      >
        Registry API ↗
      </a>
    </div>
  </header>
</template>

<style scoped>
/* Centered nav pill (Aurora family pattern). Absolutely centered so it holds
   the optical middle regardless of the asymmetric logo / controls. */
.nav-pill-wrap {
  position: absolute;
  left: 50%;
  top: 50%;
  transform: translate(-50%, -50%);
}
.nav-pill {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  padding: 4px;
  border: 1px solid var(--edge-strong);
  border-radius: 999px;
  background: var(--surface2);
}
.nav-pill-item {
  padding: 7px 13px;
  border-radius: 999px;
  font-size: 13.5px;
  font-weight: 500;
  color: var(--ink2);
  text-decoration: none;
  white-space: nowrap;
  transition: color 0.18s ease, background-color 0.18s ease;
}
.nav-pill-item:hover {
  color: var(--ink);
}
.nav-pill-item--on {
  background: var(--surface);
  color: var(--ink);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.06), 0 1px 6px rgba(0, 0, 0, 0.18);
}

@media (prefers-reduced-motion: reduce) {
  .nav-pill-item {
    transition: none;
  }
}
</style>
