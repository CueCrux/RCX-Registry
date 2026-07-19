<script setup lang="ts">
const currentYear = new Date().getFullYear()
const api = useRuntimeConfig().public.registryApiUrl
</script>

<template>
  <footer class="border-t border-edge py-10 px-5">
    <div class="mx-auto max-w-6xl flex flex-col gap-8">
      <div class="flex flex-col sm:flex-row sm:items-start justify-between gap-8">
        <div class="flex items-center gap-3">
          <svg viewBox="0 0 32 32" class="h-8 w-8" aria-hidden="true">
            <rect x="2.5" y="2.5" width="27" height="27" rx="8" fill="var(--surface)" stroke="var(--edge-strong)" />
            <path d="M6.5 12.5 v-2 a4 4 0 0 1 4 -4 h2" fill="none" stroke="var(--acc)" stroke-width="2" stroke-linecap="round" />
            <path d="M25.5 19.5 v2 a4 4 0 0 1 -4 4 h-2" fill="none" stroke="var(--trust)" stroke-width="2" stroke-linecap="round" />
            <path d="M11 16.4 l3.2 3.1 l6.8 -7.4" fill="none" stroke="var(--ok)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
          <div>
            <p class="font-display font-bold text-ink leading-tight">RCX-Registry</p>
            <p class="text-xs text-ink3">Mirror. Verify. Receipt.</p>
          </div>
        </div>

        <nav class="grid grid-cols-2 sm:flex sm:flex-wrap gap-x-8 gap-y-2 text-sm" aria-label="Footer">
          <NuxtLink to="/verify" class="text-ink2 hover:text-ink transition-colors">Verify</NuxtLink>
          <NuxtLink to="/publish" class="text-ink2 hover:text-ink transition-colors">Publish</NuxtLink>
          <NuxtLink to="/subregistry" class="text-ink2 hover:text-ink transition-colors">Subregistry</NuxtLink>
          <NuxtLink to="/badge" class="text-ink2 hover:text-ink transition-colors">Badge</NuxtLink>
          <a :href="api" class="text-ink2 hover:text-ink transition-colors">Registry API ↗</a>
          <a href="https://github.com/CueCrux/RCX-Registry" class="text-ink2 hover:text-ink transition-colors">GitHub ↗</a>
          <a href="https://registry.modelcontextprotocol.io" class="text-ink2 hover:text-ink transition-colors">Upstream MCP registry ↗</a>
          <NuxtLink to="/legal" class="text-ink2 hover:text-ink transition-colors">Legal</NuxtLink>
        </nav>
      </div>

      <p class="text-xs text-ink3">
        &copy; {{ currentYear }} RCX-Registry, an open-source project by CueCrux Limited. Apache-2.0.
        Not affiliated with Anthropic or the Model Context Protocol project.
      </p>
    </div>
  </footer>
</template>
