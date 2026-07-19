import { defineNuxtConfig } from 'nuxt/config'

// RCX-Registry frontdoor (rcxprotocol.org). Pure marketing/docs SSR site:
// no BFF, no auth, no payments. The registry API + publisher onboarding live
// on a separate host (registry.rcxprotocol.org) and are only ever linked to,
// never proxied — the site builds and renders with the registry offline.
export default defineNuxtConfig({
  compatibilityDate: '2024-12-01',
  ssr: true,
  devtools: { enabled: false },

  // View Transitions API for soft cross-page morphs; no-op where unsupported.
  experimental: {
    viewTransition: true,
  },

  modules: ['@nuxtjs/tailwindcss', '@nuxtjs/color-mode', '@nuxt/content'],

  css: ['~/assets/css/aurora.css', '~/assets/css/tailwind.css', '~/assets/css/site.css'],

  runtimeConfig: {
    public: {
      siteUrl: process.env.NUXT_PUBLIC_SITE_URL || 'https://rcxprotocol.org',
      // Where the registry API + publisher onboarding are served. Linked to,
      // never proxied. Overridable so a staging host can point elsewhere.
      registryApiUrl: process.env.NUXT_PUBLIC_REGISTRY_API_URL || 'https://registry.rcxprotocol.org',
    },
  },

  // Dark Glass is the default theme; Light Glass is the secondary.
  // classSuffix '' -> <html class="dark"> / <html class="light">.
  colorMode: {
    classSuffix: '',
    preference: 'dark',
    fallback: 'dark',
  },

  content: {
    highlight: false,
  },

  app: {
    head: {
      htmlAttrs: { lang: 'en' },
      title: 'RCX-Registry: verifiable, MCP-compatible discovery for MCP servers',
      meta: [
        { name: 'viewport', content: 'width=device-width, initial-scale=1' },
        {
          name: 'description',
          content:
            'A verifiable subregistry that mirrors the official MCP registry and makes its history tamper-evident: signed CROWN receipts, verified publishers, drop-in shape-compatible with existing MCP clients.',
        },
      ],
      link: [
        { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' },
        { rel: 'preconnect', href: 'https://fonts.googleapis.com' },
        { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: '' },
        {
          rel: 'stylesheet',
          href: 'https://fonts.googleapis.com/css2?family=Archivo:wght@700;800&family=Public+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap',
        },
      ],
    },
  },

  nitro: {
    preset: 'node-server',
  },

  typescript: {
    shim: false,
  },
})
