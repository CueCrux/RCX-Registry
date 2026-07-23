<template>
  <div class="aurora-ambient min-h-screen flex flex-col">
    <a href="#main-content" class="skip-link">Skip to main content</a>
    <SiteHeader />

    <main id="main-content" class="flex-1 pt-[68px]" tabindex="-1">
      <slot />
    </main>

    <SiteFooter />
  </div>
</template>
