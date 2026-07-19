<template>
  <div class="aurora-ambient min-h-screen flex flex-col">
    <SiteHeader />

    <main class="flex-1 pt-[68px]">
      <slot />
    </main>

    <SiteFooter />
  </div>
</template>
