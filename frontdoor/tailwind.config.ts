import type { Config } from 'tailwindcss'

/**
 * Tailwind theme mapped onto the canonical Aurora tokens (assets/css/aurora.css).
 * Every colour used in templates must resolve to an aurora token — do not add
 * raw hex values here.
 */
export default {
  darkMode: 'class',
  content: ['./app.vue', './error.vue', './components/**/*.{vue,ts}', './layouts/**/*.vue', './pages/**/*.vue'],
  theme: {
    extend: {
      fontFamily: {
        display: ['var(--font-display)'],
        sans: ['var(--font-sans)'],
        mono: ['var(--font-mono)'],
      },
      colors: {
        ground: 'var(--bg)',
        surface: 'var(--surface)',
        surface2: 'var(--surface2)',
        edge: 'var(--edge)',
        'edge-strong': 'var(--edge-strong)',
        panel: 'var(--panel-bg)',
        ink: 'var(--ink)',
        ink2: 'var(--ink2)',
        ink3: 'var(--ink3)',
        acc: 'var(--acc)',
        trust: 'var(--trust)',
        ok: 'var(--ok)',
        warn: 'var(--warn)',
        crit: 'var(--crit)',
        'approve-a': 'var(--approve-a)',
        'approve-b': 'var(--approve-b)',
        'approve-ink': 'var(--approve-ink)',
      },
      borderRadius: {
        card: 'var(--radius)',
        ctrl: 'var(--radius-sm)',
      },
      boxShadow: {
        card: 'var(--shadow-card)',
        lift: 'var(--shadow-lift)',
        browser: 'var(--shadow-browser)',
      },
      backdropBlur: {
        glass: 'var(--blur)',
      },
      transitionTimingFunction: {
        'expo-out': 'cubic-bezier(0.16, 1, 0.3, 1)',
      },
    },
  },
} satisfies Config
