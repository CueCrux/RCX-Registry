import { defineContentConfig, defineCollection } from '@nuxt/content'
import { fileURLToPath } from 'node:url'

const specV1Dir = fileURLToPath(new URL('../spec/v1', import.meta.url))

export default defineContentConfig({
  collections: {
    content: defineCollection({
      type: 'page',
      source: '**/*.md',
    }),
    specV1: defineCollection({
      type: 'page',
      source: {
        cwd: specV1Dir,
        include: '**/*.md',
        exclude: ['reimpl/**'],
        prefix: '/spec/v1',
      },
    }),
  },
})
