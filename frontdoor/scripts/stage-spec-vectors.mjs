import { copyFile, mkdir, readdir, rm } from 'node:fs/promises'

const sourceDir = new URL('../../spec/v1/vectors/', import.meta.url)
const publicDir = new URL('../public/spec/v1/vectors/', import.meta.url)

const entries = (await readdir(sourceDir, { withFileTypes: true }))
  .filter((entry) => entry.isFile() && entry.name.endsWith('.json'))
  .sort((left, right) => left.name.localeCompare(right.name))

if (entries.length === 0) {
  throw new Error('spec/v1/vectors contains no JSON fixtures')
}

await rm(publicDir, { recursive: true, force: true })
await mkdir(publicDir, { recursive: true })

await Promise.all(
  entries.map((entry) =>
    copyFile(new URL(entry.name, sourceDir), new URL(entry.name, publicDir))
  )
)
