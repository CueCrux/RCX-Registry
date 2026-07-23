import { execFileSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

const repositoryRoot = fileURLToPath(new URL('../..', import.meta.url))
const manifest = JSON.parse(
  await readFile(new URL('../spec-v1-freeze.json', import.meta.url), 'utf8')
)

execFileSync('git', ['cat-file', '-e', `${manifest.sourceCommit}^{commit}`], {
  cwd: repositoryRoot,
  stdio: 'inherit',
})
execFileSync('git', ['diff', '--exit-code', manifest.sourceCommit, '--', 'spec/v1'], {
  cwd: repositoryRoot,
  stdio: 'inherit',
})
