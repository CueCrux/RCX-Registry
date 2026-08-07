import { execFileSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

const repositoryRoot = fileURLToPath(new URL('../..', import.meta.url))
const manifest = JSON.parse(
  await readFile(new URL('../spec-v1-freeze.json', import.meta.url), 'utf8')
)

// Assert on the tree hash of spec/v1, not on a diff against a commit sha: a sha
// stops resolving once the PR that introduced it is squash-merged, so a
// commit-pinned check goes red on main the moment it is legitimately bumped.
// The tree hash is the content itself and holds across squashes and shallow
// clones. Bump it only for a dated erratum in spec/v1/README.md.
// HEAD:spec/v1 is the committed content, so it says nothing about uncommitted
// edits. Assert both: no working-tree drift, then the committed tree matches.
execFileSync('git', ['diff', '--exit-code', 'HEAD', '--', 'spec/v1'], {
  cwd: repositoryRoot,
  stdio: 'inherit',
})

const actual = execFileSync('git', ['rev-parse', 'HEAD:spec/v1'], {
  cwd: repositoryRoot,
  encoding: 'utf8',
}).trim()

if (actual !== manifest.specTree) {
  console.error(
    `spec/v1 has drifted from the freeze.\n` +
      `  frozen: ${manifest.specTree}\n` +
      `  actual: ${actual}\n` +
      `v1's wire format is frozen. If this is a deliberate erratum, record it in ` +
      `spec/v1/README.md § Errata and bump specTree in ` +
      `frontdoor/spec-v1-freeze.json. Otherwise, revert the change.\n` +
      `Everything applied since the original freeze: ` +
      `git diff ${manifest.sourceCommit} -- spec/v1`
  )
  process.exit(1)
}
