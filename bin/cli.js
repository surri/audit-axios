#!/usr/bin/env node

// audit-axios — Scan local repos for vulnerable axios versions and patch interactively
// Usage: audit-axios [options] [directories...]
// Options:
//   --scan-only     Only scan, don't prompt for actions
//   --auto-patch    Automatically patch all vulnerable repos
//   --min-version   Minimum safe version (default: 1.15.0)
//   --target        Target version to patch to (default: ^1.15.0)
//   --help          Show help

const fs = require('fs')
const path = require('path')
const { execSync } = require('child_process')
const c = require('../lib/colors')
const { checkboxSelect, actionSelect, restoreTerminal } = require('../lib/ui')

// ─── Constants ───────────────────────────────────────────────────────────────

const DEFAULT_MIN_VERSION = '1.15.0'
const DEFAULT_TARGET = '^1.15.0'
const MAX_DEPTH = 4
const ADVISORY_ID = 'GHSA-fvcv-3m26-pcqx'
const CVE_ID = 'CVE-2026-40175'
const VERSION_SPEC_RE = /^[\^~>=<\s]*\d+\.\d+\.\d+(-[\w.]+)?$/
const SEMVER_RE = /^\d+\.\d+(\.\d+)?/

// Always skipped — never useful to recurse into
const ALWAYS_IGNORED = new Set([
  'node_modules', '.next', '.git',
])

// Skipped by default, included with --include-all
const SOFT_IGNORED = new Set([
  '.cache',
  // IDE extensions (explicit)
  '.vscode', '.cursor', '.kiro', '.zed', '.antigravity',
  // Package managers / caches
  '.npm', '.yarn', '.pnpm-store', '.bun',
  // Other tooling
  '.cargo', '.rustup', '.gradle', '.m2', '.cocoapods',
  'Library', '.Trash',
])

function isIgnoredDir(dirPath, entryName, includeAll) {
  if (ALWAYS_IGNORED.has(entryName)) return true
  if (includeAll) return false
  if (SOFT_IGNORED.has(entryName)) return true
  if (entryName.startsWith('.') && fs.existsSync(path.join(dirPath, entryName, 'extensions'))) return true
  return false
}

// ─── Environment ─────────────────────────────────────────────────────────────

function getHomeDir() {
  const home = process.env.HOME || process.env.USERPROFILE
  if (!home) {
    console.error(c.red('Error: HOME directory not set'))
    process.exit(1)
  }
  return home
}

const HOME = getHomeDir()

// ─── Version Utilities ───────────────────────────────────────────────────────

function parseVersion(ver) {
  if (!ver || typeof ver !== 'string') return null
  const cleaned = ver.replace(/^[\^~>=<\s]+/, '')
  if (!SEMVER_RE.test(cleaned)) return null
  const parts = cleaned.split('.').map(Number)
  return { major: parts[0] || 0, minor: parts[1] || 0, patch: parts[2] || 0 }
}

function isVulnerable(version, minSafe) {
  const v = parseVersion(version)
  const m = parseVersion(minSafe)
  if (!v || !m) return true

  if (v.major !== m.major) return v.major < m.major
  if (v.minor !== m.minor) return v.minor < m.minor
  return v.patch < m.patch
}

function severityLabel(version) {
  const v = parseVersion(version)
  if (!v) return c.red('CRITICAL')
  if (v.major === 0) return c.red('CRITICAL')
  if (v.minor < 10) return c.red('HIGH')
  return c.yellow('MEDIUM')
}

// ─── File System Scanning ────────────────────────────────────────────────────

function resolveTilde(dir) {
  return path.resolve(dir.replace(/^~(?=$|\/)/, HOME))
}

function findPackageJsonFiles(dirs, maxDepth, includeAll) {
  const results = []

  function walk(dir, depth) {
    if (depth > maxDepth) return

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true })

      for (const entry of entries) {
        if (isIgnoredDir(dir, entry.name, includeAll)) continue
        if (entry.isSymbolicLink()) continue

        const fullPath = path.join(dir, entry.name)

        if (entry.name === 'package.json' && entry.isFile()) {
          results.push(fullPath)
        } else if (entry.isDirectory()) {
          walk(fullPath, depth + 1)
        }
      }
    } catch {
      // permission denied — skip
    }
  }

  for (const dir of dirs) {
    const resolved = resolveTilde(dir)
    if (fs.existsSync(resolved)) {
      walk(resolved, 0)
    } else {
      console.error(c.yellow(`  Warning: ${dir} does not exist, skipping`))
    }
  }

  return results
}

function detectPackageManager(dir) {
  let current = dir
  const root = path.parse(current).root

  while (current !== root) {
    const rootPkg = path.join(current, 'package.json')
    if (fs.existsSync(rootPkg)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(rootPkg, 'utf8'))
        if (pkg.packageManager) {
          if (pkg.packageManager.startsWith('pnpm')) return 'pnpm'
          if (pkg.packageManager.startsWith('yarn')) return 'yarn'
          if (pkg.packageManager.startsWith('npm')) return 'npm'
        }
      } catch { /* ignore */ }
    }
    if (fs.existsSync(path.join(current, 'pnpm-lock.yaml'))) return 'pnpm'
    if (fs.existsSync(path.join(current, 'yarn.lock'))) return 'yarn'
    if (fs.existsSync(path.join(current, 'package-lock.json'))) return 'npm'

    const parent = path.dirname(current)
    if (parent === current) break
    current = parent
  }

  return 'unknown'
}

function getInstalledVersion(dir) {
  const axiosPkg = path.join(dir, 'node_modules', 'axios', 'package.json')
  if (!fs.existsSync(axiosPkg)) return null

  try {
    return JSON.parse(fs.readFileSync(axiosPkg, 'utf8')).version
  } catch {
    return null
  }
}

function getSpecVersion(pkgPath) {
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
    const depVersion = pkg.dependencies?.axios
    const devDepVersion = pkg.devDependencies?.axios
    return {
      version: depVersion || devDepVersion || null,
      section: depVersion ? 'dependencies' : devDepVersion ? 'devDependencies' : null,
    }
  } catch {
    return { version: null, section: null }
  }
}

// ─── Scanning ────────────────────────────────────────────────────────────────

function scanRepos(dirs, minVersion, includeAll) {
  const packageJsonFiles = findPackageJsonFiles(dirs, MAX_DEPTH, includeAll)
  const seen = new Set()

  return packageJsonFiles.reduce((repos, pkgPath) => {
    const realPath = fs.realpathSync(pkgPath)
    if (seen.has(realPath)) return repos
    seen.add(realPath)

    const spec = getSpecVersion(pkgPath)
    if (!spec.version) return repos

    const dir = path.dirname(pkgPath)
    const installed = getInstalledVersion(dir)
    const pm = detectPackageManager(dir)
    const effectiveVersion = installed || spec.version
    const vulnerable = isVulnerable(effectiveVersion, minVersion)

    return [...repos, {
      dir,
      shortDir: dir.replace(HOME, '~'),
      specVersion: spec.version,
      installedVersion: installed,
      section: spec.section,
      packageManager: pm,
      vulnerable,
    }]
  }, [])
}

// ─── Workspace Detection ─────────────────────────────────────────────────────

function findWorkspaceRoot(dir) {
  let current = path.dirname(dir)
  const root = path.parse(current).root

  while (current !== root) {
    const pkgPath = path.join(current, 'package.json')
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
        const hasWorkspaces = pkg.workspaces ||
          fs.existsSync(path.join(current, 'pnpm-workspace.yaml'))

        if (hasWorkspaces) return current
      } catch { /* ignore */ }
    }

    const parent = path.dirname(current)
    if (parent === current) break
    current = parent
  }

  return null
}

// ─── Path Validation ─────────────────────────────────────────────────────────

function validateWritePath(filePath) {
  const realPath = fs.realpathSync(path.dirname(filePath))
  if (realPath !== HOME && !realPath.startsWith(HOME + path.sep)) {
    throw new Error(`Refusing to write outside HOME: ${realPath}`)
  }
}

// ─── Actions ─────────────────────────────────────────────────────────────────

function updatePackageJson(pkgPath, targetVersion) {
  const raw = fs.readFileSync(pkgPath, 'utf8')
  const pkg = JSON.parse(raw)
  const indent = raw.match(/^(\s+)/m)?.[1] || '  '

  const updatedPkg = {
    ...pkg,
    ...(pkg.dependencies?.axios && {
      dependencies: { ...pkg.dependencies, axios: targetVersion },
    }),
    ...(pkg.devDependencies?.axios && {
      devDependencies: { ...pkg.devDependencies, axios: targetVersion },
    }),
  }

  fs.writeFileSync(pkgPath, JSON.stringify(updatedPkg, null, indent) + '\n')
}

function runInstall(packageManager, dir, minVersion) {
  const cmds = {
    npm: 'npm install --legacy-peer-deps',
    yarn: 'yarn install --ignore-engines',
    pnpm: 'pnpm install --no-frozen-lockfile',
  }
  const cmd = cmds[packageManager]
  const installDir = findWorkspaceRoot(dir) || dir

  process.stdout.write(c.dim(`  Running ${cmd}...`))
  execSync(cmd, { cwd: installDir, stdio: 'pipe', timeout: 120_000 })

  const newVersion = getInstalledVersion(dir)
  if (newVersion && !isVulnerable(newVersion, minVersion)) {
    console.log(c.green(` installed ${newVersion}`))
    return { success: true, version: newVersion }
  }

  console.log(c.yellow(` installed ${newVersion || 'unknown'} (verify manually)`))
  return { success: true, version: newVersion }
}

function patchRepo(repo, targetVersion, minVersion) {
  const pkgPath = path.join(repo.dir, 'package.json')

  try {
    validateWritePath(pkgPath)
    updatePackageJson(pkgPath, targetVersion)

    if (repo.packageManager === 'unknown') {
      console.log(c.yellow('  package.json updated (no lock file — run install manually)'))
      return { success: true, version: null }
    }

    return runInstall(repo.packageManager, repo.dir, minVersion)
  } catch (err) {
    console.log(c.red(`  Failed: ${err.message}`))
    return { success: false, version: null }
  }
}

function removeAxios(repo) {
  try {
    const wsRoot = findWorkspaceRoot(repo.dir)
    const cmd = wsRoot
      ? buildWorkspaceRemoveCmd(repo.packageManager, repo.dir, wsRoot)
      : buildRemoveCmd(repo.packageManager)

    if (!cmd) {
      console.log(c.yellow('  Unknown package manager — remove manually'))
      return false
    }

    process.stdout.write(c.dim(`  Running ${cmd}...`))
    execSync(cmd, { cwd: wsRoot || repo.dir, stdio: 'pipe', timeout: 60_000 })
    console.log(c.green(' done'))
    return true
  } catch (err) {
    console.log(c.red(`  Failed: ${err.message}`))
    return false
  }
}

function buildRemoveCmd(pm) {
  const cmds = { npm: 'npm uninstall axios', yarn: 'yarn remove axios', pnpm: 'pnpm remove axios' }
  return cmds[pm] || null
}

function buildWorkspaceRemoveCmd(pm, pkgDir, wsRoot) {
  const pkgName = readPackageName(pkgDir)

  if (pm === 'pnpm') return pkgName ? `pnpm remove axios --filter ${pkgName}` : `pnpm remove axios --filter ${pkgDir}`
  if (pm === 'yarn') return pkgName ? `yarn workspace ${pkgName} remove axios` : null
  if (pm === 'npm') return pkgName ? `npm uninstall axios -w ${pkgName}` : null
  return null
}

function readPackageName(dir) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).name || null
  } catch {
    return null
  }
}

// ─── Display ─────────────────────────────────────────────────────────────────

function printHeader(minVersion) {
  console.log('')
  console.log(c.bold('  axios vulnerability scanner'))
  console.log(c.dim(`  ${CVE_ID} (${ADVISORY_ID})`))
  console.log(c.dim(`  Vulnerable: < ${minVersion} | Fix: upgrade to >= ${minVersion}`))
  console.log('')
}

function printScanResults(repos) {
  const vulnerable = repos.filter((r) => r.vulnerable)
  const safe = repos.filter((r) => !r.vulnerable)

  console.log(c.bold(`  Found ${repos.length} repos with axios`))
  console.log(
    `  ${c.red(`${vulnerable.length} vulnerable`)}  ${c.green(`${safe.length} safe`)}`,
  )
  console.log('')

  if (vulnerable.length === 0) {
    console.log(c.green('  All repos are patched!'))
    return
  }

  console.log(c.bold('  Vulnerable repos:'))
  console.log(c.dim('  ─'.repeat(35)))

  for (const [i, repo] of vulnerable.entries()) {
    const ver = repo.installedVersion || repo.specVersion
    const severity = severityLabel(ver)
    const pm = c.dim(`[${repo.packageManager}]`)

    console.log(`  ${c.dim(`${i + 1}.`)} ${repo.shortDir}`)
    console.log(`     ${severity} ${c.cyan(ver)} ${pm}`)
  }

  console.log('')
}

// ─── Interactive Mode ────────────────────────────────────────────────────────

async function interactiveMode(vulnerableRepos, targetVersion, minVersion) {
  // Step 1: Checkbox select repos
  console.log(c.bold('  Select repos to act on:\n'))
  const selected = await checkboxSelect(vulnerableRepos, severityLabel)

  if (!selected) {
    console.log(c.dim('\n  Aborted.'))
    return { patched: 0, removed: 0, skipped: vulnerableRepos.length, failed: 0 }
  }

  if (selected.length === 0) {
    console.log(c.yellow('\n  No repos selected.'))
    return { patched: 0, removed: 0, skipped: vulnerableRepos.length, failed: 0 }
  }

  const skippedCount = vulnerableRepos.length - selected.length

  // Step 2: Choose action
  console.log(`\n  ${c.bold(`${selected.length} repos selected.`)} Choose action:\n`)
  const action = await actionSelect(targetVersion)

  if (!action || action === 'skip') {
    console.log(c.dim('\n  Skipped.'))
    return { patched: 0, removed: 0, skipped: vulnerableRepos.length, failed: 0 }
  }

  // Step 3: Execute
  console.log('')
  const results = selected.reduce((acc, repo) => {
    const ver = repo.installedVersion || repo.specVersion
    console.log(`  ${c.cyan(repo.shortDir)} ${c.dim(`(${ver})`)}`)

    if (action === 'patch') {
      const result = patchRepo(repo, targetVersion, minVersion)
      console.log('')
      return result.success
        ? { ...acc, patched: acc.patched + 1 }
        : { ...acc, failed: acc.failed + 1 }
    }

    if (action === 'remove') {
      const ok = removeAxios(repo)
      console.log('')
      return ok
        ? { ...acc, removed: acc.removed + 1 }
        : { ...acc, failed: acc.failed + 1 }
    }

    console.log('')
    return acc
  }, { patched: 0, removed: 0, skipped: skippedCount, failed: 0 })

  return results
}

// ─── CLI Argument Parsing ────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = {
    dirs: [],
    scanOnly: false,
    autoPatch: false,
    minVersion: DEFAULT_MIN_VERSION,
    target: DEFAULT_TARGET,
    includeAll: false,
    help: false,
  }

  let i = 2
  while (i < argv.length) {
    const arg = argv[i]

    switch (arg) {
      case '--scan-only':
        args.scanOnly = true
        break
      case '--auto-patch':
        args.autoPatch = true
        break
      case '--include-all':
        args.includeAll = true
        break
      case '--min-version':
        if (i + 1 >= argv.length) { console.error(c.red('--min-version requires a value')); process.exit(1) }
        args.minVersion = argv[++i]
        if (!VERSION_SPEC_RE.test(args.minVersion)) {
          console.error(c.red(`Invalid --min-version: ${args.minVersion} (expected semver like 1.15.0)`))
          process.exit(1)
        }
        break
      case '--target':
        if (i + 1 >= argv.length) { console.error(c.red('--target requires a value')); process.exit(1) }
        args.target = argv[++i]
        if (!VERSION_SPEC_RE.test(args.target)) {
          console.error(c.red(`Invalid --target: ${args.target} (expected version spec like ^1.15.0)`))
          process.exit(1)
        }
        break
      case '--help':
      case '-h':
        args.help = true
        break
      default:
        args.dirs.push(arg)
    }

    i++
  }

  if (args.dirs.length === 0) {
    args.dirs = ['.']
  }

  return args
}

function printHelp() {
  console.log(`
${c.bold('audit-axios')} — Scan local repos for vulnerable axios versions

${c.bold('USAGE')}
  audit-axios [options] [directories...]

${c.bold('OPTIONS')}
  --scan-only          Only scan and report, no prompts
  --auto-patch         Patch all vulnerable repos without prompting
  --min-version VER    Minimum safe version (default: ${DEFAULT_MIN_VERSION})
  --target VER         Target version spec (default: ${DEFAULT_TARGET})
  --include-all        Include IDE extensions, caches, and other system dirs
  -h, --help           Show this help

${c.bold('INTERACTIVE CONTROLS')}
  space        Toggle select/deselect repo
  a            Select all
  n            Deselect all
  j/k or arrows  Navigate up/down
  enter        Confirm selection → choose action
  q            Quit

${c.bold('EXAMPLES')}
  audit-axios ~/Workspace ~/Projects
  audit-axios --scan-only ~/Workspace
  audit-axios --auto-patch ~/Projects/itall
  audit-axios --min-version 1.16.0 ~/Workspace

${c.bold('VULNERABILITY')}
  ${CVE_ID} (${ADVISORY_ID})
  CRLF Header Injection → Request Smuggling → SSRF
  Severity: Critical (CVSS 9.9)
  Affected: all axios < ${DEFAULT_MIN_VERSION}
  Advisory: https://github.com/axios/axios/security/advisories/${ADVISORY_ID}
`)
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv)

  if (args.help) {
    printHelp()
    process.exit(0)
  }

  printHeader(args.minVersion)

  process.stdout.write(c.dim('  Scanning...'))
  const repos = scanRepos(args.dirs, args.minVersion, args.includeAll)
  console.log(c.dim(` done\n`))

  printScanResults(repos)

  const vulnerable = repos.filter((r) => r.vulnerable)
  if (vulnerable.length === 0) {
    process.exit(0)
  }

  if (args.scanOnly) {
    process.exit(vulnerable.length > 0 ? 1 : 0)
  }

  if (args.autoPatch) {
    console.log(c.bold('  Auto-patching all vulnerable repos...\n'))
    let failed = 0

    for (const repo of vulnerable) {
      console.log(`  ${c.cyan(repo.shortDir)}`)
      const result = patchRepo(repo, args.target, args.minVersion)
      failed += result.success ? 0 : 1
      console.log('')
    }

    const patched = vulnerable.length - failed
    console.log(c.bold(`\n  Done: ${c.green(`${patched} patched`)} ${failed > 0 ? c.red(`${failed} failed`) : ''}`))
    process.exit(failed > 0 ? 1 : 0)
  }

  // Interactive mode
  const summary = await interactiveMode(vulnerable, args.target, args.minVersion)

  console.log(c.bold('  Summary'))
  console.log(c.dim('  ─'.repeat(20)))
  if (summary.patched > 0) console.log(`  ${c.green(`${summary.patched} patched`)}`)
  if (summary.removed > 0) console.log(`  ${c.blue(`${summary.removed} removed`)}`)
  if (summary.skipped > 0) console.log(`  ${c.yellow(`${summary.skipped} skipped`)}`)
  if (summary.failed > 0) console.log(`  ${c.red(`${summary.failed} failed`)}`)
  console.log('')
}

main().catch((err) => {
  restoreTerminal()
  console.error(c.red(`Error: ${err.message}`))
  process.exit(1)
})
