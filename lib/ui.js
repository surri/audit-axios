const c = require('./colors')

// ─── Terminal Utilities ──────────────────────────────────────────────────────

let interactiveActive = false

const term = {
  clearLine: () => process.stdout.write('\x1b[2K'),
  cursorTo: (col) => process.stdout.write(`\x1b[${col}G`),
  cursorUp: (n) => { if (n > 0) process.stdout.write(`\x1b[${n}A`) },
  cursorDown: (n) => { if (n > 0) process.stdout.write(`\x1b[${n}B`) },
  hideCursor: () => { if (process.stdout.isTTY) process.stdout.write('\x1b[?25l') },
  showCursor: () => { if (process.stdout.isTTY) process.stdout.write('\x1b[?25h') },
}

function restoreTerminal() {
  if (!interactiveActive) return
  if (process.stdin.isTTY && process.stdin.isRaw) process.stdin.setRawMode(false)
  term.showCursor()
  interactiveActive = false
}

process.on('uncaughtException', (err) => {
  restoreTerminal()
  console.error(c.red(`\n  Fatal: ${err.message}`))
  process.exit(1)
})

process.on('exit', restoreTerminal)

// ─── Scrollable Interactive Menu ─────────────────────────────────────────────

function createInteractiveMenu(items, renderFn, onSelect) {
  return new Promise((resolve) => {
    let cursor = 0
    let scrollOffset = 0
    let rendered = 0

    const footerSize = 2
    const maxVisible = Math.max(3, (process.stdout.rows || 20) - footerSize - 2)

    function draw() {
      if (cursor < scrollOffset) scrollOffset = cursor
      if (cursor >= scrollOffset + maxVisible) scrollOffset = cursor - maxVisible + 1

      term.cursorUp(rendered)

      const allLines = renderFn(items, cursor)
      const itemLines = allLines.slice(0, items.length)
      const footerLines = allLines.slice(items.length)
      const visibleItems = itemLines.slice(scrollOffset, scrollOffset + maxVisible)

      const hasMore = items.length > maxVisible
      const topIndicator = hasMore && scrollOffset > 0
        ? c.dim(`  ↑ ${scrollOffset} more`) : ''
      const bottomMore = items.length - scrollOffset - maxVisible
      const bottomIndicator = hasMore && bottomMore > 0
        ? c.dim(`  ↓ ${bottomMore} more`) : ''

      const output = [
        ...(topIndicator ? [topIndicator] : []),
        ...visibleItems,
        ...(bottomIndicator ? [bottomIndicator] : []),
        ...footerLines,
      ]

      for (const line of output) {
        term.clearLine()
        term.cursorTo(1)
        console.log(line)
      }

      const extra = rendered - output.length
      for (let i = 0; i < extra; i++) {
        term.clearLine()
        term.cursorTo(1)
        console.log('')
      }

      rendered = output.length + Math.max(0, extra)
    }

    function cleanup() {
      process.stdin.setRawMode(false)
      process.stdin.removeListener('data', onKey)
      process.stdin.pause()
      term.showCursor()
      interactiveActive = false
    }

    function onKey(key) {
      if (key === '\x03') { cleanup(); process.exit(0) }
      if (key === 'q') { cleanup(); resolve(null); return }

      if (key === '\x1b[A' || key === 'k') {
        const prev = cursor
        cursor = (cursor - 1 + items.length) % items.length
        if (prev === 0 && cursor === items.length - 1) {
          scrollOffset = Math.max(0, items.length - maxVisible)
        }
        draw()
        return
      }
      if (key === '\x1b[B' || key === 'j') {
        cursor = (cursor + 1) % items.length
        if (cursor === 0) scrollOffset = 0
        draw()
        return
      }

      const result = onSelect(key, cursor, items, draw)
      if (result !== undefined) { cleanup(); resolve(result) }
    }

    interactiveActive = true
    term.hideCursor()
    draw()
    process.stdin.setRawMode(true)
    process.stdin.resume()
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', onKey)
  })
}

// ─── Checkbox Select ─────────────────────────────────────────────────────────

function checkboxSelect(repos, severityLabel) {
  let checked = new Array(repos.length).fill(false)

  function render(items, cursor) {
    const lines = items.map((repo, i) => {
      const ver = repo.installedVersion || repo.specVersion
      const severity = severityLabel(ver)
      const pm = c.dim(`[${repo.packageManager}]`)
      const checkbox = checked[i] ? c.green('[x]') : '[ ]'
      const pointer = i === cursor ? c.cyan(' >') : '  '
      const name = i === cursor ? c.bold(repo.shortDir) : repo.shortDir
      return `${pointer} ${checkbox} ${name} ${severity} ${c.cyan(ver)} ${pm}`
    })
    lines.push('', c.dim('  space: toggle  a: all  n: none  enter: confirm  q: quit'))
    return lines
  }

  function onSelect(key, cursor, items, draw) {
    if (key === ' ') {
      checked = checked.map((v, i) => i === cursor ? !v : v)
      draw()
      return undefined
    }
    if (key === 'a') {
      checked = new Array(items.length).fill(true)
      draw()
      return undefined
    }
    if (key === 'n') {
      checked = new Array(items.length).fill(false)
      draw()
      return undefined
    }
    if (key === '\r' || key === '\n') {
      return items.filter((_, i) => checked[i])
    }
    return undefined
  }

  return createInteractiveMenu(repos, render, onSelect)
}

// ─── Action Select ───────────────────────────────────────────────────────────

function actionSelect(targetVersion) {
  const actions = [
    { key: 'p', label: 'patch', desc: `Upgrade to ${targetVersion}` },
    { key: 'r', label: 'remove', desc: 'Uninstall axios' },
    { key: 's', label: 'skip', desc: 'Do nothing' },
  ]

  function render(items, cursor) {
    const lines = items.map((a, i) => {
      const pointer = i === cursor ? c.cyan(' >') : '  '
      const label = i === cursor ? c.bold(a.label) : a.label
      return `${pointer} ${label}  ${c.dim(a.desc)}`
    })
    lines.push('', c.dim('  j/k or arrows: move  enter: confirm'))
    return lines
  }

  function onSelect(key, cursor, items) {
    const match = items.findIndex((a) => a.key === key)
    if (match !== -1) return items[match].label
    if (key === '\r' || key === '\n') return items[cursor].label
    return undefined
  }

  return createInteractiveMenu(actions, render, onSelect)
}

module.exports = { checkboxSelect, actionSelect, restoreTerminal }
