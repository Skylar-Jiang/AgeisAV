// Chosen design only: rejected routes and scroll controls must not ship.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const frontend = path.resolve(__dirname, '..');
for (const direction of ['paper', 'slate', 'obsidian']) {
  assert(!fs.existsSync(path.join(frontend, 'src/app', direction, 'page.tsx')), `unused source: ${direction}`);
  assert(!fs.existsSync(path.join(frontend, 'src/app', direction, 'detail/page.tsx')), `unused detail: ${direction}`);
  assert(!fs.existsSync(path.join(frontend, 'out', direction)), `unused export: ${direction}`);
}
for (const name of ['prototype-shell.tsx', 'workspace.tsx', 'linen-scroll-controls.tsx']) {
  assert(!fs.existsSync(path.join(frontend, 'src/components', name)), `unused component: ${name}`);
}
const css = fs.readFileSync(path.join(frontend, 'src/app/globals.css'), 'utf8');
assert(!/theme-(paper|slate|obsidian)|scroll-snap|chooser|linen-scroll-controls/.test(css));
console.log('Single Linen design: source, export and CSS checks passed.');
