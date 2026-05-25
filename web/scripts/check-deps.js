#!/usr/bin/env node
// Pre-start dependency guard.
// Checks every package in package.json "dependencies" exists in node_modules.
// If any are missing, runs `npm install --legacy-peer-deps` automatically.
// Invoked by the `prestart` npm hook before server.js binds its port.

import { readFileSync, existsSync } from 'fs';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, '..');

const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
const deps = Object.keys(pkg.dependencies ?? {});

const missing = deps.filter(dep => !existsSync(path.join(root, 'node_modules', dep)));

if (missing.length === 0) {
  console.log('[check-deps] All dependencies present — starting server.');
  process.exit(0);
}

console.warn(`[check-deps] Missing packages detected: ${missing.join(', ')}`);
console.log('[check-deps] Running npm install --legacy-peer-deps...');

try {
  execFileSync('npm', ['install', '--legacy-peer-deps'], { cwd: root, stdio: 'inherit' });
  console.log('[check-deps] Install complete — continuing startup.');
} catch (err) {
  console.error('[check-deps] FATAL: npm install failed. Fix package.json or node_modules and retry.');
  console.error(err.message);
  process.exit(1);
}
