#!/usr/bin/env node

const os = require('os');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const VERSION = '0.2.1';
const REPO = process.env.GITHUB_REPOSITORY || 'Morendais/mcp-audit';

function getPlatformBinary() {
  const platform = os.platform();
  const arch = os.arch();

  let osName = '';
  if (platform === 'win32') osName = 'windows';
  else if (platform === 'darwin') osName = 'darwin';
  else if (platform === 'linux') osName = 'linux';
  else throw new Error(`Unsupported platform: ${platform}`);

  let archName = '';
  if (arch === 'x64') archName = 'amd64';
  else if (arch === 'arm64') archName = 'arm64';
  else throw new Error(`Unsupported architecture: ${arch}`);

  const ext = platform === 'win32' ? '.exe' : '';
  const binName = `mcpaudit${ext}`;
  const legacyName = `mcp-audit${ext}`;

  return { osName, archName, binName, legacyName };
}

function resolveBinaryPath() {
  const { osName, archName, binName, legacyName } = getPlatformBinary();

  // 1. Check adjacent compiled binary (e.g. repo root or local build)
  const localPaths = [
    path.join(__dirname, '..', binName),
    path.join(__dirname, '..', legacyName),
    path.join(__dirname, binName),
    path.join(__dirname, legacyName),
    path.join(__dirname, '..', 'dist', binName),
    path.join(__dirname, '..', 'dist', legacyName),
    path.join(__dirname, '..', 'bin', `${osName}_${archName}`, binName),
    path.join(__dirname, '..', 'bin', `${osName}_${archName}`, legacyName)
  ];

  for (const p of localPaths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }

  // 2. Check user cache directory (~/.mcpaudit/bin)
  const cacheDir = path.join(os.homedir(), '.mcpaudit', 'bin');
  const cachedBin = path.join(cacheDir, `${binName}`);
  if (fs.existsSync(cachedBin)) {
    return cachedBin;
  }

  return null;
}

function main() {
  const args = process.argv.slice(2);

  if (args[0] === '--check-install') {
    return;
  }

  const binPath = resolveBinaryPath();

  if (binPath) {
    const result = spawnSync(binPath, args, { stdio: 'inherit' });
    process.exit(result.status ?? 0);
  }

  // If local binary is not found, check if mcpaudit or mcp-audit is in system PATH
  const lookupCmd = os.platform() === 'win32' ? 'where' : 'which';
  for (const candidate of ['mcpaudit', 'mcp-audit']) {
    const whichResult = spawnSync(lookupCmd, [candidate], { encoding: 'utf-8' });
    if (whichResult.status === 0 && whichResult.stdout) {
      const systemBin = whichResult.stdout.trim().split(/\r?\n/)[0];
      if (systemBin && fs.existsSync(systemBin)) {
        const result = spawnSync(systemBin, args, { stdio: 'inherit' });
        process.exit(result.status ?? 0);
      }
    }
  }

  // Fallback: Inform user how to build or download
  console.log('\x1b[1;36m[mcpaudit]\x1b[0m Zero-config MCP security scanner');
  console.log('\x1b[33mPre-built binary not found locally in npm package.\x1b[0m');
  console.log('Options to install:');
  console.log('  1. Download binary archive from GitHub Releases:');
  console.log(`     https://github.com/${REPO}/releases/latest`);
  console.log('  2. Install via Go:');
  console.log(`     go install github.com/${REPO}@latest`);
  console.log('  3. Build from source:');
  console.log(`     git clone https://github.com/${REPO} && cd mcp-audit && go build -o mcpaudit`);
  process.exit(1);
}

main();
