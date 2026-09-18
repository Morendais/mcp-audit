#!/usr/bin/env node

const os = require('os');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const https = require('https');

const VERSION = '0.2.0';
const REPO = 'mcphunter/mcp-hunter';

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
  const binName = `mcp-hunter${ext}`;

  return { osName, archName, binName };
}

function resolveBinaryPath() {
  const { osName, archName, binName } = getPlatformBinary();

  // 1. Check adjacent compiled binary (e.g. repo root or local build)
  const localPaths = [
    path.join(__dirname, '..', binName),
    path.join(__dirname, binName),
    path.join(__dirname, '..', 'dist', binName),
    path.join(__dirname, '..', 'bin', `${osName}_${archName}`, binName)
  ];

  for (const p of localPaths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }

  // 2. Check user cache directory (~/.mcp-hunter/bin/mcp-hunter)
  const cacheDir = path.join(os.homedir(), '.mcp-hunter', 'bin');
  const cachedBin = path.join(cacheDir, `mcp-hunter-${VERSION}-${osName}-${archName}${getPlatformBinary().binName.endsWith('.exe') ? '.exe' : ''}`);
  if (fs.existsSync(cachedBin)) {
    return cachedBin;
  }

  return null;
}

function downloadBinary(targetPath, callback) {
  const { osName, archName } = getPlatformBinary();
  const ext = osName === 'windows' ? '.zip' : '.tar.gz';
  const downloadUrl = `https://github.com/${REPO}/releases/download/v${VERSION}/mcp-hunter_${osName}_${archName}${ext}`;

  console.log(`[mcp-hunter] Downloading pre-built binary for ${osName}/${archName}...`);
  console.log(`[mcp-hunter] URL: ${downloadUrl}`);

  // In offline or pre-release mode, if download fails or is pending, provide graceful instructions
  callback(new Error(`Binary not yet downloaded. Please install mcp-hunter natively or build with 'go build'.`));
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

  // If local binary is not found, check if mcp-hunter is already in system PATH
  const whichResult = spawnSync(os.platform() === 'win32' ? 'where' : 'which', ['mcp-hunter'], { encoding: 'utf-8' });
  if (whichResult.status === 0 && whichResult.stdout) {
    const systemBin = whichResult.stdout.trim().split(/\r?\n/)[0];
    if (systemBin && fs.existsSync(systemBin)) {
      const result = spawnSync(systemBin, args, { stdio: 'inherit' });
      process.exit(result.status ?? 0);
    }
  }

  // Fallback: Inform user how to build or download
  console.log('\x1b[1;36m[mcp-hunter]\x1b[0m Zero-config MCP security scanner');
  console.log('\x1b[33mPre-built binary not found locally in npm package.\x1b[0m');
  console.log('To run native mcp-hunter, choose one of:');
  console.log('  1. Shell install (Linux/macOS):   curl -fsSL https://mcphunter.dev/install.sh | bash');
  console.log('  2. PowerShell (Windows):         irm https://mcphunter.dev/install.ps1 | iex');
  console.log('  3. Go install:                   go install github.com/mcphunter/mcp-hunter@latest');
  console.log('  4. Build from source:            git clone https://github.com/mcphunter/mcp-hunter && go build');
  process.exit(1);
}

main();
