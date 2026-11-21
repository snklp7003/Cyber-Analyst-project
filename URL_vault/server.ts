/**
 * server.ts
 * Main Express backend for URLVault (runs on http://localhost:3000).
 * Has 2 API endpoints:
 *   1. POST /api/scan-url            -> Runs live security checks on a URL or QR link
 *   2. POST /api/generate-lookalikes -> Generates typosquat/homoglyph variants & probes live DNS
 */

import 'dotenv/config';
import { exec } from 'node:child_process';
import dns from 'node:dns';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import {
  checkLiveDns,
  checkLiveRdap,
  checkLiveTls,
  checkThreatFeeds,
  getBaseDomain,
  probeVariantDns,
} from './server/domainIntel.ts';
import {
  checkHomoglyphs,
  findSpoofedBrand,
  generateLookalikeDomains,
} from './server/homoglyphTools.ts';
import type {
  LiveScanResult,
  LookalikeGenerationResult,
  RiskClassification,
  ScanFinding,
} from './src/types/scan.ts';

if (typeof dns.setDefaultResultOrder === 'function') {
  dns.setDefaultResultOrder('ipv4first');
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_PORT = Number(process.env.PORT) || 3000;

const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'rb.gy']);
const LOGIN_WORDS = ['login', 'signin', 'verify', 'password', 'account', 'banking', 'secure'];

// Simple helper: convert a 0-100 score into a risk label
function getRiskLabel(score: number): RiskClassification {
  if (score >= 50) return 'High Risk';
  if (score >= 25) return 'Suspicious';
  return 'Lower Risk';
}

function getNetworkAddress(): string | null {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const netInfo of interfaces[name] || []) {
      if (netInfo.family === 'IPv4' && !netInfo.internal) {
        return netInfo.address;
      }
    }
  }
  return null;
}

function checkPortAvailable(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.once('listening', () => {
      s.close(() => resolve(true));
    });
    s.listen(port, '0.0.0.0');
  });
}

async function getAvailablePort(desiredPort: number): Promise<number> {
  for (let p = desiredPort; p < desiredPort + 20; p++) {
    if (await checkPortAvailable(p)) return p;
  }
  return desiredPort;
}

function openBrowser(url: string) {
  if (process.env.BROWSER === 'none' || process.env.NO_OPEN === 'true') return;
  const cmd =
    process.platform === 'win32'
      ? `start "" "${url}"`
      : process.platform === 'darwin'
        ? `open "${url}"`
        : `xdg-open "${url}"`;
  exec(cmd, () => {});
}

async function startServer() {
  const app = express();
  const httpServer = http.createServer(app);
  app.use(express.json({ limit: '1mb' }));

  // Route 1: Live URL & Domain Intelligence Scanner
  app.post('/api/scan-url', async (req, res) => {
    try {
      const rawUrl = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
      const source: 'url' | 'qr' = req.body?.source === 'qr' ? 'qr' : 'url';
      const qrFileName = typeof req.body?.qrFileName === 'string' ? req.body.qrFileName : undefined;

      if (!rawUrl || /\s/.test(rawUrl)) {
        res.status(400).json({ error: 'Please enter a valid website URL without spaces.' });
        return;
      }

      if (/^(javascript|data|file):/i.test(rawUrl)) {
        res.status(400).json({ error: 'Only http:// and https:// website URLs are supported.' });
        return;
      }

      // Add https:// if the user typed only a domain like "github.com"
      const fullUrl = /^[a-zA-Z]+:\/\//.test(rawUrl) ? rawUrl : `https://${rawUrl}`;
      let parsed: URL;
      try {
        parsed = new URL(fullUrl);
      } catch {
        res.status(400).json({ error: 'Invalid URL format. Example: https://example.com' });
        return;
      }

      const hostname = parsed.hostname.toLowerCase();
      if (!hostname || (!hostname.includes('.') && !net.isIP(hostname))) {
        res.status(400).json({ error: 'Could not extract a valid domain or IP address.' });
        return;
      }

      const baseDomain = getBaseDomain(hostname);
      const homoglyph = checkHomoglyphs(hostname);

      // Run all live internet checks in parallel
      const [dnsInfo, rdapInfo, threatIntel] = await Promise.all([
        checkLiveDns(hostname),
        checkLiveRdap(baseDomain),
        checkThreatFeeds(parsed.href, hostname),
      ]);

      const tlsPort = parsed.port ? Number(parsed.port) : 443;
      const tlsInfo =
        parsed.protocol === 'https:'
          ? await checkLiveTls(hostname, tlsPort, dnsInfo.ipv4)
          : { checked: false, valid: false, error: 'Uses unencrypted HTTP (no SSL certificate).' };

      // Calculate Risk Score (0 - 100) using simple, transparent rules
      const findings: ScanFinding[] = [];
      let score = 0;

      function addRisk(id: string, sourceLabel: string, label: string, points: number, detail: string) {
        score += points;
        findings.push({
          id,
          source: sourceLabel,
          label,
          severity: points >= 30 ? 'danger' : 'warn',
          points,
          detail,
        });
      }

      // Check threat feed results
      for (const feed of threatIntel) {
        if (feed.status === 'malicious') {
          addRisk(`feed-${feed.engine}`, feed.engine, `Flagged malicious by ${feed.engine}`, 70, feed.summary);
        } else if (feed.status === 'suspicious') {
          addRisk(`feed-${feed.engine}`, feed.engine, `Flagged suspicious by ${feed.engine}`, 30, feed.summary);
        }
      }

      // Check homoglyph / Punycode spoof
      if (homoglyph.isPunycode || homoglyph.hasMixedScript) {
        addRisk(
          'homoglyph',
          'Homoglyph Check',
          'IDN Homoglyph / Punycode domain detected',
          40,
          `ASCII "${homoglyph.asciiDomain}" displays as "${homoglyph.unicodeDomain}".`
        );
      }

      // Check DNS, HTTPS/TLS, and RDAP domain age
      if (!dnsInfo.resolved) {
        addRisk('dns', 'Live DNS', 'Domain does not resolve in DNS', 25, dnsInfo.error || 'No IP record found.');
      }
      if (parsed.protocol === 'http:') {
        addRisk('http', 'Transport', 'Unencrypted HTTP protocol', 20, 'Uses http:// instead of https://.');
      } else if (tlsInfo.checked && !tlsInfo.valid) {
        addRisk('tls', 'Live TLS', 'Invalid SSL/TLS certificate', 30, tlsInfo.error || 'Untrusted certificate.');
      }
      if (rdapInfo.found && typeof rdapInfo.domainAgeDays === 'number' && rdapInfo.domainAgeDays < 30) {
        addRisk(
          'new-domain',
          'Live RDAP',
          `Newly registered domain (${rdapInfo.domainAgeDays} days old)`,
          30,
          'Very new domains are frequently used for phishing campaigns.'
        );
      }

      // Check basic structural red flags
      if (net.isIP(hostname)) {
        addRisk('ip', 'Host Check', 'Raw IP address used instead of domain', 35, `Host "${hostname}" is an IP address.`);
      }
      if (rawUrl.includes('@')) {
        addRisk('at-sign', 'URL Structure', 'Contains "@" redirect trick', 25, 'The "@" symbol can hide the real host.');
      }
      if (SHORTENERS.has(baseDomain)) {
        addRisk('shortener', 'URL Structure', `URL shortener (${baseDomain})`, 15, 'Shortened links hide the real destination.');
      }

      const spoofed = findSpoofedBrand(hostname, baseDomain);
      if (spoofed && !homoglyph.isPunycode) {
        addRisk(
          'spoof',
          'Typosquat Check',
          `Possible lookalike of "${spoofed}"`,
          35,
          `Domain "${hostname}" resembles "${spoofed}" while pointing to "${baseDomain}".`
        );
      }

      const isOldTrustedDomain = rdapInfo.found && (rdapInfo.domainAgeDays ?? 0) >= 365;
      const foundWords = LOGIN_WORDS.filter((w) => rawUrl.toLowerCase().includes(w));
      if (foundWords.length > 0 && (!isOldTrustedDomain || parsed.protocol === 'http:' || !dnsInfo.resolved)) {
        addRisk(
          'keywords',
          'URL Content',
          `Credential keyword(s): ${foundWords.slice(0, 3).join(', ')}`,
          15,
          'Uses login/verification terms on an unencrypted or unestablished host.'
        );
      }

      const riskScore = Math.min(100, score);
      const classification = getRiskLabel(riskScore);

      const summary =
        classification === 'High Risk'
          ? `High Risk (${riskScore}/100): Strong phishing or security warning signs found on ${hostname}.`
          : classification === 'Suspicious'
            ? `Suspicious (${riskScore}/100): Some warning signs were detected on ${hostname}. Verify before trusting.`
            : `Lower Risk (${riskScore}/100): Live checks found no major threats on ${hostname}. Always verify before entering passwords.`;

      const result: LiveScanResult = {
        source,
        scannedUrl: rawUrl,
        extractedDomain: hostname,
        baseDomain,
        protocol: parsed.protocol.replace(':', '').toUpperCase(),
        scannedAt: new Date().toISOString(),
        riskScore,
        classification,
        summary,
        findings,
        homoglyph,
        dns: dnsInfo,
        tls: tlsInfo,
        rdap: rdapInfo,
        threatIntel,
        qrFileName,
      };

      res.json({ result });
    } catch {
      res.status(500).json({ error: 'Live scan failed due to an unexpected server error.' });
    }
  });

  // Route 2: Defensive Homoglyph & Typosquatting Generator + Live DNS Probe
  app.post('/api/generate-lookalikes', async (req, res) => {
    try {
      const input = typeof req.body?.domain === 'string' ? req.body.domain.trim() : '';
      const clean = input
        .toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/^www\./, '')
        .split('/')[0];

      if (!clean || !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(clean) || net.isIP(clean)) {
        res.status(400).json({ error: 'Enter a valid domain name such as github.com or example.com.' });
        return;
      }

      const base = getBaseDomain(clean);
      const rawList = generateLookalikeDomains(base);
      const probed = await Promise.all(rawList.map((item) => probeVariantDns(item)));
      probed.sort((a, b) => Number(b.isActive) - Number(a.isActive));

      const result: LookalikeGenerationResult = {
        sourceDomain: base,
        generatedAt: new Date().toISOString(),
        totalGenerated: probed.length,
        activeCount: probed.filter((v) => v.isActive).length,
        mxActiveCount: probed.filter((v) => v.hasMx).length,
        homoglyphCount: probed.filter((v) => v.category === 'homoglyph').length,
        variants: probed,
      };

      res.json({ result });
    } catch {
      res.status(500).json({ error: 'Failed to generate lookalike domains.' });
    }
  });

  // Attach Vite frontend in development, or serve built files in production
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  // Find an available port if DEFAULT_PORT (3000) is held by another process
  const activePort = await getAvailablePort(DEFAULT_PORT);
  if (activePort !== DEFAULT_PORT) {
    console.log(`\x1b[33m\n[Port Notice] Port ${DEFAULT_PORT} is in use. Automatically switching to port ${activePort}...\x1b[0m`);
  }

  httpServer.listen(activePort, '0.0.0.0', () => {
    const localUrl = `http://localhost:${activePort}`;
    const lanIp = getNetworkAddress();
    const networkUrl = lanIp ? `http://${lanIp}:${activePort}` : null;

    const gsb = process.env.GOOGLE_SAFE_BROWSING_API_KEY?.trim() ? 'Active' : 'Optional (Not set)';
    const vt = process.env.VIRUSTOTAL_API_KEY?.trim() ? 'Active' : 'Optional (Not set)';

    console.log('');
    console.log('  \x1b[36m\x1b[1m🛡️   URLVault — Phishing Domain Generator & Quishing Scanner\x1b[0m');
    console.log('');
    console.log(`  \x1b[32m➜\x1b[0m  \x1b[1mLocal:\x1b[0m    \x1b[36m${localUrl}/\x1b[0m  \x1b[90m(Ctrl + Click to open in browser)\x1b[0m`);
    if (networkUrl) {
      console.log(`  \x1b[32m➜\x1b[0m  \x1b[1mNetwork:\x1b[0m  \x1b[36m${networkUrl}/\x1b[0m`);
    }
    console.log('');
    console.log(`  \x1b[90m• Live Engines: DNS, TLS/SSL, RDAP, urlscan.io, URLhaus\x1b[0m`);
    console.log(`  \x1b[90m• Threat Feeds: Google Safe Browsing (${gsb}) | VirusTotal (${vt})\x1b[0m`);
    console.log('');

    // Open browser automatically in dev mode so the user doesn't have to manually navigate
    if (process.env.NODE_ENV !== 'production') {
      openBrowser(localUrl);
    }
  });
}

startServer();
