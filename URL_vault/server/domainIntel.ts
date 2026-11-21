/**
 * domainIntel.ts
 * Performs live internet checks for a domain without ever opening the webpage:
 * 1. Live DNS records (IP address, nameservers, mail servers)
 * 2. Live SSL/TLS certificate check
 * 3. Live RDAP domain registration & age check
 * 4. Live Threat Intelligence APIs (urlscan.io, URLhaus, Google Safe Browsing, VirusTotal)
 */

import dnsPromises from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';
import type {
  LiveDnsInfo,
  LiveRdapInfo,
  LiveTlsInfo,
  LookalikeVariant,
  ThreatEngineResult,
} from '../src/types/scan.ts';

const TIMEOUT_MS = 4500;

// Official public RDAP servers for common domain extensions (free, no API key needed)
const RDAP_SERVERS: Record<string, string> = {
  com: 'https://rdap.verisign.com/com/v1/',
  net: 'https://rdap.verisign.com/net/v1/',
  org: 'https://rdap.publicinterestregistry.org/rdap/',
  io: 'https://rdap.identitydigital.services/rdap/',
  ai: 'https://rdap.identitydigital.services/rdap/',
  me: 'https://rdap.identitydigital.services/rdap/',
  dev: 'https://pubapi.registry.google/rdap/',
  app: 'https://pubapi.registry.google/rdap/',
  in: 'https://rdap.nixiregistry.in/rdap/',
  uk: 'https://rdap.nominet.uk/uk/',
};

// Helper: fetch with an automatic timeout so slow APIs never freeze the app
async function simpleFetch(url: string, options: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; URLVault/1.0)',
        ...(options.headers || {}),
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

// Helper: extract root domain (e.g. www.github.com -> github.com)
export function getBaseDomain(hostname: string): string {
  const clean = hostname.toLowerCase().replace(/^www\./, '');
  if (net.isIP(clean)) return clean;
  const parts = clean.split('.').filter(Boolean);
  if (parts.length <= 2) return clean;
  return parts.slice(-2).join('.');
}

// Helper: block scanning private/local IPs like 127.0.0.1 or 192.168.x.x
function isPrivateIp(ip: string): boolean {
  if (!net.isIPv4(ip)) return ip === '::1';
  const [a, b, c] = ip.split('.').map(Number);
  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && c === 2)
  );
}

/**
 * 1. LIVE DNS CHECK — checks if the domain resolves to a real IP address.
 */
export async function checkLiveDns(hostname: string): Promise<LiveDnsInfo> {
  if (net.isIP(hostname)) {
    return {
      resolved: true,
      ipv4: net.isIPv4(hostname) ? [hostname] : [],
      ipv6: net.isIPv6(hostname) ? [hostname] : [],
      nameservers: [],
      hasMx: false,
    };
  }

  const base = getBaseDomain(hostname);
  const [aRes, nsRes, mxRes] = await Promise.allSettled([
    dnsPromises.resolve4(hostname),
    dnsPromises.resolveNs(base),
    dnsPromises.resolveMx(base),
  ]);

  let ipv4 = aRes.status === 'fulfilled' ? aRes.value : [];
  const nameservers = nsRes.status === 'fulfilled' ? nsRes.value.slice(0, 3) : [];
  const hasMx = mxRes.status === 'fulfilled' && mxRes.value.length > 0;

  // Fallback to standard OS lookup if direct A-record lookup failed (handles CNAMEs)
  if (ipv4.length === 0) {
    try {
      const lookup = await dnsPromises.lookup(hostname);
      ipv4 = [lookup.address];
    } catch {
      return {
        resolved: false,
        ipv4: [],
        ipv6: [],
        nameservers,
        hasMx,
        error: 'Domain does not resolve to an active IP address in live DNS.',
      };
    }
  }

  return { resolved: true, ipv4: ipv4.slice(0, 4), ipv6: [], nameservers, hasMx };
}

/**
 * 2. LIVE SSL / TLS CERTIFICATE CHECK — inspects the HTTPS padlock certificate safely.
 */
export function checkLiveTls(
  hostname: string,
  port: number,
  ips: string[]
): Promise<LiveTlsInfo> {
  if (hostname === 'localhost' || isPrivateIp(hostname) || ips.some(isPrivateIp)) {
    return Promise.resolve({
      checked: false,
      valid: false,
      error: 'TLS check skipped for private or reserved IP address.',
    });
  }

  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: net.isIP(hostname) ? undefined : hostname,
        rejectUnauthorized: false,
        timeout: TIMEOUT_MS,
      },
      () => {
        const cert = socket.getPeerCertificate();
        const isTrusted = socket.authorized;
        const protocol = socket.getProtocol() || undefined;
        socket.destroy();

        if (!cert || !cert.subject) {
          resolve({ checked: true, valid: false, error: 'Server returned no TLS certificate.' });
          return;
        }

        const expiryTime = cert.valid_to ? Date.parse(cert.valid_to) : NaN;
        const daysRemaining = Number.isNaN(expiryTime)
          ? undefined
          : Math.floor((expiryTime - Date.now()) / (1000 * 60 * 60 * 24));

        resolve({
          checked: true,
          valid: isTrusted,
          issuer: String(cert.issuer?.O || cert.issuer?.CN || 'Unknown Issuer'),
          subject: String(cert.subject?.CN || hostname),
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          daysRemaining,
          protocol,
          error: isTrusted ? undefined : 'SSL certificate failed trust verification.',
        });
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ checked: true, valid: false, error: 'TLS handshake timed out.' });
    });

    socket.on('error', (err) => {
      socket.destroy();
      resolve({ checked: true, valid: false, error: `TLS error: ${err.message}` });
    });
  });
}

/**
 * 3. LIVE DOMAIN AGE CHECK (RDAP) — finds real registration date & registrar.
 */
export async function checkLiveRdap(baseDomain: string): Promise<LiveRdapInfo> {
  if (net.isIP(baseDomain)) {
    return { checked: false, found: false, error: 'RDAP applies to domain names, not IP addresses.' };
  }

  const tld = baseDomain.split('.').pop()?.toLowerCase() || '';
  const serverUrl = RDAP_SERVERS[tld] || 'https://rdap.org/';

  try {
    const res = await simpleFetch(`${serverUrl}domain/${encodeURIComponent(baseDomain)}`, {
      headers: { Accept: 'application/rdap+json, application/json' },
    });

    if (!res.ok) {
      return { checked: true, found: false, error: 'Registration details not available via RDAP.' };
    }

    const data = (await res.json()) as {
      events?: Array<{ eventAction?: string; eventDate?: string }>;
      entities?: Array<{ roles?: string[]; vcardArray?: unknown[] }>;
    };

    const created = (data.events || []).find((e) =>
      ['registration', 'creation', 'registered'].includes((e.eventAction || '').toLowerCase())
    );
    const expires = (data.events || []).find(
      (e) => (e.eventAction || '').toLowerCase() === 'expiration'
    );

    // Extract registrar name if present in RDAP entities
    let registrar: string | undefined;
    const regEntity = (data.entities || []).find((ent) => ent.roles?.includes('registrar'));
    if (regEntity && Array.isArray(regEntity.vcardArray) && Array.isArray(regEntity.vcardArray[1])) {
      const fnRow = (regEntity.vcardArray[1] as unknown[][]).find((row) => row[0] === 'fn');
      if (fnRow && typeof fnRow[3] === 'string') registrar = fnRow[3];
    }

    let domainAgeDays: number | undefined;
    if (created?.eventDate) {
      const createdMs = Date.parse(created.eventDate);
      if (!Number.isNaN(createdMs)) {
        domainAgeDays = Math.max(0, Math.floor((Date.now() - createdMs) / (1000 * 60 * 60 * 24)));
      }
    }

    return {
      checked: true,
      found: true,
      registrar,
      createdDate: created?.eventDate,
      expiresDate: expires?.eventDate,
      domainAgeDays,
    };
  } catch {
    return { checked: true, found: false, error: 'RDAP lookup timed out.' };
  }
}

/**
 * 4. LIVE THREAT FEEDS — urlscan.io, URLhaus, plus optional Google Safe Browsing & VirusTotal.
 */
export async function checkThreatFeeds(
  fullUrl: string,
  hostname: string
): Promise<ThreatEngineResult[]> {
  const [urlscan, urlhaus, safeBrowsing, virusTotal] = await Promise.all([
    checkUrlscan(hostname),
    checkUrlhaus(fullUrl),
    checkGoogleSafeBrowsing(fullUrl),
    checkVirusTotal(fullUrl, hostname),
  ]);

  return [urlscan, urlhaus, safeBrowsing, virusTotal];
}

async function checkUrlscan(hostname: string): Promise<ThreatEngineResult> {
  try {
    const res = await simpleFetch(
      `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(hostname)}&size=10`
    );
    if (!res.ok) {
      return { engine: 'urlscan.io', status: 'unavailable', summary: `HTTP ${res.status}` };
    }
    const data = (await res.json()) as {
      results?: Array<{ verdicts?: { overall?: { malicious?: boolean } } }>;
    };
    const scans = data.results || [];
    const malicious = scans.filter((s) => s.verdicts?.overall?.malicious === true).length;

    if (malicious > 0) {
      return {
        engine: 'urlscan.io',
        status: 'malicious',
        summary: `${malicious} of ${scans.length} recent scans flagged this domain as malicious.`,
      };
    }
    return {
      engine: 'urlscan.io',
      status: 'clean',
      summary:
        scans.length > 0
          ? `0 malicious flags across ${scans.length} recent live scans.`
          : 'No malicious scans recorded for this domain.',
    };
  } catch {
    return { engine: 'urlscan.io', status: 'unavailable', summary: 'Lookup timed out.' };
  }
}

async function checkUrlhaus(fullUrl: string): Promise<ThreatEngineResult> {
  try {
    const body = new URLSearchParams({ url: fullUrl });
    const res = await simpleFetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    if (!res.ok) {
      return { engine: 'URLhaus (abuse.ch)', status: 'unavailable', summary: `HTTP ${res.status}` };
    }
    const data = (await res.json()) as { query_status?: string; threat?: string };
    if (data.query_status === 'ok') {
      return {
        engine: 'URLhaus (abuse.ch)',
        status: 'malicious',
        summary: `Listed in URLhaus active threat feed (${data.threat || 'malware'}).`,
      };
    }
    return {
      engine: 'URLhaus (abuse.ch)',
      status: 'clean',
      summary: 'Not listed in abuse.ch URLhaus active threat database.',
    };
  } catch {
    return { engine: 'URLhaus (abuse.ch)', status: 'unavailable', summary: 'Database unreachable.' };
  }
}

async function checkGoogleSafeBrowsing(fullUrl: string): Promise<ThreatEngineResult> {
  const key = process.env.GOOGLE_SAFE_BROWSING_API_KEY?.trim();
  if (!key) {
    return {
      engine: 'Google Safe Browsing v4',
      status: 'not_configured',
      summary: 'Optional — add GOOGLE_SAFE_BROWSING_API_KEY in .env to enable.',
    };
  }

  try {
    const res = await simpleFetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'urlvault', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: fullUrl }],
          },
        }),
      }
    );
    if (!res.ok) {
      return { engine: 'Google Safe Browsing v4', status: 'unavailable', summary: `HTTP ${res.status}` };
    }
    const data = (await res.json()) as { matches?: Array<{ threatType?: string }> };
    if (data.matches && data.matches.length > 0) {
      return {
        engine: 'Google Safe Browsing v4',
        status: 'malicious',
        summary: `Flagged for ${data.matches[0].threatType || 'phishing/malware'}.`,
      };
    }
    return {
      engine: 'Google Safe Browsing v4',
      status: 'clean',
      summary: 'No phishing or malware matches found.',
    };
  } catch {
    return { engine: 'Google Safe Browsing v4', status: 'unavailable', summary: 'Request timed out.' };
  }
}

async function checkVirusTotal(fullUrl: string, hostname: string): Promise<ThreatEngineResult> {
  const key = process.env.VIRUSTOTAL_API_KEY?.trim();
  if (!key) {
    return {
      engine: 'VirusTotal API v3',
      status: 'not_configured',
      summary: 'Optional — add VIRUSTOTAL_API_KEY in .env to enable 90+ vendor checks.',
    };
  }

  try {
    const urlId = Buffer.from(fullUrl).toString('base64url');
    let res = await simpleFetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': key },
    });

    // If exact URL is new (404), check domain reputation instead
    if (res.status === 404 && !net.isIP(hostname)) {
      res = await simpleFetch(
        `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(hostname)}`,
        { headers: { 'x-apikey': key } }
      );
    }

    if (!res.ok) {
      return { engine: 'VirusTotal API v3', status: 'unavailable', summary: `HTTP ${res.status}` };
    }

    const data = (await res.json()) as {
      data?: {
        attributes?: {
          last_analysis_stats?: {
            malicious?: number;
            suspicious?: number;
            harmless?: number;
            undetected?: number;
          };
        };
      };
    };
    const stats = data.data?.attributes?.last_analysis_stats;
    if (!stats) {
      return { engine: 'VirusTotal API v3', status: 'clean', summary: 'No malicious record found.' };
    }

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = malicious + suspicious + (stats.harmless || 0) + (stats.undetected || 0);

    if (malicious > 0) {
      return {
        engine: 'VirusTotal API v3',
        status: 'malicious',
        summary: `${malicious} of ${total} security vendors flagged this target as malicious.`,
      };
    }
    if (suspicious > 0) {
      return {
        engine: 'VirusTotal API v3',
        status: 'suspicious',
        summary: `${suspicious} of ${total} vendors marked this target as suspicious.`,
      };
    }
    return {
      engine: 'VirusTotal API v3',
      status: 'clean',
      summary: `0 of ${total} VirusTotal vendors flagged this target.`,
    };
  } catch {
    return { engine: 'VirusTotal API v3', status: 'unavailable', summary: 'Request timed out.' };
  }
}

/**
 * Checks live DNS (IPv4 + MX mail) for one generated lookalike domain.
 */
export async function probeVariantDns(
  variant: Omit<LookalikeVariant, 'dnsChecked' | 'isActive'>
): Promise<LookalikeVariant> {
  const timeout = new Promise<null>((resolve) => setTimeout(() => resolve(null), 2000));

  const check = (async () => {
    const [aRes, mxRes] = await Promise.allSettled([
      dnsPromises.resolve4(variant.asciiDomain),
      dnsPromises.resolveMx(variant.asciiDomain),
    ]);
    const ipv4 = aRes.status === 'fulfilled' ? aRes.value[0] : undefined;
    const hasMx = mxRes.status === 'fulfilled' && mxRes.value.length > 0;
    return { ipv4, hasMx, isActive: Boolean(ipv4 || hasMx) };
  })();

  const result = await Promise.race([check, timeout]);
  return {
    ...variant,
    dnsChecked: true,
    isActive: Boolean(result?.isActive),
    ipv4: result?.ipv4,
    hasMx: result?.hasMx,
  };
}
