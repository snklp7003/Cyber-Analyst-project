/**
 * homoglyphTools.ts
 * Algorithmic Homoglyph & Typosquatting Analysis Engine:
 * 1. Confusable Cyrillic/Greek Unicode homoglyph detector & Punycode (xn--) parser.
 * 2. Damerau-Levenshtein edit-distance & leet-speak brand spoofing detection.
 * 3. Algorithmic lookalike permutation generator for brand protection audits.
 */

import { domainToASCII, domainToUnicode } from 'node:url';
import type { HomoglyphAnalysis, LookalikeVariant } from '../src/types/scan.ts';

// Comprehensive Unicode Confusables dictionary (Cyrillic & Greek homoglyphs)
const CONFUSABLES: Record<string, { char: string; script: string; codePoint: string }> = {
  a: { char: '\u0430', script: 'Cyrillic', codePoint: 'U+0430' },
  c: { char: '\u0441', script: 'Cyrillic', codePoint: 'U+0441' },
  e: { char: '\u0435', script: 'Cyrillic', codePoint: 'U+0435' },
  i: { char: '\u0456', script: 'Cyrillic', codePoint: 'U+0456' },
  j: { char: '\u0458', script: 'Cyrillic', codePoint: 'U+0458' },
  o: { char: '\u043E', script: 'Cyrillic', codePoint: 'U+043E' },
  p: { char: '\u0440', script: 'Cyrillic', codePoint: 'U+0440' },
  s: { char: '\u0455', script: 'Cyrillic', codePoint: 'U+0455' },
  x: { char: '\u0445', script: 'Cyrillic', codePoint: 'U+0445' },
  y: { char: '\u0443', script: 'Cyrillic', codePoint: 'U+0443' },
  d: { char: '\u0501', script: 'Cyrillic', codePoint: 'U+0501' },
};

const REVERSE_LOOKUP: Record<string, { script: string; looksLike: string }> = Object.fromEntries(
  Object.entries(CONFUSABLES).map(([latin, info]) => [info.char, { script: info.script, looksLike: latin }])
);

// QWERTY keyboard adjacency map for physical typo simulation
const QWERTY_NEIGHBORS: Record<string, string[]> = {
  a: ['q', 'w', 's', 'z'], b: ['v', 'g', 'h', 'n'], c: ['x', 'd', 'f', 'v'],
  d: ['s', 'e', 'r', 'f', 'x'], e: ['w', 's', 'd', 'r'], f: ['d', 'r', 't', 'g', 'v'],
  g: ['f', 't', 'y', 'h', 'b'], h: ['g', 'y', 'u', 'j', 'n'], i: ['u', 'j', 'k', 'o'],
  j: ['h', 'u', 'i', 'k', 'm'], k: ['j', 'i', 'o', 'l'], l: ['k', 'o', 'p'],
  m: ['n', 'j', 'k'], n: ['b', 'h', 'j', 'm'], o: ['i', 'k', 'l', 'p'],
  p: ['o', 'l'], q: ['w', 'a'], r: ['e', 'd', 'f', 't'], s: ['a', 'w', 'e', 'd', 'x', 'z'],
  t: ['r', 'f', 'g', 'y'], u: ['y', 'h', 'j', 'i'], v: ['c', 'f', 'g', 'b'],
  w: ['q', 'a', 's', 'e'], x: ['z', 's', 'd', 'c'], y: ['t', 'g', 'h', 'u'],
  z: ['a', 's', 'x'],
};

const TARGET_BRANDS: Record<string, string> = {
  google: 'google.com', paypal: 'paypal.com', microsoft: 'microsoft.com',
  apple: 'apple.com', amazon: 'amazon.com', github: 'github.com',
  netflix: 'netflix.com', instagram: 'instagram.com', facebook: 'facebook.com',
  linkedin: 'linkedin.com', coinbase: 'coinbase.com', binance: 'binance.com',
  chase: 'chase.com', wellsfargo: 'wellsfargo.com', bankofamerica: 'bankofamerica.com',
};

/**
 * Damerau-Levenshtein distance algorithm:
 * Calculates minimum single-character edits (insertions, deletions,
 * substitutions, and adjacent transpositions) between two strings.
 */
export function damerauLevenshtein(a: string, b: string): number {
  const la = a.length;
  const lb = b.length;
  if (!la) return lb;
  if (!lb) return la;

  const dp: number[][] = Array.from({ length: la + 1 }, () => new Array(lb + 1).fill(0));
  for (let i = 0; i <= la; i++) dp[i][0] = i;
  for (let j = 0; j <= lb; j++) dp[0][j] = j;

  for (let i = 1; i <= la; i++) {
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,       // deletion
        dp[i][j - 1] + 1,       // insertion
        dp[i - 1][j - 1] + cost // substitution
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1); // transposition
      }
    }
  }
  return dp[la][lb];
}

/**
 * Normalizes visual character substitutions (leet-speak & common optical tricks)
 */
export function normalizeLeetSpeak(str: string): string {
  return str
    .toLowerCase()
    .replace(/[0]/g, 'o')
    .replace(/[1!|]/g, 'l')
    .replace(/[3]/g, 'e')
    .replace(/[4@]/g, 'a')
    .replace(/[5$]/g, 's')
    .replace(/[8]/g, 'b')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w');
}

/**
 * Detects whether a domain uses Punycode (xn--) or mixes Cyrillic/Greek scripts with Latin.
 */
export function checkHomoglyphs(hostname: string): HomoglyphAnalysis {
  const asciiDomain = domainToASCII(hostname) || hostname;
  const unicodeDomain = domainToUnicode(asciiDomain) || hostname;
  const isPunycode = asciiDomain.includes('xn--');

  const suspiciousChars: HomoglyphAnalysis['suspiciousChars'] = [];
  let hasLatin = false;
  let hasNonAscii = false;

  for (const ch of unicodeDomain) {
    const code = ch.codePointAt(0) ?? 0;
    if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) {
      hasLatin = true;
    } else if (code > 127) {
      hasNonAscii = true;
      const hex = 'U+' + code.toString(16).toUpperCase().padStart(4, '0');
      const match = REVERSE_LOOKUP[ch];
      suspiciousChars.push({
        char: ch,
        codePoint: hex,
        script: match ? match.script : 'Unicode',
        looksLike: match ? match.looksLike : 'Latin letter',
      });
    }
  }

  return {
    isPunycode,
    hasMixedScript: hasLatin && hasNonAscii,
    asciiDomain,
    unicodeDomain,
    suspiciousChars,
  };
}

/**
 * Uses Damerau-Levenshtein distance & normalized leet-speak to detect brand impersonation.
 */
export function findSpoofedBrand(hostname: string, baseDomain: string): string | null {
  const host = hostname.toLowerCase();
  const base = baseDomain.toLowerCase();

  // If host is the exact official brand domain or legitimate subdomain, ignore
  for (const official of Object.values(TARGET_BRANDS)) {
    if (host === official || host.endsWith('.' + official)) {
      return null;
    }
  }

  const [rawName] = base.split('.');
  const normName = normalizeLeetSpeak(rawName);

  for (const [brandKey, officialDomain] of Object.entries(TARGET_BRANDS)) {
    // Direct normalized match (e.g. g00gle -> google)
    if (normName === brandKey) {
      return officialDomain;
    }

    // Levenshtein distance check (1 edit for <= 5 chars, 2 edits for longer)
    const maxDist = brandKey.length <= 5 ? 1 : 2;
    const dist = damerauLevenshtein(normName, brandKey);
    if (dist <= maxDist && dist > 0) {
      return officialDomain;
    }

    // Phishing lures with embedded brand (e.g. paypal-login, secure-apple)
    if (normName.includes(brandKey) && rawName !== brandKey) {
      return officialDomain;
    }
  }

  return null;
}

/**
 * Generates defensive typosquatting, homoglyph, and combo-lure domain permutations.
 */
export function generateLookalikeDomains(
  cleanDomain: string
): Array<Omit<LookalikeVariant, 'dnsChecked' | 'isActive'>> {
  const parts = cleanDomain.toLowerCase().split('.');
  const name = parts[0];
  const tld = parts.slice(1).join('.');

  const seen = new Set<string>([cleanDomain]);
  const variants: Array<Omit<LookalikeVariant, 'dnsChecked' | 'isActive'>> = [];

  const add = (
    dom: string,
    technique: LookalikeVariant['technique'],
    category: LookalikeVariant['category'],
    note: string
  ) => {
    const ascii = domainToASCII(dom);
    if (!ascii || seen.has(ascii)) return;
    seen.add(ascii);
    variants.push({ domain: dom, asciiDomain: ascii, technique, category, note });
  };

  // 1. Unicode Homoglyphs (Cyrillic confusable substitution)
  for (let i = 0; i < name.length && variants.length < 5; i++) {
    const conf = CONFUSABLES[name[i]];
    if (conf) {
      const spoof = name.slice(0, i) + conf.char + name.slice(i + 1);
      add(
        `${spoof}.${tld}`,
        'Homoglyph (IDN)',
        'homoglyph',
        `Replaces "${name[i]}" with ${conf.script} "${conf.char}" (${conf.codePoint})`
      );
    }
  }

  // 2. Optical Visual Swaps (l->1, o->0, m->rn, etc.)
  const visualSwaps: [string, string][] = [
    ['l', '1'], ['o', '0'], ['e', '3'], ['s', '5'], ['m', 'rn'], ['w', 'vv']
  ];
  for (const [from, to] of visualSwaps) {
    if (name.includes(from)) {
      add(`${name.replaceAll(from, to)}.${tld}`, 'Visual Swap', 'homoglyph', `Substitutes "${from}" → "${to}"`);
    }
  }

  // 3. Omission Typos (missing key)
  if (name.length >= 4) {
    for (let i = 1; i < Math.min(name.length, 4); i++) {
      add(`${name.slice(0, i) + name.slice(i + 1)}.${tld}`, 'Omission', 'typosquat', `Omits character "${name[i]}"`);
    }
  }

  // 4. Transposition Typos (swapped adjacent keys)
  for (let i = 0; i < Math.min(name.length - 1, 3); i++) {
    if (name[i] !== name[i + 1]) {
      const swapped = name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2);
      add(`${swapped}.${tld}`, 'Transposition', 'typosquat', `Swaps "${name[i]}${name[i + 1]}" → "${name[i + 1]}${name[i]}"`);
    }
  }

  // 5. Physical Keyboard Adjacent (QWERTY distance)
  for (let i = 0; i < Math.min(name.length, 3); i++) {
    const neighbors = QWERTY_NEIGHBORS[name[i]];
    if (neighbors && neighbors[0]) {
      add(
        `${name.slice(0, i) + neighbors[0] + name.slice(i + 1)}.${tld}`,
        'Keyboard Adjacent',
        'typosquat',
        `Near-key typo "${name[i]}" → "${neighbors[0]}"`
      );
    }
  }

  // 6. Combo Phishing Lures
  const lures = ['login', 'verify', 'security', 'auth', 'portal'];
  for (const lure of lures) {
    add(`${name}-${lure}.${tld}`, 'Combo-Squat', 'combo_tld', `Adds "-${lure}" lure`);
    add(`${lure}-${name}.${tld}`, 'Combo-Squat', 'combo_tld', `Adds "${lure}-" prefix`);
  }

  // 7. TLD Permutations
  for (const alt of ['net', 'org', 'co', 'xyz', 'info']) {
    if (alt !== tld) {
      add(`${name}.${alt}`, 'TLD Swap', 'combo_tld', `Alternate .${alt} extension`);
    }
  }

  return variants.slice(0, 24);
}
