export type RiskClassification = 'Lower Risk' | 'Suspicious' | 'High Risk';

export type CheckStatus = 'pass' | 'warn' | 'danger' | 'info';

export interface ScanFinding {
  id: string;
  source: string;
  label: string;
  severity: CheckStatus;
  points: number;
  detail: string;
}

export interface LiveDnsInfo {
  resolved: boolean;
  ipv4: string[];
  ipv6: string[];
  nameservers: string[];
  hasMx: boolean;
  error?: string;
}

export interface LiveTlsInfo {
  checked: boolean;
  valid: boolean;
  issuer?: string;
  subject?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  protocol?: string;
  error?: string;
}

export interface LiveRdapInfo {
  checked: boolean;
  found: boolean;
  registrar?: string;
  createdDate?: string;
  expiresDate?: string;
  domainAgeDays?: number;
  error?: string;
}

export interface ThreatEngineResult {
  engine: string;
  status: 'clean' | 'malicious' | 'suspicious' | 'unavailable' | 'not_configured';
  summary: string;
  detections?: number;
  totalChecks?: number;
}

export interface HomoglyphAnalysis {
  isPunycode: boolean;
  hasMixedScript: boolean;
  asciiDomain: string;
  unicodeDomain: string;
  suspiciousChars: Array<{
    char: string;
    codePoint: string;
    script: string;
    looksLike: string;
  }>;
}

export interface LiveScanResult {
  source: 'url' | 'qr';
  scannedUrl: string;
  extractedDomain: string;
  baseDomain: string;
  protocol: string;
  scannedAt: string;
  riskScore: number;
  classification: RiskClassification;
  summary: string;
  findings: ScanFinding[];
  homoglyph: HomoglyphAnalysis;
  dns: LiveDnsInfo;
  tls: LiveTlsInfo;
  rdap: LiveRdapInfo;
  threatIntel: ThreatEngineResult[];
  qrFileName?: string;
}

export interface QrPlainTextResult {
  source: 'qr';
  contentType: 'text';
  extractedText: string;
  qrFileName: string;
  detectedFormat: 'PNG' | 'JPEG';
}

export type LookalikeTechnique =
  | 'Homoglyph (IDN)'
  | 'Visual Swap'
  | 'Omission'
  | 'Transposition'
  | 'Keyboard Adjacent'
  | 'Repetition'
  | 'Hyphenation'
  | 'Combo-Squat'
  | 'TLD Swap';

export interface LookalikeVariant {
  domain: string;
  asciiDomain: string;
  technique: LookalikeTechnique;
  category: 'homoglyph' | 'typosquat' | 'combo_tld';
  note: string;
  dnsChecked: boolean;
  isActive: boolean;
  ipv4?: string;
  hasMx?: boolean;
}

export interface LookalikeGenerationResult {
  sourceDomain: string;
  generatedAt: string;
  totalGenerated: number;
  activeCount: number;
  mxActiveCount: number;
  homoglyphCount: number;
  variants: LookalikeVariant[];
}
