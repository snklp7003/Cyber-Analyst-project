import { useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  FileText,
  Globe,
  Lock,
  Printer,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Zap,
} from 'lucide-react';
import type { LiveScanResult, QrPlainTextResult, ThreatEngineResult } from '../types/scan';

interface ResultsDashboardProps {
  scanResult: LiveScanResult | null;
  qrTextResult: QrPlainTextResult | null;
  errorMessage: string | null;
  isScanning: boolean;
  onClear: () => void;
  onBackToScanner: () => void;
}

function formatDomainAge(days: number, createdDate?: string): string {
  if (createdDate) {
    const start = new Date(createdDate);
    const now = new Date();
    if (!Number.isNaN(start.getTime()) && start <= now) {
      let years = now.getUTCFullYear() - start.getUTCFullYear();
      let months = now.getUTCMonth() - start.getUTCMonth();
      const dayDiff = now.getUTCDate() - start.getUTCDate();

      if (dayDiff < 0) months -= 1;
      if (months < 0) {
        years -= 1;
        months += 12;
      }

      if (years > 0) {
        return months > 0
          ? `${years} yr ${months} mo (${days.toLocaleString()} days)`
          : `${years} year${years > 1 ? 's' : ''} (${days.toLocaleString()} days)`;
      }
      if (months > 0) {
        return `${months} mo (${days.toLocaleString()} days)`;
      }
    }
  }
  return `${days} day${days === 1 ? '' : 's'}`;
}

export function ResultsDashboard({
  scanResult,
  qrTextResult,
  errorMessage,
  isScanning,
  onClear,
  onBackToScanner,
}: ResultsDashboardProps) {
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [copiedSummary, setCopiedSummary] = useState(false);

  const hasResult = Boolean(scanResult || qrTextResult || errorMessage);

  const copyToClipboard = async (text: string, setter: (val: boolean) => void) => {
    try {
      await navigator.clipboard.writeText(text);
      setter(true);
      setTimeout(() => setter(false), 2000);
    } catch {
      // Ignore clipboard write restrictions
    }
  };

  const handleCopySummary = () => {
    if (!scanResult) return;
    const summaryText = [
      `=== SECURITY SCAN REPORT: ${scanResult.extractedDomain} ===`,
      `Classification: ${scanResult.classification} (Risk Score: ${scanResult.riskScore}/100)`,
      `Scanned URL: ${scanResult.scannedUrl}`,
      `Protocol: ${scanResult.protocol} | Resolved IP: ${scanResult.dns.ipv4[0] || 'Unresolved'}`,
      `SSL/TLS: ${scanResult.tls.valid ? 'Valid & Trusted' : scanResult.tls.checked ? 'Untrusted' : 'None'} (${scanResult.tls.issuer || 'N/A'})`,
      `RDAP Age: ${scanResult.rdap.domainAgeDays ? `${scanResult.rdap.domainAgeDays} days` : 'Unknown'} | Registrar: ${scanResult.rdap.registrar || 'N/A'}`,
      `Homoglyph/Punycode: ${scanResult.homoglyph.isPunycode ? `YES (${scanResult.homoglyph.asciiDomain})` : 'No'}`,
      `Findings (${scanResult.findings.length}):`,
      ...scanResult.findings.map((f) => ` - [${f.severity.toUpperCase()}] +${f.points}pts: ${f.label} (${f.detail})`),
      `\nVerdict: ${scanResult.summary}`,
    ].join('\n');

    copyToClipboard(summaryText, setCopiedSummary);
  };

  const getRiskTheme = (classification: LiveScanResult['classification']) => {
    if (classification === 'High Risk') {
      return {
        textColor: 'text-red-400',
        bgColor: 'bg-red-500/10',
        borderColor: 'border-red-500/30',
        badgeColor: 'bg-red-950/80 text-red-200 border-red-800/80',
        barColor: 'bg-gradient-to-r from-red-600 to-rose-500',
        icon: ShieldAlert,
        bandLabel: '50–100 · High Risk / Malicious Threat',
      };
    }
    if (classification === 'Suspicious') {
      return {
        textColor: 'text-amber-400',
        bgColor: 'bg-amber-500/10',
        borderColor: 'border-amber-500/30',
        badgeColor: 'bg-amber-950/80 text-amber-200 border-amber-800/80',
        barColor: 'bg-gradient-to-r from-amber-600 to-yellow-500',
        icon: ShieldQuestion,
        bandLabel: '25–49 · Suspicious / Potential Phishing',
      };
    }
    return {
      textColor: 'text-emerald-400',
      bgColor: 'bg-emerald-500/10',
      borderColor: 'border-emerald-500/30',
      badgeColor: 'bg-emerald-950/80 text-emerald-200 border-emerald-800/80',
      barColor: 'bg-gradient-to-r from-emerald-600 to-teal-500',
      icon: ShieldCheck,
      bandLabel: '0–24 · Low Risk / Established Clean',
    };
  };

  const getEngineColor = (status: ThreatEngineResult['status']) => {
    if (status === 'malicious') return 'text-red-400 bg-red-950/40 border-red-800/60';
    if (status === 'suspicious') return 'text-amber-400 bg-amber-950/40 border-amber-800/60';
    if (status === 'clean') return 'text-emerald-400 bg-emerald-950/40 border-emerald-800/60';
    if (status === 'not_configured') return 'text-[#616B7A] bg-[#161B24] border-[#222834]';
    return 'text-[#939DAC] bg-[#161B24] border-[#222834]';
  };

  const getEngineLabel = (status: ThreatEngineResult['status']) => {
    if (status === 'malicious') return 'Malicious';
    if (status === 'suspicious') return 'Suspicious';
    if (status === 'clean') return 'Clean';
    if (status === 'not_configured') return 'Key Not Configured';
    return 'Unavailable';
  };

  return (
    <section
      aria-label="Inspection Report"
      className="bg-[#12151C] border border-[#222834] rounded-xl overflow-hidden shadow-2xl"
    >
      {/* Report Top Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 px-6 py-4 border-b border-[#222834] bg-[#0D1016]">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
            <h1 className="text-base font-bold text-[#EAECEF] tracking-tight">Security Audit Report</h1>
          </div>
          <p className="text-xs text-[#939DAC] mt-0.5 truncate">
            {scanResult
              ? scanResult.source === 'qr'
                ? `Decoded QR Code Quishing Payload · ${scanResult.qrFileName || 'Uploaded image'}`
                : `Live Internet Intelligence · ${scanResult.extractedDomain}`
              : qrTextResult
                ? `QR Code Payload · ${qrTextResult.qrFileName} (${qrTextResult.detectedFormat})`
                : 'No active scan'}
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {scanResult && (
            <>
              <button
                type="button"
                onClick={handleCopySummary}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#C4CBD6] bg-[#191E28] hover:bg-[#222834] border border-[#2B3342] rounded-md transition-colors cursor-pointer"
                title="Copy Full Audit Text"
              >
                {copiedSummary ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied!</span>
                  </>
                ) : (
                  <>
                    <FileText className="w-3.5 h-3.5" />
                    <span>Copy Summary</span>
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={() => window.print()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#C4CBD6] bg-[#191E28] hover:bg-[#222834] border border-[#2B3342] rounded-md transition-colors cursor-pointer"
                title="Print or Save PDF"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>Print PDF</span>
              </button>
            </>
          )}

          <button
            type="button"
            onClick={onBackToScanner}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-md transition-colors whitespace-nowrap cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>New Scan</span>
          </button>

          {hasResult && (
            <button
              type="button"
              onClick={onClear}
              className="p-1.5 text-[#939DAC] hover:text-[#EAECEF] bg-[#191E28] hover:bg-[#222834] border border-[#2B3342] rounded-md transition-colors cursor-pointer"
              title="Clear Results"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Body */}
      <div className="p-6">
        {isScanning ? (
          <div className="py-16 text-center space-y-3">
            <div className="w-10 h-10 mx-auto rounded-full border-2 border-blue-500 border-t-transparent animate-spin" />
            <p className="text-base font-semibold text-[#EAECEF]">Running Live Security Diagnostics…</p>
            <p className="text-xs text-[#939DAC] max-w-md mx-auto">
              Querying live DNS A/MX records, inspecting SSL/TLS certificates, validating RDAP domain age, checking homoglyph confusables, and polling threat feeds.
            </p>
          </div>
        ) : errorMessage ? (
          <div
            role="alert"
            className="p-5 rounded-lg bg-red-950/35 border border-red-900/60 text-red-200 flex items-start gap-3"
          >
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <div className="min-w-0">
              <h2 className="text-sm font-semibold text-red-100">Scan Execution Notice</h2>
              <p className="text-xs text-red-200/90 mt-1 leading-relaxed">{errorMessage}</p>
            </div>
          </div>
        ) : scanResult ? (
          (() => {
            const theme = getRiskTheme(scanResult.classification);
            const RiskIcon = theme.icon;

            return (
              <div className="space-y-6">
                {/* Executive Score & Verdict Card */}
                <div className={`p-6 rounded-xl border ${theme.borderColor} ${theme.bgColor} space-y-4`}>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="flex items-center gap-4">
                      {/* Visual Circular Gauge Placeholder */}
                      <div className="relative flex items-center justify-center w-20 h-20 rounded-full border-4 border-[#222834] bg-[#0D1016] shadow-inner shrink-0">
                        <div className="text-center">
                          <span className="font-mono text-2xl font-black text-[#EAECEF]">
                            {scanResult.riskScore}
                          </span>
                          <span className="block text-[10px] text-[#616B7A] uppercase font-mono">/ 100</span>
                        </div>
                      </div>

                      <div>
                        <div className="flex items-center gap-2">
                          <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${theme.badgeColor}`}>
                            {scanResult.classification.toUpperCase()}
                          </span>
                          {scanResult.source === 'qr' && (
                            <span className="px-2 py-0.5 rounded-full text-[11px] font-mono bg-purple-950/80 text-purple-200 border border-purple-800/80">
                              QUISHING DETECTED
                            </span>
                          )}
                        </div>
                        <h2 className={`text-xl font-bold mt-1.5 flex items-center gap-2 ${theme.textColor}`}>
                          <RiskIcon className="w-5 h-5 shrink-0" />
                          <span>{scanResult.classification} Security Verdict</span>
                        </h2>
                        <p className="text-xs text-[#939DAC] mt-0.5 font-mono">
                          Evaluation Band: {theme.bandLabel}
                        </p>
                      </div>
                    </div>

                    <div className="text-right hidden sm:block">
                      <span className="text-xs text-[#616B7A] block">Timestamp</span>
                      <span className="text-xs font-mono text-[#939DAC]">
                        {new Date(scanResult.scannedAt).toLocaleTimeString()} · {new Date(scanResult.scannedAt).toLocaleDateString()}
                      </span>
                    </div>
                  </div>

                  {/* Progress bar */}
                  <div className="w-full h-2 rounded-full bg-[#1A202C] overflow-hidden">
                    <div
                      className={`h-full ${theme.barColor} transition-all duration-700`}
                      style={{ width: `${Math.max(scanResult.riskScore, 4)}%` }}
                    />
                  </div>

                  <p className="text-sm text-[#C4CBD6] leading-relaxed pt-1">
                    {scanResult.summary}
                  </p>
                </div>

                {/* Inspected Target Bar */}
                <div className="p-4 rounded-lg bg-[#0D1016] border border-[#222834] space-y-2">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-xs font-semibold text-[#939DAC] uppercase tracking-wider">
                      Inspected Target Link (Safely Evaluated Without Remote Execution)
                    </span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(scanResult.scannedUrl, setCopiedUrl)}
                      className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors cursor-pointer"
                    >
                      {copiedUrl ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy URL</span>
                        </>
                      )}
                    </button>
                  </div>
                  <div className="font-mono text-sm text-[#EAECEF] break-all select-all bg-[#090B0F] p-2.5 rounded border border-[#1A202C]">
                    {scanResult.scannedUrl}
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 text-xs">
                    <div>
                      <span className="text-[#616B7A] block">Hostname</span>
                      <span className="font-mono text-[#EAECEF] font-medium break-all">{scanResult.extractedDomain}</span>
                    </div>
                    <div>
                      <span className="text-[#616B7A] block">Base Domain</span>
                      <span className="font-mono text-[#EAECEF] font-medium">{scanResult.baseDomain}</span>
                    </div>
                    <div>
                      <span className="text-[#616B7A] block">Protocol</span>
                      <span className="font-mono text-blue-300 font-medium">{scanResult.protocol}</span>
                    </div>
                    <div>
                      <span className="text-[#616B7A] block">DNS Resolution</span>
                      <span className={`font-mono font-medium ${scanResult.dns.resolved ? 'text-emerald-400' : 'text-red-400'}`}>
                        {scanResult.dns.resolved ? scanResult.dns.ipv4[0] || 'Resolved' : 'No IP Record'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Homoglyph / Punycode Breakdown when present */}
                {(scanResult.homoglyph.isPunycode || scanResult.homoglyph.hasMixedScript) && (
                  <div className="p-5 rounded-xl bg-red-950/20 border border-red-500/40 space-y-4">
                    <div className="flex items-center gap-2 text-red-400 font-bold text-sm">
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                      <span>CRITICAL: IDN Homoglyph / Punycode Confusable Detected!</span>
                    </div>
                    <p className="text-xs text-red-200/90 leading-relaxed">
                      This domain uses non-Latin (Cyrillic or Greek) characters that visually impersonate legitimate Latin characters to deceive victims in browser address bars and emails.
                    </p>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                      <div className="p-3 rounded-lg bg-[#0D1016] border border-red-900/40">
                        <span className="text-[#939DAC] block font-sans text-[11px] mb-1">
                          Visual Deceptive Rendering (Victim View)
                        </span>
                        <span className="text-red-300 font-bold text-sm break-all">
                          {scanResult.homoglyph.unicodeDomain}
                        </span>
                      </div>
                      <div className="p-3 rounded-lg bg-[#0D1016] border border-amber-900/40">
                        <span className="text-[#939DAC] block font-sans text-[11px] mb-1">
                          Actual ASCII Punycode (Network Resolution)
                        </span>
                        <span className="text-amber-300 font-bold text-sm break-all">
                          {scanResult.homoglyph.asciiDomain}
                        </span>
                      </div>
                    </div>

                    {scanResult.homoglyph.suspiciousChars.length > 0 && (
                      <div className="pt-2 border-t border-red-900/40">
                        <span className="text-xs font-semibold text-red-300 block mb-2">
                          Character Spoof Breakdown:
                        </span>
                        <div className="overflow-x-auto">
                          <table className="w-full text-left text-xs font-mono">
                            <thead>
                              <tr className="text-[#939DAC] border-b border-red-900/30">
                                <th className="pb-1.5">Spoofed Glyph</th>
                                <th className="pb-1.5">Code Point</th>
                                <th className="pb-1.5">Real Script</th>
                                <th className="pb-1.5">Mimics Latin</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-red-900/20">
                              {scanResult.homoglyph.suspiciousChars.map((c, idx) => (
                                <tr key={idx}>
                                  <td className="py-1.5 text-red-300 font-bold text-sm">&quot;{c.char}&quot;</td>
                                  <td className="py-1.5 text-amber-300">{c.codePoint}</td>
                                  <td className="py-1.5 text-[#C4CBD6]">{c.script}</td>
                                  <td className="py-1.5 text-emerald-400 font-bold">&quot;{c.looksLike}&quot;</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Threat Intelligence Feeds Matrix */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-[#EAECEF] flex items-center gap-2">
                      <Shield className="w-4 h-4 text-blue-400" />
                      <span>Live Threat Intelligence Feeds</span>
                    </h3>
                    <span className="text-xs text-[#939DAC] font-mono">4 Engine Feeds</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {scanResult.threatIntel.map((feed) => (
                      <div
                        key={feed.engine}
                        className="p-3.5 rounded-lg bg-[#0D1016] border border-[#222834] flex flex-col justify-between"
                      >
                        <div>
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-bold text-[#EAECEF]">{feed.engine}</span>
                            <span
                              className={`px-2 py-0.5 rounded text-[11px] font-mono border ${getEngineColor(
                                feed.status
                              )}`}
                            >
                              {getEngineLabel(feed.status)}
                            </span>
                          </div>
                          <p className="text-xs text-[#939DAC] mt-2 leading-relaxed">
                            {feed.summary}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Infrastructure Intelligence: SSL/TLS & RDAP */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* SSL/TLS Certificate */}
                  <div className="p-4 rounded-lg bg-[#0D1016] border border-[#222834] space-y-3">
                    <div className="flex items-center justify-between border-b border-[#222834] pb-2">
                      <div className="flex items-center gap-2">
                        <Lock className="w-4 h-4 text-emerald-400" />
                        <h4 className="text-xs font-bold text-[#EAECEF] uppercase tracking-wide">
                          SSL / TLS Certificate
                        </h4>
                      </div>
                      <span
                        className={`text-xs font-semibold ${
                          scanResult.tls.valid
                            ? 'text-emerald-400'
                            : scanResult.tls.checked
                              ? 'text-red-400'
                              : 'text-amber-400'
                        }`}
                      >
                        {scanResult.tls.valid
                          ? 'Valid & Trusted'
                          : scanResult.tls.checked
                            ? 'Invalid / Untrusted'
                            : 'Unencrypted HTTP'}
                      </span>
                    </div>

                    <dl className="text-xs space-y-2 text-[#C4CBD6]">
                      <div className="flex justify-between gap-3">
                        <dt className="text-[#939DAC]">Issuer</dt>
                        <dd className="text-right font-medium truncate max-w-[200px]">
                          {scanResult.tls.issuer || 'N/A'}
                        </dd>
                      </div>
                      <div className="flex justify-between gap-3">
                        <dt className="text-[#939DAC]">Subject / CN</dt>
                        <dd className="text-right font-mono truncate max-w-[200px]">
                          {scanResult.tls.subject || scanResult.extractedDomain}
                        </dd>
                      </div>
                      {typeof scanResult.tls.daysRemaining === 'number' && (
                        <div className="flex justify-between gap-3">
                          <dt className="text-[#939DAC]">Validity Remaining</dt>
                          <dd className="font-mono text-emerald-400 font-semibold">
                            {scanResult.tls.daysRemaining} days
                          </dd>
                        </div>
                      )}
                      {scanResult.tls.protocol && (
                        <div className="flex justify-between gap-3">
                          <dt className="text-[#939DAC]">TLS Protocol</dt>
                          <dd className="font-mono">{scanResult.tls.protocol}</dd>
                        </div>
                      )}
                      {scanResult.tls.error && (
                        <p className="text-amber-400/90 text-[11px] pt-1">
                          Notice: {scanResult.tls.error}
                        </p>
                      )}
                    </dl>
                  </div>

                  {/* RDAP Domain Registry & DNS */}
                  <div className="p-4 rounded-lg bg-[#0D1016] border border-[#222834] space-y-3">
                    <div className="flex items-center justify-between border-b border-[#222834] pb-2">
                      <div className="flex items-center gap-2">
                        <Globe className="w-4 h-4 text-blue-400" />
                        <h4 className="text-xs font-bold text-[#EAECEF] uppercase tracking-wide">
                          RDAP Registration &amp; DNS
                        </h4>
                      </div>
                      <span
                        className={`text-xs font-semibold ${
                          scanResult.rdap.found ? 'text-blue-400' : 'text-[#939DAC]'
                        }`}
                      >
                        {scanResult.rdap.found ? 'Record Available' : 'RDAP Unavailable'}
                      </span>
                    </div>

                    <dl className="text-xs space-y-2 text-[#C4CBD6]">
                      {scanResult.rdap.registrar && (
                        <div className="flex justify-between gap-3">
                          <dt className="text-[#939DAC]">Registrar</dt>
                          <dd className="text-right font-medium truncate max-w-[200px]">
                            {scanResult.rdap.registrar}
                          </dd>
                        </div>
                      )}
                      {scanResult.rdap.createdDate && (
                        <div className="flex justify-between gap-3">
                          <dt className="text-[#939DAC]">Registration Date</dt>
                          <dd className="font-mono text-right">
                            {scanResult.rdap.createdDate.slice(0, 10)}
                          </dd>
                        </div>
                      )}
                      {typeof scanResult.rdap.domainAgeDays === 'number' && (
                        <div className="flex justify-between gap-3">
                          <dt className="text-[#939DAC]">Domain Age</dt>
                          <dd
                            className={`font-mono font-semibold ${
                              scanResult.rdap.domainAgeDays < 30
                                ? 'text-red-400'
                                : 'text-emerald-400'
                            }`}
                          >
                            {formatDomainAge(
                              scanResult.rdap.domainAgeDays,
                              scanResult.rdap.createdDate
                            )}
                          </dd>
                        </div>
                      )}
                      <div className="flex justify-between gap-3">
                        <dt className="text-[#939DAC]">Mail Exchange (MX)</dt>
                        <dd className="font-mono">
                          {scanResult.dns.hasMx ? (
                            <span className="text-amber-400">Configured (Mail-Active)</span>
                          ) : (
                            <span className="text-[#616B7A]">None</span>
                          )}
                        </dd>
                      </div>
                      {scanResult.dns.nameservers.length > 0 && (
                        <div className="flex justify-between gap-3">
                          <dt className="text-[#939DAC]">Nameserver</dt>
                          <dd className="font-mono text-right truncate max-w-[200px]">
                            {scanResult.dns.nameservers[0]}
                          </dd>
                        </div>
                      )}
                    </dl>
                  </div>
                </div>

                {/* Flagged Risk Signals */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-[#EAECEF] flex items-center gap-2">
                      <Zap className="w-4 h-4 text-amber-400" />
                      <span>Evaluated Risk Signals ({scanResult.findings.length})</span>
                    </h3>
                    <span className="text-xs text-[#939DAC] font-mono">
                      Weighted Scoring Breakdown
                    </span>
                  </div>

                  {scanResult.findings.length > 0 ? (
                    <div className="divide-y divide-[#222834] border border-[#222834] rounded-lg overflow-hidden bg-[#0D1016]">
                      {scanResult.findings.map((f) => (
                        <div key={f.id} className="p-3.5 flex items-start justify-between gap-4">
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span
                                className={`w-2 h-2 rounded-full ${
                                  f.severity === 'danger' ? 'bg-red-500' : 'bg-amber-500'
                                }`}
                              />
                              <p className="text-xs font-bold text-[#EAECEF]">{f.label}</p>
                              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#161B24] text-[#939DAC] border border-[#222834]">
                                {f.source}
                              </span>
                            </div>
                            <p className="text-xs text-[#939DAC] mt-1 leading-relaxed pl-4">
                              {f.detail}
                            </p>
                          </div>
                          <span className="font-mono text-xs font-bold text-amber-300 shrink-0 px-2 py-1 rounded bg-amber-950/40 border border-amber-800/40">
                            +{f.points} pts
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-500/30 text-emerald-300 flex items-center gap-2.5 text-xs">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                      <span>
                        Clean heuristic evaluation: No security warnings or deceptive patterns were triggered across live DNS, TLS, RDAP, homoglyphs, and threat feeds.
                      </span>
                    </div>
                  )}
                </div>
              </div>
            );
          })()
        ) : qrTextResult ? (
          <div className="space-y-5">
            <div className="p-4 rounded-lg bg-[#0D1016] border border-[#222834]">
              <h2 className="text-base font-semibold text-[#EAECEF]">
                Plain Text Decoded from QR Code
              </h2>
              <p className="text-xs text-[#939DAC] mt-1">
                The uploaded QR code contained plaintext content rather than an HTTP link. URL threat scanning was safely bypassed.
              </p>
            </div>

            <div>
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="text-xs font-mono text-[#939DAC]">
                  Verified {qrTextResult.detectedFormat} · {qrTextResult.qrFileName}
                </span>
                <button
                  type="button"
                  onClick={() => copyToClipboard(qrTextResult.extractedText, setCopiedUrl)}
                  className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors cursor-pointer"
                >
                  {copiedUrl ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Text</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="p-4 rounded-lg bg-[#0D1016] border border-[#222834] font-mono text-sm text-[#EAECEF] whitespace-pre-wrap break-words select-all">
                {qrTextResult.extractedText}
              </pre>
            </div>
          </div>
        ) : (
          <div className="py-16 text-center space-y-4">
            <Shield className="w-12 h-12 text-[#616B7A] mx-auto" />
            <h2 className="text-base font-bold text-[#EAECEF]">No Active Scan Loaded</h2>
            <p className="text-xs text-[#939DAC] max-w-sm mx-auto leading-relaxed">
              Submit a domain URL, upload a QR code image, or audit lookalikes to generate a comprehensive live security audit report.
            </p>
            <button
              type="button"
              onClick={onBackToScanner}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-md transition-colors cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Go to Scanner Workbench</span>
            </button>
          </div>
        )}
      </div>
    </section>
  );
}
