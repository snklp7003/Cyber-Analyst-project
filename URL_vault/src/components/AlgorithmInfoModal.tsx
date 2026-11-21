import { BookOpen, CheckCircle, Cpu, Globe, KeyRound, QrCode, ShieldAlert, X } from 'lucide-react';

interface AlgorithmInfoModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function AlgorithmInfoModal({ isOpen, onClose }: AlgorithmInfoModalProps) {
  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in"
    >
      <div className="relative w-full max-w-3xl max-h-[90vh] flex flex-col bg-[#0D1016] border border-[#2B3342] rounded-xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#222834] bg-[#12151C]">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-[#EAECEF]">
                Algorithms &amp; Security Architecture
              </h2>
              <p className="text-xs text-[#939DAC]">
                Mathematical models, heuristic scoring, and defensive detection methods
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 text-[#939DAC] hover:text-[#EAECEF] hover:bg-[#1A202C] rounded-md transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="p-6 overflow-y-auto space-y-6 text-sm text-[#C4CBD6]">
          {/* Section 1: Homoglyph & Punycode */}
          <div className="p-4 rounded-lg bg-[#12151C] border border-[#222834]">
            <div className="flex items-center gap-2 text-blue-400 font-semibold mb-2">
              <Globe className="w-4 h-4" />
              <span>1. Unicode Homoglyph &amp; Punycode (RFC 3492) Detection</span>
            </div>
            <p className="text-xs leading-relaxed text-[#939DAC] mb-3">
              Homoglyph attacks exploit lookalike glyphs across different alphabets (e.g., Latin &quot;a&quot; <code className="text-amber-300">U+0061</code> vs Cyrillic &quot;а&quot; <code className="text-amber-300">U+0430</code>). Modern browsers encode these as Punycode prefixed with <code className="text-blue-300">xn--</code>.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
              <div className="p-2.5 rounded bg-[#0A0D12] border border-[#1E2430]">
                <span className="text-[#616B7A] block font-sans text-[11px]">Visual Display (Victim view)</span>
                <span className="text-red-400 font-semibold">https://pаypal.com</span>
              </div>
              <div className="p-2.5 rounded bg-[#0A0D12] border border-[#1E2430]">
                <span className="text-[#616B7A] block font-sans text-[11px]">True ASCII Punycode</span>
                <span className="text-amber-300 font-semibold">https://xn--pypal-4ve.com</span>
              </div>
            </div>
          </div>

          {/* Section 2: Damerau-Levenshtein */}
          <div className="p-4 rounded-lg bg-[#12151C] border border-[#222834]">
            <div className="flex items-center gap-2 text-emerald-400 font-semibold mb-2">
              <KeyRound className="w-4 h-4" />
              <span>2. Damerau-Levenshtein Distance &amp; Leet-Speak Normalization</span>
            </div>
            <p className="text-xs leading-relaxed text-[#939DAC] mb-2">
              To detect typosquatting and impersonation of enterprise brands (Google, PayPal, GitHub, Microsoft, Apple, Banking), our engine implements a dynamic programming <strong>Damerau-Levenshtein algorithm</strong> combined with optical character mapping:
            </p>
            <ul className="text-xs space-y-1 text-[#C4CBD6] list-disc list-inside">
              <li>Handles 4 distinct edit operations: insertions, deletions, substitutions, and adjacent transpositions.</li>
              <li>Normalizes visual leet-speak trickery: <code className="text-blue-300">0 → o</code>, <code className="text-blue-300">1 → l</code>, <code className="text-blue-300">rn → m</code>, <code className="text-blue-300">vv → w</code>, <code className="text-blue-300">5 → s</code>.</li>
              <li>Evaluates normalized base domains against high-value target brands to alert before brand abuse succeeds.</li>
            </ul>
          </div>

          {/* Section 3: QR Quishing Analysis */}
          <div className="p-4 rounded-lg bg-[#12151C] border border-[#222834]">
            <div className="flex items-center gap-2 text-amber-400 font-semibold mb-2">
              <QrCode className="w-4 h-4" />
              <span>3. Quishing Defense: Binary Magic-Byte Inspection</span>
            </div>
            <p className="text-xs leading-relaxed text-[#939DAC] mb-2">
              Quishing (QR Phishing) bypasses standard email link filters by embedding malicious URLs in images. Our offline inspection pipeline protects the analyst:
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono">
              <div className="p-2.5 rounded bg-[#0A0D12] border border-[#1E2430]">
                <span className="text-[#616B7A] block font-sans text-[11px]">Magic-Byte Check</span>
                <span className="text-emerald-400">PNG: 89 50 4E 47</span>
              </div>
              <div className="p-2.5 rounded bg-[#0A0D12] border border-[#1E2430]">
                <span className="text-[#616B7A] block font-sans text-[11px]">Decoupled Sandbox</span>
                <span className="text-blue-300">Zero browser execution</span>
              </div>
              <div className="p-2.5 rounded bg-[#0A0D12] border border-[#1E2430]">
                <span className="text-[#616B7A] block font-sans text-[11px]">Multi-Scale Raster</span>
                <span className="text-purple-300">jsQR 3-pass decode</span>
              </div>
            </div>
          </div>

          {/* Section 4: Domain Intelligence */}
          <div className="p-4 rounded-lg bg-[#12151C] border border-[#222834]">
            <div className="flex items-center gap-2 text-purple-400 font-semibold mb-2">
              <ShieldAlert className="w-4 h-4" />
              <span>4. Multi-Vector Risk Scoring Formula (0 - 100)</span>
            </div>
            <p className="text-xs leading-relaxed text-[#939DAC] mb-2">
              The overall security score is derived from transparent weighted telemetry across 5 core vectors:
            </p>
            <div className="space-y-1.5 text-xs">
              <div className="flex justify-between py-1 border-b border-[#1E2430]">
                <span>Active Threat Feeds (URLhaus, urlscan.io, Google Safe Browsing, VirusTotal)</span>
                <span className="font-mono text-red-400 font-semibold">+30 to +70 pts</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#1E2430]">
                <span>IDN Homoglyph / Mixed Script Confusable</span>
                <span className="font-mono text-red-400 font-semibold">+40 pts</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#1E2430]">
                <span>Spoofed Brand (Damerau-Levenshtein similarity)</span>
                <span className="font-mono text-amber-400 font-semibold">+35 pts</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#1E2430]">
                <span>Brand New Domain Registration (&lt; 30 days old via RDAP)</span>
                <span className="font-mono text-amber-400 font-semibold">+30 pts</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#1E2430]">
                <span>Missing/Invalid SSL Certificate or Plaintext HTTP</span>
                <span className="font-mono text-amber-400 font-semibold">+20 to +30 pts</span>
              </div>
              <div className="flex justify-between py-1">
                <span>Direct IP Host, Auth @ Symbol, or Shortener Redirection</span>
                <span className="font-mono text-blue-400 font-semibold">+15 to +35 pts</span>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-3.5 border-t border-[#222834] bg-[#12151C]">
          <span className="text-xs text-[#616B7A]">URLVault Defense Architecture</span>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-md transition-colors cursor-pointer"
          >
            Close Guide
          </button>
        </div>
      </div>
    </div>
  );
}
