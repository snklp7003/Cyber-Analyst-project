import { useState, type FormEvent } from 'react';
import {
  AlertTriangle,
  ArrowUpRight,
  Download,
  Dna,
  Filter,
  Globe,
  Mail,
  Search,
  Sparkles,
  X,
} from 'lucide-react';
import { requestLookalikeGeneration } from '../lib/qrScanner';
import type { LookalikeGenerationResult, LookalikeVariant } from '../types/scan';

interface LookalikeGeneratorProps {
  result: LookalikeGenerationResult | null;
  onResultChange: (res: LookalikeGenerationResult | null) => void;
  onInspectDomain: (domainUrl: string) => void;
  isInspecting: boolean;
}

type FilterMode = 'all' | 'active' | 'homoglyph' | 'typosquat' | 'combo_tld';

const AUDIT_PRESETS = [
  'paypal.com',
  'github.com',
  'google.com',
  'microsoft.com',
  'apple.com',
  'amazon.com',
];

export function LookalikeGenerator({
  result,
  onResultChange,
  onInspectDomain,
  isInspecting,
}: LookalikeGeneratorProps) {
  const [domainInput, setDomainInput] = useState(result?.sourceDomain || '');
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<FilterMode>('all');

  const executeGeneration = async (target: string) => {
    const clean = target.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
    if (!clean) {
      setError('Please enter a target domain name to audit (e.g. example.com).');
      return;
    }

    setDomainInput(clean);
    setIsGenerating(true);
    setError(null);
    const { result: genResult, error: genError } = await requestLookalikeGeneration(clean);
    setIsGenerating(false);

    if (genError || !genResult) {
      setError(genError || 'Could not generate domain permutations.');
      return;
    }

    setFilter('all');
    onResultChange(genResult);
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    await executeGeneration(domainInput);
  };

  const filteredVariants: LookalikeVariant[] = result
    ? result.variants.filter((v) => {
        if (filter === 'active') return v.isActive;
        if (filter === 'homoglyph') return v.category === 'homoglyph';
        if (filter === 'typosquat') return v.category === 'typosquat';
        if (filter === 'combo_tld') return v.category === 'combo_tld';
        return true;
      })
    : [];

  const handleExportCsv = () => {
    if (!result) return;
    const rows = [
      ['Display Domain', 'ASCII / Punycode', 'Technique', 'Category', 'Note', 'Active DNS', 'IPv4', 'MX Configured'],
      ...result.variants.map((v) => [
        v.domain,
        v.asciiDomain,
        v.technique,
        v.category,
        v.note,
        v.isActive ? 'Active' : 'Unregistered',
        v.ipv4 || '',
        v.hasMx ? 'Yes' : 'No',
      ]),
    ];
    const csv = rows
      .map((r) => r.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(','))
      .join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `domain-defense-${result.sourceDomain}-lookalikes.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const filterButtons: { id: FilterMode; label: string; count?: number }[] = [
    { id: 'all', label: 'All Permutations', count: result?.totalGenerated },
    { id: 'active', label: 'Active in Live DNS', count: result?.activeCount },
    { id: 'homoglyph', label: 'IDN Homoglyphs', count: result?.homoglyphCount },
    { id: 'typosquat', label: 'Typosquatting' },
    { id: 'combo_tld', label: 'Combo & TLDs' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="space-y-1.5">
        <div className="flex items-center gap-2">
          <Dna className="w-5 h-5 text-blue-400" />
          <h1 className="text-2xl font-bold tracking-tight text-[#EAECEF]">
            Homoglyph &amp; Typosquatting Generator
          </h1>
        </div>
        <p className="text-sm text-[#939DAC] max-w-2xl leading-relaxed">
          Algorithmic brand protection laboratory. Generates Unicode IDN homoglyphs, Punycode spoofs, optical visual swaps, and typosquat variations, probing live DNS to detect impersonators registered in the wild.
        </p>
      </div>

      {/* Input Workbench Bar */}
      <section className="bg-[#12151C] border border-[#222834] rounded-xl p-5 shadow-lg space-y-3">
        <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3" noValidate>
          <div className="flex-1">
            <label htmlFor="lookalike-domain-input" className="sr-only">
              Target domain name
            </label>
            <input
              id="lookalike-domain-input"
              type="text"
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              placeholder="Enter legitimate domain (e.g. paypal.com, github.com, google.com)"
              autoComplete="off"
              spellCheck={false}
              disabled={isGenerating}
              className="w-full px-4 py-2.5 text-sm font-mono bg-[#0D1016] border border-[#2B3342] rounded-lg text-[#EAECEF] placeholder:text-[#616B7A] focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:opacity-60"
            />
          </div>
          <button
            type="submit"
            disabled={isGenerating}
            className="inline-flex items-center justify-center gap-2 px-6 py-2.5 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-lg transition-colors whitespace-nowrap cursor-pointer shadow-md"
          >
            <Search className="w-4 h-4" />
            {isGenerating ? 'Synthesizing & Probing DNS…' : 'Generate & Probe DNS'}
          </button>
        </form>

        {/* Quick Presets */}
        <div className="flex flex-wrap items-center gap-2 pt-1 text-xs text-[#939DAC]">
          <span className="flex items-center gap-1 text-[#616B7A]">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span>Preset targets:</span>
          </span>
          {AUDIT_PRESETS.map((brand) => (
            <button
              key={brand}
              type="button"
              disabled={isGenerating}
              onClick={() => executeGeneration(brand)}
              className="px-2.5 py-1 rounded-md bg-[#0D1016] border border-[#222834] text-[#C4CBD6] hover:text-white hover:border-blue-500/50 transition-colors font-mono cursor-pointer"
            >
              {brand}
            </button>
          ))}
        </div>

        {error && (
          <div
            role="alert"
            className="mt-3 p-3.5 rounded-lg bg-red-950/35 border border-red-900/60 text-red-200 flex items-start justify-between gap-3 text-xs"
          >
            <div className="flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
            <button
              type="button"
              onClick={() => setError(null)}
              className="text-red-300 hover:text-red-100 cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </section>

      {/* Output Table */}
      {result && (
        <section className="bg-[#12151C] border border-[#222834] rounded-xl overflow-hidden shadow-xl">
          {/* Metrics Strip */}
          <div className="grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-[#222834] border-b border-[#222834] bg-[#0D1016]">
            <div className="px-5 py-3.5">
              <p className="text-xs text-[#939DAC]">Variants Generated</p>
              <p className="font-mono text-xl font-bold text-[#EAECEF] mt-0.5">
                {result.totalGenerated}
              </p>
            </div>
            <div className="px-5 py-3.5">
              <p className="text-xs text-[#939DAC]">Active in Live DNS</p>
              <p
                className={`font-mono text-xl font-bold mt-0.5 ${
                  result.activeCount > 0 ? 'text-amber-400' : 'text-emerald-400'
                }`}
              >
                {result.activeCount}
              </p>
            </div>
            <div className="px-5 py-3.5">
              <p className="text-xs text-[#939DAC]">IDN / Homoglyphs</p>
              <p className="font-mono text-xl font-bold text-[#EAECEF] mt-0.5">
                {result.homoglyphCount}
              </p>
            </div>
            <div className="px-5 py-3.5">
              <p className="text-xs text-[#939DAC]">Mail-Capable (MX)</p>
              <p className="font-mono text-xl font-bold text-[#EAECEF] mt-0.5">
                {result.mxActiveCount}
              </p>
            </div>
          </div>

          {/* Filter & Export Toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3 border-b border-[#222834] bg-[#0D1016]/60">
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-xs text-[#616B7A] flex items-center gap-1 mr-1">
                <Filter className="w-3.5 h-3.5" />
                <span>Filter:</span>
              </span>
              {filterButtons.map((btn) => {
                const active = filter === btn.id;
                return (
                  <button
                    key={btn.id}
                    type="button"
                    onClick={() => setFilter(btn.id)}
                    className={`px-3 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                      active
                        ? 'bg-blue-600 text-white font-semibold'
                        : 'text-[#939DAC] hover:text-[#EAECEF] hover:bg-[#191E28]'
                    }`}
                  >
                    {btn.label} {typeof btn.count === 'number' ? `(${btn.count})` : ''}
                  </button>
                );
              })}
            </div>

            <button
              type="button"
              onClick={handleExportCsv}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-[#EAECEF] bg-[#191E28] hover:bg-[#222834] border border-[#2B3342] rounded-md transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export CSV</span>
            </button>
          </div>

          {/* Analyst Data Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#222834] text-xs font-semibold text-[#939DAC] bg-[#0D1016]/40">
                  <th className="py-3 px-5">Permuted Lookalike Domain</th>
                  <th className="py-3 px-5">Vector &amp; Technique</th>
                  <th className="py-3 px-5">Live DNS Resolution</th>
                  <th className="py-3 px-5">MX Mail</th>
                  <th className="py-3 px-5 text-right">Deep Analysis</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#222834]/80 text-sm">
                {filteredVariants.length > 0 ? (
                  filteredVariants.map((variant) => {
                    const isPuny = variant.asciiDomain !== variant.domain;
                    return (
                      <tr
                        key={variant.asciiDomain}
                        className="hover:bg-[#161B24] transition-colors"
                      >
                        <td className="py-3 px-5 font-mono text-xs text-[#EAECEF]">
                          <div className="font-semibold break-all text-sm">{variant.domain}</div>
                          {isPuny && (
                            <div className="text-[11px] text-amber-300 font-mono mt-0.5 break-all">
                              Punycode: {variant.asciiDomain}
                            </div>
                          )}
                        </td>
                        <td className="py-3 px-5">
                          <div className="text-xs font-semibold text-[#EAECEF]">
                            {variant.technique}
                          </div>
                          <div className="text-[11px] text-[#939DAC] mt-0.5">{variant.note}</div>
                        </td>
                        <td className="py-3 px-5 font-mono text-xs whitespace-nowrap">
                          {variant.isActive ? (
                            <span className="inline-flex items-center gap-1.5 text-amber-400 font-semibold px-2 py-0.5 rounded bg-amber-950/40 border border-amber-800/40">
                              <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-ping" />
                              Active {variant.ipv4 ? `(${variant.ipv4})` : ''}
                            </span>
                          ) : (
                            <span className="text-[#616B7A]">Unregistered</span>
                          )}
                        </td>
                        <td className="py-3 px-5 font-mono text-xs whitespace-nowrap">
                          {variant.hasMx ? (
                            <span className="inline-flex items-center gap-1 text-amber-300">
                              <Mail className="w-3.5 h-3.5" />
                              <span>Configured</span>
                            </span>
                          ) : (
                            <span className="text-[#616B7A]">—</span>
                          )}
                        </td>
                        <td className="py-3 px-5 text-right whitespace-nowrap">
                          <button
                            type="button"
                            disabled={isInspecting}
                            onClick={() => onInspectDomain(`https://${variant.asciiDomain}`)}
                            className="inline-flex items-center gap-1 text-xs font-semibold text-blue-400 hover:text-blue-300 disabled:opacity-50 transition-colors cursor-pointer"
                          >
                            <span>Inspect Target</span>
                            <ArrowUpRight className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={5} className="py-12 px-5 text-center text-xs text-[#939DAC]">
                      No generated domains match the selected filter.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
