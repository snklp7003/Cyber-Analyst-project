import { useRef, useState, type DragEvent, type FormEvent } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  BookOpen,
  Dna,
  Globe,
  QrCode,
  Shield,
  Upload,
  X,
  Zap,
} from 'lucide-react';
import {
  decodeQrImageFile,
  MAX_QR_FILE_BYTES,
  requestLiveUrlScan,
} from './lib/qrScanner';
import type {
  LiveScanResult,
  LookalikeGenerationResult,
  QrPlainTextResult,
} from './types/scan';
import { ResultsDashboard } from './components/ResultsDashboard';
import { LookalikeGenerator } from './components/LookalikeGenerator';
import { AlgorithmInfoModal } from './components/AlgorithmInfoModal';

type ActivePage = 'scanner' | 'generator' | 'report';

export default function App() {
  const [activePage, setActivePage] = useState<ActivePage>('scanner');
  const [urlInput, setUrlInput] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewDataUrl, setPreviewDataUrl] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isAlgorithmModalOpen, setIsAlgorithmModalOpen] = useState(false);

  const [scanResult, setScanResult] = useState<LiveScanResult | null>(null);
  const [qrTextResult, setQrTextResult] = useState<QrPlainTextResult | null>(null);
  const [lookalikeResult, setLookalikeResult] = useState<LookalikeGenerationResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  const urlInputRef = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const navigateTo = (page: ActivePage) => {
    setActivePage(page);
    window.scrollTo(0, 0);
  };

  const clearResults = () => {
    setScanResult(null);
    setQrTextResult(null);
    setErrorMessage(null);
    navigateTo('scanner');
  };

  const resetAllAndFocus = () => {
    setUrlInput('');
    setSelectedFile(null);
    setPreviewDataUrl(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
    setScanResult(null);
    setQrTextResult(null);
    setErrorMessage(null);
    navigateTo('scanner');
    setTimeout(() => {
      urlInputRef.current?.focus();
    }, 0);
  };

  const executeLiveUrlScan = async (
    targetUrl: string,
    source: 'url' | 'qr' = 'url',
    qrFileName?: string
  ) => {
    setIsScanning(true);
    setErrorMessage(null);
    setScanResult(null);
    setQrTextResult(null);

    const { result, error } = await requestLiveUrlScan(targetUrl, source, qrFileName);
    setIsScanning(false);

    if (error || !result) {
      setErrorMessage(error || 'Live URL scan failed.');
      navigateTo('scanner');
      return;
    }

    setScanResult(result);
    navigateTo('report');
  };

  const handleUrlSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const trimmed = urlInput.trim();
    if (!trimmed) {
      setErrorMessage('Please enter a website URL or domain name to inspect.');
      window.scrollTo(0, 0);
      return;
    }
    await executeLiveUrlScan(trimmed, 'url');
  };

  const handleQrSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      setErrorMessage('Please upload or generate a QR code image to inspect.');
      window.scrollTo(0, 0);
      return;
    }

    setIsScanning(true);
    setErrorMessage(null);
    setScanResult(null);
    setQrTextResult(null);

    const decoded = await decodeQrImageFile(selectedFile);
    if (decoded.error) {
      setIsScanning(false);
      setErrorMessage(decoded.error);
      window.scrollTo(0, 0);
      return;
    }

    if (decoded.isUrl && decoded.extractedText) {
      await executeLiveUrlScan(decoded.extractedText, 'qr', selectedFile.name);
      return;
    }

    setIsScanning(false);
    if (decoded.plainTextResult) {
      setQrTextResult(decoded.plainTextResult);
      navigateTo('report');
    }
  };

  const handleFilePicked = (file: File | null) => {
    if (!file) return;
    if (file.size > MAX_QR_FILE_BYTES) {
      setSelectedFile(null);
      setPreviewDataUrl(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
      setErrorMessage(
        `File "${file.name}" is ${(file.size / (1024 * 1024)).toFixed(
          2
        )} MB. Maximum allowed image size is 5 MB.`
      );
      window.scrollTo(0, 0);
      return;
    }
    setErrorMessage(null);
    setSelectedFile(file);

    // Create preview
    const reader = new FileReader();
    reader.onload = () => {
      setPreviewDataUrl(typeof reader.result === 'string' ? reader.result : null);
    };
    reader.readAsDataURL(file);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    handleFilePicked(e.dataTransfer.files?.[0] || null);
  };

  const navItems: { id: ActivePage; label: string; icon: typeof Globe }[] = [
    { id: 'scanner', label: 'Quishing & URL Scanner', icon: Globe },
    { id: 'generator', label: 'Lookalike Generator', icon: Dna },
    { id: 'report', label: 'Security Report', icon: Shield },
  ];

  return (
    <div className="min-h-screen flex flex-col bg-[#0B0D11] text-[#EAECEF] selection:bg-blue-600/30 selection:text-blue-100">
      {/* Top Navigation Bar — Modern Cybersecurity Header */}
      <header className="bg-[#0D1016]/90 backdrop-blur-md border-b border-[#222834] sticky top-0 z-40">
        <div className="max-w-6xl mx-auto px-5 h-16 flex items-center justify-between gap-6">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => navigateTo('scanner')}
              className="flex items-center gap-2.5 text-base font-bold tracking-tight text-[#EAECEF] cursor-pointer"
            >
              <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center text-white shadow-md shadow-blue-500/20">
                <Shield className="w-4 h-4" />
              </div>
              <span className="font-extrabold tracking-wider">URLVault</span>
            </button>
            <span className="hidden md:inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/20">
              v1.0 Security Suite
            </span>
          </div>

          <nav aria-label="Main navigation" className="hidden sm:flex items-center gap-2">
            {navItems.map((item) => {
              const isActive = activePage === item.id;
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => navigateTo(item.id)}
                  className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                    isActive
                      ? 'bg-[#191E28] text-white border border-[#2B3342] shadow-sm'
                      : 'text-[#939DAC] hover:text-[#EAECEF] hover:bg-[#12151C]'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          <div className="flex items-center gap-2.5">
            <button
              type="button"
              onClick={() => setIsAlgorithmModalOpen(true)}
              className="hidden lg:inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-400 hover:text-blue-300 bg-blue-950/30 hover:bg-blue-950/50 border border-blue-900/50 rounded-lg transition-colors cursor-pointer"
            >
              <BookOpen className="w-3.5 h-3.5" />
              <span>Learn More</span>
            </button>

            <button
              type="button"
              onClick={resetAllAndFocus}
              className="px-3.5 py-1.5 text-xs font-semibold text-[#EAECEF] bg-[#191E28] hover:bg-[#222834] border border-[#2B3342] rounded-lg transition-colors whitespace-nowrap cursor-pointer"
            >
              New Scan
            </button>
          </div>
        </div>

        {/* Mobile Navigation */}
        <nav
          aria-label="Mobile navigation"
          className="sm:hidden border-t border-[#222834] px-4 flex items-center justify-around"
        >
          {navItems.map((item) => {
            const isActive = activePage === item.id;
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => navigateTo(item.id)}
                className={`py-2.5 text-xs font-medium flex items-center gap-1.5 border-b-2 transition-colors cursor-pointer ${
                  isActive
                    ? 'text-white border-blue-500'
                    : 'text-[#939DAC] border-transparent'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </header>

      {/* Main Workspace */}
      <main className="flex-1 max-w-6xl w-full mx-auto px-5 py-8">
        {activePage === 'scanner' && (
          <div className="space-y-6">
            {/* Project Hero Header matching user's table description */}
            <div className="p-6 rounded-2xl bg-gradient-to-r from-[#12151C] via-[#161B24] to-[#12151C] border border-[#222834] shadow-xl">
              <div className="space-y-1.5">
                <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-[#EAECEF]">
                  Phishing Domain Generator &amp; Quishing Scanner
                </h1>
                <p className="text-xs sm:text-sm text-[#939DAC] max-w-2xl leading-relaxed">
                  Homoglyph attacks • Typosquatting • QR code analysis • Domain intelligence
                </p>
              </div>

              {/* Real-time Engine Status Pill Bar */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-5 mt-5 border-t border-[#222834]/80 text-[11px] font-mono">
                <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-[#0D1016] border border-[#1A202C]">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-[#C4CBD6]">Live DNS: Active</span>
                </div>
                <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-[#0D1016] border border-[#1A202C]">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-[#C4CBD6]">TLS/SSL: Ready</span>
                </div>
                <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-[#0D1016] border border-[#1A202C]">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-[#C4CBD6]">RDAP Registry: Active</span>
                </div>
                <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-[#0D1016] border border-[#1A202C]">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-[#C4CBD6]">Quishing Engine: Ready</span>
                </div>
              </div>
            </div>

            {errorMessage && (
              <div
                role="alert"
                className="p-4 rounded-xl bg-red-950/35 border border-red-900/60 text-red-200 flex items-start justify-between gap-4"
              >
                <div className="flex items-start gap-3 min-w-0">
                  <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-red-100">Scan Warning</p>
                    <p className="text-xs text-red-200/90 mt-0.5 leading-relaxed">{errorMessage}</p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setErrorMessage(null)}
                  className="p-1 text-red-300 hover:text-red-100 cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            )}

            {/* Split Dual-Workbench */}
            <section className="bg-[#12151C] border border-[#222834] rounded-xl overflow-hidden shadow-xl">
              <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-[#222834]">
                {/* Left Pane: URL & Domain Intelligence */}
                <div className="p-6 flex flex-col justify-between space-y-6">
                  <div>
                    <div className="flex items-center gap-2">
                      <Globe className="w-5 h-5 text-blue-400" />
                      <h2 className="text-base font-bold text-[#EAECEF]">
                        URL &amp; Domain Intelligence
                      </h2>
                    </div>
                    <p className="text-xs text-[#939DAC] mt-1.5 leading-relaxed">
                      Inspect standard domains, raw IP hosts, or Punycode homoglyphs. Executes live DNS, SSL/TLS, RDAP age heuristics, and threat feeds safely.
                    </p>

                    <form onSubmit={handleUrlSubmit} className="mt-5 space-y-4" noValidate>
                      <div>
                        <label
                          htmlFor="url-input"
                          className="block text-xs font-semibold text-[#C4CBD6] mb-1.5"
                        >
                          Target URL or Domain
                        </label>
                        <input
                          ref={urlInputRef}
                          id="url-input"
                          type="text"
                          value={urlInput}
                          onChange={(e) => setUrlInput(e.target.value)}
                          placeholder="e.g. https://pаypal.com or g00gle.com"
                          autoComplete="off"
                          spellCheck={false}
                          disabled={isScanning}
                          className="w-full px-4 py-2.5 text-sm font-mono bg-[#0D1016] border border-[#2B3342] rounded-lg text-[#EAECEF] placeholder:text-[#616B7A] focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:opacity-60"
                        />
                      </div>

                      <button
                        type="submit"
                        disabled={isScanning}
                        className="w-full px-4 py-2.5 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-lg transition-colors cursor-pointer shadow-md flex items-center justify-center gap-2"
                      >
                        {isScanning ? (
                          <>
                            <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                            <span>Running Live Security Checks…</span>
                          </>
                        ) : (
                          <>
                            <Zap className="w-4 h-4" />
                            <span>Analyze Target URL</span>
                          </>
                        )}
                      </button>
                    </form>
                  </div>

                  <p className="text-[11px] text-[#616B7A] pt-4 border-t border-[#222834]">
                    Supports plain domains, HTTPS/HTTP URLs, bare IP addresses, and Punycode (<code className="text-blue-300">xn--</code>) IDN links.
                  </p>
                </div>

                {/* Right Pane: QR Quishing Scanner */}
                <div className="p-6 flex flex-col justify-between space-y-6">
                  <div>
                    <div className="flex items-center gap-2">
                      <QrCode className="w-5 h-5 text-purple-400" />
                      <h2 className="text-base font-bold text-[#EAECEF]">
                        QR Code Quishing Scanner
                      </h2>
                    </div>
                    <p className="text-xs text-[#939DAC] mt-1.5 leading-relaxed">
                      Upload or generate a QR code image. Magic-byte binary verification decodes the embedded payload safely without remote script execution.
                    </p>

                    <form onSubmit={handleQrSubmit} className="mt-5 space-y-4">
                      <div
                        onDragOver={(e) => {
                          e.preventDefault();
                          setIsDragging(true);
                        }}
                        onDragLeave={() => setIsDragging(false)}
                        onDrop={handleDrop}
                        className={`rounded-xl border border-dashed p-4 text-center transition-colors ${
                          isDragging
                            ? 'border-blue-400 bg-blue-950/20'
                            : 'border-[#2B3342] bg-[#0D1016]'
                        }`}
                      >
                        <input
                          ref={fileInputRef}
                          id="qr-file-input"
                          type="file"
                          accept=".png,.jpg,.jpeg,image/png,image/jpeg"
                          onChange={(e) => handleFilePicked(e.target.files?.[0] || null)}
                          className="sr-only"
                        />

                        {selectedFile ? (
                          <div className="flex items-center gap-3 text-left">
                            {previewDataUrl && (
                              <img
                                src={previewDataUrl}
                                alt="QR Preview"
                                className="w-16 h-16 rounded-md object-contain bg-white p-1 border border-[#222834] shrink-0"
                              />
                            )}
                            <div className="min-w-0 flex-1">
                              <p className="text-xs font-semibold text-[#EAECEF] truncate">
                                {selectedFile.name}
                              </p>
                              <p className="text-[11px] font-mono text-[#939DAC] mt-0.5">
                                {(selectedFile.size / 1024).toFixed(1)} KB · Magic-bytes verified
                              </p>
                            </div>
                            <button
                              type="button"
                              onClick={() => {
                                setSelectedFile(null);
                                setPreviewDataUrl(null);
                                if (fileInputRef.current) fileInputRef.current.value = '';
                              }}
                              className="p-1.5 text-[#939DAC] hover:text-[#EAECEF] cursor-pointer"
                            >
                              <X className="w-4 h-4" />
                            </button>
                          </div>
                        ) : (
                          <label
                            htmlFor="qr-file-input"
                            className="flex flex-col items-center cursor-pointer py-3"
                          >
                            <Upload className="w-5 h-5 text-[#939DAC] mb-2" />
                            <span className="text-xs font-medium text-[#EAECEF]">
                              Select a PNG or JPG QR image, or drag &amp; drop
                            </span>
                            <span className="text-[11px] text-[#616B7A] mt-1">
                              Max 5 MB · Verified by genuine binary magic bytes
                            </span>
                          </label>
                        )}
                      </div>

                      <button
                        type="submit"
                        disabled={isScanning || !selectedFile}
                        className="w-full px-4 py-2.5 text-sm font-semibold text-[#EAECEF] bg-[#1D2330] hover:bg-[#262E3F] border border-[#2F384A] disabled:opacity-50 rounded-lg transition-colors cursor-pointer flex items-center justify-center gap-2"
                      >
                        {isScanning ? (
                          <>
                            <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                            <span>Decoding &amp; Inspecting…</span>
                          </>
                        ) : (
                          <>
                            <QrCode className="w-4 h-4" />
                            <span>Inspect Decoded QR</span>
                          </>
                        )}
                      </button>
                    </form>
                  </div>

                  <p className="text-[11px] text-[#616B7A] pt-4 border-t border-[#222834]">
                    Non-URL QR codes display raw plaintext safely without initiating outbound network requests.
                  </p>
                </div>
              </div>
            </section>

            {/* Quick Link to Defensive Lookalike Generator */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl bg-[#12151C] border border-[#222834]">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  <Dna className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-bold text-sm text-[#EAECEF]">
                    Defensive Lookalike &amp; Typosquat Generator
                  </h3>
                  <p className="text-xs text-[#939DAC] mt-0.5">
                    Generate permutations for any domain, probe live DNS to see who registered them, and export brand audit CSVs.
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => navigateTo('generator')}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors whitespace-nowrap self-start sm:self-center cursor-pointer shadow-md"
              >
                <span>Launch Generator</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}

        {activePage === 'generator' && (
          <LookalikeGenerator
            result={lookalikeResult}
            onResultChange={setLookalikeResult}
            onInspectDomain={(domainUrl) => executeLiveUrlScan(domainUrl, 'url')}
            isInspecting={isScanning}
          />
        )}

        {activePage === 'report' && (
          <div className="max-w-4xl mx-auto">
            <ResultsDashboard
              scanResult={scanResult}
              qrTextResult={qrTextResult}
              errorMessage={errorMessage}
              isScanning={isScanning}
              onClear={clearResults}
              onBackToScanner={() => navigateTo('scanner')}
            />
          </div>
        )}
      </main>

      {/* Algorithm & Architecture Modal */}
      <AlgorithmInfoModal
        isOpen={isAlgorithmModalOpen}
        onClose={() => setIsAlgorithmModalOpen(false)}
      />

      {/* Footer */}
      <footer className="border-t border-[#222834] bg-[#0D1016] py-5">
        <div className="max-w-6xl mx-auto px-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-[#616B7A]">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-blue-500" />
            <span className="font-semibold text-[#939DAC]">
              URLVault — Phishing Domain Generator &amp; Quishing Scanner
            </span>
          </div>
          <div className="flex items-center gap-4">
            <button
              type="button"
              onClick={() => setIsAlgorithmModalOpen(true)}
              className="hover:text-[#EAECEF] transition-colors cursor-pointer"
            >
              Algorithms &amp; Architecture
            </button>
            <span>•</span>
            <span>Local VS Code Defense Suite</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
