import React, { useState, useRef, useCallback } from 'react';
import {
  AlertTriangle, ShieldCheck, Lock, RefreshCw, WifiOff,
  CheckCircle2, XCircle, SkipForward, Loader2, Download,
  Upload, X, Terminal, Wifi, Database,
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import SEO from '../components/SEO';
import { useVault } from '../context/VaultContext';
import { daemon } from '../utils/daemonClient';
import { COMMON_PASSWORDS } from '../data/common-passwords';
import type { Credential } from '../types';

type ScanState = 'idle' | 'scanning' | 'done' | 'error';
type CheckMethod = 'daemon' | 'api' | 'common' | 'wordlist' | 'unknown';

interface ScanResult {
  credential: Credential;
  pwned: boolean;
  filterAvailable: boolean;
  skipped: boolean;
  method: CheckMethod;
}

// ── Plan B: HIBP k-anonymity API ────────────────────────────────────────────
async function checkViaHibpApi(password: string): Promise<boolean> {
  const msgBuffer = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  const prefix = hashHex.slice(0, 5);
  const suffix = hashHex.slice(5);
  const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { 'Add-Padding': 'true' },
  });
  if (!resp.ok) throw new Error('HIBP API error');
  const text = await resp.text();
  return text.split('\n').some(line => line.split(':')[0].trim() === suffix);
}

// ── Plan C: custom wordlist (rockyou.txt or any newline list) ────────────────
async function buildWordlistSet(file: File): Promise<Set<string>> {
  const text = await file.text();
  const lines = text.split(/\r?\n/);
  const set = new Set<string>();
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed) set.add(trimmed);
  }
  return set;
}

export default function BreachMonitor() {
  const { t } = useTranslation();
  const { credentials, daemonConnected } = useVault();
  const [scanState, setScanState] = useState<ScanState>('idle');
  const [results, setResults] = useState<ScanResult[]>([]);
  const [progress, setProgress] = useState(0);
  const cancelRef = useRef(false);

  // Custom wordlist state (Plan C+)
  const [wordlist, setWordlist] = useState<Set<string> | null>(null);
  const [wordlistName, setWordlistName] = useState('');
  const [wordlistLoading, setWordlistLoading] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const credentialsWithPasswords = credentials.filter(c => c.password && c.password.length > 0);

  // Determine which plan was used and whether the password was found
  async function checkPassword(password: string): Promise<{ pwned: boolean; filterAvailable: boolean; method: CheckMethod }> {
    // Plan A: local daemon Cuckoo filter
    if (daemonConnected) {
      const { pwned, filter_available } = await daemon.checkPasswordBreached(password);
      if (filter_available) return { pwned, filterAvailable: true, method: 'daemon' };
      // Filter not installed - fall through to Plan B / C
    }

    // Plan B: HIBP k-anonymity API
    try {
      const pwned = await checkViaHibpApi(password);
      return { pwned, filterAvailable: true, method: 'api' };
    } catch {
      // API unavailable - fall through to Plan C
    }

    // Plan C+: custom loaded wordlist (rockyou.txt etc.)
    if (wordlist) {
      return { pwned: wordlist.has(password), filterAvailable: true, method: 'wordlist' };
    }

    // Plan C: bundled common passwords
    return { pwned: COMMON_PASSWORDS.has(password), filterAvailable: true, method: 'common' };
  }

  async function runScan() {
    if (scanState === 'scanning') return;
    cancelRef.current = false;
    setScanState('scanning');
    setResults([]);
    setProgress(0);

    const accumulated: ScanResult[] = [];
    const total = credentialsWithPasswords.length;

    for (let i = 0; i < total; i++) {
      if (cancelRef.current) break;
      const cred = credentialsWithPasswords[i];
      try {
        const { pwned, filterAvailable, method } = await checkPassword(cred.password!);
        accumulated.push({ credential: cred, pwned, filterAvailable, skipped: false, method });
      } catch {
        accumulated.push({ credential: cred, pwned: false, filterAvailable: true, skipped: true, method: 'unknown' });
      }
      setResults([...accumulated]);
      setProgress(i + 1);
    }

    setScanState(cancelRef.current ? 'idle' : 'done');
  }

  function cancelScan() {
    cancelRef.current = true;
  }

  // ── Wordlist loading ───────────────────────────────────────────────────────
  async function loadWordlistFile(file: File) {
    if (!file.name.endsWith('.txt') && !file.name.endsWith('.lst')) return;
    setWordlistLoading(true);
    try {
      const set = await buildWordlistSet(file);
      setWordlist(set);
      setWordlistName(file.name);
    } finally {
      setWordlistLoading(false);
    }
  }

  const handleFileDrop = useCallback(async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) await loadWordlistFile(file);
  }, []);

  const handleFileInput = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) await loadWordlistFile(file);
    e.target.value = '';
  }, []);

  // ── Stats ──────────────────────────────────────────────────────────────────
  const pwnedCount   = results.filter(r => r.pwned).length;
  const cleanCount   = results.filter(r => !r.pwned && !r.skipped).length;
  const skippedCount = results.filter(r => r.skipped).length;
  const filterMissing = daemonConnected && results.some(r => !r.filterAvailable);
  const total = credentialsWithPasswords.length;

  const activeMethods = new Set(results.map(r => r.method));
  const usedPlanC = activeMethods.has('common') || activeMethods.has('wordlist');

  function methodLabel(m: CheckMethod): string {
    const map: Record<CheckMethod, string> = {
      daemon:   t('breachMonitor.methodDaemon', 'Local Filter'),
      api:      t('breachMonitor.methodApi', 'HIBP API'),
      common:   t('breachMonitor.methodCommon', 'Common List'),
      wordlist: t('breachMonitor.methodWordlist', 'Custom Wordlist'),
      unknown:  t('breachMonitor.methodUnknown', 'Unknown'),
    };
    return map[m];
  }

  return (
    <div className="max-w-6xl mx-auto">
      <SEO
        title={t('breachMonitor.title', 'Breach Monitor')}
        description={t('breachMonitor.description', 'Monitor your vault credentials against the local offline HIBP dataset.')}
      />

      {/* ── Hero ──────────────────────────────────────────────────────────── */}
      <section className="mb-12 relative overflow-hidden rounded-xl bg-primary-container text-white p-12">
        <div className="relative z-10 max-w-2xl">
          <div className="flex items-center gap-2 text-on-primary-container mb-4">
            <AlertTriangle size={24} fill="currentColor" />
            <span className="font-headline font-extrabold text-sm uppercase tracking-[0.2em]">
              {t('breachMonitor.offlineCheck', 'Offline Breach Check')}
            </span>
          </div>
          <h1 className="text-4xl md:text-5xl font-headline font-black tracking-tighter mb-4 leading-tight">
            {scanState === 'done' && pwnedCount > 0
              ? t('breachMonitor.pwnedTitle', { count: pwnedCount, defaultValue: `${pwnedCount} Password${pwnedCount !== 1 ? 's' : ''} Found in Breaches` })
              : scanState === 'done'
              ? t('breachMonitor.allClear', 'All Clear - No Breached Passwords')
              : t('breachMonitor.scanTitle', 'Vault Password Breach Scan')}
          </h1>
          <p className="text-surface-container-highest/70 text-lg mb-8 leading-relaxed">
            {daemonConnected
              ? t('breachMonitor.daemonDesc', 'Checks every vault password against the local offline HIBP filter. Passwords never leave your device.')
              : t('breachMonitor.onlineDesc', 'Using the HIBP k-anonymity API - only the first 5 characters of your password hash are sent. Your passwords never leave your device in plaintext.')}
          </p>
          <div className="flex gap-4">
            {scanState !== 'scanning' ? (
              <button
                onClick={runScan}
                disabled={total === 0}
                className="bg-white text-black px-8 py-4 rounded-md font-bold hover:bg-surface-container-low transition-all scale-95 active:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                <RefreshCw size={16} />
                {scanState === 'done'
                  ? t('breachMonitor.rescan', 'Re-scan Vault')
                  : t('breachMonitor.runScan', 'Scan Vault Now')}
              </button>
            ) : (
              <button
                onClick={cancelScan}
                className="bg-white/20 text-white border border-white/30 px-8 py-4 rounded-md font-bold hover:bg-white/30 transition-all flex items-center gap-2"
              >
                <Loader2 size={16} className="animate-spin" />
                {t('breachMonitor.cancel', `Scanning ${progress}/${total} - Cancel`)}
              </button>
            )}
          </div>
        </div>
        <div className="absolute right-0 top-0 w-1/2 h-full bg-gradient-to-l from-on-primary-container/30 to-transparent" />
        <div className="absolute -right-20 -bottom-20 w-96 h-96 bg-error rounded-full blur-[60px] opacity-20" />
      </section>

      {/* ── Detection method banners ───────────────────────────────────────── */}
      {!daemonConnected && scanState !== 'idle' && (
        <section className="mb-6 flex items-start gap-3 px-5 py-4 rounded-xl border border-blue-200 bg-blue-50 dark:bg-blue-950/30 dark:border-blue-900/50 text-blue-800 dark:text-blue-200">
          <WifiOff size={18} className="shrink-0 mt-0.5" />
          <p className="text-sm font-semibold">
            {t('breachMonitor.offlineMode', 'Vault daemon offline - scanning via the HIBP public API (k-anonymity). Connect the daemon for fully offline scanning.')}
          </p>
        </section>
      )}

      {usedPlanC && (
        <section className="mb-6 flex items-start gap-3 px-5 py-4 rounded-xl border border-amber-200 bg-amber-50 dark:bg-amber-950/30 dark:border-amber-900/50 text-amber-800 dark:text-amber-200">
          <AlertTriangle size={18} className="shrink-0 mt-0.5" />
          <p className="text-sm font-semibold">
            {wordlist
              ? t('breachMonitor.rockyouFallback', { count: wordlist.size, defaultValue: `Using custom wordlist (${wordlist.size} passwords loaded).` })
              : t('breachMonitor.planCFallback', 'Plans A & B unavailable - using bundled common password list.')}
          </p>
        </section>
      )}

      {filterMissing && (
        <section className="mb-6 flex items-start gap-3 px-5 py-4 rounded-xl border border-amber-200 bg-amber-50 dark:bg-amber-950/30 dark:border-amber-900/50 text-amber-800 dark:text-amber-200">
          <AlertTriangle size={18} className="shrink-0 mt-0.5" />
          <p className="text-sm font-semibold">
            {t('breachMonitor.filterMissing', 'HIBP filter not installed - run hibp/build-filter.sh then reload the daemon to enable breach lookups.')}
          </p>
        </section>
      )}

      {/* ── Summary cards ─────────────────────────────────────────────────── */}
      {(scanState === 'scanning' || scanState === 'done') && results.length > 0 && (
        <section className="grid grid-cols-3 gap-6 mb-10">
          {[
            { label: t('breachMonitor.pwned', 'Pwned'),   value: pwnedCount,    color: 'text-red-600',              bg: 'bg-red-50 dark:bg-red-950/30',    border: 'border-red-200 dark:border-red-900/50' },
            { label: t('breachMonitor.clean', 'Clean'),   value: cleanCount,    color: 'text-green-700',            bg: 'bg-green-50 dark:bg-green-950/30', border: 'border-green-200 dark:border-green-900/50' },
            { label: t('breachMonitor.checked', 'Checked'), value: results.length, color: 'text-black dark:text-white', bg: 'bg-surface-container-low',         border: 'border-outline-variant/20' },
          ].map(({ label, value, color, bg, border }) => (
            <div key={label} className={`${bg} border ${border} rounded-2xl p-6 text-center`}>
              <p className={`text-4xl font-black font-headline ${color}`}>{value}</p>
              <p className="text-xs font-black uppercase tracking-widest text-on-surface-variant mt-1">{label}</p>
            </div>
          ))}
        </section>
      )}

      {/* ── Progress bar ───────────────────────────────────────────────────── */}
      {scanState === 'scanning' && (
        <div className="mb-8">
          <div className="h-2 bg-surface-container-high rounded-full overflow-hidden">
            <motion.div
              className="h-full bg-black dark:bg-white rounded-full"
              animate={{ width: `${total > 0 ? (progress / total) * 100 : 0}%` }}
              transition={{ ease: 'linear', duration: 0.3 }}
            />
          </div>
        </div>
      )}

      {/* ── Results list ──────────────────────────────────────────────────── */}
      <AnimatePresence>
        {results.length > 0 && (
          <section className="mb-16">
            <h2 className="text-xl font-headline font-extrabold tracking-tight mb-6">
              {t('breachMonitor.resultsTitle', 'Scan Results')}
            </h2>
            <div className="space-y-3">
              {results.map((r, i) => (
                <motion.div
                  key={String(r.credential.id)}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: Math.min(i, 10) * 0.04 }}
                  className={`flex items-center gap-5 p-5 rounded-xl border ${
                    r.skipped
                      ? 'border-outline-variant/20 bg-surface-container-low/50'
                      : r.pwned
                      ? 'border-red-200 dark:border-red-900/50 bg-red-50 dark:bg-red-950/20'
                      : 'border-green-200 dark:border-green-900/50 bg-green-50 dark:bg-green-950/20'
                  }`}
                >
                  <div className="shrink-0">
                    {r.skipped
                      ? <SkipForward size={20} className="text-on-surface-variant" />
                      : r.pwned
                      ? <XCircle size={20} className="text-red-600" />
                      : <CheckCircle2 size={20} className="text-green-600" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="font-bold text-sm truncate text-black dark:text-white">{r.credential.service}</p>
                    {r.credential.username && r.credential.username !== 'No username' && (
                      <p className="text-xs text-on-surface-variant truncate">{r.credential.username}</p>
                    )}
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-[9px] font-black uppercase tracking-widest text-on-surface-variant/60 bg-surface-container-high px-2 py-1 rounded-md">
                      {methodLabel(r.method)}
                    </span>
                    <span className={`text-[10px] font-black uppercase tracking-widest ${
                      r.skipped ? 'text-on-surface-variant' : r.pwned ? 'text-red-700 dark:text-red-400' : 'text-green-700 dark:text-green-400'
                    }`}>
                      {r.skipped
                        ? t('breachMonitor.errorResult', 'Error')
                        : !r.filterAvailable
                        ? t('breachMonitor.filterUnavailable', 'Filter N/A')
                        : r.pwned
                        ? t('breachMonitor.pwnedLabel', 'Breached')
                        : t('breachMonitor.cleanLabel', 'Safe')}
                    </span>
                  </div>
                </motion.div>
              ))}
            </div>
          </section>
        )}
      </AnimatePresence>

      {/* ── Empty vault notice ─────────────────────────────────────────────── */}
      {scanState === 'idle' && total === 0 && (
        <section className="mb-16 flex flex-col items-center justify-center gap-3 py-16 text-on-surface-variant">
          <ShieldCheck size={40} className="opacity-40" />
          <p className="font-bold">{t('breachMonitor.noCredentials', 'No credentials with passwords to scan.')}</p>
        </section>
      )}

      {/* ── Detection Methods ──────────────────────────────────────────────── */}
      <section className="mb-10">
        <h2 className="text-xl font-headline font-extrabold tracking-tight mb-6">
          {t('breachMonitor.detectionMethods', 'Detection Methods')}
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Plan A */}
          <div className={`rounded-2xl p-6 border-2 transition-all ${
            daemonConnected ? 'border-green-500/40 bg-green-50 dark:bg-green-950/20' : 'border-outline-variant/20 bg-surface-container-low opacity-60'
          }`}>
            <div className="flex items-center gap-3 mb-3">
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${daemonConnected ? 'bg-green-600 text-white' : 'bg-surface-container-high text-on-surface-variant'}`}>
                <Database size={16} />
              </div>
              <span className={`text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full ${daemonConnected ? 'bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-300' : 'bg-surface-container-high text-on-surface-variant'}`}>
                {daemonConnected ? 'Active' : 'Offline'}
              </span>
            </div>
            <h3 className="font-bold text-sm mb-1">{t('breachMonitor.planA', 'Plan A - Local HIBP Filter')}</h3>
            <p className="text-xs text-on-surface-variant">{t('breachMonitor.planADesc', '8 GB Cuckoo filter on-device via daemon. Zero network requests.')}</p>
          </div>

          {/* Plan B */}
          <div className={`rounded-2xl p-6 border-2 transition-all ${
            !daemonConnected ? 'border-blue-500/40 bg-blue-50 dark:bg-blue-950/20' : 'border-outline-variant/20 bg-surface-container-low'
          }`}>
            <div className="flex items-center gap-3 mb-3">
              <div className="w-8 h-8 rounded-lg bg-blue-600 text-white flex items-center justify-center">
                <Wifi size={16} />
              </div>
              <span className="text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300">
                {!daemonConnected ? 'Active' : 'Fallback'}
              </span>
            </div>
            <h3 className="font-bold text-sm mb-1">{t('breachMonitor.planB', 'Plan B - HIBP k-Anonymity API')}</h3>
            <p className="text-xs text-on-surface-variant">{t('breachMonitor.planBDesc', 'Only the first 5 SHA-1 characters are sent. Password never transmitted in full.')}</p>
          </div>

          {/* Plan C */}
          <div className="rounded-2xl p-6 border-2 border-outline-variant/20 bg-surface-container-low">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-8 h-8 rounded-lg bg-amber-500 text-white flex items-center justify-center">
                <Terminal size={16} />
              </div>
              <span className="text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300">
                {wordlist ? 'Custom' : 'Bundled'}
              </span>
            </div>
            <h3 className="font-bold text-sm mb-1">{t('breachMonitor.planC', 'Plan C - Common Password List')}</h3>
            <p className="text-xs text-on-surface-variant">{t('breachMonitor.planCDesc', '500+ most-common passwords checked locally when Plans A & B are unavailable.')}</p>
          </div>
        </div>
      </section>

      {/* ── HIBP Filter Setup ──────────────────────────────────────────────── */}
      {daemonConnected && filterMissing && (
        <section className="mb-10 rounded-2xl border-2 border-amber-200 dark:border-amber-900/50 bg-amber-50 dark:bg-amber-950/20 p-8">
          <div className="flex items-start gap-5">
            <div className="w-12 h-12 rounded-xl bg-amber-500 text-white flex items-center justify-center shrink-0">
              <Download size={22} />
            </div>
            <div className="flex-1">
              <h3 className="font-bold text-lg mb-1">{t('breachMonitor.downloadFilter', 'HIBP Filter Setup')}</h3>
              <p className="text-sm text-on-surface-variant mb-4">
                {t('breachMonitor.downloadFilterDesc', 'The local Cuckoo filter is not installed. Run the script below to build it (~8 GB, one-time download).')}
              </p>
              <div className="bg-black rounded-xl px-5 py-4 font-mono text-sm text-green-400 select-all">
                {t('breachMonitor.filterCommand', 'cd hibp && bash build-filter.sh')}
              </div>
            </div>
          </div>
        </section>
      )}

      {daemonConnected && !filterMissing && results.length > 0 && (
        <section className="mb-10 flex items-center gap-3 px-5 py-4 rounded-xl border border-green-200 dark:border-green-900/50 bg-green-50 dark:bg-green-950/20 text-green-800 dark:text-green-200">
          <ShieldCheck size={18} className="shrink-0" />
          <p className="text-sm font-semibold">{t('breachMonitor.filterInstalled', 'Local HIBP filter is active.')}</p>
        </section>
      )}

      {/* ── Custom Wordlist (Plan C+) ──────────────────────────────────────── */}
      <section className="mb-16">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-xl font-headline font-extrabold tracking-tight">
              {t('breachMonitor.customWordlist', 'Load Custom Wordlist (Plan C+)')}
            </h2>
            <p className="text-sm text-on-surface-variant mt-1">
              {t('breachMonitor.customWordlistDesc', 'Drop rockyou.txt or any newline-separated password file for deeper local checking.')}
            </p>
          </div>
          {wordlist && (
            <button
              onClick={() => { setWordlist(null); setWordlistName(''); }}
              className="flex items-center gap-2 text-xs font-bold text-on-surface-variant hover:text-black dark:hover:text-white transition-colors"
            >
              <X size={14} />
              {t('breachMonitor.clearWordlist', 'Clear Wordlist')}
            </button>
          )}
        </div>

        {wordlist ? (
          <div className="flex items-center gap-4 p-5 rounded-xl border-2 border-green-500/40 bg-green-50 dark:bg-green-950/20">
            <CheckCircle2 size={20} className="text-green-600 shrink-0" />
            <div>
              <p className="font-bold text-sm text-black dark:text-white">{wordlistName}</p>
              <p className="text-xs text-on-surface-variant">
                {t('breachMonitor.wordlistLoaded', { count: wordlist.size, defaultValue: `${wordlist.size} passwords loaded from wordlist` })}
              </p>
            </div>
          </div>
        ) : wordlistLoading ? (
          <div className="flex items-center gap-4 p-6 rounded-xl border-2 border-outline-variant/20 bg-surface-container-low">
            <Loader2 size={20} className="text-on-surface-variant animate-spin shrink-0" />
            <p className="text-sm font-semibold text-on-surface-variant">
              {t('breachMonitor.wordlistLoading', 'Processing wordlist…')}
            </p>
          </div>
        ) : (
          <div
            role="button"
            tabIndex={0}
            aria-label={t('breachMonitor.dropFile', 'Drop .txt file here or click to browse')}
            onClick={() => fileInputRef.current?.click()}
            onKeyDown={e => e.key === 'Enter' && fileInputRef.current?.click()}
            onDragOver={e => { e.preventDefault(); setIsDragOver(true); }}
            onDragLeave={() => setIsDragOver(false)}
            onDrop={handleFileDrop}
            className={`flex flex-col items-center justify-center gap-3 p-10 rounded-xl border-2 border-dashed cursor-pointer transition-all ${
              isDragOver
                ? 'border-black dark:border-white bg-black/5 dark:bg-white/5'
                : 'border-outline-variant/40 hover:border-outline-variant/80 bg-surface-container-low'
            }`}
          >
            <Upload size={28} className="text-on-surface-variant" />
            <p className="text-sm font-semibold text-on-surface-variant text-center">
              {t('breachMonitor.dropFile', 'Drop .txt file here or click to browse')}
            </p>
            <p className="text-xs text-on-surface-variant/60">rockyou.txt, darkweb2017.txt, etc.</p>
          </div>
        )}
        <input
          ref={fileInputRef}
          type="file"
          accept=".txt,.lst"
          className="hidden"
          onChange={handleFileInput}
        />
      </section>

      {/* ── Footer: zero-knowledge info ────────────────────────────────────── */}
      <section className="grid grid-cols-1 md:grid-cols-2 gap-12 items-center bg-surface-container-low/50 rounded-2xl p-12">
        <div>
          <h2 className="text-2xl md:text-3xl font-headline font-black tracking-tight mb-6">
            {t('breachMonitor.zeroKnowledge', 'Zero-Knowledge, Fully Offline')}
          </h2>
          <p className="text-on-surface-variant leading-relaxed mb-8">
            {t('breachMonitor.zeroKnowledgeDesc', 'PWDnow checks your passwords against a local Cuckoo-filter built from the full HIBP dataset. The daemon hashes each password with SHA-1 and queries the filter in memory - nothing is sent over the network.')}
          </p>
          <div className="space-y-6">
            <div className="flex items-start gap-4">
              <div className="p-2 bg-black text-white rounded-lg shrink-0">
                <ShieldCheck size={20} />
              </div>
              <div>
                <h4 className="font-bold text-sm">{t('breachMonitor.offlineFilter', 'Offline Filter')}</h4>
                <p className="text-xs text-on-surface-variant">
                  {t('breachMonitor.offlineFilterDesc', '900 M+ breached passwords stored in an 8 GB Cuckoo filter, queried entirely on-device.')}
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <div className="p-2 bg-black text-white rounded-lg shrink-0">
                <Lock size={20} />
              </div>
              <div>
                <h4 className="font-bold text-sm">{t('breachMonitor.hashedComparisons', 'SHA-1 Hashed Comparisons')}</h4>
                <p className="text-xs text-on-surface-variant">
                  {t('breachMonitor.hashedComparisonsDesc', 'Only the hash is compared against the filter. Your plaintext password never leaves the daemon process.')}
                </p>
              </div>
            </div>
          </div>
        </div>
        <div className="flex items-center justify-center">
          <div className="w-40 h-40 bg-surface-container-high rounded-full flex items-center justify-center shadow-lg">
            <ShieldCheck size={72} className="text-black dark:text-white opacity-80" />
          </div>
        </div>
      </section>
    </div>
  );
}
