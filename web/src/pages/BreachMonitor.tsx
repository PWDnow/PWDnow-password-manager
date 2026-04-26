import React, { useState, useRef } from 'react';
import { AlertTriangle, ShieldCheck, Lock, RefreshCw, WifiOff, CheckCircle2, XCircle, SkipForward, Loader2 } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import SEO from '../components/SEO';
import { useVault } from '../context/VaultContext';
import { daemon } from '../utils/daemonClient';
import type { Credential } from '../types';

type ScanState = 'idle' | 'scanning' | 'done' | 'error';

interface ScanResult {
  credential: Credential;
  pwned: boolean;
  filterAvailable: boolean;
  skipped: boolean;
}

export default function BreachMonitor() {
  const { t } = useTranslation();
  const { credentials, daemonConnected } = useVault();
  const [scanState, setScanState] = useState<ScanState>('idle');
  const [results, setResults] = useState<ScanResult[]>([]);
  const [progress, setProgress] = useState(0);
  const cancelRef = useRef(false);

  const credentialsWithPasswords = credentials.filter(c => c.password && c.password.length > 0);

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
        if (daemonConnected) {
          const { pwned, filter_available } = await daemon.checkPasswordBreached(cred.password!);
          accumulated.push({ credential: cred, pwned, filterAvailable: filter_available, skipped: false });
        } else {
          const pwned = await checkViaHibpApi(cred.password!);
          accumulated.push({ credential: cred, pwned, filterAvailable: true, skipped: false });
        }
      } catch {
        accumulated.push({ credential: cred, pwned: false, filterAvailable: true, skipped: true });
      }
      setResults([...accumulated]);
      setProgress(i + 1);
    }

    setScanState(cancelRef.current ? 'idle' : 'done');
  }

  function cancelScan() {
    cancelRef.current = true;
  }

  const pwnedCount  = results.filter(r => r.pwned).length;
  const cleanCount  = results.filter(r => !r.pwned && !r.skipped).length;
  const skippedCount = results.filter(r => r.skipped).length;
  const filterMissing = results.some(r => !r.filterAvailable);
  const total = credentialsWithPasswords.length;

  return (
    <div className="max-w-6xl mx-auto">
      <SEO
        title={t('breachMonitor.title', 'Breach Monitor')}
        description={t('breachMonitor.description', 'Monitor your vault credentials against the local offline HIBP dataset.')}
      />

      {/* Hero */}
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
              ? t('breachMonitor.allClear', 'All Clear — No Breached Passwords')
              : t('breachMonitor.scanTitle', 'Vault Password Breach Scan')}
          </h1>
          <p className="text-surface-container-highest/70 text-lg mb-8 leading-relaxed">
            {daemonConnected
              ? t('breachMonitor.daemonDesc', 'Checks every vault password against the local offline HIBP filter. Passwords never leave your device.')
              : t('breachMonitor.onlineDesc', 'Using the HIBP k-anonymity API — only the first 5 characters of your password hash are sent. Your passwords never leave your device in plaintext.')}
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
                {t('breachMonitor.cancel', `Scanning ${progress}/${total} — Cancel`)}
              </button>
            )}
          </div>
        </div>
        <div className="absolute right-0 top-0 w-1/2 h-full bg-gradient-to-l from-on-primary-container/30 to-transparent" />
        <div className="absolute -right-20 -bottom-20 w-96 h-96 bg-error rounded-full blur-[60px] opacity-20" />
      </section>

      {/* Daemon disconnected info banner — only shown once a scan is in progress or done */}
      {!daemonConnected && scanState !== 'idle' && (
        <section className="mb-8 flex items-start gap-3 px-5 py-4 rounded-xl border border-blue-200 bg-blue-50 dark:bg-blue-950/30 dark:border-blue-900/50 text-blue-800 dark:text-blue-200">
          <WifiOff size={18} className="shrink-0 mt-0.5" />
          <p className="text-sm font-semibold">
            {t('breachMonitor.offlineMode', 'Vault daemon offline — scanning via the HIBP public API (k-anonymity). Connect the daemon for fully offline scanning.')}
          </p>
        </section>
      )}

      {/* Filter missing warning */}
      {daemonConnected && filterMissing && (
        <div className="mb-8 flex items-start gap-3 px-5 py-4 rounded-xl border border-amber-200 bg-amber-50 dark:bg-amber-950/30 dark:border-amber-900/50 text-amber-800 dark:text-amber-200">
          <AlertTriangle size={18} className="shrink-0 mt-0.5" />
          <p className="text-sm font-semibold">
            {t('breachMonitor.filterMissing', 'HIBP filter not installed — run hibp/build-filter.sh then reload the daemon to enable breach lookups.')}
          </p>
        </div>
      )}

      {/* Summary cards */}
      {(scanState === 'scanning' || scanState === 'done') && results.length > 0 && (
        <section className="grid grid-cols-3 gap-6 mb-10">
          {[
            { label: t('breachMonitor.pwned', 'Pwned'), value: pwnedCount, color: 'text-red-600', bg: 'bg-red-50 dark:bg-red-950/30', border: 'border-red-200 dark:border-red-900/50' },
            { label: t('breachMonitor.clean', 'Clean'), value: cleanCount, color: 'text-green-700', bg: 'bg-green-50 dark:bg-green-950/30', border: 'border-green-200 dark:border-green-900/50' },
            { label: t('breachMonitor.checked', 'Checked'), value: results.length, color: 'text-black dark:text-white', bg: 'bg-surface-container-low', border: 'border-outline-variant/20' },
          ].map(({ label, value, color, bg, border }) => (
            <div key={label} className={`${bg} border ${border} rounded-2xl p-6 text-center`}>
              <p className={`text-4xl font-black font-headline ${color}`}>{value}</p>
              <p className="text-xs font-black uppercase tracking-widest text-on-surface-variant mt-1">{label}</p>
            </div>
          ))}
        </section>
      )}

      {/* Progress bar */}
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

      {/* Results list */}
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
                  <span className={`text-[10px] font-black uppercase tracking-widest shrink-0 ${
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
                </motion.div>
              ))}
            </div>
          </section>
        )}
      </AnimatePresence>

      {/* Empty vault notice */}
      {daemonConnected && scanState === 'idle' && total === 0 && (
        <section className="mb-16 flex flex-col items-center justify-center gap-3 py-16 text-on-surface-variant">
          <ShieldCheck size={40} className="opacity-40" />
          <p className="font-bold">{t('breachMonitor.noCredentials', 'No credentials with passwords to scan.')}</p>
        </section>
      )}

      {/* Footer: zero-knowledge info */}
      <section className="grid grid-cols-1 md:grid-cols-2 gap-12 items-center bg-surface-container-low/50 rounded-2xl p-12">
        <div>
          <h2 className="text-2xl md:text-3xl font-headline font-black tracking-tight mb-6">
            {t('breachMonitor.zeroKnowledge', 'Zero-Knowledge, Fully Offline')}
          </h2>
          <p className="text-on-surface-variant leading-relaxed mb-8">
            {t('breachMonitor.zeroKnowledgeDesc', 'PWDnow checks your passwords against a local Cuckoo-filter built from the full HIBP dataset. The daemon hashes each password with SHA-1 and queries the filter in memory — nothing is sent over the network.')}
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
