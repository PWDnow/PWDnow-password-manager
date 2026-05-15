import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { keyStore } from '../crypto/keystore';
import { motion, AnimatePresence } from 'motion/react';
import {
  ShieldCheck, ArrowRight, ArrowLeft, CheckCircle,
  Monitor, Lock, Globe, Shield, Cpu, Server,
  AlertTriangle, RefreshCw, BookOpen, Github,
  HardDrive, Key, Fingerprint, X, ExternalLink,
  Loader2, CheckCircle2, XCircle, Copy,
} from 'lucide-react';
import SEO from '../components/SEO';

// ── Types ─────────────────────────────────────────────────────────────────────

interface TpmInfo {
  present: boolean;
  version: string;   // '2.0' | '1.2' | 'unknown'
  type: string;      // 'firmware_intel_ptt' | 'firmware_amd_ftpm' | 'discrete' | 'unknown'
}

interface HsmInfo {
  present: boolean;
  type: string;      // e.g. 'YubiHSM 2', 'Nitrokey HSM', ''
}

interface DriveEncryptionInfo {
  encrypted: boolean;
  technology: string;   // 'LUKS' | 'VeraCrypt' | 'ZFS' | 'OPAL/SED' | ''
  cipher: string;       // e.g. 'aes-xts-plain64'
  fips_140: string;     // 'true' | 'false'
  csfc: boolean;
}

interface SystemInfo {
  os: string;
  os_pretty: string;
  os_lts: boolean;
  version: string;
  kernel: string;
  arch: string;
  cpu_model: string;
  hostname: string;
  ubuntu_pro: boolean;
  fips_enabled: boolean;
  tpm: TpmInfo;
  hsm: HsmInfo;
  drive_encryption: DriveEncryptionInfo;
  error?: string;
}

// ── Step indicator ─────────────────────────────────────────────────────────────

function StepDots({ current, total }: { current: number; total: number }) {
  return (
    <div className="flex items-center gap-2">
      {Array.from({ length: total }).map((_, i) => (
        <motion.div
          key={i}
          initial={false}
          animate={{
            width: i === current ? 24 : 8,
            backgroundColor: i === current ? '#2563eb' : i < current ? '#93c5fd' : '#d1d5db',
          }}
          transition={{ duration: 0.3 }}
          className="h-2 rounded-full"
        />
      ))}
    </div>
  );
}

// ── TPM type label helper ──────────────────────────────────────────────────────

function tpmTypeLabel(type: string): string {
  switch (type) {
    case 'firmware_intel_ptt': return 'Intel PTT (firmware)';
    case 'firmware_amd_ftpm':  return 'AMD fTPM (firmware)';
    case 'discrete':           return 'Discrete chip';
    default:                   return type || 'Unknown type';
  }
}

// ── System info card ───────────────────────────────────────────────────────────

function InfoCard({
  icon: Icon,
  label,
  value,
  status,
  badge,
  action,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  status?: 'ok' | 'warn' | 'neutral';
  badge?: { text: string; color: 'green' | 'blue' | 'amber' };
  action?: { label: string; onClick: () => void };
}) {
  const statusColor =
    status === 'ok'   ? 'text-green-700 dark:text-green-400 bg-green-50 dark:bg-green-950/40 border-green-200 dark:border-green-800' :
    status === 'warn' ? 'text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800' :
                        'text-on-surface-variant bg-surface-container-high border-outline-variant/20';

  const badgeColor =
    badge?.color === 'green' ? 'bg-green-100 dark:bg-green-900/50 text-green-800 dark:text-green-300' :
    badge?.color === 'blue'  ? 'bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300' :
                               'bg-amber-100 dark:bg-amber-900/50 text-amber-800 dark:text-amber-300';

  return (
    <div className={`flex items-center gap-4 p-4 rounded-xl border ${statusColor}`}>
      <div className="shrink-0">
        <Icon size={20} />
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-[10px] font-black uppercase tracking-widest opacity-60 mb-0.5">{label}</p>
        <p className="font-bold text-sm truncate">{value}</p>
      </div>
      {badge && (
        <span className={`shrink-0 text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full ${badgeColor}`}>
          {badge.text}
        </span>
      )}
      {action && (
        <button
          onClick={action.onClick}
          className="shrink-0 text-[10px] font-black uppercase tracking-widest px-3 py-1.5 rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition-colors"
        >
          {action.label}
        </button>
      )}
    </div>
  );
}

// ── Shared modal shell ─────────────────────────────────────────────────────────

function ModalShell({
  accentColor, icon: Icon, title, subtitle, onClose, children,
}: {
  accentColor: string;
  icon: React.ElementType;
  title: string;
  subtitle: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#000000]/40">
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 16 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 16 }}
        transition={{ duration: 0.2, ease: 'easeOut' }}
        className="w-full max-w-lg bg-white dark:bg-[#1a1a1a] rounded-3xl shadow-2xl border border-outline-variant/10 overflow-hidden max-h-[90vh] flex flex-col"
      >
        <div className="flex items-center justify-between px-8 pt-8 pb-6 border-b border-outline-variant/10 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ backgroundColor: accentColor }}>
              <Icon size={20} className="text-white" />
            </div>
            <div>
              <h2 className="font-headline font-black text-lg text-black dark:text-white leading-tight">{title}</h2>
              <p className="text-[11px] text-on-surface-variant font-medium">{subtitle}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 rounded-xl hover:bg-surface-container-high transition-colors text-on-surface-variant">
            <X size={18} />
          </button>
        </div>
        <div className="px-8 py-6 space-y-5 overflow-y-auto">{children}</div>
      </motion.div>
    </div>
  );
}

// ── Shared step-progress row ───────────────────────────────────────────────────

type StepStatus = 'pending' | 'running' | 'done' | 'error' | 'skipped';

function StepRow({ label, status, output }: { label: string; status: StepStatus; output?: string }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-3">
        <div className="shrink-0 w-5 h-5 flex items-center justify-center">
          {status === 'running' && <Loader2 size={16} className="animate-spin text-blue-600" />}
          {status === 'done'    && <CheckCircle2 size={16} className="text-green-600" />}
          {status === 'error'   && <XCircle size={16} className="text-red-500" />}
          {status === 'skipped' && <CheckCircle2 size={16} className="text-slate-400" />}
          {status === 'pending' && <div className="w-2 h-2 rounded-full bg-slate-300 dark:bg-slate-600 mx-auto" />}
        </div>
        <span className={`text-sm font-bold ${
          status === 'pending' ? 'text-on-surface-variant' :
          status === 'error'   ? 'text-red-700 dark:text-red-400' :
          status === 'skipped' ? 'text-on-surface-variant' :
                                 'text-black dark:text-white'
        }`}>{label}</span>
      </div>
      {output && (
        <pre className="ml-8 text-[10px] text-on-surface-variant whitespace-pre-wrap font-mono leading-relaxed max-h-28 overflow-y-auto bg-surface-container-low rounded-lg p-2 border border-outline-variant/10">
          {output}
        </pre>
      )}
    </div>
  );
}

// ── Ubuntu Pro modal (show copy-paste command) ──────────────────────────────────

function UbuntuProModal({ onClose, onActivated }: { onClose: () => void; onActivated: () => void }) {
  const [token, setToken] = useState('');
  const [copied, setCopied] = useState(false);

  const command = token.trim()
    ? `sudo pro attach ${token.trim()} && sudo pro enable fips --assume-yes`
    : '';

  const handleCopy = () => {
    if (!command) return;
    navigator.clipboard.writeText(command).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <ModalShell accentColor="#E95420" icon={Shield} title="Ubuntu Pro" subtitle="Free for personal use · up to 5 machines" onClose={onClose}>
      {/* Benefits */}
      <div className="space-y-3">
        <p className="text-sm text-on-surface-variant leading-relaxed">
          Ubuntu Pro expands your Ubuntu LTS with enterprise-grade security features at{' '}
          <strong className="text-black dark:text-white">no cost for personal use</strong>.
          Attaching your token will also <strong className="text-black dark:text-white">automatically enable FIPS 140-2</strong> certified modules.
        </p>
        <div className="grid grid-cols-1 gap-2">
          {[
            { label: 'Expanded Security Maintenance (ESM)',  sub: '10 years of security patches for 30,000+ packages' },
            { label: 'FIPS 140-2 certified modules',         sub: 'Certified OpenSSL, kernel crypto - enabled automatically on attach' },
            { label: 'Kernel Livepatch',                     sub: 'Apply kernel security patches without rebooting' },
            { label: 'USG / CIS hardening',                  sub: 'Automated compliance with DISA-STIG & CIS benchmarks' },
          ].map(({ label, sub }) => (
            <div key={label} className="flex items-start gap-3 p-3 rounded-xl bg-surface-container-low border border-outline-variant/10">
              <CheckCircle2 size={15} className="text-[#E95420] shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-bold text-black dark:text-white">{label}</p>
                <p className="text-[11px] text-on-surface-variant">{sub}</p>
              </div>
            </div>
          ))}
        </div>
        <a href="https://ubuntu.com/pro" target="_blank" rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 text-xs font-bold text-[#E95420] hover:underline">
          <ExternalLink size={12} />
          ubuntu.com/pro - register for a free token (up to 5 machines)
        </a>
      </div>

      {/* Token input */}
      <div>
        <label htmlFor="pro-token" className="block text-sm font-bold text-black dark:text-white mb-2">
          I have a licence
        </label>
        <input
          id="pro-token"
          type="text"
          value={token}
          onChange={e => setToken(e.target.value)}
          placeholder="Paste your Ubuntu Pro token…"
          className="w-full px-4 py-3 rounded-xl border border-outline-variant/30 dark:border-white/10 bg-slate-50 dark:bg-[#141414] text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-white/30 focus:ring-2 focus:ring-[#E95420] focus:border-transparent outline-none text-sm font-mono"
          spellCheck={false}
          autoComplete="off"
        />
      </div>

      {/* Generated command */}
      {command && (
        <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="space-y-2">
          <p className="text-xs font-bold text-black dark:text-white">
            Run this command in your terminal:
          </p>
          <div className="relative group">
            <pre className="text-[11px] font-mono bg-slate-900 dark:bg-[#0d0d0d] text-green-400 px-4 py-3 rounded-xl border border-outline-variant/20 whitespace-pre-wrap break-all leading-relaxed pr-12">
              {command}
            </pre>
            <button
              onClick={handleCopy}
              className="absolute top-2 right-2 p-1.5 rounded-lg bg-white/10 hover:bg-white/20 transition-colors"
              title="Copy command"
            >
              {copied
                ? <CheckCircle2 size={14} className="text-green-400" />
                : <Copy size={14} className="text-white/60" />
              }
            </button>
          </div>
          <p className="text-[11px] text-on-surface-variant">
            A reboot may be required after FIPS modules are installed.
          </p>
        </motion.div>
      )}

      {/* Done button */}
      <button
        onClick={onActivated}
        disabled={!token.trim()}
        className="w-full py-3 rounded-xl bg-[#E95420] text-white font-black text-sm hover:bg-[#c94418] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
      >
        Done - I've run the command
      </button>
    </ModalShell>
  );
}

// ── FIPS enable modal (standalone - for already-Pro users) ─────────────────────

function FipsEnableModal({ onClose, onEnabled }: { onClose: () => void; onEnabled: () => void }) {
  const [copied, setCopied] = useState(false);
  const command = 'sudo pro enable fips --assume-yes';

  const handleCopy = () => {
    navigator.clipboard.writeText(command).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <ModalShell accentColor="#2563eb" icon={Lock} title="Enable FIPS 140-2" subtitle="Requires Ubuntu Pro · reboot needed after" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-on-surface-variant leading-relaxed">
          This will install <strong className="text-black dark:text-white">FIPS 140-2 certified cryptographic modules</strong> (OpenSSL, kernel, libgcrypt) and replace the standard Ubuntu packages.
        </p>
        <p className="text-xs text-on-surface-variant/70 italic leading-relaxed">
          Ubuntu Pro currently ships FIPS 140-2 validated modules; FIPS 140-3 module rollout is in progress upstream. PWDnow&apos;s vault daemon cryptography is FIPS 140-3-aligned — see Technical Reference §6.0.
        </p>
        <div className="space-y-2">
          {[
            'FIPS 140-2 validated OpenSSL & libssl',
            'FIPS 140-2 kernel cryptographic API',
            'Required for NIST / CMMC / FedRAMP compliance',
          ].map(line => (
            <div key={line} className="flex items-center gap-2.5 text-sm">
              <CheckCircle2 size={14} className="text-blue-600 shrink-0" />
              <span className="text-black dark:text-white font-medium">{line}</span>
            </div>
          ))}
        </div>

        {/* Command to run */}
        <div className="space-y-2">
          <p className="text-xs font-bold text-black dark:text-white">
            Run this command in your terminal:
          </p>
          <div className="relative">
            <pre className="text-[11px] font-mono bg-slate-900 dark:bg-[#0d0d0d] text-green-400 px-4 py-3 rounded-xl border border-outline-variant/20 whitespace-pre-wrap break-all leading-relaxed pr-12">
              {command}
            </pre>
            <button
              onClick={handleCopy}
              className="absolute top-2 right-2 p-1.5 rounded-lg bg-white/10 hover:bg-white/20 transition-colors"
              title="Copy command"
            >
              {copied
                ? <CheckCircle2 size={14} className="text-green-400" />
                : <Copy size={14} className="text-white/60" />
              }
            </button>
          </div>
        </div>

        <div className="flex items-start gap-3 p-3.5 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800">
          <AlertTriangle size={15} className="text-amber-600 shrink-0 mt-0.5" />
          <p className="text-[11px] text-amber-800 dark:text-amber-300 font-medium">
            A reboot will be required after FIPS modules are installed. The system will not use FIPS until restarted.
          </p>
        </div>

        <div className="flex gap-3 pt-1">
          <button onClick={onClose}
            className="flex-1 py-3 rounded-xl bg-surface-container-low text-black dark:text-white font-black text-sm hover:bg-surface-container-high transition-colors border border-outline-variant/20">
            Cancel
          </button>
          <button onClick={onEnabled}
            className="flex-1 py-3 rounded-xl bg-blue-600 text-white font-black text-sm hover:bg-blue-700 transition-colors shadow-lg shadow-blue-600/20">
            Done - I've run it
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function Setup() {
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const [direction, setDirection] = useState(1); // 1 = forward, -1 = backward

  // System scan state
  const [scanning, setScanning] = useState(false);
  const [sysInfo, setSysInfo] = useState<SystemInfo | null>(null);

  // Ubuntu Pro modal
  const [showProModal, setShowProModal] = useState(false);

  // FIPS enable modal (standalone - for users already on Pro)
  const [showFipsModal, setShowFipsModal] = useState(false);

  // Completion state
  const [completing, setCompleting] = useState(false);

  // ── Guard: if setup already done, go to login ──────────────────────────────
  useEffect(() => {
    fetch('/api/setup-status')
      .then(r => r.json())
      .then(({ completed }: { completed: boolean }) => {
        if (completed) {
          const hasServerSession = document.cookie.split(';').some(c => c.trim().startsWith('_pwd_csrf='));
          navigate(keyStore.hasToken || hasServerSession ? '/vault' : '/login', { replace: true });
        }
      })
      .catch(() => { /* server may not be up yet - stay on setup */ });
  }, [navigate]);

  // ── Fetch system info when step 1 mounts ──────────────────────────────────
  useEffect(() => {
    if (step !== 1) return;
    setScanning(true);
    fetch('/api/system-info')
      .then(r => r.json())
      .then((data: SystemInfo) => setSysInfo(data))
      .catch(() => setSysInfo({ os: 'unknown', os_pretty: 'Unknown', os_lts: false, version: '', kernel: '', arch: '', cpu_model: '', hostname: '', ubuntu_pro: false, fips_enabled: false, tpm: { present: false, version: 'unknown', type: 'unknown' }, hsm: { present: false, type: '' }, drive_encryption: { encrypted: false, technology: '', cipher: '', fips_140: 'false', csfc: false }, error: 'Could not reach /api/system-info' }))
      .finally(() => setScanning(false));
  }, [step]);

  // ── Navigation helpers ─────────────────────────────────────────────────────
  const goNext = () => { setDirection(1); setStep(s => s + 1); };
  const goBack = () => { setDirection(-1); setStep(s => s - 1); };

  const handleComplete = async () => {
    setCompleting(true);
    try {
      await fetch('/api/setup-complete', { method: 'POST' });
    } catch { /* best-effort */ }
    navigate('/register', { replace: true });
  };

  // ── Animation variants ────────────────────────────────────────────────────
  const variants = {
    enter:  (d: number) => ({ opacity: 0, x: d > 0 ?  40 : -40 }),
    center: { opacity: 1, x: 0 },
    exit:   (d: number) => ({ opacity: 0, x: d > 0 ? -40 :  40 }),
  };

  // Re-fetch system info (called after Pro activation to update the card)
  const refreshSysInfo = () => {
    setScanning(true);
    fetch('/api/system-info')
      .then(r => r.json())
      .then((data: SystemInfo) => setSysInfo(data))
      .catch(() => {})
      .finally(() => setScanning(false));
  };

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-surface flex flex-col items-center justify-center p-6">
      <SEO title="Setup - PWDnow" description="First-run setup wizard for PWDnow." />

      <div className="w-full max-w-xl">
        {/* Logo bar */}
        <div className="flex items-center gap-3 mb-12 justify-center">
          <div className="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center shadow-lg shadow-blue-600/30">
            <ShieldCheck size={22} className="text-white" />
          </div>
          <span className="font-headline font-black text-xl tracking-tight">PWDnow</span>
        </div>

        {/* Card */}
        <div className="bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl border border-outline-variant/10 overflow-hidden">
          <AnimatePresence mode="wait" custom={direction}>
            {/* ════════════════════════════════════════════════════
                STEP 0 - Welcome
            ════════════════════════════════════════════════════ */}
            {step === 0 && (
              <motion.div
                key="step-0"
                custom={direction}
                variants={variants}
                initial="enter"
                animate="center"
                exit="exit"
                transition={{ duration: 0.28, ease: 'easeInOut' }}
                className="p-10 flex flex-col gap-8"
              >
                {/* Hero */}
                <div className="flex flex-col items-center text-center gap-5">
                  <div className="w-20 h-20 rounded-2xl bg-blue-600 flex items-center justify-center shadow-xl shadow-blue-600/25">
                    <ShieldCheck size={40} className="text-white" />
                  </div>
                  <div>
                    <h1 className="font-headline font-black text-3xl md:text-4xl tracking-tight text-black dark:text-white mb-3">
                      Welcome to PWDnow
                    </h1>
                    <p className="text-on-surface-variant text-base leading-relaxed max-w-md">
                      Your self-hosted, open-source password manager - built for security-conscious teams and individuals.
                    </p>
                  </div>
                </div>

                {/* Feature chips */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  {[
                    { icon: Lock,   label: 'End-to-end encrypted',  sub: 'AES-256 + Argon2id' },
                    { icon: Globe,  label: 'Open source',           sub: 'MIT licensed' },
                    { icon: Shield, label: 'FIPS-ready',            sub: 'FIPS 140-2 support' },
                  ].map(({ icon: Icon, label, sub }) => (
                    <div key={label} className="flex flex-col items-center gap-2 p-4 rounded-2xl bg-surface-container-low border border-outline-variant/10 text-center">
                      <div className="w-10 h-10 rounded-xl bg-blue-50 dark:bg-blue-950/40 flex items-center justify-center">
                        <Icon size={20} className="text-blue-600 dark:text-blue-400" />
                      </div>
                      <div>
                        <p className="font-bold text-sm">{label}</p>
                        <p className="text-[10px] text-on-surface-variant">{sub}</p>
                      </div>
                    </div>
                  ))}
                </div>

                {/* About text */}
                <div className="p-5 rounded-2xl bg-surface-container-low border border-outline-variant/10 space-y-3 text-sm text-on-surface-variant leading-relaxed">
                  <p>
                    PWDnow stores all credentials locally - <strong className="text-black dark:text-white">no cloud, no telemetry, no vendor lock-in.</strong> You own your data.
                  </p>
                  <p>
                    Supports TOTP, WebAuthn hardware keys, and email OTP for multi-factor authentication. Full audit log. Recovery kit. Emergency access controls.
                  </p>
                  <div className="flex items-center gap-4 pt-1">
                    <a
                      href="https://github.com/pwdnow/pwdnow"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1.5 text-xs font-bold text-black dark:text-white hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
                    >
                      <Github size={14} />GitHub
                    </a>
                    <a
                      href="https://docs.pwdnow.app"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1.5 text-xs font-bold text-black dark:text-white hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
                    >
                      <BookOpen size={14} />Documentation
                    </a>
                  </div>
                </div>

                {/* Next */}
                <button
                  onClick={goNext}
                  className="w-full py-4 bg-blue-600 text-white rounded-xl font-black uppercase tracking-widest text-sm hover:bg-blue-700 active:scale-[0.99] transition-all shadow-lg shadow-blue-600/20 flex items-center justify-center gap-2"
                >
                  Get Started <ArrowRight size={18} />
                </button>
              </motion.div>
            )}

            {/* ════════════════════════════════════════════════════
                STEP 1 - System Scan
            ════════════════════════════════════════════════════ */}
            {step === 1 && (
              <motion.div
                key="step-1"
                custom={direction}
                variants={variants}
                initial="enter"
                animate="center"
                exit="exit"
                transition={{ duration: 0.28, ease: 'easeInOut' }}
                className="p-10 flex flex-col gap-8"
              >
                <div>
                  <h2 className="font-headline font-black text-2xl text-black dark:text-white mb-2">System Requirements</h2>
                  <p className="text-on-surface-variant text-sm leading-relaxed">
                    Scanning your host system for compatibility and security features.
                  </p>
                </div>

                {/* Scan results */}
                {scanning ? (
                  <div className="flex flex-col items-center justify-center gap-4 py-10">
                    <RefreshCw size={32} className="text-blue-600 animate-spin" />
                    <p className="text-sm text-on-surface-variant font-bold">Scanning system…</p>
                  </div>
                ) : sysInfo?.error ? (
                  <div className="p-5 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-2xl flex items-start gap-3">
                    <AlertTriangle size={20} className="text-amber-600 shrink-0 mt-0.5" />
                    <div>
                      <p className="font-bold text-sm text-amber-800 dark:text-amber-300 mb-1">Could not scan system</p>
                      <p className="text-xs text-amber-700/80 dark:text-amber-400/80">{sysInfo.error}</p>
                    </div>
                  </div>
                ) : sysInfo ? (
                  <div className="space-y-3">
                    {/* OS */}
                    <InfoCard
                      icon={Monitor}
                      label="Operating System"
                      value={`${sysInfo.os_pretty}${sysInfo.version ? ` (${sysInfo.version})` : ''}`}
                      status="neutral"
                      badge={sysInfo.os_lts ? { text: 'LTS', color: 'green' } : undefined}
                    />
                    {/* Hostname */}
                    <InfoCard
                      icon={Server}
                      label="Hostname"
                      value={sysInfo.hostname || '-'}
                      status="neutral"
                    />
                    {/* Kernel + Arch */}
                    <InfoCard
                      icon={Cpu}
                      label="Kernel / Architecture"
                      value={`${sysInfo.kernel} · ${sysInfo.arch}`}
                      status="neutral"
                    />
                    {/* Ubuntu Pro - only shown for Ubuntu */}
                    {sysInfo.os === 'ubuntu' && (
                      <InfoCard
                        icon={Shield}
                        label="Ubuntu Pro"
                        value={sysInfo.ubuntu_pro ? 'Active - expanded security patches' : 'Not active'}
                        status={sysInfo.ubuntu_pro ? 'ok' : 'neutral'}
                        action={!sysInfo.ubuntu_pro ? { label: 'Enable', onClick: () => setShowProModal(true) } : undefined}
                      />
                    )}
                    {/* FIPS kernel - shown if ubuntu or if enabled */}
                    {(sysInfo.os === 'ubuntu' || sysInfo.fips_enabled) && (
                      <InfoCard
                        icon={Lock}
                        label="FIPS 140-2 Kernel"
                        value={sysInfo.fips_enabled ? 'Enabled - approved crypto modules active' : 'Not enabled'}
                        status={sysInfo.fips_enabled ? 'ok' : 'neutral'}
                        action={
                          !sysInfo.fips_enabled && sysInfo.ubuntu_pro
                            ? { label: 'Enable', onClick: () => setShowFipsModal(true) }
                            : undefined
                        }
                      />
                    )}
                    {/* TPM */}
                    <InfoCard
                      icon={Fingerprint}
                      label="TPM"
                      value={
                        sysInfo.tpm.present
                          ? `TPM ${sysInfo.tpm.version} · ${tpmTypeLabel(sysInfo.tpm.type)}`
                          : 'Not detected'
                      }
                      status={sysInfo.tpm.present ? 'ok' : 'neutral'}
                    />
                    {/* HSM */}
                    <InfoCard
                      icon={Key}
                      label="Hardware Security Module (HSM)"
                      value={sysInfo.hsm.present ? sysInfo.hsm.type || 'Detected' : 'Not detected'}
                      status={sysInfo.hsm.present ? 'ok' : 'neutral'}
                    />
                    {/* Drive encryption */}
                    <InfoCard
                      icon={HardDrive}
                      label="Drive Encryption"
                      value={
                        sysInfo.drive_encryption.encrypted
                          ? `${sysInfo.drive_encryption.technology}${sysInfo.drive_encryption.cipher ? ` · ${sysInfo.drive_encryption.cipher}` : ''}`
                          : 'Not detected'
                      }
                      status={sysInfo.drive_encryption.encrypted ? 'ok' : 'warn'}
                    />
                    {/* CSfC banner */}
                    {sysInfo.drive_encryption.csfc && (
                      <div className="flex items-center gap-3 p-4 rounded-xl bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800">
                        <ShieldCheck size={18} className="text-blue-600 shrink-0" />
                        <p className="text-xs font-bold text-blue-800 dark:text-blue-300">
                          CSfC dual-layer encryption detected - two independent encryption layers are active.
                        </p>
                      </div>
                    )}
                    {/* FIPS 140 drive encryption banner */}
                    {sysInfo.drive_encryption.fips_140 === 'true' && (
                      <div className="flex items-center gap-3 p-4 rounded-xl bg-green-50 dark:bg-green-950/40 border border-green-200 dark:border-green-800">
                        <CheckCircle size={18} className="text-green-600 shrink-0" />
                        <p className="text-xs font-bold text-green-800 dark:text-green-300">
                          FIPS 140 drive encryption - AES-XTS-512 with FIPS-validated kernel modules.
                        </p>
                      </div>
                    )}
                    {/* FIPS kernel compliance banner (kernel-level, not drive) */}
                    {sysInfo.fips_enabled && sysInfo.drive_encryption.fips_140 !== 'true' && (
                      <div className="flex items-center gap-3 p-4 rounded-xl bg-green-50 dark:bg-green-950/40 border border-green-200 dark:border-green-800">
                        <CheckCircle size={18} className="text-green-600 shrink-0" />
                        <p className="text-xs font-bold text-green-800 dark:text-green-300">
                          FIPS 140-2 compliant - all kernel cryptographic operations use approved modules.
                        </p>
                      </div>
                    )}
                  </div>
                ) : null}

                {/* Navigation */}
                <div className="flex gap-3">
                  <button
                    onClick={goBack}
                    className="flex items-center gap-2 px-6 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all"
                  >
                    <ArrowLeft size={16} />Back
                  </button>
                  <button
                    onClick={goNext}
                    disabled={scanning}
                    className="flex-1 py-4 bg-blue-600 text-white rounded-xl font-black uppercase tracking-widest text-sm hover:bg-blue-700 active:scale-[0.99] transition-all shadow-lg shadow-blue-600/20 flex items-center justify-center gap-2 disabled:opacity-50"
                  >
                    Continue <ArrowRight size={18} />
                  </button>
                </div>
              </motion.div>
            )}

            {/* ════════════════════════════════════════════════════
                STEP 2 - Complete
            ════════════════════════════════════════════════════ */}
            {step === 2 && (
              <motion.div
                key="step-2"
                custom={direction}
                variants={variants}
                initial="enter"
                animate="center"
                exit="exit"
                transition={{ duration: 0.28, ease: 'easeInOut' }}
                className="p-10 flex flex-col items-center gap-8 text-center"
              >
                {/* Animated checkmark */}
                <motion.div
                  initial={{ scale: 0.5, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  transition={{ delay: 0.1, type: 'spring', stiffness: 200, damping: 15 }}
                  className="w-24 h-24 rounded-full bg-green-50 dark:bg-green-950/40 flex items-center justify-center"
                >
                  <CheckCircle size={48} className="text-green-600" />
                </motion.div>

                <div>
                  <h2 className="font-headline font-black text-3xl text-black dark:text-white mb-3">
                    Setup complete
                  </h2>
                  <p className="text-on-surface-variant text-sm leading-relaxed max-w-sm">
                    PWDnow is ready. Create your admin account to start managing credentials securely.
                  </p>
                </div>

                {/* Summary chips */}
                <div className="w-full space-y-2 text-left">
                  {[
                    { icon: Lock,         text: 'End-to-end encryption enabled' },
                    { icon: ShieldCheck,  text: 'Vault daemon ready' },
                    { icon: Monitor,      text: sysInfo ? `Running on ${sysInfo.os_pretty}` : 'System scanned' },
                  ].map(({ icon: Icon, text }) => (
                    <div key={text} className="flex items-center gap-3 px-4 py-3 rounded-xl bg-surface-container-low border border-outline-variant/10">
                      <Icon size={16} className="text-green-600 shrink-0" />
                      <span className="text-sm font-bold">{text}</span>
                    </div>
                  ))}
                </div>

                <div className="w-full flex gap-3">
                  <button
                    onClick={goBack}
                    className="flex items-center gap-2 px-6 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all"
                  >
                    <ArrowLeft size={16} />Back
                  </button>
                  <button
                    onClick={handleComplete}
                    disabled={completing}
                    className="flex-1 py-4 bg-blue-600 text-white rounded-xl font-black uppercase tracking-widest text-sm hover:bg-blue-700 active:scale-[0.99] transition-all shadow-lg shadow-blue-600/20 flex items-center justify-center gap-2 disabled:opacity-50"
                  >
                    {completing ? <RefreshCw size={18} className="animate-spin" /> : <ArrowRight size={18} />}
                    {completing ? 'Starting…' : 'Create Admin Account'}
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Progress dots */}
        <div className="flex justify-center mt-8">
          <StepDots current={step} total={3} />
        </div>
      </div>

      {/* Ubuntu Pro modal */}
      <AnimatePresence>
        {showProModal && (
          <UbuntuProModal
            onClose={() => setShowProModal(false)}
            onActivated={() => {
              setShowProModal(false);
              refreshSysInfo();
            }}
          />
        )}
      </AnimatePresence>

      {/* FIPS enable modal (standalone) */}
      <AnimatePresence>
        {showFipsModal && (
          <FipsEnableModal
            onClose={() => setShowFipsModal(false)}
            onEnabled={() => {
              setShowFipsModal(false);
              refreshSysInfo();
            }}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
