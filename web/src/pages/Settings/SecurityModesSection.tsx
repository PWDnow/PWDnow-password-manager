import React, { useState, useCallback } from 'react';
import {
  ChevronDown, CheckCircle, Edit3, Flame, ShieldCheck,
  History as HistoryIcon, Share2, Server, Plane, Skull,
  X, AlertTriangle, Check, Eye, EyeOff, Loader2,
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { useVault } from '../../context/VaultContext';
import { daemon } from '../../utils/daemonClient';
import { BROWSER_AUTOFILL } from '../../utils/cardUtils';
import {
  getDuressModeConfig, getDuressModeConfigFull,
  getTravelModeConfig, getTravelModeConfigAsync,
  armDuressMode, disarmDuressMode,
  enableTravelMode, disableTravelMode,
  wipeVaultData,
  type DuressModeConfig, type TravelModeConfig,
} from '../../utils/securityModes';
import type { EmailServerConfig } from '../../types';

// ── Flowbite-style SVG icons ────────────────────────────────────────────────
type SvgP = { size?: number; className?: string };
const FbTimer = ({ size = 20, className = '' }: SvgP) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <circle cx="12" cy="13" r="8"/><path d="M12 9v4l2.5 2.5"/><path d="M9 2h6"/><path d="M12 2v3"/>
  </svg>
);
const FbServer = ({ size = 20, className = '' }: SvgP) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/>
    <line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>
  </svg>
);
const FbPlane = ({ size = 20, className = '' }: SvgP) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.72 12 19.79 19.79 0 0 1 1.64 3.4 2 2 0 0 1 3.62 1.22h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L7.91 8.82a16 16 0 0 0 6.29 6.29l.97-.97a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7a2 2 0 0 1 1.74 2.03z"/>
  </svg>
);
const FbSkull = ({ size = 20, className = '' }: SvgP) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <circle cx="9" cy="12" r="1"/><circle cx="15" cy="12" r="1"/>
    <path d="M8 20v2h8v-2"/><path d="m12.5 17-.5-1-.5 1"/>
    <path d="M16 20a2 2 0 0 0 1.56-3.25 8 8 0 1 0-11.12 0A2 2 0 0 0 8 20"/>
  </svg>
);

interface Props {
  sessionLockTimeout: string;
  handleSessionLockChange: (v: string) => void;
  emailServerConfig: EmailServerConfig | null;
  setEmailServerForm: (v: EmailServerConfig) => void;
  setIsEmailServerModalOpen: (v: boolean) => void;
  DEFAULT_EMAIL_CONFIG: EmailServerConfig;
  isAuditLogOpen: boolean;
  setIsAuditLogOpen: (v: boolean) => void;
  isSharesOpen: boolean;
  setIsSharesOpen: (v: boolean) => void;
}

export default function SecurityModesSection({
  sessionLockTimeout, handleSessionLockChange,
  emailServerConfig, setEmailServerForm, setIsEmailServerModalOpen, DEFAULT_EMAIL_CONFIG,
  isAuditLogOpen, setIsAuditLogOpen, isSharesOpen, setIsSharesOpen,
}: Props) {
  const { t } = useTranslation();
  const { credentials, folders, reloadLocal } = useVault();

  // ── Duress mode state ─────────────────────────────────────────────────────
  const [duressConfig, setDuressConfig] = useState<DuressModeConfig>(getDuressModeConfig);
  const [isDuressModalOpen, setIsDuressModalOpen] = useState(false);
  const [duressStep, setDuressStep] = useState<1 | 2 | 3>(1);
  const [duressPassword, setDuressPassword] = useState('');
  const [confirmDuressPassword, setConfirmDuressPassword] = useState('');
  const [showDuressPassword, setShowDuressPassword] = useState(false);
  const [duressMaxAttempts, setDuressMaxAttempts] = useState(() => getDuressModeConfig().maxAttempts || 5);
  const [duressError, setDuressError] = useState('');
  const [isArmingDuress, setIsArmingDuress] = useState(false);
  const [isDuressWipeOpen, setIsDuressWipeOpen] = useState(false);
  const [isWiping, setIsWiping] = useState(false);

  // ── Travel mode state ─────────────────────────────────────────────────────
  const [travelConfig, setTravelConfig] = useState<TravelModeConfig>(getTravelModeConfig);
  const [isTravelModalOpen, setIsTravelModalOpen] = useState(false);
  const [travelStep, setTravelStep] = useState<1 | 2 | 3 | 4>(1);
  const [travelHiddenFolderIds, setTravelHiddenFolderIds] = useState<string[]>([]);
  const [travelPassword, setTravelPassword] = useState('');
  const [confirmTravelPassword, setConfirmTravelPassword] = useState('');
  const [showTravelPassword, setShowTravelPassword] = useState(false);
  const [travelError, setTravelError] = useState('');
  const [isEnablingTravel, setIsEnablingTravel] = useState(false);
  const [isDisableTravelOpen, setIsDisableTravelOpen] = useState(false);
  const [disableTravelPw, setDisableTravelPw] = useState('');
  const [disableTravelError, setDisableTravelError] = useState('');
  const [isDisablingTravel, setIsDisablingTravel] = useState(false);

  // ── Sync with server on mount ─────────────────────────────────────────────
  React.useEffect(() => {
    getDuressModeConfigFull().then(setDuressConfig);
    getTravelModeConfigAsync().then(setTravelConfig);
  }, []);

  // ── Duress handlers ───────────────────────────────────────────────────────
  const toggleTravelFolder = (id: string) =>
    setTravelHiddenFolderIds(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);

  const handleArmDuress = useCallback(async () => {
    if (duressPassword.length < 8) { setDuressError(t('settings.duressPasswordMinError', 'Duress password must be at least 8 characters.')); return; }
    if (duressPassword !== confirmDuressPassword) { setDuressError(t('settings.duressPasswordMismatch', 'Passwords do not match.')); return; }
    setIsArmingDuress(true);
    await armDuressMode(duressPassword, duressMaxAttempts);
    setDuressConfig(getDuressModeConfig());
    setIsArmingDuress(false);
    setDuressStep(3);
  }, [duressPassword, confirmDuressPassword, duressMaxAttempts, t]);

  const handleDisarmDuress = useCallback(async () => {
    await disarmDuressMode();
    setDuressConfig(getDuressModeConfig());
    setIsDuressModalOpen(false);
  }, []);

  const handleTriggerWipe = useCallback(async () => {
    setIsWiping(true);
    await wipeVaultData(daemon.isConnected ? daemon : undefined);
    window.location.replace('/login');
  }, []);

  // ── Travel handlers ───────────────────────────────────────────────────────
  const handleEnableTravel = useCallback(async () => {
    if (travelHiddenFolderIds.length === 0) { setTravelError(t('settings.travelSelectAtLeastOne', 'Select at least one folder to hide.')); return; }
    if (travelPassword.length < 8) { setTravelError(t('settings.travelPasswordMinError', 'Minimum 8 characters.')); return; }
    if (travelPassword !== confirmTravelPassword) { setTravelError(t('settings.travelPasswordMismatch', 'Passwords do not match.')); return; }
    setIsEnablingTravel(true);
    await enableTravelMode(travelPassword, travelHiddenFolderIds, credentials, folders);
    setTravelConfig(getTravelModeConfig());
    setIsEnablingTravel(false);
    await reloadLocal();
    setTravelStep(4);
  }, [travelHiddenFolderIds, travelPassword, confirmTravelPassword, credentials, folders, t]);

  const handleDisableTravel = useCallback(async () => {
    setIsDisablingTravel(true);
    const result = await disableTravelMode(disableTravelPw, credentials, folders);
    if (!result.ok) {
      setDisableTravelError(t('settings.travelWrongPassword', 'Incorrect password.'));
      setIsDisablingTravel(false);
      return;
    }
    setTravelConfig(getTravelModeConfig());
    setIsDisablingTravel(false);
    setIsDisableTravelOpen(false);
    await reloadLocal();
  }, [disableTravelPw, credentials, folders, t, reloadLocal]);

  return (
    <div className="space-y-16">

      {/* ── Session Lock ────────────────────────────────────────────────────── */}
      <section>
        <div className="mb-6">
          <h2 className="text-[15px] font-semibold text-neutral-900 dark:text-white leading-snug">{t('settings.sessionLock', 'Session Lock')}</h2>
          <div className="mt-4 h-px bg-neutral-200 dark:bg-white/8" />
        </div>
        <div className="bg-surface-container-low p-10 rounded-xl flex items-center justify-between gap-8">
          <div>
            <h3 className="font-bold text-xl mb-2">{t('settings.autoLock', 'Auto-Lock After Inactivity')}</h3>
            <p className="text-sm text-on-surface-variant leading-relaxed">
              {t('settings.autoLockDesc', 'Automatically sign you out after a period of inactivity to protect your vault.')}
            </p>
          </div>
          <div className="relative shrink-0">
            <select
              value={sessionLockTimeout}
              onChange={(e) => handleSessionLockChange(e.target.value)}
              className="appearance-none bg-surface-container-high text-sm font-bold px-6 py-3 pr-10 rounded-lg cursor-pointer focus:outline-none focus:ring-2 focus:ring-black dark:focus:ring-white"
            >
              <option value="30000">{t('settings.lock30s', '30 seconds')}</option>
              <option value="60000">{t('settings.lock1m', '1 minute')}</option>
              <option value="300000">{t('settings.lock5m', '5 minutes')}</option>
              <option value="600000">{t('settings.lock10m', '10 minutes')}</option>
              <option value="1500000">{t('settings.lock25m', '25 minutes')}</option>
              <option value="off">{t('settings.lockOff', 'Off')}</option>
            </select>
            <ChevronDown size={16} className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none text-on-surface-variant" />
          </div>
        </div>
      </section>

      {/* ── Email Server ─────────────────────────────────────────────────────── */}
      <section>
        <div className="mb-6">
          <h2 className="text-[15px] font-semibold text-neutral-900 dark:text-white leading-snug">{t('settings.emailServer', 'Email Server')}</h2>
          <div className="mt-4 h-px bg-neutral-200 dark:bg-white/8" />
        </div>
        <div className="bg-surface-container-low p-10 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6">
          <div>
            <h3 className="font-bold text-xl mb-2">{t('settings.emailServerTitle', 'SMTP Configuration')}</h3>
            <p className="text-sm text-on-surface-variant leading-relaxed max-w-md">
              {t('settings.emailServerDesc', 'Configure your outgoing mail server for password resets and notifications.')}
            </p>
            {emailServerConfig && (
              <div className="mt-3 flex items-center gap-2 flex-wrap">
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 text-xs font-bold uppercase tracking-wider">
                  <CheckCircle size={12} /> {t('settings.emailServerConnected', 'Configured')}
                </span>
                <span className="text-xs text-on-surface-variant font-mono">{emailServerConfig.host}:{emailServerConfig.port}</span>
              </div>
            )}
          </div>
          <button
            onClick={() => {
              let initial = emailServerConfig ?? { ...DEFAULT_EMAIL_CONFIG };
              if (!initial.protocol) {
                initial = { ...initial, protocol: initial.secure ? 'ssl_tls' : 'starttls' };
              }
              setEmailServerForm(initial);
              setIsEmailServerModalOpen(true);
            }}
            className="shrink-0 px-8 py-4 bg-black dark:bg-white text-white dark:text-black rounded-xl font-bold text-sm hover:opacity-90 transition-all flex items-center gap-3 shadow-lg"
          >
            {emailServerConfig ? <><Edit3 size={18} />{t('settings.editEmailServer', 'Edit')}</> : <><Server size={18} />{t('settings.setupEmailServer', 'Setup')}</>}
          </button>
        </div>
      </section>

      {/* ── Travel Mode ───────────────────────────────────────────────────────── */}
      <section>
        <div className="mb-6">
          <h2 className="text-[15px] font-semibold text-neutral-900 dark:text-white leading-snug">{t('settings.offlineTravelMode', 'Travel Mode')}</h2>
          <div className="mt-4 h-px bg-neutral-200 dark:bg-white/8" />
        </div>
        <div className={`rounded-xl p-10 border-2 transition-all ${travelConfig.active ? 'bg-blue-950 border-blue-700' : 'bg-surface-container-low border-transparent'}`}>
          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-6">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-3">
                <h3 className={`font-bold text-xl ${travelConfig.active ? 'text-white' : ''}`}>
                  {travelConfig.active ? t('settings.travelModeActive', 'Travel Mode Active') : t('settings.travelMode', 'Travel Mode')}
                </h3>
                {travelConfig.active
                  ? <span className="text-[9px] px-2.5 py-1 bg-blue-500 text-white rounded-full font-black uppercase tracking-widest animate-pulse">{t('settings.travelActive', 'Active')}</span>
                  : <span className="text-[9px] px-2.5 py-1 bg-surface-container-high text-on-surface-variant rounded-full font-black uppercase tracking-widest">{t('settings.travelInactive', 'Inactive')}</span>
                }
              </div>
              <p className={`text-sm leading-relaxed max-w-xl mb-4 ${travelConfig.active ? 'text-blue-200' : 'text-on-surface-variant'}`}>
                {travelConfig.active
                  ? t('settings.travelActiveDesc', '{{count}} folder(s) hidden — vault appears sanitized.', { count: travelConfig.hiddenFolderIds.length })
                  : t('settings.travelInactiveDesc', 'Hide designated vault folders when crossing borders or entering high-risk environments. Hidden data is encrypted on-device with your travel password — invisible to inspection, fully restorable with the travel password.')}
              </p>
            </div>
            <div className="shrink-0">
              {travelConfig.active ? (
                <button
                  onClick={() => { setIsDisableTravelOpen(true); setDisableTravelPw(''); setDisableTravelError(''); }}
                  className="px-8 py-4 bg-blue-500 hover:bg-blue-400 text-white rounded-xl font-bold text-sm transition-all flex items-center gap-3 shadow-lg shadow-blue-900/50"
                >
                  <Plane size={18} />
                  {t('settings.disableTravelMode', 'Disable Travel Mode')}
                </button>
              ) : (
                <button
                  onClick={() => { setIsTravelModalOpen(true); setTravelStep(1); setTravelHiddenFolderIds([]); setTravelPassword(''); setConfirmTravelPassword(''); setTravelError(''); }}
                  className="px-8 py-4 bg-black dark:bg-white text-white dark:text-black rounded-xl font-bold text-sm hover:opacity-90 transition-all flex items-center gap-3 shadow-lg"
                >
                  <Plane size={18} />
                  {t('settings.enableTravelMode', 'Enable Travel Mode')}
                </button>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* ── Offline Duress Mode ───────────────────────────────────────────────── */}
      <section>
        <div className="mb-6">
          <h2 className="text-[15px] font-semibold text-neutral-900 dark:text-white leading-snug">{t('settings.offlineDuressMode', 'Offline Duress Mode')}</h2>
          <div className="mt-4 h-px bg-neutral-200 dark:bg-white/8" />
        </div>
        <div className={`rounded-xl p-10 border-2 transition-all ${duressConfig.armed ? 'bg-red-950 border-red-800' : 'bg-surface-container-low border-transparent'}`}>
          <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-8">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-3">
                <h3 className={`font-bold text-xl ${duressConfig.armed ? 'text-white' : ''}`}>
                  {duressConfig.armed ? t('settings.duressModeArmed', 'Duress Mode Armed') : t('settings.duressModeDisarmed', 'Duress Mode')}
                </h3>
                {duressConfig.armed
                  ? <span className="text-[9px] px-2.5 py-1 bg-red-600 text-white rounded-full font-black uppercase tracking-widest animate-pulse">{t('settings.duressArmed', 'Armed')}</span>
                  : <span className="text-[9px] px-2.5 py-1 bg-surface-container-high text-on-surface-variant rounded-full font-black uppercase tracking-widest">{t('settings.duressDisarmed', 'Disarmed')}</span>
                }
              </div>
              <p className={`text-sm leading-relaxed max-w-xl mb-6 ${duressConfig.armed ? 'text-red-200' : 'text-on-surface-variant'}`}>
                {duressConfig.armed
                  ? t('settings.duressArmedDesc', 'Entering the duress password triggers immediate forensic wipe.')
                  : t('settings.duressDisarmedDesc', 'A separate duress password entered at login silently wipes all vault data (3-pass CSPRNG overwrite). Also auto-triggers after a configurable number of failed login attempts.')}
              </p>
              <div className="flex items-center gap-4">
                <label className={`text-[10px] font-black uppercase tracking-widest shrink-0 ${duressConfig.armed ? 'text-red-300' : 'text-on-surface-variant'}`}>
                  {t('settings.duressAutoWipeAfter', 'Auto-wipe after')}
                </label>
                <div className="relative">
                  <select
                    value={duressMaxAttempts}
                    onChange={e => setDuressMaxAttempts(Number(e.target.value))}
                    disabled={duressConfig.armed}
                    className={`appearance-none text-sm font-bold px-5 py-2.5 pr-9 rounded-lg cursor-pointer transition-all ${duressConfig.armed ? 'bg-red-900/50 text-red-100 border border-red-700' : 'bg-surface-container-high'}`}
                  >
                    {[3, 5, 10, 35, 60].map(n => (
                      <option key={n} value={n}>{n} {t('settings.failedAttempts', 'failed attempt(s)')}</option>
                    ))}
                  </select>
                  <ChevronDown size={14} className="absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                </div>
              </div>
            </div>
            <div className="flex flex-col gap-3 shrink-0">
              {duressConfig.armed ? (
                <>
                  <button
                    onClick={() => setIsDuressWipeOpen(true)}
                    className="px-8 py-4 bg-red-600 hover:bg-red-500 text-white rounded-xl font-bold text-sm transition-all flex items-center gap-3 shadow-lg shadow-red-900/50"
                  >
                    <Flame size={18} />
                    {t('settings.duressTriggerWipe', 'Trigger Wipe Now')}
                  </button>
                  <button
                    onClick={handleDisarmDuress}
                    className="px-8 py-4 bg-red-950 hover:bg-red-900 border border-red-800 text-red-300 rounded-xl font-bold text-sm transition-all flex items-center gap-3"
                  >
                    <ShieldCheck size={18} />
                    {t('settings.duressDisarm', 'Disarm')}
                  </button>
                </>
              ) : (
                <button
                  onClick={() => { setIsDuressModalOpen(true); setDuressStep(1); setDuressPassword(''); setConfirmDuressPassword(''); setDuressError(''); }}
                  className="px-8 py-4 bg-black dark:bg-white text-white dark:text-black rounded-xl font-bold text-sm hover:opacity-90 transition-all flex items-center gap-3 shadow-lg"
                >
                  <Skull size={18} />
                  {t('settings.duressArm', 'Arm Duress Mode')}
                </button>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* ── Management Row ───────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-surface-container-low p-8 rounded-2xl border border-outline-variant/10 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-black/5 flex items-center justify-center">
              <HistoryIcon size={20} />
            </div>
            <div>
              <h4 className="font-bold text-base mb-0.5">{t('settings.auditLog', 'Security Audit Log')}</h4>
              <p className="text-xs text-on-surface-variant">{t('settings.auditLogDesc', 'Review login events, MFA changes, and account activity.')}</p>
            </div>
          </div>
          <button onClick={() => setIsAuditLogOpen(true)} className="px-5 py-2.5 bg-white dark:bg-surface-container-high border border-outline-variant/30 rounded-lg text-xs font-black uppercase tracking-widest hover:border-black transition-all">
            {t('settings.viewLog', 'View Log')}
          </button>
        </div>
        <div className="bg-surface-container-low p-8 rounded-2xl border border-outline-variant/10 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-black/5 flex items-center justify-center">
              <Share2 size={20} />
            </div>
            <div>
              <h4 className="font-bold text-base mb-0.5">{t('settings.activeShares', 'Active Share Links')}</h4>
              <p className="text-xs text-on-surface-variant">{t('settings.sharesDesc2', 'View and revoke active one-time share links.')}</p>
            </div>
          </div>
          <button onClick={() => setIsSharesOpen(true)} className="px-5 py-2.5 bg-white dark:bg-surface-container-high border border-outline-variant/30 rounded-lg text-xs font-black uppercase tracking-widest hover:border-black transition-all">
            {t('settings.manageSharesBtn', 'Manage')}
          </button>
        </div>
      </div>

      {/* ═══════════════════════════════════════════════════════════════════════
          MODALS
      ═══════════════════════════════════════════════════════════════════════ */}

      {/* Travel Mode — Enable wizard */}
      <AnimatePresence>
        {isTravelModalOpen && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40" onClick={() => setIsTravelModalOpen(false)} />
            <motion.div initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-lg bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl border border-outline-variant/10 overflow-hidden max-h-[90vh] flex flex-col"
            >
              <div className="p-8 border-b border-outline-variant/10 flex items-center justify-between shrink-0">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-2xl bg-blue-600 flex items-center justify-center">
                    <Plane className="text-white" size={22} />
                  </div>
                  <div>
                    <h3 className="text-xl font-headline font-black">{t('settings.enableTravelMode', 'Enable Travel Mode')}</h3>
                    <p className="text-xs text-on-surface-variant mt-0.5">{t('settings.travelStep', 'Step {{step}} of 4', { step: travelStep })}</p>
                  </div>
                </div>
                <button onClick={() => setIsTravelModalOpen(false)} className="p-2 hover:bg-surface-container-high rounded-full transition-colors"><X size={20} /></button>
              </div>

              <div className="overflow-y-auto flex-1 p-8">
                {/* Step 1 — select folders */}
                {travelStep === 1 && (
                  <div className="space-y-6">
                    <p className="text-sm text-on-surface-variant leading-relaxed">
                      {t('settings.travelStep1Desc', 'Select which folders to hide when Travel Mode is active. These folders will be AES-256-GCM encrypted and invisible until you disable Travel Mode with your travel password.')}
                    </p>
                    <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('settings.travelSelectFolders', 'Select folders to hide')}</p>
                    {folders.length === 0 ? (
                      <p className="text-sm text-on-surface-variant text-center py-8">{t('settings.travelNoFolders', 'No folders found. Create folders in your vault first.')}</p>
                    ) : (
                      <div className="space-y-2">
                        {folders.map(folder => {
                          const selected = travelHiddenFolderIds.includes(folder.id);
                          return (
                            <button key={folder.id} type="button" onClick={() => toggleTravelFolder(folder.id)}
                              className={`w-full flex items-center justify-between p-4 rounded-xl border-2 transition-all text-left ${selected ? 'border-blue-600 bg-blue-50 dark:bg-blue-950/30' : 'border-outline-variant/20 hover:border-outline-variant/50'}`}
                            >
                              <span className={`font-bold text-sm ${selected ? 'text-blue-700 dark:text-blue-300' : 'text-black dark:text-white'}`}>{folder.label}</span>
                              <div className={`w-5 h-5 rounded border-2 flex items-center justify-center transition-all ${selected ? 'border-blue-600 bg-blue-600' : 'border-outline-variant/40'}`}>
                                {selected && <Check size={12} className="text-white" strokeWidth={3} />}
                              </div>
                            </button>
                          );
                        })}
                      </div>
                    )}
                    {travelError && <p className="text-xs font-bold text-red-600 uppercase tracking-widest">{travelError}</p>}
                    <button
                      onClick={() => { if (travelHiddenFolderIds.length === 0) { setTravelError(t('settings.travelSelectAtLeastOne', 'Select at least one folder to hide.')); return; } setTravelError(''); setTravelStep(2); }}
                      className="w-full py-4 bg-blue-600 text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-blue-700 transition-all"
                    >
                      {t('settings.travelNextStep', 'Next — Set Travel Password')}
                    </button>
                  </div>
                )}

                {/* Step 2 — set password */}
                {travelStep === 2 && (
                  <div className="space-y-6">
                    <p className="text-sm text-on-surface-variant leading-relaxed">
                      {t('settings.travelPasswordDesc', 'This password is required to restore hidden folders. It is separate from your main vault password.')}
                    </p>
                    <div className="space-y-3">
                      <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('settings.travelPasswordLabel', 'Password')}</label>
                      <div className="relative">
                        <input type={showTravelPassword ? 'text' : 'password'} value={travelPassword}
                          onChange={e => { setTravelPassword(e.target.value); setTravelError(''); }}
                          placeholder={t('settings.travelPasswordMin', 'Minimum 8 characters')}
                          className="w-full px-5 py-4 pr-12 bg-surface-container-low rounded-xl border border-zinc-300 dark:border-zinc-600 text-black dark:text-white font-bold focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500 outline-none transition-all"
                        />
                        <button type="button" tabIndex={-1} onClick={() => setShowTravelPassword(v => !v)}
                          className="absolute right-4 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-black dark:hover:text-white transition-colors"
                        >
                          {showTravelPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                        </button>
                      </div>
                    </div>
                    <div className="space-y-3">
                      <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('settings.travelPasswordConfirm', 'Confirm Password')}</label>
                      <input type="password" value={confirmTravelPassword}
                        onChange={e => { setConfirmTravelPassword(e.target.value); setTravelError(''); }}
                        placeholder={t('settings.travelRepeatPassword', 'Repeat password')}
                        autoComplete="new-password"
                        className="w-full px-5 py-4 bg-surface-container-low rounded-xl border border-zinc-300 dark:border-zinc-600 text-black dark:text-white font-bold focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500 outline-none transition-all"
                      />
                    </div>
                    {travelError && <p className="text-xs font-bold text-red-600 uppercase tracking-widest">{travelError}</p>}
                    <div className="flex gap-3">
                      <button onClick={() => setTravelStep(1)} className="flex-1 py-4 bg-surface-container-low rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.back', 'Back')}</button>
                      <button
                        onClick={() => { if (travelPassword.length < 8) { setTravelError(t('settings.travelPasswordMinError', 'Minimum 8 characters.')); return; } if (travelPassword !== confirmTravelPassword) { setTravelError(t('settings.travelPasswordMismatch', 'Passwords do not match.')); return; } setTravelError(''); setTravelStep(3); }}
                        className="flex-1 py-4 bg-blue-600 text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-blue-700 transition-all"
                      >
                        {t('common.continue', 'Continue')}
                      </button>
                    </div>
                  </div>
                )}

                {/* Step 3 — confirm & activate */}
                {travelStep === 3 && (
                  <div className="space-y-6">
                    <div className="p-5 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-2xl flex items-start gap-3">
                      <AlertTriangle size={20} className="text-amber-600 shrink-0 mt-0.5" />
                      <div>
                        <p className="font-bold text-sm text-amber-800 dark:text-amber-300 mb-1">{t('settings.travelWarningTitle', 'Store your password safely')}</p>
                        <p className="text-xs text-amber-700/70 dark:text-amber-400/70 leading-relaxed">
                          {t('settings.travelWarningDesc', 'If you forget it, the hidden folders cannot be recovered — there is no backdoor.')}
                        </p>
                      </div>
                    </div>
                    <div className="space-y-3">
                      <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('settings.travelFoldersToHide', 'Folders that will be hidden')}</p>
                      {folders.filter(f => travelHiddenFolderIds.includes(f.id)).map(f => (
                        <div key={f.id} className="flex items-center gap-3 p-3 bg-surface-container-low rounded-xl">
                          <Plane size={16} className="text-blue-600 shrink-0" />
                          <span className="font-bold text-sm">{f.label}</span>
                          <span className="text-xs text-on-surface-variant ml-auto">
                            {t('settings.travelCredentialCount', '{{count}} credential(s)', { count: credentials.filter(c => c.folderId === f.id).length })}
                          </span>
                        </div>
                      ))}
                    </div>
                    {travelError && <p className="text-xs font-bold text-red-600 uppercase tracking-widest">{travelError}</p>}
                    <div className="flex gap-3">
                      <button onClick={() => setTravelStep(2)} className="flex-1 py-4 bg-surface-container-low rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.back', 'Back')}</button>
                      <button onClick={handleEnableTravel} disabled={isEnablingTravel}
                        className="flex-1 py-4 bg-blue-600 text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-blue-700 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                      >
                        {isEnablingTravel ? <Loader2 size={18} className="animate-spin" /> : <><Plane size={16} />{t('settings.travelActivate', 'Activate Travel Mode')}</>}
                      </button>
                    </div>
                  </div>
                )}

                {/* Step 4 — success */}
                {travelStep === 4 && (
                  <div className="text-center py-6 space-y-6">
                    <div className="w-20 h-20 rounded-full bg-blue-100 dark:bg-blue-950/50 flex items-center justify-center mx-auto">
                      <Plane size={40} className="text-blue-600" />
                    </div>
                    <div>
                      <h3 className="text-xl font-headline font-black mb-2">{t('settings.travelActivateConfirmTitle', 'Travel Mode Active')}</h3>
                      <p className="text-sm text-on-surface-variant leading-relaxed">
                        {t('settings.travelActivateConfirmDesc', 'Hidden folders are encrypted and invisible. Your vault has been updated.')}
                      </p>
                    </div>
                    <button onClick={() => setIsTravelModalOpen(false)}
                      className="w-full py-4 bg-blue-600 text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-blue-700 transition-all"
                    >
                      {t('common.done', 'Done')}
                    </button>
                  </div>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Travel Mode — Disable */}
      <AnimatePresence>
        {isDisableTravelOpen && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40" onClick={() => setIsDisableTravelOpen(false)} />
            <motion.div initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-md bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl border border-outline-variant/10 p-8"
            >
              <div className="flex items-center justify-between mb-8">
                <div className="w-12 h-12 rounded-2xl bg-blue-600 flex items-center justify-center">
                  <Plane className="text-white" size={22} />
                </div>
                <button onClick={() => setIsDisableTravelOpen(false)} className="p-2 hover:bg-surface-container-high rounded-full transition-colors"><X size={20} /></button>
              </div>
              <h3 className="text-xl font-headline font-black mb-2">{t('settings.travelDisableTitle', 'Disable Travel Mode')}</h3>
              <p className="text-sm text-on-surface-variant leading-relaxed mb-8">
                {t('settings.travelDisableDesc', 'Enter your travel password to decrypt and restore {{count}} hidden folder(s).', { count: travelConfig.hiddenFolderIds.length })}
              </p>
              <div className="space-y-3 mb-6">
                <input type="password" value={disableTravelPw}
                  onChange={e => { setDisableTravelPw(e.target.value); setDisableTravelError(''); }}
                  placeholder={t('settings.travelPasswordPlaceholder', 'Enter your travel password')}
                  autoComplete={BROWSER_AUTOFILL ? 'current-password' : 'new-password'}
                  className="w-full px-5 py-4 bg-surface-container-low rounded-xl border border-zinc-300 dark:border-zinc-600 text-black dark:text-white font-bold focus:ring-2 focus:ring-blue-600/20 focus:border-blue-600 outline-none transition-all"
                  onKeyDown={e => e.key === 'Enter' && handleDisableTravel()}
                  autoFocus
                />
                {disableTravelError && <p className="text-xs font-bold text-red-600 uppercase tracking-widest">{disableTravelError}</p>}
              </div>
              <div className="flex gap-3">
                <button onClick={() => setIsDisableTravelOpen(false)} className="flex-1 py-4 bg-surface-container-low rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.cancel', 'Cancel')}</button>
                <button onClick={handleDisableTravel} disabled={isDisablingTravel || !disableTravelPw}
                  className="flex-1 py-4 bg-blue-600 text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-blue-700 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {isDisablingTravel ? <><Loader2 size={16} className="animate-spin" />{t('settings.travelDecrypting', 'Decrypting…')}</> : t('settings.travelRestoreFolders', 'Restore Folders')}
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Duress Mode — Arm wizard */}
      <AnimatePresence>
        {isDuressModalOpen && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40" onClick={() => setIsDuressModalOpen(false)} />
            <motion.div initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-md bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl border border-outline-variant/10 overflow-hidden"
            >
              <div className="p-8">
                <div className="flex items-center justify-between mb-8">
                  <div className="w-12 h-12 rounded-2xl bg-red-600 flex items-center justify-center">
                    <Skull className="text-white" size={22} />
                  </div>
                  <button onClick={() => setIsDuressModalOpen(false)} className="p-2 hover:bg-surface-container-high rounded-full transition-colors"><X size={20} /></button>
                </div>

                {duressStep === 3 ? (
                  <div className="text-center py-4 space-y-6">
                    <div className="w-20 h-20 rounded-full bg-red-100 dark:bg-red-950/50 flex items-center justify-center mx-auto">
                      <Skull size={40} className="text-red-600" />
                    </div>
                    <div>
                      <h3 className="text-xl font-headline font-black mb-2">{t('settings.duressArmedTitle', 'Duress Mode Armed')}</h3>
                      <p className="text-sm text-on-surface-variant">
                        {t('settings.duressArmedConfirmDesc', 'Entering the duress password at login will trigger an immediate forensic wipe. Auto-wipe activates after {{count}} failed attempt(s).', { count: duressMaxAttempts })}
                      </p>
                    </div>
                    <button onClick={() => setIsDuressModalOpen(false)}
                      className="w-full py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-neutral-800 transition-all"
                    >
                      {t('common.done', 'Done')}
                    </button>
                  </div>
                ) : (
                  <>
                    <h3 className="text-xl font-headline font-black mb-2">{t('settings.duressSetupTitle', 'Arm Duress Mode')}</h3>
                    <p className="text-sm text-on-surface-variant leading-relaxed mb-8">
                      {duressStep === 1
                        ? t('settings.duressStep1Desc', 'Set a duress password — different from your main password. Entering it at login triggers an immediate forensic wipe of all vault data.')
                        : t('settings.duressStep2Desc', 'Confirm your duress password. This cannot be recovered.')}
                    </p>
                    <div className="space-y-5">
                      {duressStep === 1 && (
                        <div className="space-y-3">
                          <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('settings.duressPasswordLabel', 'Duress Password')}</label>
                          <div className="relative">
                            <input type={showDuressPassword ? 'text' : 'password'} value={duressPassword}
                              onChange={e => { setDuressPassword(e.target.value); setDuressError(''); }}
                              placeholder={t('settings.duressPasswordMin', 'Minimum 8 characters')}
                              className="w-full px-5 py-4 pr-12 bg-surface-container-low rounded-xl border border-outline-variant/20 text-black dark:text-white font-bold focus:ring-2 focus:ring-red-600/20 focus:border-red-600 outline-none transition-all"
                            />
                            <button type="button" tabIndex={-1} onClick={() => setShowDuressPassword(v => !v)}
                              className="absolute right-4 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-black transition-colors"
                            >
                              {showDuressPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                            </button>
                          </div>
                        </div>
                      )}
                      {duressStep === 2 && (
                        <div className="space-y-3">
                          <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('settings.duressConfirmLabel', 'Confirm Duress Password')}</label>
                          <input type="password" value={confirmDuressPassword}
                            onChange={e => { setConfirmDuressPassword(e.target.value); setDuressError(''); }}
                            placeholder={t('settings.duressRepeat', 'Repeat duress password')}
                            autoComplete="new-password"
                            autoFocus
                            className="w-full px-5 py-4 bg-surface-container-low rounded-xl border border-outline-variant/20 text-black dark:text-white font-bold focus:ring-2 focus:ring-red-600/20 focus:border-red-600 outline-none transition-all"
                          />
                        </div>
                      )}
                      {duressError && <p className="text-xs font-bold text-red-600 uppercase tracking-widest">{duressError}</p>}
                      <div className="p-4 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900 rounded-xl flex items-start gap-3">
                        <AlertTriangle size={16} className="text-red-600 shrink-0 mt-0.5" />
                        <p className="text-xs text-red-700 dark:text-red-300 leading-relaxed">
                          {t('settings.duressWipeWarning', 'Triggering wipe performs a 3-pass CSPRNG overwrite of all localStorage, sessionStorage, IndexedDB, and Cache Storage. This is irreversible.')}
                        </p>
                      </div>
                      <div className="flex gap-3">
                        {duressStep === 2 && (
                          <button onClick={() => setDuressStep(1)} className="flex-1 py-4 bg-surface-container-low rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.back', 'Back')}</button>
                        )}
                        <button
                          onClick={() => {
                            if (duressStep === 1) {
                              if (duressPassword.length < 8) { setDuressError(t('settings.duressPasswordMinError', 'Duress password must be at least 8 characters.')); return; }
                              setDuressError(''); setDuressStep(2);
                            } else {
                              handleArmDuress();
                            }
                          }}
                          disabled={isArmingDuress}
                          className="flex-1 py-4 bg-red-600 text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-red-700 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                        >
                          {isArmingDuress
                            ? <><Loader2 size={16} className="animate-spin" />{t('settings.duressArming', 'Arming…')}</>
                            : duressStep === 1 ? t('common.next', 'Next') : <><Skull size={16} />{t('settings.duressArm', 'Arm Duress Mode')}</>
                          }
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Duress Mode — Trigger Wipe confirmation */}
      <AnimatePresence>
        {isDuressWipeOpen && (
          <div className="fixed inset-0 z-[110] flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40" onClick={() => !isWiping && setIsDuressWipeOpen(false)} />
            <motion.div initial={{ opacity: 0, scale: 0.9, y: 30 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.9, y: 30 }}
              className="relative w-full max-w-sm bg-red-950 rounded-3xl shadow-2xl border border-red-800 p-8 text-white text-center"
            >
              <div className="w-20 h-20 rounded-full bg-red-900/60 border-2 border-red-700 flex items-center justify-center mx-auto mb-6">
                <Flame size={40} className="text-red-400" />
              </div>
              <h3 className="text-2xl font-headline font-black mb-3">{t('settings.duressConfirmWipeTitle', 'Confirm Wipe')}</h3>
              <p className="text-red-200 text-sm leading-relaxed mb-8">
                {t('settings.duressConfirmWipeDesc', 'This will immediately perform a 3-pass forensic overwrite and delete ALL vault data, sessions, and credentials.')} <strong className="text-white">{t('settings.duressCannotUndo', 'This cannot be undone.')}</strong>
              </p>
              {isWiping ? (
                <div className="flex flex-col items-center gap-3">
                  <Loader2 size={32} className="animate-spin text-red-400" />
                  <p className="text-red-300 font-bold text-sm uppercase tracking-widest">{t('settings.duressWiping', 'Wiping…')}</p>
                </div>
              ) : (
                <div className="flex gap-3">
                  <button onClick={() => setIsDuressWipeOpen(false)}
                    className="flex-1 py-4 bg-red-900/50 border border-red-800 text-red-300 rounded-xl font-black uppercase tracking-widest text-xs hover:bg-red-900 transition-all"
                  >
                    {t('common.cancel', 'Cancel')}
                  </button>
                  <button onClick={handleTriggerWipe}
                    className="flex-1 py-4 bg-red-600 text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-red-500 transition-all flex items-center justify-center gap-2"
                  >
                    <Flame size={16} />
                    {t('settings.duressWipeNow', 'Wipe Now')}
                  </button>
                </div>
              )}
            </motion.div>
          </div>
        )}
      </AnimatePresence>

    </div>
  );
}
