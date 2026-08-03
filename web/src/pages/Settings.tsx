import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Sun, Moon, Monitor, Loader2, ChevronRight,
  X, AlertTriangle, CheckCircle, Download, Upload, FileUp, FileJson, FileText, Lock,
  Server, Eye, EyeOff, Globe,
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { useUser } from '../context/UserContext';
import { useVault } from '../context/VaultContext';
import { useTheme } from '../context/ThemeContext';
import { useNotification } from '../context/NotificationContext';
import SEO from '../components/SEO';
import type { EmailServerConfig } from '../types';
import { generateUUID, generateRecoveryKey } from '../utils/crypto';
import {
  exportToPWDnow, exportToPWDnowCSV, exportToPWDnowXML, exportToPWDnow1PUX,
  exportToP2W,
  exportToBitwardenJSON, exportToBitwardenCSV,
  exportTo1PasswordCSV, exportToNordPass, exportToLastPass,
  exportToChrome, exportToFirefox,
  exportToKeePassXML, exportToKeePassCSV,
  exportToKeeperJSON, exportToKeeperCSV,
  exportToDashlaneJSON, exportToRoboForm, exportToProtonPass,
  exportToZohoCSV, exportToPassboltCSV, exportToPadlocJSON,
  exportToPasskyJSON, exportToEnpassCSV, exportToButtercupJSON,
  triggerDownload, triggerBinaryDownload, importFromFile,
  getFormat, FORMATS, FORMAT_GROUPS,
  type ImportResult, type FormatDef,
} from '../utils/importExport';

import { writeEncryptedLocal } from '../utils/localCrypto';
import { daemon } from '../utils/daemonClient';
import { apiFetch } from '../utils/api';
import ProfileSection from './Settings/ProfileSection';
import MfaSection from './Settings/MfaSection';
import RecoveryKeySection from './Settings/RecoveryKeySection';
import RecoveryKeyModal from './Settings/RecoveryKeyModal';
import SecurityModesSection from './Settings/SecurityModesSection';
import AuditLogModal from './Settings/AuditLogModal';
import SharesModal from './Settings/SharesModal';

import EmergencyAccessModal from '../components/EmergencyAccessModal';
import { useSecurityModes } from './Settings/hooks/useSecurityModes';

// ── SVG icons ─────────────────────────────────────────────────────────────────
type SvgP = { size?: number; className?: string };

const FbUserCircle = ({ size = 20, className = '' }: SvgP) => (
  <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <circle cx="12" cy="12" r="10"/>
    <circle cx="12" cy="8.5" r="2.5"/>
    <path d="M6.5 19.8C7.2 17.1 9.4 15.5 12 15.5s4.8 1.6 5.5 4.3"/>
  </svg>
);

const FbPalette = ({ size = 20, className = '' }: SvgP) => (
  <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <path d="M12 2C6.48 2 2 6.48 2 12c0 5.52 4.48 10 10 10 1.1 0 2-.9 2-2 0-.51-.2-.97-.52-1.32-.31-.33-.5-.77-.5-1.18 0-1.1.9-2 2-2h2.35C19.47 15.5 22 13.14 22 10 22 5.59 17.52 2 12 2z"/>
    <circle cx="6.5" cy="11.5" r="1.5" fill="currentColor" stroke="none"/>
    <circle cx="9.5" cy="7.5" r="1.5" fill="currentColor" stroke="none"/>
    <circle cx="14.5" cy="7.5" r="1.5" fill="currentColor" stroke="none"/>
    <circle cx="17.5" cy="11.5" r="1.5" fill="currentColor" stroke="none"/>
  </svg>
);

const FbShieldLock = ({ size = 20, className = '' }: SvgP) => (
  <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <rect x="9" y="11" width="6" height="5" rx="1"/>
    <path d="M10 11V9.5a2 2 0 1 1 4 0V11"/>
  </svg>
);

const FbGearCog = ({ size = 20, className = '' }: SvgP) => (
  <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"/>
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
  </svg>
);

const FbKey = ({ size = 20, className = '' }: SvgP) => (
  <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <circle cx="7.5" cy="15.5" r="5.5"/>
    <path d="m21 2-9.6 9.6"/>
    <path d="m15.5 7.5 3 3L22 7l-3-3"/>
  </svg>
);

const FbLifeRing = ({ size = 20, className = '' }: SvgP) => (
  <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <circle cx="12" cy="12" r="10"/>
    <circle cx="12" cy="12" r="4"/>
    <line x1="4.93" y1="4.93" x2="9.17" y2="9.17"/>
    <line x1="14.83" y1="14.83" x2="19.07" y2="19.07"/>
    <line x1="14.83" y1="9.17" x2="19.07" y2="4.93"/>
    <line x1="4.93" y1="19.07" x2="9.17" y2="14.83"/>
  </svg>
);

const FbClockRotate = ({ size = 20, className = '' }: SvgP) => (
  <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/>
    <path d="M3 3v5h5"/>
    <path d="M12 7v5l4 2"/>
  </svg>
);

const FbShare = ({ size = 20, className = '' }: SvgP) => (
  <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <circle cx="18" cy="5" r="3"/>
    <circle cx="6" cy="12" r="3"/>
    <circle cx="18" cy="19" r="3"/>
    <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
    <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
  </svg>
);

const FbImportExport = ({ size = 20, className = '' }: SvgP) => (
  <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <path d="M8 17L4 21M4 21L0 17M4 21V3"/>
    <path d="M16 7L20 3M20 3L24 7M20 3V21"/>
    <rect x="8" y="7" width="8" height="10" rx="2" strokeWidth="1.5"/>
  </svg>
);

// ── Navigation structure ───────────────────────────────────────────────────────
type NavItem = { id: string; label: string; Icon: React.ComponentType<SvgP> };
type NavGroup = { label: string; items: NavItem[] };

type NavStructureItem = { id: string; labelKey: string; Icon: React.ComponentType<SvgP> };
type NavStructureGroup = { groupKey: string; items: NavStructureItem[] };

const NAV_STRUCTURE: NavStructureGroup[] = [
  {
    groupKey: 'groupAccount',
    items: [{ id: 'profile',    labelKey: 'navProfile',    Icon: FbUserCircle }],
  },
  {
    groupKey: 'groupPreferences',
    items: [
      { id: 'appearance', labelKey: 'navAppearance', Icon: FbPalette },
      { id: 'import',     labelKey: 'navImport',     Icon: FbImportExport },
    ],
  },
  {
    groupKey: 'groupSecurity',
    items: [
      { id: 'auth',       labelKey: 'navAuth',       Icon: FbShieldLock },
      { id: 'security',   labelKey: 'navSecurity',   Icon: FbGearCog },
      { id: 'recovery',   labelKey: 'navRecovery',   Icon: FbKey },
      { id: 'emergency',  labelKey: 'navEmergency',  Icon: FbLifeRing },
    ],
  },
  {
    groupKey: 'groupActivity',
    items: [{ id: 'log', labelKey: 'navLog', Icon: FbClockRotate }],
  },
];

// ── Enterprise section heading ─────────────────────────────────────────────────
function SectionHeading({ title, description }: { title: string; description?: string }) {
  return (
    <div className="mb-6">
      <h2 className="text-[15px] font-semibold text-neutral-900 dark:text-white leading-snug">{title}</h2>
      {description && (
        <p className="mt-1 text-[13px] text-neutral-600 dark:text-neutral-300 leading-relaxed">{description}</p>
      )}
      <div className="mt-4 h-px bg-neutral-200 dark:bg-white/8" />
    </div>
  );
}

// ── Theme option button (segmented control) ────────────────────────────────────
function ThemeButton({ current, value, setTheme, icon, label }: {
  current: string; value: string;
  setTheme: (v: 'light' | 'dark' | 'system') => void;
  icon: React.ReactNode; label: string;
}) {
  const active = current === value;
  return (
    <button
      onClick={() => setTheme(value as 'light' | 'dark' | 'system')}
      aria-pressed={active}
      className={`flex items-center gap-2 px-4 py-2 rounded-md text-[13px] font-medium transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 dark:focus-visible:ring-white focus-visible:ring-offset-1 ${
        active
          ? 'bg-white dark:bg-white/15 text-neutral-900 dark:text-white shadow-sm border border-neutral-200 dark:border-white/20'
          : 'text-neutral-700 dark:text-neutral-300 hover:text-neutral-900 dark:hover:text-neutral-200'
      }`}
    >
      {icon}
      {label}
    </button>
  );
}

// ── Action row (log, shares) ───────────────────────────────────────────────────
function ActionRow({ icon, title, desc, btnLabel, onClick }: {
  icon: React.ReactNode; title: string; desc: string; btnLabel: string; onClick: () => void;
}) {
  return (
    <div className="flex items-center justify-between py-4 border-b border-neutral-100 dark:border-white/5 last:border-0">
      <div className="flex items-center gap-3 min-w-0 mr-6">
        <div className="w-8 h-8 rounded-lg bg-neutral-100 dark:bg-white/5 flex items-center justify-center shrink-0 text-neutral-600 dark:text-neutral-300">
          {icon}
        </div>
        <div className="min-w-0">
          <p className="text-[13px] font-medium text-neutral-900 dark:text-white">{title}</p>
          <p className="text-[12px] text-neutral-600 dark:text-neutral-300 mt-0.5 leading-relaxed">{desc}</p>
        </div>
      </div>
      <button
        onClick={onClick}
        className="shrink-0 px-3 py-1.5 text-[12px] font-medium border border-neutral-200 dark:border-white/12 rounded-lg bg-white dark:bg-transparent text-neutral-700 dark:text-neutral-300 hover:bg-neutral-50 dark:hover:bg-white/5 hover:border-neutral-300 dark:hover:border-white/20 transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 dark:focus-visible:ring-white focus-visible:ring-offset-1"
      >
        {btnLabel}
      </button>
    </div>
  );
}

// ── DNS row ────────────────────────────────────────────────────────────────────
function DnsRow({ label, ok, detail, required, optional }: {
  label: string; ok: boolean; detail?: string; required?: boolean; optional?: boolean;
}) {
  const { t } = useTranslation();
  return (
    <div className="flex items-center gap-2 text-xs">
      {ok
        ? <CheckCircle size={12} className="text-emerald-500 shrink-0" />
        : <X size={12} className={optional ? 'text-neutral-400 shrink-0' : 'text-red-500 shrink-0'} />
      }
      <span className={`font-medium ${!ok && required ? 'text-red-600 dark:text-red-400' : 'text-neutral-700 dark:text-neutral-300'}`}>{label}</span>
      {optional && !ok && <span className="text-neutral-600 dark:text-neutral-300 text-[10px]">{t('common.optional', '(optional)')}</span>}
      {detail && <span className="text-neutral-600 dark:text-neutral-300 truncate">{detail}</span>}
    </div>
  );
}

// ── Shared input class ─────────────────────────────────────────────────────────
const inputCls = 'w-full px-3 py-2.5 bg-neutral-50 dark:bg-white/5 rounded-lg border border-neutral-200 dark:border-white/10 text-[13px] text-neutral-900 dark:text-white placeholder:text-neutral-400 dark:placeholder:text-neutral-600 focus:border-neutral-400 dark:focus:border-white/30 focus:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 dark:focus-visible:ring-white focus-visible:ring-offset-1 transition-colors';

// ── Main component ─────────────────────────────────────────────────────────────
export default function Settings() {
  const { t } = useTranslation();

  const NAV_GROUPS: NavGroup[] = useMemo(() =>
    NAV_STRUCTURE.map(g => ({
      label: t(`settings.${g.groupKey}`, g.groupKey),
      items: g.items.map(item => ({
        id: item.id,
        label: t(`settings.${item.labelKey}`, item.labelKey),
        Icon: item.Icon,
      })),
    })),
  [t]);
  const NAV = useMemo(() => NAV_GROUPS.flatMap(g => g.items), [NAV_GROUPS]);

  const { profile, updateProfile, reloadProfile } = useUser();
  const { theme, setTheme } = useTheme();
  const { addNotification } = useNotification();
  const { credentials, folders, addCredential, addFolder, deleteCredential } = useVault();
  const [activeSection, setActiveSection] = useState<string>('profile');

  const [isEmergencyModalOpen, setIsEmergencyModalOpen] = useState(false);
  const [isRecoveryModalOpen, setIsRecoveryModalOpen] = useState(false);
  const [isAuditLogOpen, setIsAuditLogOpen] = useState(false);
  const [isSharesOpen, setIsSharesOpen] = useState(false);

  const [isGeneratingRecovery, setIsGeneratingRecovery] = useState(false);
  const [generatedRecoveryKey, setGeneratedRecoveryKey] = useState('');
  const [recoveryAuthPassword, setRecoveryAuthPassword] = useState('');
  const [recoveryAuthError, setRecoveryAuthError] = useState('');

  const handleGenerateRecovery = async () => {
    if (!recoveryAuthPassword) {
      setRecoveryAuthError(t('settings.passwordRequired', 'Please enter your master password to continue.'));
      return;
    }
    setIsGeneratingRecovery(true);
    setRecoveryAuthError('');
    try {
      await daemon.verifyPassword(recoveryAuthPassword);

      const newKey = generateRecoveryKey();

      await daemon.enrollRecoveryKey(newKey);
      await apiFetch('/api/auth/recovery-key', {
        method: 'POST',
        body: JSON.stringify({ recoveryKey: newKey, password: recoveryAuthPassword })
      });
      setGeneratedRecoveryKey(newKey);
      setIsRecoveryModalOpen(true);
      reloadProfile();
      addNotification({ title: t('settings.recoveryKey', 'Recovery Key'), message: t('settings.keyGenerated', 'New recovery key generated successfully.'), type: 'success' });
      setRecoveryAuthPassword('');
    } catch (e: any) {
      setRecoveryAuthError(e.message || t('settings.recoveryKeyError', 'Failed to generate recovery key.'));
    } finally {
      setIsGeneratingRecovery(false);
    }
  };

  const { sessionLockTimeout, handleSessionLockChange, emailServerConfig, setEmailServerConfig } = useSecurityModes();

  const [isEmailServerModalOpen, setIsEmailServerModalOpen] = useState(false);
  const [emailServerForm, setEmailServerForm] = useState<EmailServerConfig | null>(null);
  const [emailServerError, setEmailServerError] = useState('');
  const [isSavingEmailServer, setIsSavingEmailServer] = useState(false);
  const [showEmailPass, setShowEmailPass] = useState(false);

  type DnsResult = { domain: string; mx: string[]; spf: boolean; dmarc: boolean; dkim: boolean; bimi: boolean; vmc: boolean };
  const [dnsCheckResult, setDnsCheckResult] = useState<DnsResult | null>(null);
  const [isDnsChecking, setIsDnsChecking] = useState(false);

  useEffect(() => { if (isEmailServerModalOpen) setDnsCheckResult(null); }, [isEmailServerModalOpen]);

  const DEFAULT_EMAIL_CONFIG: EmailServerConfig = { host: '', port: 587, user: '', pass: '', protocol: 'starttls' };

  const extractSmtpDomain = (host: string, user: string): string => {
    if (user.includes('@')) return user.split('@').pop()!.trim().toLowerCase();
    return host.replace(/^(smtp|mail|email|imap|pop3|mx)\./i, '').toLowerCase();
  };

  const handleDnsCheck = useCallback(async () => {
    if (!emailServerForm) return;
    const domain = extractSmtpDomain(emailServerForm.host.trim(), emailServerForm.user.trim());
    if (!domain) { setEmailServerError(t('settings.cannotDetermineDomain', 'Cannot determine domain to check.')); return; }
    setIsDnsChecking(true); setDnsCheckResult(null); setEmailServerError('');
    try {
      const res = await fetch(`/api/system/dns-check?domain=${encodeURIComponent(domain)}`);
      if (!res.ok) throw new Error('DNS check failed');
      setDnsCheckResult(await res.json());
    } catch { setEmailServerError(t('settings.dnsCheckFailed', 'DNS check failed. Please try again.')); }
    finally { setIsDnsChecking(false); }
  }, [emailServerForm, t]);

  const handleSaveEmailServer = useCallback(async () => {
    if (!emailServerForm) return;
    if (!emailServerForm.host.trim()) { setEmailServerError(t('settings.emailServerHostRequired', 'Host is required.')); return; }
    if (!emailServerForm.user.trim()) { setEmailServerError(t('settings.emailServerUserRequired', 'Username is required.')); return; }
    setIsSavingEmailServer(true); setEmailServerError('');
    try {
      let check = dnsCheckResult;
      if (!check) {
        const domain = extractSmtpDomain(emailServerForm.host.trim(), emailServerForm.user.trim());
        if (domain) {
          try {
            const r = await fetch(`/api/system/dns-check?domain=${encodeURIComponent(domain)}`);
            if (r.ok) { check = await r.json(); setDnsCheckResult(check); }
          } catch { /* allow save if DNS unreachable */ }
        }
      }
      if (check && check.mx.length === 0) {
        setEmailServerError(t('settings.emailServerNoMx', `No MX records found for "${check.domain}" — email delivery would fail.`));
        return;
      }
      await writeEncryptedLocal('email_server_config', JSON.stringify(emailServerForm));
      // Update UI immediately after local write — don't wait for the server sync
      setEmailServerConfig(emailServerForm);
      setIsEmailServerModalOpen(false);
      // Also persist to server so login OTP emails use the configured SMTP
      try {
        await apiFetch('/api/vault/smtp-config', {
          method: 'PUT',
          body: JSON.stringify({
            host: emailServerForm.host.trim(),
            port: emailServerForm.port,
            protocol: emailServerForm.protocol || (emailServerForm.secure ? 'ssl_tls' : 'starttls'),
            username: emailServerForm.user.trim(),
            password: emailServerForm.pass || '',
            fromName: emailServerForm.fromName || 'PWDnow',
            fromAddress: emailServerForm.user.trim(),
            mxVerified: !!(check && check.mx.length > 0),
          }),
        });
      } catch (e) {
        console.warn('[smtp-config] Server persist failed:', e);
      }
      addNotification({ title: t('settings.emailServerSaved', 'SMTP Saved'), message: t('settings.emailServerSavedDesc', 'Email server configuration saved.'), type: 'success' });
    } catch { setEmailServerError(t('settings.emailServerSaveFailed', 'Failed to save configuration.')); }
    finally { setIsSavingEmailServer(false); }
  }, [emailServerForm, dnsCheckResult, setEmailServerConfig, addNotification, t]);

  // ── Import / Export state ────────────────────────────────────────────────────
  const [selectedFormatId, setSelectedFormatId] = useState('pwdnow-p2w');
  const [exportCategory, setExportCategory] = useState('pwdnow');
  const [exportPassphrase, setExportPassphrase] = useState('');
  const [exportPassphraseConfirm, setExportPassphraseConfirm] = useState('');
  const [exportPassphraseError, setExportPassphraseError] = useState('');
  const [importResult, setImportResult] = useState<ImportResult | null>(null);
  const [importFileName, setImportFileName] = useState('');
  const [isImportModalOpen, setIsImportModalOpen] = useState(false);
  const [importMode, setImportMode] = useState<'merge' | 'replace'>('merge');
  const [isImporting, setIsImporting] = useState(false);
  const [importError, setImportError] = useState('');
  const [pendingEncryptedFile, setPendingEncryptedFile] = useState<File | null>(null);
  const [importPassphrase, setImportPassphrase] = useState('');
  const [importPassphraseError, setImportPassphraseError] = useState('');
  const [isDragOver, setIsDragOver] = useState(false);

  const selectedFmt: FormatDef | undefined = getFormat(selectedFormatId);
  const categoryExportFormats = FORMATS.filter(f => f.group === exportCategory && f.canExport);

  const runExport = useCallback(async (formatId: string, passphrase?: string) => {
    const fmt = getFormat(formatId);
    if (!fmt?.canExport) return;
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    switch (formatId) {
      case 'pwdnow-p2w':      { const b = await exportToP2W(credentials, folders, passphrase!); triggerBinaryDownload(b, `pwdnow_${date}.p2w`, 'application/x-pwdnow-vault'); break; }
      case 'pwdnow-json':     triggerDownload(exportToPWDnow(credentials, folders), `pwdnow_${date}.json`, 'application/json'); break;
      case 'pwdnow-csv':      triggerDownload(exportToPWDnowCSV(credentials), `pwdnow_${date}.csv`, 'text/csv'); break;
      case 'pwdnow-xml':      triggerDownload(exportToPWDnowXML(credentials, folders), `pwdnow_${date}.xml`, 'text/xml'); break;
      case 'pwdnow-1pux':     triggerBinaryDownload(exportToPWDnow1PUX(credentials, folders), `pwdnow_${date}.1pux`, 'application/zip'); break;
      case 'bitwarden-json':  triggerDownload(exportToBitwardenJSON(credentials, folders), `bitwarden_${date}.json`, 'application/json'); break;
      case 'bitwarden-csv':   triggerDownload(exportToBitwardenCSV(credentials, folders), `bitwarden_${date}.csv`, 'text/csv'); break;
      case '1password-csv':   triggerDownload(exportTo1PasswordCSV(credentials), `1password_${date}.csv`, 'text/csv'); break;
      case 'keeper-json':     triggerDownload(exportToKeeperJSON(credentials, folders), `keeper_${date}.json`, 'application/json'); break;
      case 'keeper-csv':      triggerDownload(exportToKeeperCSV(credentials, folders), `keeper_${date}.csv`, 'text/csv'); break;
      case 'dashlane-json':   triggerDownload(exportToDashlaneJSON(credentials), `dashlane_${date}.json`, 'application/json'); break;
      case 'nordpass-csv':    triggerDownload(exportToNordPass(credentials), `nordpass_${date}.csv`, 'text/csv'); break;
      case 'lastpass-csv':    triggerDownload(exportToLastPass(credentials), `lastpass_${date}.csv`, 'text/csv'); break;
      case 'protonpass-json': triggerDownload(exportToProtonPass(credentials, folders), `protonpass_${date}.json`, 'application/json'); break;
      case 'zoho-csv':        triggerDownload(exportToZohoCSV(credentials), `zoho_${date}.csv`, 'text/csv'); break;
      case 'passbolt-csv':    triggerDownload(exportToPassboltCSV(credentials), `passbolt_${date}.csv`, 'text/csv'); break;
      case 'padloc-json':     triggerDownload(exportToPadlocJSON(credentials, folders), `padloc_${date}.json`, 'application/json'); break;
      case 'passky-json':     triggerDownload(exportToPasskyJSON(credentials), `passky_${date}.json`, 'application/json'); break;
      case 'keepass-xml':     triggerDownload(exportToKeePassXML(credentials, folders), `keepass_${date}.xml`, 'text/xml'); break;
      case 'keepass-csv':     triggerDownload(exportToKeePassCSV(credentials), `keepass_${date}.csv`, 'text/csv'); break;
      case 'roboform-csv':    triggerDownload(exportToRoboForm(credentials, folders), `roboform_${date}.csv`, 'text/csv'); break;
      case 'enpass-csv':      triggerDownload(exportToEnpassCSV(credentials), `enpass_${date}.csv`, 'text/csv'); break;
      case 'buttercup-json':  triggerDownload(exportToButtercupJSON(credentials, folders), `buttercup_${date}.json`, 'application/json'); break;
      case 'chrome-csv':      triggerDownload(exportToChrome(credentials), `chrome_passwords_${date}.csv`, 'text/csv'); break;
      case 'firefox-csv':     triggerDownload(exportToFirefox(credentials), `firefox_passwords_${date}.csv`, 'text/csv'); break;
    }
  }, [credentials, folders]);

  const handleExport = useCallback(async () => {
    if (!selectedFmt?.canExport) return;
    setExportPassphraseError('');
    if (selectedFmt.needsPassphrase) {
      if (!exportPassphrase) { setExportPassphraseError(t('settings.exportPassphraseRequired', 'Enter a passphrase to encrypt the export.')); return; }
      if (exportPassphrase !== exportPassphraseConfirm) { setExportPassphraseError(t('settings.exportPassphraseMismatch', 'Passphrases do not match.')); return; }
    }
    try {
      await runExport(selectedFormatId, exportPassphrase || undefined);
      if (selectedFmt.needsPassphrase) { setExportPassphrase(''); setExportPassphraseConfirm(''); }
    } catch (err) {
      setExportPassphraseError(err instanceof Error ? err.message : t('settings.exportFailed', 'Export failed.'));
    }
  }, [selectedFormatId, selectedFmt, exportPassphrase, exportPassphraseConfirm, runExport, t]);

  const processImportFile = useCallback(async (file: File) => {
    setImportError('');
    try {
      const result = await importFromFile(file);
      const untitled = t('settings.importUntitled', 'Untitled');
      result.credentials = result.credentials.map(c => c.service === 'Untitled' ? { ...c, service: untitled } : c);
      setImportResult(result); setImportFileName(file.name);
      setImportMode('merge'); setIsImportModalOpen(true);
    } catch (err) {
      const msg = err instanceof Error ? err.message : '';
      if (msg === 'ENCRYPTED_PWDNOW') {
        setPendingEncryptedFile(file); setImportPassphrase(''); setImportPassphraseError('');
      } else {
        setImportError(msg || t('settings.importFailed', 'Failed to parse file.'));
      }
    }
  }, [t]);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (file) processImportFile(file);
  }, [processImportFile]);

  const handleFileDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); setIsDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) processImportFile(file);
  }, [processImportFile]);

  const handleEncryptedImport = useCallback(async () => {
    if (!pendingEncryptedFile || !importPassphrase) return;
    setImportPassphraseError('');
    try {
      const result = await importFromFile(pendingEncryptedFile, importPassphrase);
      if (result.credentials.length === 0) { setImportPassphraseError(t('settings.importNoCredentials', 'No credentials found in file.')); return; }
      const untitled = t('settings.importUntitled', 'Untitled');
      result.credentials = result.credentials.map(c => c.service === 'Untitled' ? { ...c, service: untitled } : c);
      setPendingEncryptedFile(null); setImportPassphrase('');
      setImportResult(result); setImportFileName(pendingEncryptedFile.name);
      setImportMode('merge'); setIsImportModalOpen(true);
    } catch { setImportPassphraseError(t('settings.importWrongPassphrase', 'Wrong passphrase or corrupted file.')); }
  }, [pendingEncryptedFile, importPassphrase, t]);

  const handleConfirmImport = useCallback(async () => {
    if (!importResult) return;
    setIsImporting(true);
    try {
      if (importMode === 'replace') {
        for (const cred of credentials) await deleteCredential(cred.id);
      }
      const importedLabel = t('settings.importedFolderLabel', 'Imported');
      let importFolderId = folders.find(f => f.label === importedLabel || f.label === 'Imported')?.id;
      if (!importFolderId) {
        const newFolder = { id: generateUUID(), label: importedLabel, description: t('settings.importedFolderDesc', 'Credentials imported from an external source'), iconName: 'Download' };
        await addFolder(newFolder);
        importFolderId = newFolder.id;
      }
      for (const cred of importResult.credentials) {
        let folderId = importFolderId;
        if ((importResult.detectedFormat === 'pwdnow' || importResult.detectedFormat === 'pwdnow-json') && cred.folderId) {
          const match = folders.find(f => f.id === cred.folderId || f.label === cred.folderId);
          if (match) folderId = match.id;
        }
        await addCredential({ ...cred, folderId });
      }
      setIsImportModalOpen(false); setImportResult(null);
      addNotification({ title: t('settings.importSuccess', 'Import complete'), message: t('settings.importSuccessMsg', '{{count}} credential(s) imported.', { count: importResult.credentials.length }), type: 'success' });
    } finally { setIsImporting(false); }
  }, [importResult, importMode, credentials, folders, deleteCredential, addFolder, addCredential, addNotification, t]);

  // Scroll-spy
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) setActiveSection(entry.target.id.replace('settings-panel-', ''));
        }
      },
      { threshold: 0.15, rootMargin: '-80px 0px -55% 0px' },
    );
    NAV.forEach(({ id }) => {
      const el = document.getElementById(`settings-panel-${id}`);
      if (el) observer.observe(el);
    });
    return () => observer.disconnect();
  }, []);

  const scrollTo = (id: string) => {
    document.getElementById(`settings-panel-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    setActiveSection(id);
  };

  return (
    <div className="min-h-full">
      <SEO title="Settings | PWDnow" />

      <div className="max-w-5xl mx-auto px-5 lg:px-8 py-8 lg:py-10">

        {/* Page header */}
        <div className="mb-8 lg:mb-10">
          <h1 className="text-xl font-semibold text-neutral-900 dark:text-white">
            {t('settings.title', 'Settings')}
          </h1>
          <p className="mt-1 text-[13px] text-neutral-600 dark:text-neutral-300">
            {t('settings.subtitle', 'Manage your account, security, and preferences.')}
          </p>
        </div>

        {/* Mobile horizontal nav — ARIA tablist */}
        <div role="tablist" aria-label={t('settings.settingsNavMobile', 'Settings sections')} className="lg:hidden flex gap-1.5 overflow-x-auto no-scrollbar pb-4 mb-8">
          {NAV.map(({ id, label, Icon }) => (
            <button
              key={id}
              role="tab"
              id={`settings-tab-${id}`}
              aria-selected={activeSection === id}
              aria-controls={`settings-panel-${id}`}
              tabIndex={activeSection === id ? 0 : -1}
              onClick={() => setActiveSection(id)}
              onKeyDown={(e) => {
                const ids = NAV.map(n => n.id);
                const cur = ids.indexOf(id);
                let next = cur;
                if (e.key === 'ArrowRight') next = (cur + 1) % ids.length;
                else if (e.key === 'ArrowLeft') next = (cur - 1 + ids.length) % ids.length;
                else if (e.key === 'Home') next = 0;
                else if (e.key === 'End') next = ids.length - 1;
                else return;
                e.preventDefault();
                setActiveSection(ids[next]);
                document.getElementById(`settings-tab-${ids[next]}`)?.focus();
              }}
              className={`flex items-center gap-1.5 shrink-0 px-3 py-1.5 rounded-full text-[12px] font-medium transition-all border focus:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 dark:focus-visible:ring-white focus-visible:ring-offset-1 ${
                activeSection === id
                  ? 'bg-neutral-900 dark:bg-white text-white dark:text-neutral-900 border-transparent'
                  : 'bg-white dark:bg-white/5 border-neutral-200 dark:border-white/10 text-neutral-700 dark:text-neutral-300 hover:border-neutral-300 dark:hover:border-white/20 hover:text-neutral-900 dark:hover:text-white'
              }`}
            >
              <Icon size={12} aria-hidden="true" />
              {label}
            </button>
          ))}
        </div>

        <div className="lg:flex gap-10 items-start">

          {/* ── Sidebar ───────────────────────────────────────────────────────── */}
          <aside className="hidden lg:block w-48 shrink-0">
            <nav aria-label={t('settings.settingsNavDesktop', 'Settings sidebar')} className="sticky top-6 space-y-5">
              {NAV_GROUPS.map(group => (
                <div key={group.label}>
                  <p className="text-[10px] font-semibold tracking-[0.1em] uppercase text-neutral-600 dark:text-neutral-300 px-2.5 mb-1.5">
                    {group.label}
                  </p>
                  <div className="space-y-0.5">
                    {group.items.map(({ id, label, Icon }) => {
                      const active = activeSection === id;
                      return (
                        <button
                          key={id}
                          onClick={() => scrollTo(id)}
                          aria-current={active ? 'true' : undefined}
                          className={`w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-[13px] transition-all text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 dark:focus-visible:ring-white focus-visible:ring-offset-1 ${
                            active
                              ? 'bg-neutral-100 dark:bg-white/8 text-neutral-900 dark:text-white font-medium'
                              : 'text-neutral-700 dark:text-neutral-300 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-50 dark:hover:bg-white/5'
                          }`}
                        >
                          <Icon size={14} className="shrink-0 opacity-75" aria-hidden="true" />
                          <span>{label}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))}
            </nav>
          </aside>

          {/* ── Content ───────────────────────────────────────────────────────── */}
          <div className="flex-1 min-w-0 space-y-12">

            {/* ── Profile ─────────────────────────────────────────────────────── */}
            <section id="settings-panel-profile" role="tabpanel" aria-labelledby="settings-tab-profile" className={`scroll-mt-24${activeSection !== 'profile' ? ' hidden lg:block' : ''}`}>
              <ProfileSection profile={profile} updateProfile={updateProfile} reloadProfile={reloadProfile} />
            </section>

            <div className="h-px bg-neutral-200 dark:bg-white/8 hidden lg:block" />

            {/* ── Appearance ──────────────────────────────────────────────────── */}
            <section id="settings-panel-appearance" role="tabpanel" aria-labelledby="settings-tab-appearance" className={`scroll-mt-24${activeSection !== 'appearance' ? ' hidden lg:block' : ''}`}>
              <SectionHeading
                title={t('settings.appearance', 'Appearance')}
                description={t('settings.appearanceDesc', 'Choose your preferred interface color scheme.')}
              />
              <div role="group" aria-label={t('settings.appearance', 'Theme')} className="inline-flex items-center gap-0.5 p-1 bg-neutral-100 dark:bg-white/5 rounded-xl border border-neutral-200 dark:border-white/10">
                <ThemeButton current={theme} value="light" setTheme={setTheme}
                  icon={<Sun size={14} />} label={t('settings.themeLight', 'Light')} />
                <ThemeButton current={theme} value="dark" setTheme={setTheme}
                  icon={<Moon size={14} />} label={t('settings.themeDark', 'Dark')} />
                <ThemeButton current={theme} value="system" setTheme={setTheme}
                  icon={<Monitor size={14} />} label={t('settings.themeSystem', 'System')} />
              </div>
            </section>

            <div className="h-px bg-neutral-200 dark:bg-white/8 hidden lg:block" />

            {/* ── Import & Export ──────────────────────────────────────────────── */}
            <section id="settings-panel-import" role="tabpanel" aria-labelledby="settings-tab-import" className={`scroll-mt-24${activeSection !== 'import' ? ' hidden lg:block' : ''}`}>
              <SectionHeading
                title={t('settings.importExport', 'Import & Export')}
                description={t('settings.importExportDesc', 'Move your credentials between password managers.')}
              />
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

                {/* Import card */}
                <div className="border border-neutral-200 dark:border-white/10 rounded-xl overflow-hidden">
                  <div className="px-5 py-3.5 border-b border-neutral-100 dark:border-white/5 flex items-center gap-3 bg-neutral-50/50 dark:bg-white/2">
                    <div className="w-7 h-7 rounded-lg bg-neutral-200 dark:bg-white/10 flex items-center justify-center shrink-0 text-neutral-600 dark:text-neutral-300">
                      <Upload size={13} />
                    </div>
                    <div>
                      <h3 className="text-[13px] font-semibold text-neutral-900 dark:text-white">{t('settings.importVaultTitle', 'Import')}</h3>
                      <p className="text-[11px] text-neutral-600 dark:text-neutral-300 leading-tight">{t('settings.importVaultDesc', 'Bring in credentials from any password manager')}</p>
                    </div>
                  </div>

                  <div className="p-5 flex flex-col gap-4">
                    {!pendingEncryptedFile && (
                      <label htmlFor="import-vault-file"
                        className={`relative flex flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed p-8 cursor-pointer transition-all ${
                          isDragOver
                            ? 'border-neutral-400 dark:border-white/30 bg-neutral-50 dark:bg-white/5'
                            : 'border-neutral-200 dark:border-white/10 hover:border-neutral-300 dark:hover:border-white/20 hover:bg-neutral-50/50 dark:hover:bg-white/3'
                        }`}
                        onDragOver={e => { e.preventDefault(); setIsDragOver(true); }}
                        onDragEnter={e => { e.preventDefault(); setIsDragOver(true); }}
                        onDragLeave={() => setIsDragOver(false)}
                        onDrop={handleFileDrop}
                      >
                        <input id="import-vault-file" type="file" accept=".json,.csv,.xml,.1pux,.p2w" className="sr-only" onChange={handleFileSelect} />
                        <div className={`w-10 h-10 rounded-xl flex items-center justify-center transition-colors ${isDragOver ? 'bg-neutral-200 dark:bg-white/20' : 'bg-neutral-100 dark:bg-white/5'}`}>
                          <FileUp size={18} className="text-neutral-600 dark:text-neutral-300" />
                        </div>
                        <div className="text-center">
                          <p className="text-[13px] font-medium text-neutral-900 dark:text-white">
                            {isDragOver ? t('settings.dropHere', 'Drop to import') : t('settings.importDropzone', 'Drop file or click to browse')}
                          </p>
                          <p className="text-[11px] text-neutral-600 dark:text-neutral-300 mt-1">JSON · CSV · XML · 1PUX · P2W</p>
                        </div>
                      </label>
                    )}

                    {pendingEncryptedFile && (
                      <div className="space-y-3 border border-neutral-200 dark:border-white/10 rounded-lg p-4">
                        <div className="flex items-center gap-2">
                          <Lock size={12} className="text-neutral-600 dark:text-neutral-300 shrink-0" />
                          <p className="text-[12px] font-medium text-neutral-900 dark:text-white">{t('settings.importEncryptedDetected', 'Encrypted — enter passphrase to unlock')}</p>
                        </div>
                        <p className="text-[11px] text-neutral-600 dark:text-neutral-300 truncate">{pendingEncryptedFile.name}</p>
                        <input
                          type="password"
                          value={importPassphrase}
                          onChange={e => { setImportPassphrase(e.target.value); setImportPassphraseError(''); }}
                          onKeyDown={e => e.key === 'Enter' && handleEncryptedImport()}
                          placeholder={t('settings.importPassphrasePlaceholder', 'Export passphrase…')}
                          className={inputCls}
                          autoComplete="new-password"
                          autoFocus
                        />
                        {importPassphraseError && <p className="text-[11px] text-red-500">{importPassphraseError}</p>}
                        <div className="flex gap-2">
                          <button onClick={handleEncryptedImport} className="flex-1 py-2 bg-neutral-900 dark:bg-white text-white dark:text-neutral-900 rounded-lg text-[12px] font-medium hover:opacity-90 transition-opacity">
                            {t('settings.importDecryptButton', 'Decrypt & Import')}
                          </button>
                          <button onClick={() => { setPendingEncryptedFile(null); setImportPassphrase(''); }}
                            className="px-3 py-2 rounded-lg text-[12px] font-medium text-neutral-600 dark:text-neutral-300 hover:bg-neutral-100 dark:hover:bg-white/5 transition-colors border border-neutral-200 dark:border-white/10">
                            {t('common.cancel', 'Cancel')}
                          </button>
                        </div>
                      </div>
                    )}

                    {importError && (
                      <p className="text-[12px] font-medium text-red-500 flex items-center gap-1.5">
                        <AlertTriangle size={12} /> {importError}
                      </p>
                    )}

                    <p className="text-[11px] text-neutral-600 dark:text-neutral-300 leading-relaxed">
                      {t('settings.importAutoDetect', 'Format detected automatically. Supports 20+ password managers.')}
                    </p>
                  </div>
                </div>

                {/* Export card */}
                <div className="border border-neutral-200 dark:border-white/10 rounded-xl overflow-hidden">
                  <div className="px-5 py-3.5 border-b border-neutral-100 dark:border-white/5 flex items-center gap-3 bg-neutral-50/50 dark:bg-white/2">
                    <div className="w-7 h-7 rounded-lg bg-neutral-900 dark:bg-white flex items-center justify-center shrink-0">
                      <Download size={13} className="text-white dark:text-neutral-900" />
                    </div>
                    <div>
                      <h3 className="text-[13px] font-semibold text-neutral-900 dark:text-white">{t('settings.exportVaultTitle', 'Export')}</h3>
                      <p className="text-[11px] text-neutral-600 dark:text-neutral-300 leading-tight">{t('settings.exportVaultDesc', 'Download credentials for backup or migration')}</p>
                    </div>
                  </div>

                  <div className="p-5 flex flex-col gap-4">
                    {/* Category tabs */}
                    <div className="flex gap-0.5 p-1 bg-neutral-100 dark:bg-white/5 rounded-lg border border-neutral-200 dark:border-white/10">
                      {Object.entries(FORMAT_GROUPS).map(([gId, gLabel]) => {
                        const hasExportable = FORMATS.some(f => f.group === gId && f.canExport);
                        if (!hasExportable) return null;
                        const active = exportCategory === gId;
                        return (
                          <button
                            key={gId}
                            onClick={() => {
                              setExportCategory(gId);
                              const first = FORMATS.find(f => f.group === gId && f.canExport);
                              if (first) { setSelectedFormatId(first.id); setExportPassphrase(''); setExportPassphraseConfirm(''); setExportPassphraseError(''); }
                            }}
                            className={`flex-1 py-1.5 px-2 rounded-md text-[11px] font-medium transition-all ${
                              active
                                ? 'bg-white dark:bg-white/15 text-neutral-900 dark:text-white shadow-sm'
                                : 'text-neutral-600 dark:text-neutral-300 hover:text-neutral-900 dark:hover:text-white'
                            }`}
                          >
                            {t(`settings.formatGroup_${gId}`, gLabel.split(' ')[0])}
                          </button>
                        );
                      })}
                    </div>

                    {/* Format grid */}
                    <div className="grid grid-cols-2 gap-1.5">
                      {categoryExportFormats.map(fmt => {
                        const active = selectedFormatId === fmt.id;
                        return (
                          <button
                            key={fmt.id}
                            onClick={() => { setSelectedFormatId(fmt.id); setExportPassphrase(''); setExportPassphraseConfirm(''); setExportPassphraseError(''); }}
                            className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-[12px] font-medium transition-all text-left ${
                              active
                                ? 'border-neutral-900 dark:border-white/30 bg-neutral-900 dark:bg-white/12 text-white dark:text-white'
                                : 'border-neutral-200 dark:border-white/8 bg-white dark:bg-transparent text-neutral-600 dark:text-neutral-300 hover:border-neutral-300 dark:hover:border-white/18 hover:text-neutral-900 dark:hover:text-white'
                            }`}
                          >
                            {fmt.exportExt === 'json' || fmt.exportExt === '1pux' ? <FileJson size={11} className="shrink-0" /> : <FileText size={11} className="shrink-0" />}
                            <span className="truncate">{fmt.label.replace(/^PWDnow /, '')}</span>
                          </button>
                        );
                      })}
                    </div>

                    {selectedFmt?.needsPassphrase && (
                      <div className="space-y-2">
                        <label htmlFor="export-passphrase" className="text-[11px] font-medium text-neutral-600 dark:text-neutral-300 flex items-center gap-1.5">
                          <Lock size={10} /> {t('settings.exportPassphraseLabel', 'Encryption passphrase')}
                        </label>
                        <input id="export-passphrase" aria-label={t('settings.exportPassphraseLabel', 'Encryption passphrase')} type="password" value={exportPassphrase}
                          onChange={e => { setExportPassphrase(e.target.value); setExportPassphraseError(''); }}
                          placeholder={t('settings.exportPassphrasePlaceholder', 'Enter a strong passphrase…')}
                          className={inputCls}
                          autoComplete="new-password"
                        />
                        <label htmlFor="confirm-passphrase" className="sr-only">
                          {t('settings.exportPassphraseConfirmLabel', 'Confirm passphrase')}
                        </label>
                        <input id="confirm-passphrase" aria-label={t('settings.exportPassphraseConfirmLabel', 'Confirm passphrase')} type="password" value={exportPassphraseConfirm}
                          onChange={e => { setExportPassphraseConfirm(e.target.value); setExportPassphraseError(''); }}
                          placeholder={t('settings.exportPassphraseConfirmPlaceholder', 'Confirm passphrase…')}
                          className={inputCls}
                          autoComplete="new-password"
                        />
                        {exportPassphraseError && <p className="text-[11px] text-red-500">{exportPassphraseError}</p>}
                      </div>
                    )}

                    <button
                      onClick={handleExport}
                      disabled={!selectedFmt?.canExport || credentials.length === 0}
                      className="w-full py-2.5 bg-neutral-900 dark:bg-white text-white dark:text-neutral-900 rounded-lg text-[13px] font-medium hover:opacity-90 transition-opacity flex items-center justify-center gap-2 disabled:opacity-30"
                    >
                      <Download size={14} />
                      {t('settings.exportButton', 'Export')}
                      {credentials.length > 0 && <span className="text-[12px] text-neutral-300 dark:text-neutral-700">({credentials.length})</span>}
                    </button>

                    <p className="text-[11px] text-neutral-600 dark:text-neutral-300 leading-relaxed">
                      {selectedFmt?.needsPassphrase
                        ? t('settings.exportWarningEncrypted', 'AES-256-GCM · PBKDF2-SHA-256 · 600 000 iterations. Keep the passphrase — required to re-import.')
                        : t('settings.exportWarningCleartext', 'Credentials exported in cleartext for compatibility. Delete the file after migration.')}
                    </p>
                  </div>
                </div>
              </div>
            </section>

            <div className="h-px bg-neutral-200 dark:bg-white/8 hidden lg:block" />

            {/* ── Authentication ───────────────────────────────────────────────── */}
            <section id="settings-panel-auth" role="tabpanel" aria-labelledby="settings-tab-auth" className={`scroll-mt-24${activeSection !== 'auth' ? ' hidden lg:block' : ''}`}>
              <MfaSection profile={profile} emailServerConfig={emailServerConfig} />
            </section>

            <div className="h-px bg-neutral-200 dark:bg-white/8 hidden lg:block" />

            {/* ── Security Modes ───────────────────────────────────────────────── */}
            <section id="settings-panel-security" role="tabpanel" aria-labelledby="settings-tab-security" className={`scroll-mt-24${activeSection !== 'security' ? ' hidden lg:block' : ''}`}>
              <SecurityModesSection
                sessionLockTimeout={sessionLockTimeout}
                handleSessionLockChange={handleSessionLockChange}
                emailServerConfig={emailServerConfig}
                setEmailServerForm={setEmailServerForm}
                setIsEmailServerModalOpen={setIsEmailServerModalOpen}
                DEFAULT_EMAIL_CONFIG={DEFAULT_EMAIL_CONFIG}
                isAuditLogOpen={isAuditLogOpen}
                setIsAuditLogOpen={setIsAuditLogOpen}
                isSharesOpen={isSharesOpen}
                setIsSharesOpen={setIsSharesOpen}
              />
            </section>

            <div className="h-px bg-neutral-200 dark:bg-white/8 hidden lg:block" />

            {/* ── Recovery Key ─────────────────────────────────────────────────── */}
            <section id="settings-panel-recovery" role="tabpanel" aria-labelledby="settings-tab-recovery" className={`scroll-mt-24${activeSection !== 'recovery' ? ' hidden lg:block' : ''}`}>
              <RecoveryKeySection
                profile={profile}
                setIsRecoveryModalOpen={setIsRecoveryModalOpen}
                isGeneratingRecovery={isGeneratingRecovery}
                handleGenerateRecovery={handleGenerateRecovery}
                recoveryAuthPassword={recoveryAuthPassword}
                setRecoveryAuthPassword={setRecoveryAuthPassword}
                recoveryAuthError={recoveryAuthError}
              />
            </section>

            <div className="h-px bg-neutral-200 dark:bg-white/8 hidden lg:block" />

            {/* ── Emergency Access ─────────────────────────────────────────────── */}
            <section id="settings-panel-emergency" role="tabpanel" aria-labelledby="settings-tab-emergency" className={`scroll-mt-24${activeSection !== 'emergency' ? ' hidden lg:block' : ''}`}>
              <SectionHeading
                title={t('settings.emergencyAccess', 'Emergency Access')}
                description={t('settings.emergencyAccessDesc', 'Designate trusted contacts who can request emergency vault access.')}
              />
              <button
                onClick={() => setIsEmergencyModalOpen(true)}
                className="w-full border border-neutral-200 dark:border-white/10 rounded-xl p-5 flex items-center justify-between group hover:border-neutral-300 dark:hover:border-white/18 hover:bg-neutral-50/50 dark:hover:bg-white/3 transition-all text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 dark:focus-visible:ring-white focus-visible:ring-offset-1"
              >
                <div className="flex items-center gap-4">
                  <div className="w-9 h-9 rounded-xl bg-amber-100 dark:bg-amber-900/25 flex items-center justify-center shrink-0 text-amber-600 dark:text-amber-400">
                    <FbLifeRing size={16} />
                  </div>
                  <div>
                    <p className="text-[13px] font-medium text-neutral-900 dark:text-white">
                      {t('settings.configureEmergency', 'Configure Trusted Contacts')}
                    </p>
                    <p className="text-[12px] text-neutral-600 dark:text-neutral-300 mt-0.5">
                      {t('settings.emergencyAccessClickDesc', 'Set up emergency vault access for trusted people')}
                    </p>
                  </div>
                </div>
                <ChevronRight size={16} className="text-neutral-600 dark:text-neutral-300 shrink-0 transition-transform group-hover:translate-x-0.5" />
              </button>
            </section>

            <div className="h-px bg-neutral-200 dark:bg-white/8 hidden lg:block" />

            {/* ── Sessions & Log ───────────────────────────────────────────────── */}
            <section id="settings-panel-log" role="tabpanel" aria-labelledby="settings-tab-log" className={`scroll-mt-24${activeSection !== 'log' ? ' hidden lg:block' : ''}`}>
              <SectionHeading
                title={t('settings.sessionsAndLog', 'Sessions & Security Log')}
                description={t('settings.sessionsAndLogDesc', 'Monitor account activity and manage credential shares.')}
              />
              <div className="border border-neutral-200 dark:border-white/10 rounded-xl overflow-hidden">
                <div className="px-5 divide-y divide-neutral-100 dark:divide-white/5">
                  <ActionRow
                    icon={<FbClockRotate size={15} />}
                    title={t('settings.auditLog', 'Security Audit Log')}
                    desc={t('settings.auditLogDesc', 'Review login events, MFA changes, and account activity.')}
                    btnLabel={t('settings.viewLog', 'View Log')}
                    onClick={() => setIsAuditLogOpen(true)}
                  />
                  <ActionRow
                    icon={<FbShare size={15} />}
                    title={t('settings.activeShares', 'Active Credential Shares')}
                    desc={t('settings.sharesDesc2', 'View and revoke active one-time share links.')}
                    btnLabel={t('settings.manageSharesBtn', 'Manage')}
                    onClick={() => setIsSharesOpen(true)}
                  />
                </div>
              </div>
            </section>

            <div className="h-20" />
          </div>
        </div>
      </div>

      {/* ── Modals ─────────────────────────────────────────────────────────────── */}
      <AnimatePresence>
        {isEmergencyModalOpen && (
          <EmergencyAccessModal onClose={() => setIsEmergencyModalOpen(false)} />
        )}
      </AnimatePresence>
      <AuditLogModal isOpen={isAuditLogOpen} onClose={() => setIsAuditLogOpen(false)} />
      <SharesModal isOpen={isSharesOpen} onClose={() => setIsSharesOpen(false)} />
      <RecoveryKeyModal isOpen={isRecoveryModalOpen} onClose={() => setIsRecoveryModalOpen(false)} recoveryKey={generatedRecoveryKey} />

      {/* ── Import Preview Modal ───────────────────────────────────────────────── */}
      <AnimatePresence>
        {isImportModalOpen && importResult && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-black/50 backdrop-blur-[2px]"
              onClick={() => !isImporting && setIsImportModalOpen(false)}
            />
            <motion.div initial={{ opacity: 0, scale: 0.97, y: 10 }} animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.97, y: 10 }} transition={{ duration: 0.15 }}
              className="relative w-full max-w-xl bg-white dark:bg-neutral-900 rounded-xl shadow-2xl border border-neutral-200 dark:border-white/10 overflow-hidden max-h-[90vh] flex flex-col"
            >
              <div className="flex items-center justify-between px-6 py-4 border-b border-neutral-100 dark:border-white/8">
                <div>
                  <h3 className="text-[15px] font-semibold text-neutral-900 dark:text-white">{t('settings.importPreviewTitle', 'Import Preview')}</h3>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[10px] px-2 py-0.5 bg-neutral-100 dark:bg-white/8 rounded-full font-medium uppercase tracking-wide text-neutral-600 dark:text-neutral-300">
                      {getFormat(importResult.detectedFormat)?.label ?? importResult.detectedFormat}
                    </span>
                    <span className="text-[12px] text-neutral-600 dark:text-neutral-300">{importFileName}</span>
                  </div>
                </div>
                <button onClick={() => !isImporting && setIsImportModalOpen(false)}
                  aria-label={t('common.close', 'Close')}
                  className="p-1.5 hover:bg-neutral-100 dark:hover:bg-white/8 rounded-lg transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 dark:focus-visible:ring-white">
                  <X size={18} aria-hidden="true" className="text-neutral-600 dark:text-neutral-300" />
                </button>
              </div>

              <div className="overflow-y-auto flex-1 px-6 py-5 space-y-5">
                <div className="flex items-center gap-2.5 p-3 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800/40 rounded-lg">
                  <CheckCircle size={15} className="text-emerald-600 dark:text-emerald-400 shrink-0" />
                  <p className="text-[13px] font-medium text-emerald-800 dark:text-emerald-300">
                    {t('settings.importCredentialsFound', '{{count}} credential(s) found', { count: importResult.credentials.length })}
                  </p>
                </div>

                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-[0.1em] text-neutral-600 dark:text-neutral-300 mb-2">
                    {t('settings.importPreviewLabel', 'Preview (first 8)')}
                  </p>
                  <div className="rounded-lg border border-neutral-200 dark:border-white/10 overflow-hidden">
                    <table className="w-full text-[12px]">
                      <thead>
                        <tr className="bg-neutral-50 dark:bg-white/3">
                          <th className="text-left px-3 py-2 font-semibold text-neutral-700 dark:text-neutral-300">{t('settings.thService', 'Service')}</th>
                          <th className="text-left px-3 py-2 font-semibold text-neutral-700 dark:text-neutral-300">{t('settings.thUsername', 'Username')}</th>
                          <th className="text-left px-3 py-2 font-semibold text-neutral-700 dark:text-neutral-300 hidden sm:table-cell">{t('settings.thURL', 'URL')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {importResult.credentials.slice(0, 8).map((c, i) => (
                          <tr key={i} className="border-t border-neutral-100 dark:border-white/5 hover:bg-neutral-50 dark:hover:bg-white/3">
                            <td className="px-3 py-2 font-medium text-neutral-900 dark:text-white truncate max-w-[120px]">{c.service}</td>
                            <td className="px-3 py-2 text-neutral-600 dark:text-neutral-300 truncate max-w-[120px]">{c.username}</td>
                            <td className="px-3 py-2 text-neutral-600 dark:text-neutral-300 truncate max-w-[140px] hidden sm:table-cell">{c.url}</td>
                          </tr>
                        ))}
                        {importResult.credentials.length > 8 && (
                          <tr className="border-t border-neutral-100 dark:border-white/5">
                            <td colSpan={3} className="px-3 py-2 text-center text-neutral-600 dark:text-neutral-300 text-[11px]">
                              {t('settings.importMoreItems', '+{{count}} more', { count: importResult.credentials.length - 8 })}
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-[0.1em] text-neutral-600 dark:text-neutral-300 mb-2">
                    {t('settings.importModeLabel', 'Import mode')}
                  </p>
                  <div className="grid grid-cols-2 gap-2" role="radiogroup" aria-label={t('settings.importModeLabel', 'Import mode')}>
                    <button type="button" role="radio" aria-checked={importMode === 'merge'} onClick={() => setImportMode('merge')}
                      className={`px-4 py-3 rounded-lg border text-left transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 dark:focus-visible:ring-white focus-visible:ring-offset-1 ${
                        importMode === 'merge'
                          ? 'border-neutral-900 dark:border-white/30 bg-neutral-900 dark:bg-white/12 text-white dark:text-white'
                          : 'border-neutral-200 dark:border-white/10 hover:border-neutral-300 dark:hover:border-white/20'
                      }`}
                    >
                      <p className={`text-[13px] font-medium ${importMode === 'merge' ? '' : 'text-neutral-900 dark:text-white'}`}>
                        {t('settings.importMergeName', 'Merge')}
                      </p>
                      <p className={`text-[11px] mt-0.5 ${importMode === 'merge' ? 'opacity-60' : 'text-neutral-600 dark:text-neutral-300'}`}>
                        {t('settings.importMergeDesc', 'Add alongside existing')}
                      </p>
                    </button>
                    <button type="button" role="radio" aria-checked={importMode === 'replace'} onClick={() => setImportMode('replace')}
                      className={`px-4 py-3 rounded-lg border text-left transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 dark:focus-visible:ring-white focus-visible:ring-offset-1 ${
                        importMode === 'replace'
                          ? 'border-red-600 bg-red-600 text-white'
                          : 'border-neutral-200 dark:border-white/10 hover:border-red-300 dark:hover:border-red-700/40'
                      }`}
                    >
                      <p className={`text-[13px] font-medium ${importMode === 'replace' ? '' : 'text-neutral-900 dark:text-white'}`}>
                        {t('settings.importReplaceName', 'Replace All')}
                      </p>
                      <p className={`text-[11px] mt-0.5 ${importMode === 'replace' ? 'opacity-60' : 'text-neutral-600 dark:text-neutral-300'}`}>
                        {t('settings.importReplaceDesc', 'Delete existing first')}
                      </p>
                    </button>
                  </div>
                  {importMode === 'replace' && (
                    <div className="mt-3 p-3 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800/40 rounded-lg flex items-start gap-2">
                      <AlertTriangle size={13} className="text-red-600 shrink-0 mt-0.5" />
                      <p className="text-[12px] text-red-700 dark:text-red-400">
                        {t('settings.importReplaceWarning', 'This will permanently delete all {{count}} existing credential(s). This cannot be undone.', { count: credentials.length })}
                      </p>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex gap-3 px-6 py-4 border-t border-neutral-100 dark:border-white/8">
                <button onClick={() => setIsImportModalOpen(false)} disabled={isImporting}
                  className="flex-1 py-2.5 border border-neutral-200 dark:border-white/10 rounded-lg text-[13px] font-medium text-neutral-700 dark:text-neutral-300 hover:bg-neutral-50 dark:hover:bg-white/5 transition-colors disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 dark:focus-visible:ring-white"
                >
                  {t('common.cancel', 'Cancel')}
                </button>
                <button onClick={handleConfirmImport} disabled={isImporting}
                  className={`flex-1 py-2.5 rounded-lg text-[13px] font-medium transition-all flex items-center justify-center gap-2 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 dark:focus-visible:ring-white ${
                    importMode === 'replace'
                      ? 'bg-red-600 hover:bg-red-700 text-white'
                      : 'bg-neutral-900 dark:bg-white text-white dark:text-neutral-900 hover:opacity-90'
                  }`}
                >
                  {isImporting
                    ? <Loader2 size={15} className="animate-spin" />
                    : <><Upload size={13} />{t('settings.importButton', 'Import {{count}}', { count: importResult.credentials.length })}</>
                  }
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── SMTP Configuration Modal ───────────────────────────────────────────── */}
      <AnimatePresence>
        {isEmailServerModalOpen && emailServerForm && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-black/50 backdrop-blur-[2px]"
              onClick={() => !isSavingEmailServer && setIsEmailServerModalOpen(false)}
            />
            <motion.div initial={{ opacity: 0, scale: 0.97, y: 10 }} animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.97, y: 10 }} transition={{ duration: 0.15 }}
              className="relative w-full max-w-md bg-white dark:bg-neutral-900 rounded-xl shadow-2xl border border-neutral-200 dark:border-white/10 overflow-hidden"
            >
              <div className="flex items-center justify-between px-6 py-4 border-b border-neutral-100 dark:border-white/8">
                <div>
                  <h3 className="text-[15px] font-semibold text-neutral-900 dark:text-white">{t('settings.emailServerTitle', 'SMTP Configuration')}</h3>
                  <p className="text-[12px] text-neutral-600 dark:text-neutral-300 mt-0.5">{t('settings.emailServerModalDesc', 'Configure outgoing mail server')}</p>
                </div>
                <button onClick={() => setIsEmailServerModalOpen(false)} disabled={isSavingEmailServer}
                  className="p-1.5 hover:bg-neutral-100 dark:hover:bg-white/8 rounded-lg transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 dark:focus-visible:ring-white">
                  <X size={18} className="text-neutral-600 dark:text-neutral-300" />
                </button>
              </div>

              <div className="px-6 py-5 space-y-4">
                <div className="grid grid-cols-3 gap-3">
                  <div className="col-span-2 space-y-1.5">
                    <label htmlFor="input-smtp-host" className="text-[11px] font-medium text-neutral-600 dark:text-neutral-300">{t('settings.emailServerHost', 'SMTP Host')}</label>
<input id="input-smtp-host" type="text" value={emailServerForm.host}
                      onChange={e => { setEmailServerForm({ ...emailServerForm, host: e.target.value }); setEmailServerError(''); setDnsCheckResult(null); }}
                      placeholder="smtp.example.com"
                      className={inputCls}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label htmlFor="input-smtp-port" className="text-[11px] font-medium text-neutral-600 dark:text-neutral-300">{t('settings.emailServerPort', 'Port')}</label>
<input id="input-smtp-port" type="number" value={emailServerForm.port}
                      onChange={e => setEmailServerForm({ ...emailServerForm, port: Number(e.target.value) })}
                      min={1} max={65535}
                      className={inputCls}
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label htmlFor="input-smtp-user" className="text-[11px] font-medium text-neutral-600 dark:text-neutral-300">{t('settings.emailServerUser', 'Username / Email')}</label>
<input id="input-smtp-user" type="text" value={emailServerForm.user}
                    onChange={e => { setEmailServerForm({ ...emailServerForm, user: e.target.value }); setEmailServerError(''); setDnsCheckResult(null); }}
                    placeholder="user@example.com" autoComplete="off"
                    className={inputCls}
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[11px] font-medium text-neutral-600 dark:text-neutral-300">{t('settings.emailServerPass', 'Password / App Password')}</label>
                  <div className="relative">
                    <input type={showEmailPass ? 'text' : 'password'} value={emailServerForm.pass}
                      onChange={e => setEmailServerForm({ ...emailServerForm, pass: e.target.value })}
                      placeholder="••••••••••••" autoComplete="new-password"
                      className={inputCls + ' pr-10'}
                    />
                    <button type="button" tabIndex={-1} onClick={() => setShowEmailPass(v => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-200 transition-colors">
                      {showEmailPass ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="text-[11px] font-medium text-neutral-600 dark:text-neutral-300">{t('settings.smtpProtocol', 'Security Protocol')}</label>
                  <div className="grid grid-cols-3 gap-2">
                    {[
                      { id: 'none',     label: t('settings.smtpProtoSmtp', 'None (25)'),         port: 25 },
                      { id: 'ssl_tls',  label: t('settings.smtpProtoSslTls', 'TLS (465)'),       port: 465 },
                      { id: 'starttls', label: t('settings.smtpProtoStarttls', 'STARTTLS (587)'), port: 587 },
                    ].map(m => {
                      const active = emailServerForm.protocol === m.id || (m.id === 'ssl_tls' && emailServerForm.secure === true && !emailServerForm.protocol);
                      return (
                        <button key={m.id} type="button"
                          onClick={() => setEmailServerForm({ ...emailServerForm, protocol: m.id as any, secure: m.id === 'ssl_tls', port: m.port })}
                          className={`py-2 rounded-lg border text-[11px] font-medium transition-all ${
                            active
                              ? 'border-neutral-900 bg-neutral-900 text-white dark:border-white/30 dark:bg-white/12 dark:text-white'
                              : 'border-neutral-200 dark:border-white/10 text-neutral-600 dark:text-neutral-300 hover:border-neutral-300 dark:hover:border-white/20'
                          }`}
                        >
                          {m.label}
                        </button>
                      );
                    })}
                  </div>
                  <p className="text-[11px] text-neutral-600 dark:text-neutral-300">
                    {emailServerForm.protocol === 'ssl_tls' || (emailServerForm.secure && !emailServerForm.protocol)
                      ? t('settings.smtpProtoSslTlsDesc', 'Port 465 — Implicit TLS')
                      : emailServerForm.protocol === 'starttls'
                        ? t('settings.smtpProtoStarttlsDesc', 'Port 587 — Upgrades to TLS')
                        : t('settings.smtpProtoSmtpDesc', 'Port 25 — Legacy plaintext')
                    }
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button type="button" onClick={handleDnsCheck}
                    disabled={isDnsChecking || isSavingEmailServer || !emailServerForm.host.trim()}
                    className="flex items-center gap-1.5 px-3 py-2 text-[12px] font-medium border border-neutral-200 dark:border-white/10 rounded-lg bg-white dark:bg-transparent text-neutral-700 dark:text-neutral-300 hover:bg-neutral-50 dark:hover:bg-white/5 hover:border-neutral-300 dark:hover:border-white/20 transition-all disabled:opacity-50"
                  >
                    {isDnsChecking ? <Loader2 size={12} className="animate-spin" /> : <Globe size={12} />}
                    {isDnsChecking ? t('settings.dnsChecking', 'Checking…') : t('settings.dnsTestBtn', 'Test DNS')}
                  </button>
                  {dnsCheckResult && (
                    <span className="text-[11px] text-neutral-600 dark:text-neutral-300 font-mono">{dnsCheckResult.domain}</span>
                  )}
                </div>
                {dnsCheckResult && (
                  <div className="p-3 bg-neutral-50 dark:bg-white/3 border border-neutral-200 dark:border-white/10 rounded-lg space-y-1.5">
                    <DnsRow label="MX" ok={dnsCheckResult.mx.length > 0} detail={dnsCheckResult.mx[0]} required />
                    <DnsRow label="SPF" ok={dnsCheckResult.spf} />
                    <DnsRow label="DMARC" ok={dnsCheckResult.dmarc} />
                    <DnsRow label="DKIM" ok={dnsCheckResult.dkim} />
                    <DnsRow label="BIMI" ok={dnsCheckResult.bimi} optional />
                    <DnsRow label="VMC" ok={dnsCheckResult.vmc} optional />
                  </div>
                )}

                {emailServerError && (
                  <p className="flex items-center gap-1.5 text-[12px] font-medium text-red-600">
                    <AlertTriangle size={12} /> {emailServerError}
                  </p>
                )}
              </div>

              <div className="flex gap-3 px-6 py-4 border-t border-neutral-100 dark:border-white/8">
                <button onClick={() => setIsEmailServerModalOpen(false)} disabled={isSavingEmailServer}
                  className="flex-1 py-2.5 border border-neutral-200 dark:border-white/10 rounded-lg text-[13px] font-medium text-neutral-700 dark:text-neutral-300 hover:bg-neutral-50 dark:hover:bg-white/5 transition-colors disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 dark:focus-visible:ring-white"
                >
                  {t('common.cancel', 'Cancel')}
                </button>
                <button onClick={handleSaveEmailServer} disabled={isSavingEmailServer}
                  className="flex-1 py-2.5 bg-neutral-900 dark:bg-white text-white dark:text-neutral-900 rounded-lg text-[13px] font-medium hover:opacity-90 transition-opacity flex items-center justify-center gap-2 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-white dark:focus-visible:ring-neutral-900"
                >
                  {isSavingEmailServer ? <Loader2 size={15} className="animate-spin" /> : <><CheckCircle size={13} />{t('common.save', 'Save')}</>}
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
