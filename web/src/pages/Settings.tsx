import React, { useState, useCallback, useEffect, useRef, lazy, Suspense } from 'react';
const EmergencyAccessModal = lazy(() => import('../components/EmergencyAccessModal'));
import { User, History, ShieldAlert, Smartphone, Key, Mail, Monitor, Sun, Moon, CheckCircle, LogOut, Edit3, RefreshCw, X, ShieldCheck, Check, Eye, EyeOff, Camera, ChevronDown, Copy, AlertTriangle, Trash2, Timer, Server, Loader2, Download, Upload, Plane, Skull, Flame, FileJson, FileText, FileUp, Fingerprint, KeyRound, ToggleLeft, ToggleRight, Shield, Share2, Globe, Lock } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import QRCode from 'qrcode';
import { useUser } from '../context/UserContext';
import { useVault } from '../context/VaultContext';
import {
  getDuressModeConfig, getDuressModeConfigFull,
  getTravelModeConfig, getTravelModeConfigAsync,
  armDuressMode, disarmDuressMode,
  enableTravelMode, disableTravelMode,
  wipeVaultData,
  type DuressModeConfig, type TravelModeConfig,
} from '../utils/securityModes';
import { daemon } from '../utils/daemonClient';
import UserAvatar from '../components/UserAvatar';
import { useTheme } from '../context/ThemeContext';
import { generateUUID, generateRecoveryKey } from '../utils/crypto';
import { writeEncryptedLocal, readDecryptedLocal } from '../utils/localCrypto';
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
  FORMATS, FORMAT_GROUPS, getFormat,
  type ImportResult, type FormatDef,
} from '../utils/importExport';
import { getSessions, clearOtherSessions, formatSessionTime, type LoginSession } from '../utils/sessionTracker';
import { hasLocalQuickUnlock, enrollQuickUnlock, revokeLocalQuickUnlock } from '../utils/quickUnlock';
import SEO from '../components/SEO';
import {
  getMfaConfig, saveMfaConfig,
  generateTotpSecret, buildTotpUri, buildHotpUri, verifyTotp, verifyHotp,
  generateEmailCode, verifyEmailCode, clearPendingOtp,
  isWebAuthnSupported, isSecureContext,
  registerWebAuthn, authenticateWebAuthn,
  registerPasskey, registerPlatformAuth,
  countActiveMfaMethods, refreshLoginHints,
  isPlatformAuthAvailable, describeWebAuthnError,
  type MfaConfig, type WebAuthnCredentialMeta,
} from '../utils/mfa';
import COUNTRY_LIST from '../data/country-list.json';

export default function Settings() {
  const { t } = useTranslation();
  const { profile, updateProfile, reloadProfile } = useUser();
  const { theme, setTheme } = useTheme();
  const { 
    credentials, folders, addCredential, deleteCredential, addFolder, reloadLocal,
    persistFolders, persistCredentials
  } = useVault();
  const [localProfile, setLocalProfile] = useState(profile);

  useEffect(() => {
    setLocalProfile(profile);
  }, [profile]);

  const [isSaving, setIsSaving] = useState(false);
  const [showSaveSuccess, setShowSaveSuccess] = useState(false);

  const hasChanges = JSON.stringify(localProfile) !== JSON.stringify(profile);

  const handleLocalProfileChange = (field: string, value: string) => {
    setLocalProfile(prev => ({ ...prev, [field]: value }));
  };

  const handleSaveProfile = async () => {
    setIsSaving(true);
    try {
      // Persist name/email to the daemon so the change survives logout.
      // Without this, the previous "Save" call was a UI no-op and any edits
      // disappeared on next reload (Settings was updating React state only).
      if (daemon.isConnected) {
        await daemon.updateProfile(
          localProfile.firstName ?? '',
          localProfile.lastName ?? '',
          localProfile.email ?? '',
        );

        // Photo persistence. Three cases:
        //   1. photoUrl is a fresh blob:/data: URL  -> upload bytes.
        //   2. photoUrl cleared (was set, now empty) -> remove on the daemon.
        //   3. photoUrl unchanged (still a blob: from reloadProfile) -> no-op.
        const oldPhoto = profile.photoUrl;
        const newPhoto = localProfile.photoUrl;
        if (newPhoto && newPhoto !== oldPhoto && (newPhoto.startsWith('blob:') || newPhoto.startsWith('data:'))) {
          const bytes = new Uint8Array(await (await fetch(newPhoto)).arrayBuffer());
          await daemon.uploadProfilePicture(bytes);
        } else if (!newPhoto && oldPhoto) {
          await daemon.removeProfilePicture();
        }

        // Reload from daemon so context state reflects what's actually stored
        // (and so the blob URL gets refreshed off the daemon-returned bytes,
        // with the prior blob URL revoked in reloadProfile()).
        await reloadProfile();
      } else {
        // Daemon unavailable — keep the legacy in-memory-only behavior so the
        // UI is still responsive in offline/demo mode.
        updateProfile(localProfile);
      }
    } catch (e) {
      console.error('[Settings] save profile failed:', e);
    } finally {
      setIsSaving(false);
      setShowSaveSuccess(true);
      setTimeout(() => setShowSaveSuccess(false), 3000);
    }
  };

  // ── Modal open/close ──────────────────────────────────────────────────────
  const [isEmergencyModalOpen, setIsEmergencyModalOpen] = useState(false);
  const [isRecoveryModalOpen, setIsRecoveryModalOpen] = useState(false);
  const [recoveryKey, setRecoveryKey] = useState('');
  const [isGeneratingRecovery, setIsGeneratingRecovery] = useState(false);
  const [isChangeModalOpen, setIsChangeModalOpen] = useState(false);
  const [isAuditLogOpen, setIsAuditLogOpen] = useState(false);
  const [isRevokeModalOpen, setIsRevokeModalOpen] = useState(false);
  const [isRevoking, setIsRevoking] = useState(false);
  const [revokeSuccess, setRevokeSuccess] = useState(false);

  // Audit events (server mode only)
  const [auditTab, setAuditTab] = useState<'sessions' | 'events'>('sessions');
  const [auditEvents, setAuditEvents] = useState<any[]>([]);
  const [auditEventsTotal, setAuditEventsTotal] = useState(0);
  const [auditEventsLoading, setAuditEventsLoading] = useState(false);

  // Active share links (server mode only)
  const [isSharesOpen, setIsSharesOpen] = useState(false);
  const [shares, setShares] = useState<any[]>([]);
  const [sharesLoading, setSharesLoading] = useState(false);

  const handleRevokeAll = async () => {
    setIsRevoking(true);
    await new Promise(resolve => setTimeout(resolve, 800));
    await clearOtherSessions();
    setSessions(await getSessions());
    setIsRevoking(false);
    setRevokeSuccess(true);
  };

  // ── MFA live config (kept in sync with localStorage) ──────────────────────
  const [mfaConfig, setMfaConfig] = useState<MfaConfig>(getMfaConfig);
  const [policyError, setPolicyError] = useState('');
  // null = still checking, true/false = result of isUserVerifyingPlatformAuthenticatorAvailable()
  const [platformAuthAvail, setPlatformAuthAvail] = useState<boolean | null>(null);

  const refreshMfa = () => setMfaConfig(getMfaConfig());

  useEffect(() => {
    isPlatformAuthAvailable().then(setPlatformAuthAvail);
  }, []);

  // ── MFA modal state ────────────────────────────────────────────────────────
  type MfaType = 'totp' | 'webauthn' | 'email' | 'passkey' | 'platform';
  const [mfaModal, setMfaModal] = useState<{ type: MfaType; step: number } | null>(null);

  // TOTP / HOTP
  const [totpSecret, setTotpSecret]     = useState('');
  const [totpType, setTotpType]         = useState<'totp' | 'hotp'>('totp');
  const [hotpCounter, setHotpCounter]   = useState(0);
  const [totpCode, setTotpCode]         = useState(Array(8).fill(''));
  const [totpError, setTotpError]       = useState('');
  const [totpSecretCopied, setTotpSecretCopied] = useState(false);
  const totpRefs = useRef<(HTMLInputElement | null)[]>([]);
  // Callback ref: fires synchronously when the canvas mounts/unmounts, so the QR
  // is always drawn onto the live DOM node - even when Back navigation recreates it.
  const qrCanvasCallback = useCallback((canvas: HTMLCanvasElement | null) => {
    if (!canvas || !totpSecret) return;
    const uri = totpType === 'hotp'
      ? buildHotpUri(totpSecret, profile.email || 'user@pwdnow', hotpCounter)
      : buildTotpUri(totpSecret, profile.email || 'user@pwdnow');
    QRCode.toCanvas(canvas, uri, {
      width: 192,
      margin: 2,
      errorCorrectionLevel: 'M',
      color: { dark: '#000000', light: '#ffffff' },
    }, (err) => {
      if (err) console.error('[TOTP QR]', err);
    });
  }, [totpSecret, totpType, hotpCounter, profile.email]);

  // WebAuthn (hardware security keys)
  const [webAuthnError, setWebAuthnError]   = useState('');
  const [webAuthnBusy, setWebAuthnBusy]     = useState(false);
  const [webAuthnKeyName, setWebAuthnKeyName] = useState('My Security Key');

  // Passkey (synced, iCloud / Google)
  const [passkeyError, setPasskeyError]   = useState('');
  const [passkeyBusy, setPasskeyBusy]     = useState(false);
  const [passkeyName, setPasskeyName]     = useState('My Device');

  // Platform auth (device-bound: Touch ID, Windows Hello, Face ID)
  const [platformError, setPlatformError]   = useState('');
  const [platformBusy, setPlatformBusy]     = useState(false);
  const [platformName, setPlatformName]     = useState('This Device');

  // Email
  const [emailInput, setEmailInput]     = useState('');
  const [emailCode, setEmailCode]       = useState(['', '', '', '', '', '']);
  const [emailError, setEmailError]     = useState('');
  const [emailSimCode, setEmailSimCode] = useState(''); // shown in simulated preview
  const [emailBusy, setEmailBusy]       = useState(false);
  const emailRefs = useRef<(HTMLInputElement | null)[]>([]);

  const isEmailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailInput);

  // ── Open MFA modal ─────────────────────────────────────────────────────────
  const openMfaModal = async (type: MfaType) => {
    // Reset all per-modal state
    setTotpError('');
    setTotpCode(['', '', '', '', '', '']);
    setTotpSecretCopied(false);
    setWebAuthnError('');
    setWebAuthnBusy(false);
    setWebAuthnKeyName('My Security Key');
    setPasskeyError('');
    setPasskeyBusy(false);
    setPasskeyName('My Device');
    setPlatformError('');
    setPlatformBusy(false);
    setPlatformName('This Device');
    setEmailError('');
    setEmailCode(['', '', '', '', '', '']);
    setEmailSimCode('');
    setEmailBusy(false);

    if (type === 'totp' && !mfaConfig.totp.enabled && !mfaConfig.hotp?.enabled) {
      // New setup: show type selection first
      setTotpType('totp');
      setHotpCounter(0);
      setTotpSecret('');
      setMfaModal({ type, step: 0 });
    } else {
      setMfaModal({ type, step: 1 });
    }
  };

  const handleTotpTypeConfirm = () => {
    const secret = generateTotpSecret();
    setTotpSecret(secret);
    setMfaModal({ type: 'totp', step: 1 });
  };

  const closeMfaModal = () => {
    setMfaModal(null);
    clearPendingOtp();
  };

  // ── OTP digit-input helpers ────────────────────────────────────────────────
  const makeDigitHandlers = (
    code: string[],
    setCode: React.Dispatch<React.SetStateAction<string[]>>,
    refs: React.MutableRefObject<(HTMLInputElement | null)[]>,
    onComplete?: () => void,
  ) => ({
    onChange(index: number, value: string) {
      if (value.length > 1) value = value.slice(-1);
      if (!/^\d?$/.test(value)) return;
      const next = [...code];
      next[index] = value;
      setCode(next);
      if (value && index < code.length - 1) refs.current[index + 1]?.focus();
      if (value && index === code.length - 1 && onComplete) onComplete();
    },
    onKeyDown(index: number, e: React.KeyboardEvent<HTMLInputElement>) {
      if (e.key === 'Backspace' && !code[index] && index > 0) refs.current[index - 1]?.focus();
    },
    onPaste(e: React.ClipboardEvent) {
      e.preventDefault();
      const digits = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, code.length).split('');
      const next = [...code];
      digits.forEach((d, i) => { next[i] = d; });
      setCode(next);
      refs.current[Math.min(digits.length, code.length - 1)]?.focus();
    },
  });

  const totpHandlers  = makeDigitHandlers(totpCode,  setTotpCode,  totpRefs);
  const emailHandlers = makeDigitHandlers(emailCode, setEmailCode, emailRefs);

  // ── TOTP/HOTP: verify and save ────────────────────────────────────────────
  const handleTotpVerify = async () => {
    const token = totpCode.join('');
    const cfg = getMfaConfig();
    if (totpType === 'hotp') {
      const result = await verifyHotp(totpSecret, hotpCounter, token);
      if (!result.ok) { setTotpError('Invalid code. Make sure your app counter is in sync.'); return; }
      cfg.hotp = { enabled: true, secret: totpSecret, counter: result.nextCounter, enabledAt: Date.now() };
    } else {
      const ok = await verifyTotp(totpSecret, token, 'SHA-256', 8);
      if (!ok) { setTotpError('Invalid code. Make sure your device clock is correct.'); return; }
      cfg.totp = { enabled: true, secret: totpSecret, enabledAt: Date.now(), algorithm: 'SHA-256', digits: 8 };
    }
    saveMfaConfig(cfg);
    refreshLoginHints();
    refreshMfa();
    setMfaModal({ type: 'totp', step: 3 });
  };

  // ── TOTP/HOTP: remove ────────────────────────────────────────────────────
  const handleTotpRemove = () => {
    const cfg = getMfaConfig();
    cfg.totp = { enabled: false };
    cfg.hotp = undefined;
    saveMfaConfig(cfg);
    refreshLoginHints();
    refreshMfa();
    closeMfaModal();
  };

  // ── WebAuthn: register ────────────────────────────────────────────────────
  const handleWebAuthnRegister = async () => {
    setWebAuthnError('');
    setWebAuthnBusy(true);
    try {
      const userEmail = profile.email || 'user@pwdnow';
      await registerWebAuthn(userEmail, userEmail, profile.firstName || 'User', webAuthnKeyName.trim() || 'Security Key');
      refreshMfa();
      setMfaModal({ type: 'webauthn', step: 3 });
    } catch (err) {
      setWebAuthnError(describeWebAuthnError(err, 'securitykey'));
    } finally {
      setWebAuthnBusy(false);
    }
  };

  // ── WebAuthn: remove credential ────────────────────────────────────────────
  const handleWebAuthnRemove = (credId: string) => {
    const cfg = getMfaConfig();
    cfg.webauthn.credentials = cfg.webauthn.credentials.filter(c => c.id !== credId);
    cfg.webauthn.enabled = cfg.webauthn.credentials.length > 0;
    saveMfaConfig(cfg);
    refreshMfa();
  };

  // ── Passkey: register ─────────────────────────────────────────────────────
  const handlePasskeyRegister = async () => {
    setPasskeyError('');
    setPasskeyBusy(true);
    try {
      const userEmail = profile.email || 'user@pwdnow';
      await registerPasskey(userEmail, userEmail, profile.firstName || 'User', passkeyName.trim() || 'My Device');
      refreshMfa();
      setMfaModal({ type: 'passkey', step: 3 });
    } catch (err) {
      setPasskeyError(describeWebAuthnError(err, 'passkey'));
    } finally {
      setPasskeyBusy(false);
    }
  };

  const handlePasskeyRemove = (credId: string) => {
    const cfg = getMfaConfig();
    if (!cfg.passkey) return;
    cfg.passkey.credentials = cfg.passkey.credentials.filter(c => c.id !== credId);
    cfg.passkey.enabled = cfg.passkey.credentials.length > 0;
    saveMfaConfig(cfg);
    refreshMfa();
  };

  // ── Platform Auth (Touch ID / Windows Hello): register ────────────────────
  const handlePlatformRegister = async () => {
    setPlatformError('');
    setPlatformBusy(true);
    try {
      const userEmail = profile.email || 'user@pwdnow';
      await registerPlatformAuth(userEmail, userEmail, profile.firstName || 'User', platformName.trim() || 'This Device');
      refreshLoginHints();
      refreshMfa();
      setMfaModal({ type: 'platform', step: 3 });
    } catch (err) {
      setPlatformError(describeWebAuthnError(err, 'platform'));
    } finally {
      setPlatformBusy(false);
    }
  };

  const handlePlatformRemove = (credId: string) => {
    const cfg = getMfaConfig();
    if (!cfg.platform) return;
    cfg.platform.credentials = cfg.platform.credentials.filter(c => c.id !== credId);
    cfg.platform.enabled = cfg.platform.credentials.length > 0;
    saveMfaConfig(cfg);
    refreshLoginHints();
    refreshMfa();
  };

  const [quickUnlockEnabled, setQuickUnlockEnabled] = useState(() => hasLocalQuickUnlock());
  const [quickUnlockLoading, setQuickUnlockLoading] = useState(false);

  const handleToggleQuickUnlock = async () => {
    setQuickUnlockLoading(true);
    try {
      if (!quickUnlockEnabled) {
        const pwd = prompt('Enter your master password to enable Touch ID / Windows Hello unlock for this device:');
        if (!pwd) return;
        const dbk = await enrollQuickUnlock(profile.email || 'user');
        if (dbk) {
          await daemon.quickUnlockEnroll(pwd, dbk);
          setQuickUnlockEnabled(true);
        } else {
          alert('Touch ID / WebAuthn PRF enrollment failed or is not supported by your browser/device.');
        }
      } else {
        await daemon.quickUnlockRevoke();
        revokeLocalQuickUnlock();
        setQuickUnlockEnabled(false);
      }
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Error managing Quick Unlock');
    } finally {
      setQuickUnlockLoading(false);
    }
  };

  // ── Passwordless toggle ───────────────────────────────────────────────────
  const handlePasswordlessToggle = () => {
    const cfg = getMfaConfig();
    cfg.passwordlessEnabled = !cfg.passwordlessEnabled;
    saveMfaConfig(cfg);
    refreshLoginHints();
    refreshMfa();
  };

  // ── Password Login toggle ─────────────────────────────────────────────────
  const handlePasswordLoginToggle = () => {
    const activeMethods = countActiveMfaMethods();
    const cfg = getMfaConfig();
    const currentEnabled = cfg.passwordLoginEnabled !== false;

    // RULE: Cannot disable password login if fewer than 2 MFA methods are enabled.
    if (currentEnabled && activeMethods < 2) {
      setPolicyError('You must have at least 2 MFA methods enabled before you can disable password login.');
      return;
    }

    setPolicyError('');
    cfg.passwordLoginEnabled = !currentEnabled;
    saveMfaConfig(cfg);
    refreshLoginHints();
    refreshMfa();
  };

  // ── Email OTP: send (simulate) ─────────────────────────────────────────────
  const handleEmailSend = () => {
    setEmailBusy(true);
    const code = generateEmailCode(emailInput);
    setEmailSimCode(code); // displayed in the fake email preview
    setTimeout(() => {
      setEmailBusy(false);
      setMfaModal({ type: 'email', step: 2 });
    }, 800);
  };

  // ── Email OTP: verify ─────────────────────────────────────────────────────
  const handleEmailVerify = () => {
    const token = emailCode.join('');
    const ok = verifyEmailCode(token);
    if (!ok) { setEmailError('Incorrect code. Codes expire after 5 minutes.'); return; }
    const cfg = getMfaConfig();
    cfg.email = { enabled: true, address: emailInput, enabledAt: Date.now() };
    saveMfaConfig(cfg);
    refreshLoginHints();
    refreshMfa();
    setMfaModal({ type: 'email', step: 3 });
  };

  // ── Email OTP: remove ─────────────────────────────────────────────────────
  const handleEmailRemove = () => {
    const cfg = getMfaConfig();
    cfg.email = { enabled: false };
    saveMfaConfig(cfg);
    refreshLoginHints();
    refreshMfa();
    closeMfaModal();
  };

  const [step, setStep] = useState(1); // 1: Old Password, 2: New Password, 3: Confirmation, 4: Success
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showOldPassword, setShowOldPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [copied, setCopied] = useState(false);
  const [oldPasswordError, setOldPasswordError] = useState('');
  const [newPasswordError, setNewPasswordError] = useState('');
  const [resolvedSalt, setResolvedSalt] = useState<string | null>(null);
  const [isSavingPassword, setIsSavingPassword] = useState(false);

  // ── Import / Export ──────────────────────────────────────────────────────────
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
  const [isDecryptingKdbx, setIsDecryptingKdbx] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);

  const selectedFmt: FormatDef | undefined = getFormat(selectedFormatId);
  // Formats visible in the active export category tab (export-capable only)
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
      case 'bitwarden-enc':   triggerDownload(exportToBitwardenJSON(credentials, folders), `bitwarden_${date}.json`, 'application/json'); break;
      case '1password-csv':
      case '1password-1pif':
      case '1password-agile':
      case '1password-opvault': triggerDownload(exportTo1PasswordCSV(credentials), `1password_${date}.csv`, 'text/csv'); break;
      case 'keeper-json':     triggerDownload(exportToKeeperJSON(credentials, folders), `keeper_${date}.json`, 'application/json'); break;
      case 'keeper-csv':      triggerDownload(exportToKeeperCSV(credentials, folders), `keeper_${date}.csv`, 'text/csv'); break;
      case 'dashlane-json':
      case 'dashlane-dash':   triggerDownload(exportToDashlaneJSON(credentials), `dashlane_${date}.json`, 'application/json'); break;
      case 'nordpass-csv':    triggerDownload(exportToNordPass(credentials), `nordpass_${date}.csv`, 'text/csv'); break;
      case 'lastpass-csv':    triggerDownload(exportToLastPass(credentials), `lastpass_${date}.csv`, 'text/csv'); break;
      case 'protonpass-json': triggerDownload(exportToProtonPass(credentials, folders), `protonpass_${date}.json`, 'application/json'); break;
      case 'zoho-csv':        triggerDownload(exportToZohoCSV(credentials), `zoho_${date}.csv`, 'text/csv'); break;
      case 'passbolt-csv':    triggerDownload(exportToPassboltCSV(credentials), `passbolt_${date}.csv`, 'text/csv'); break;
      case 'padloc-json':     triggerDownload(exportToPadlocJSON(credentials, folders), `padloc_${date}.json`, 'application/json'); break;
      case 'passky-json':     triggerDownload(exportToPasskyJSON(credentials), `passky_${date}.json`, 'application/json'); break;
      case 'keepass-xml':
      case 'keepass-kdbx':    triggerDownload(exportToKeePassXML(credentials, folders), `keepass_${date}.xml`, 'text/xml'); break;
      case 'keepass-csv':
      case 'keepass-kdb':     triggerDownload(exportToKeePassCSV(credentials), `keepass_${date}.csv`, 'text/csv'); break;
      case 'roboform-csv':
      case 'roboform-rbp':    triggerDownload(exportToRoboForm(credentials, folders), `roboform_${date}.csv`, 'text/csv'); break;
      case 'enpass-csv':
      case 'enpass-enpassdb': triggerDownload(exportToEnpassCSV(credentials), `enpass_${date}.csv`, 'text/csv'); break;
      case 'buttercup-json':  triggerDownload(exportToButtercupJSON(credentials, folders), `buttercup_${date}.json`, 'application/json'); break;
      case 'passwordsafe-csv':
      case 'passwordsafe-psafe3':
      case 'passwordsafe-dat': triggerDownload(exportToKeePassCSV(credentials), `passwordsafe_${date}.csv`, 'text/csv'); break;
      case 'stickypassword-xml':
      case 'stickypassword-spdb': triggerDownload(exportToKeePassXML(credentials, folders), `stickypassword_${date}.xml`, 'text/xml'); break;
      case 'norton-csv':
      case 'norton-dat':      triggerDownload(exportTo1PasswordCSV(credentials), `norton_${date}.csv`, 'text/csv'); break;
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

  // Shared file processor - used by both file-picker and drag-and-drop
  const processImportFile = useCallback(async (file: File) => {
    setImportError('');
    try {
      const result = await importFromFile(file);
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
    e.preventDefault();
    setIsDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) processImportFile(file);
  }, [processImportFile]);

  const handleEncryptedImport = useCallback(async () => {
    if (!pendingEncryptedFile || !importPassphrase || isDecryptingKdbx) return;
    setImportPassphraseError('');
    setIsDecryptingKdbx(true);
    try {
      const result = await importFromFile(pendingEncryptedFile, importPassphrase);
      if (result.credentials.length === 0) { setImportPassphraseError(t('settings.importNoCredentials', 'No credentials found in file.')); return; }
      setPendingEncryptedFile(null); setImportPassphrase('');
      setImportResult(result); setImportFileName(pendingEncryptedFile.name);
      setImportMode('merge'); setIsImportModalOpen(true);
    } catch {
      setImportPassphraseError(t('settings.importWrongPassphrase', 'Wrong passphrase or corrupted file.'));
    } finally {
      setIsDecryptingKdbx(false);
    }
  }, [pendingEncryptedFile, importPassphrase, isDecryptingKdbx, t]);

  const handleConfirmImport = useCallback(async () => {
    if (!importResult) return;
    setIsImporting(true);
    try {
      if (importMode === 'replace') {
        for (const cred of credentials) await deleteCredential(cred.id);
      }

      const isKdbx = importResult.detectedFormat === 'keepass-kdbx';
      const kdbxFolders: import('../utils/kdbxFormat').KdbxImportResult['folders'] =
        isKdbx ? (importResult as import('../utils/kdbxFormat').KdbxImportResult).folders ?? [] : [];

      // Build a map from kdbx folder id → created folder id (may be the same if not colliding)
      const folderIdRemap = new Map<string, string>();

      if (isKdbx && kdbxFolders.length > 0) {
        for (const kf of kdbxFolders) {
          // If a folder with this label already exists, reuse it
          const existing = folders.find(f => f.label === kf.label);
          if (existing) {
            folderIdRemap.set(kf.id, existing.id);
          } else {
            const newId = await addFolder({ ...kf });
            folderIdRemap.set(kf.id, newId);
          }
        }
      }

      // Fallback folder for credentials without a group (e.g. root-level entries)
      let fallbackFolderId: string | undefined;
      const getOrCreateImportedFolder = async (): Promise<string> => {
        if (fallbackFolderId) return fallbackFolderId;
        const existing = folders.find(f => f.label === 'Imported');
        if (existing) { fallbackFolderId = existing.id; return existing.id; }
        const id = await addFolder({ id: generateUUID(), label: 'Imported', description: 'Credentials imported from an external source', iconName: 'Download' });
        fallbackFolderId = id;
        return id;
      };

      for (const cred of importResult.credentials) {
        let folderId = cred.folderId;

        if (isKdbx) {
          // Map kdbx group folder id to created folder id
          folderId = folderId ? (folderIdRemap.get(folderId) ?? await getOrCreateImportedFolder()) : await getOrCreateImportedFolder();
        } else if (importResult.detectedFormat === 'pwdnow' && folderId) {
          const match = folders.find(f => f.id === folderId || f.label === folderId);
          folderId = match?.id ?? await getOrCreateImportedFolder();
        } else {
          folderId = await getOrCreateImportedFolder();
        }

        await addCredential({ ...cred, folderId });
      }

      setIsImportModalOpen(false);
      setImportResult(null);
    } finally {
      setIsImporting(false);
    }
  }, [importResult, importMode, credentials, folders, deleteCredential, addFolder, addCredential]);

  const [sessions, setSessions] = useState<LoginSession[]>([]);

  useEffect(() => {
    getSessions().then(setSessions);
  }, []);

  const isServerMode = () => document.cookie.split(';').some(c => c.trim().startsWith('_pwd_csrf='));
  const getCsrfToken = () => document.cookie.split(';').find(c => c.trim().startsWith('_pwd_csrf='))?.split('=')[1]?.trim() ?? '';

  useEffect(() => {
    if (!isAuditLogOpen || auditTab !== 'events' || !isServerMode()) return;
    setAuditEventsLoading(true);
    fetch('/api/audit/events?limit=50', { credentials: 'include' })
      .then(r => r.json())
      .then(d => { if (d.ok) { setAuditEvents(d.events); setAuditEventsTotal(d.total); } })
      .catch(() => {})
      .finally(() => setAuditEventsLoading(false));
  }, [isAuditLogOpen, auditTab]);

  useEffect(() => {
    if (!isSharesOpen || !isServerMode()) return;
    setSharesLoading(true);
    fetch('/api/vault/shares', { credentials: 'include' })
      .then(r => r.json())
      .then(d => { if (d.ok) setShares(d.shares); })
      .catch(() => {})
      .finally(() => setSharesLoading(false));
  }, [isSharesOpen]);

  async function revokeShare(shareId: string) {
    await fetch(`/api/vault/shares/${shareId}`, { method: 'DELETE', credentials: 'include', headers: { 'X-CSRF-Token': getCsrfToken() } });
    setShares(prev => prev.filter(s => s.id !== shareId));
  }
  async function revokeAllShares() {
    if (!confirm(t('settings.revokeAllSharesConfirm', 'Revoke all active share links? Recipients will no longer be able to access them.'))) return;
    await Promise.all(shares.map(s => revokeShare(s.id)));
  }
  function formatExpiry(expiresAt: number) {
    const diff = expiresAt - Date.now();
    if (diff <= 0) return t('settings.shareExpired', 'Expired');
    const h = Math.floor(diff / 3600000);
    if (h < 24) return `${h}h remaining`;
    return `${Math.floor(h / 24)}d remaining`;
  }

  function classifyIp(ip: string): { isLoopback: boolean; isPrivate: boolean; label: string } {
    if (!ip || /^(127\.|::1$|::ffff:127\.)/.test(ip) || ip === 'Local')
      return { isLoopback: true, isPrivate: false, label: '' };
    if (/^10\./.test(ip))
      return { isLoopback: false, isPrivate: true, label: 'Internal · Block A' };
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip))
      return { isLoopback: false, isPrivate: true, label: 'Internal · Block B' };
    if (/^192\.168\./.test(ip))
      return { isLoopback: false, isPrivate: true, label: 'Internal · Block C' };
    if (/^(fc|fd)[0-9a-f]{2}:/i.test(ip))
      return { isLoopback: false, isPrivate: true, label: 'IPv6 Local (ULA)' };
    return { isLoopback: false, isPrivate: false, label: '' };
  }

  function getAuditActionLabel(action: string) {
    const map: Record<string, string> = {
      login: 'Login', login_failed: 'Login Failed', logout: 'Logout',
      credential_created: 'Credential Added', credential_updated: 'Credential Updated',
      credential_deleted: 'Credential Deleted', share_created: 'Share Created',
      share_revoked: 'Share Revoked', password_changed: 'Password Changed',
      mfa_changed: 'MFA Changed',
    };
    return map[action] ?? action;
  }
  function getAuditActionIcon(action: string) {
    if (action === 'logout') return <LogOut size={15} className="text-neutral-400" />;
    if (action.startsWith('share')) return <Share2 size={15} className="text-purple-500" />;
    if (action === 'password_changed') return <RefreshCw size={15} className="text-orange-500" />;
    if (action === 'mfa_changed') return <Smartphone size={15} className="text-indigo-500" />;
    if (action.startsWith('credential')) return <Key size={15} className="text-green-500" />;
    return <Key size={15} className="text-blue-500" />;
  }
  function getRiskBadgeClass(flag: string) {
    if (['tor', 'abuser', 'attacker'].includes(flag)) return 'bg-red-500/15 text-red-500';
    if (['proxy', 'relay'].includes(flag)) return 'bg-orange-500/15 text-orange-500';
    if (flag === 'vpn') return 'bg-yellow-500/15 text-yellow-600';
    return 'bg-neutral-500/15 text-neutral-500';
  }

  const [sessionLockTimeout, setSessionLockTimeout] = useState<string>(
    () => localStorage.getItem('session_lock_timeout') ?? '300000'
  );

  const handleSessionLockChange = (value: string) => {
    setSessionLockTimeout(value);
    localStorage.setItem('session_lock_timeout', value);
    window.dispatchEvent(new CustomEvent('sessionLockChanged'));
  };

  // ── Security Modes ─────────────────────────────────────────────────────────
  const [duressConfig, setDuressConfig] = useState<DuressModeConfig>(getDuressModeConfig);
  const [travelConfig, setTravelConfig] = useState<TravelModeConfig>(getTravelModeConfig);

  // Hydrate Travel Mode config asynchronously on mount. The sync getter reads
  // the plaintext sentinel, which is correct for new state. The async getter
  // additionally migrates legacy encrypted-only configs written by earlier
  // builds (whose v2-bound ciphertext is now undecryptable post-logout).
  useEffect(() => {
    let cancelled = false;
    getTravelModeConfigAsync().then(cfg => {
      if (!cancelled) setTravelConfig(cfg);
    }).catch(() => {});
    return () => { cancelled = true; };
  }, []);

  // Hydrate Duress Mode config asynchronously on mount. The sync getter reads
  // the plaintext sentinel (armed + maxAttempts), but in server-session mode
  // the authoritative copy lives on the server (so the config survives logout
  // / clear-site-data / new-device login). The async getter pulls from the
  // server mirror and refreshes the local cache.
  useEffect(() => {
    let cancelled = false;
    getDuressModeConfigFull().then(cfg => {
      if (cancelled) return;
      setDuressConfig(cfg);
      if (cfg.armed) setDuressMaxAttempts(cfg.maxAttempts);
    }).catch(() => {});
    return () => { cancelled = true; };
  }, []);

  // Duress mode modal
  const [isDuressModalOpen, setIsDuressModalOpen] = useState(false);
  const [duressStep, setDuressStep] = useState<1 | 2 | 3>(1);
  const [duressPassword, setDuressPassword] = useState('');
  const [confirmDuressPassword, setConfirmDuressPassword] = useState('');
  const [duressMaxAttempts, setDuressMaxAttempts] = useState<number>(duressConfig.armed ? duressConfig.maxAttempts : 5);
  const [showDuressPassword, setShowDuressPassword] = useState(false);
  const [duressError, setDuressError] = useState('');
  const [isArmingDuress, setIsArmingDuress] = useState(false);
  const [isDuressWipeOpen, setIsDuressWipeOpen] = useState(false);
  const [isWiping, setIsWiping] = useState(false);

  const handleArmDuress = async () => {
    if (duressPassword.length < 8) { setDuressError(t('settings.duressPasswordMinError', 'Duress password must be at least 8 characters.')); return; }
    if (duressPassword !== confirmDuressPassword) { setDuressError(t('settings.duressPasswordMismatch', 'Passwords do not match.')); return; }
    setIsArmingDuress(true);
    try {
      await armDuressMode(duressPassword, duressMaxAttempts);
    } catch (e) {
      // Server-side sync failed. The local sentinel is in place but the
      // server does not know duress is armed, so a cache clear would let
      // an attacker bypass the wipe. Tell the user; they can retry.
      setIsArmingDuress(false);
      setDuressError(
        t('settings.duressServerSyncFailed',
          'Could not save the duress setting on the server. Duress is armed locally, but the wipe will NOT survive clearing browser data. Please try again.')
        + ` (${e instanceof Error ? e.message : String(e)})`
      );
      return;
    }
    // Read back via the async getter so the UI reflects the server-mirrored
    // state (and so maxAttempts is sourced from the persisted config rather
    // than the sentinel's hardcoded fallback).
    setDuressConfig(await getDuressModeConfigFull());
    setIsArmingDuress(false);
    setDuressStep(3);
  };

  const handleDisarmDuress = async () => {
    await disarmDuressMode();
    setDuressConfig(getDuressModeConfig());
    setIsDuressModalOpen(false);
  };

  const handleTriggerWipe = async () => {
    setIsWiping(true);
    await wipeVaultData(daemon.isConnected ? daemon : undefined);
    window.location.replace('/login');
  };

  // Travel mode modal
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

  const toggleTravelFolder = (id: string) => {
    setTravelHiddenFolderIds(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  };

  const handleEnableTravel = async () => {
    if (travelHiddenFolderIds.length === 0) { setTravelError('Select at least one folder to hide.'); return; }
    if (travelPassword.length < 8) { setTravelError('Travel password must be at least 8 characters.'); return; }
    if (travelPassword !== confirmTravelPassword) { setTravelError('Passwords do not match.'); return; }
    setIsEnablingTravel(true);
    const { visibleCredentials, visibleFolders } = await enableTravelMode(travelPassword, travelHiddenFolderIds, credentials, folders);
    
    // Persist subsets to server (moves hidden data to local encrypted blob only)
    await persistFolders(visibleFolders as any[]);
    await persistCredentials(visibleCredentials as any[]);

    setTravelConfig(getTravelModeConfig());
    await reloadLocal();
    setIsEnablingTravel(false);
    setTravelStep(4);
  };

  const handleDisableTravel = async () => {
    setIsDisablingTravel(true);
    const result = await disableTravelMode(disableTravelPw, credentials, folders);
    if (!result.ok) {
      setDisableTravelError('Incorrect password.');
      setIsDisablingTravel(false);
      return;
    }

    // Persist merged set back to server
    await persistFolders(result.folders as any[]);
    await persistCredentials(result.credentials as any[]);

    setTravelConfig(getTravelModeConfig());
    await reloadLocal();
    setIsDisablingTravel(false);
    setIsDisableTravelOpen(false);
  };

  // ── Email Server ───────────────────────────────────────────────────────────
  type SmtpProtocol = 'smtp' | 'esmtp' | 'starttls' | 'ssl_tls';

  interface EmailServerConfig {
    protocol: SmtpProtocol;
    host: string;
    port: number;
    username: string;
    password: string;
    fromName: string;
    fromAddress: string;
  }

  const DEFAULT_EMAIL_CONFIG: EmailServerConfig = {
    protocol: 'starttls', host: '', port: 587,
    username: '', password: '', fromName: 'PWDnow', fromAddress: '',
  };

  const PROTOCOL_PORTS: Record<SmtpProtocol, number> = {
    smtp: 25, esmtp: 587, starttls: 587, ssl_tls: 465,
  };

  const [isEmailServerModalOpen, setIsEmailServerModalOpen] = useState(false);
  const [emailServerConfig, setEmailServerConfig] = useState<EmailServerConfig | null>(null);
  const [emailServerForm, setEmailServerForm] = useState<EmailServerConfig>({ ...DEFAULT_EMAIL_CONFIG });
  const [emailTestResult, setEmailTestResult] = useState<'idle' | 'testing' | 'success' | 'failure'>('idle');
  const [isSavingEmailServer, setIsSavingEmailServer] = useState(false);
  const [showSmtpPassword, setShowSmtpPassword] = useState(false);

  useEffect(() => {
    readDecryptedLocal('email_server_config').then(s => {
      if (!s) return;
      try {
        const cfg = JSON.parse(s) as EmailServerConfig;
        setEmailServerConfig(cfg);
        setEmailServerForm(cfg);
      } catch { /* ignore corrupt data */ }
    }).catch(() => {});
  }, []);

  const handleEmailProtocolChange = (protocol: SmtpProtocol) => {
    setEmailServerForm(prev => ({ ...prev, protocol, port: PROTOCOL_PORTS[protocol] }));
    setEmailTestResult('idle');
  };

  const handleTestConnection = async () => {
    if (!emailServerForm.host || !emailServerForm.username) return;
    setEmailTestResult('testing');
    await new Promise(r => setTimeout(r, 1500));
    const valid = /\.[a-z]{2,}$/i.test(emailServerForm.host);
    setEmailTestResult(valid ? 'success' : 'failure');
  };

  const handleSaveEmailServer = async () => {
    setIsSavingEmailServer(true);
    await new Promise(r => setTimeout(r, 600));
    await writeEncryptedLocal('email_server_config', JSON.stringify(emailServerForm));
    setEmailServerConfig({ ...emailServerForm });
    setIsSavingEmailServer(false);
    setIsEmailServerModalOpen(false);
  };

  // Profile State
  const [isCountryDropdownOpen, setIsCountryDropdownOpen] = useState(false);
  const [countrySearch, setCountrySearch] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsCountryDropdownOpen(false);
        setCountrySearch('');
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handlePhotoUpload = (file: File) => {
    if (file && (file.type === 'image/jpeg' || file.type === 'image/png' || file.type === 'image/jpg' || file.type === 'image/heic')) {
      // CSP (`img-src 'self' blob:`, MED-09) forbids data: URLs. Use an object
      // URL — same end result for the <img> preview, no CSP violation, and the
      // bytes never have to be base64-roundtripped through memory.
      const blobUrl = URL.createObjectURL(file);
      setLocalProfile(prev => {
        if (prev.photoUrl && prev.photoUrl.startsWith('blob:')) URL.revokeObjectURL(prev.photoUrl);
        return { ...prev, photoUrl: blobUrl };
      });
    }
  };

  const onDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const onDragLeave = () => {
    setIsDragging(false);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handlePhotoUpload(file);
  };

  const generatePassword = useCallback(() => {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=';
    const rng = new Uint8Array(24);
    crypto.getRandomValues(rng);
    let generated = '';
    for (let i = 0; i < 24; i++) {
      generated += charset.charAt(rng[i] % charset.length);
    }
    setNewPassword(generated);
    setConfirmPassword(generated);
  }, []);

  const getStrength = (pwd: string) => {
    if (!pwd) {
      return { level: 0, label: t('vault.strength.none', 'None'), color: 'text-on-surface-variant', bg: 'bg-surface-container-low', border: 'border-outline-variant/10', dot: 'bg-outline-variant', bar: 'bg-transparent', width: '0%' };
    }
    const len = pwd.length;
    const hasUpper = /[A-Z]/.test(pwd);
    const hasLower = /[a-z]/.test(pwd);
    const hasNumber = /[0-9]/.test(pwd);
    const specialChars = pwd.match(/[^A-Za-z0-9]/g) || [];
    const hasSpecial = specialChars.length > 0;

    // Special rule: > 25 chars and > 4 special chars = Strong even without uppercase
    if (len > 25 && specialChars.length > 4) {
      if (hasUpper && hasLower && hasNumber) {
        return { level: 5, label: t('vault.strength.excellent', 'Excellent'), color: 'text-green-700', bg: 'bg-green-50', border: 'border-green-100', dot: 'bg-green-600', bar: 'bg-green-500', width: '100%' };
      }
      return { level: 3, label: t('vault.strength.strong', 'Strong'), color: 'text-blue-700', bg: 'bg-blue-50', border: 'border-blue-100', dot: 'bg-blue-600', bar: 'bg-blue-500', width: '70%' };
    }

    if (len >= 16 && hasUpper && hasLower && hasNumber && hasSpecial) {
      return { level: 5, label: t('vault.strength.excellent', 'Excellent'), color: 'text-green-700', bg: 'bg-green-50', border: 'border-green-100', dot: 'bg-green-600', bar: 'bg-green-500', width: '100%' };
    }
    if (len >= 12 && hasUpper && hasLower && hasNumber && hasSpecial) {
      return { level: 4, label: t('vault.strength.veryStrong', 'Very Strong'), color: 'text-green-600', bg: 'bg-green-50', border: 'border-green-100', dot: 'bg-green-500', bar: 'bg-green-400', width: '85%' };
    }
    if (len >= 8 && hasUpper && hasLower && hasNumber) {
      return { level: 3, label: t('vault.strength.strong', 'Strong'), color: 'text-blue-700', bg: 'bg-blue-50', border: 'border-blue-100', dot: 'bg-blue-600', bar: 'bg-blue-500', width: '70%' };
    }
    if (len >= 6) {
      return { level: 2, label: t('vault.strength.medium', 'Medium'), color: 'text-orange-700', bg: 'bg-orange-50', border: 'border-orange-100', dot: 'bg-orange-600', bar: 'bg-orange-500', width: '50%' };
    }
    return { level: 1, label: t('vault.strength.weak', 'Weak'), color: 'text-red-700', bg: 'bg-red-50', border: 'border-red-100', dot: 'bg-red-600', bar: 'bg-red-500', width: '30%' };
  };

  const strength = getStrength(newPassword);
  const isStrongEnough = strength.level >= 3 && newPassword.length >= 12;
  const passwordsMatch = newPassword === confirmPassword && newPassword.length > 0;

  const handleCopy = () => {
    navigator.clipboard.writeText(newPassword);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleOpenModal = () => {
    setIsChangeModalOpen(true);
    setStep(1);
    setOldPassword('');
    setNewPassword('');
    setConfirmPassword('');
    setOldPasswordError('');
    setNewPasswordError('');
    setResolvedSalt(null);
  };

  const handleNextStep = async () => {
    if (step === 1 && oldPassword.length > 0) {
      setOldPasswordError('');
      const csrfToken = document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('_pwd_csrf='))?.split('=')[1] ?? '';
      const hasRestSession = !!csrfToken;
      setIsSavingPassword(true);
      try {
        let restSuccess = false;
        let restError = false;

        if (hasRestSession) {
          const res = await fetch('/api/auth/verify-password', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
            body: JSON.stringify({ password: oldPassword })
          });
          
          if (res.status !== 404) {
            restSuccess = true;
            const data = await res.json().catch(() => ({ ok: false }));
            if (!res.ok || !data.ok) {
              restError = true;
            }
          }
        }
        
        if (restError) {
          setOldPasswordError(t('settings.wrongOldPassword', 'Incorrect password. Please try again.'));
          return;
        }

        if (!restSuccess && daemon.isConnected) {
          const valid = await daemon.verifyPassword(oldPassword);
          if (!valid) {
            setOldPasswordError(t('settings.wrongOldPassword', 'Incorrect password. Please try again.'));
            return;
          }
        } else if (!restSuccess && !daemon.isConnected) {
          setOldPasswordError(t('settings.networkError', 'Offline mode not supported for password change.'));
          return;
        }
      } catch {
        setOldPasswordError(t('settings.networkError', 'Network error. Please try again.'));
        return;
      } finally {
        setIsSavingPassword(false);
      }
      setStep(2);
      generatePassword();
    } else if (step === 2 && isStrongEnough && passwordsMatch) {
      if (newPassword === oldPassword) {
        setNewPasswordError(t('settings.samePasswordError', 'New password must be different from your current password.'));
        return;
      }
      setNewPasswordError('');
      setStep(3);
    }
  };

  const handleConfirmUpdate = async () => {
    setIsSavingPassword(true);
    try {
      // 1. Update master password in daemon (if connected)
      if (daemon.isConnected) {
        try {
          await daemon.changePassword(oldPassword, newPassword);
        } catch {
          setOldPasswordError(t('settings.wrongOldPassword', 'Incorrect password. Please try again.'));
          setStep(1);
          return;
        }
      }

      // 2. Update master password in REST auth store (only when a server session exists;
      //    daemon-authenticated users without a REST session skip this step)
      const csrfToken = document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('_pwd_csrf='))?.split('=')[1] ?? '';
      const hasRestSession = !!csrfToken;

      if (hasRestSession) {
        const res = await fetch('/api/auth/password', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
          body: JSON.stringify({ oldPassword, newPassword })
        });

        if (!res.ok && res.status !== 404) {
          const data = await res.json().catch(() => ({}));
          const code = (data as any).error || '';
          const msg =
            code === 'invalid_credentials' ? t('settings.wrongOldPassword', 'Incorrect password. Please try again.') :
            code === 'weak_password'        ? t('settings.weakPasswordError', 'New password must be at least 12 characters.') :
            code === 'unauthenticated'      ? t('settings.sessionExpired', 'Session expired. Please log in again.') :
            t('settings.passwordUpdateFailed', 'Failed to update password. Please try again.');
          setOldPasswordError(msg);
          setStep(1);
          return;
        }
      }

      setStep(4);
      await reloadProfile();
    } catch (err: any) {
      setOldPasswordError(t('settings.networkError', 'Network error. Please try again.'));
      setStep(1);
    } finally {
      setIsSavingPassword(false);
    }
  };

  const handleRegenerateKit = () => {
    const key = generateRecoveryKey();
    setRecoveryKey(key);
    setIsRecoveryModalOpen(true);
  };

  const saveRecoveryKey = async () => {
    setIsGeneratingRecovery(true);
    try {
      const csrfToken = document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('_pwd_csrf='))?.split('=')[1] ?? '';
      const res = await fetch('/api/auth/recovery-key', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ recoveryKey })
      });
      if (!res.ok) throw new Error('failed');
      
      const content = `PWDnow Recovery Kit\n\nGenerated: ${new Date().toLocaleString()}\nRecovery Key: ${recoveryKey}\n\nKEEP THIS KEY SECURE. It can be used to access your account if you forget your master password.`;
      triggerDownload(content, `pwdnow-recovery-kit-${new Date().toISOString().slice(0,10)}.txt`, 'text/plain');
      await reloadProfile();
      setIsRecoveryModalOpen(false);
    } catch (err) {
      console.error(err);
    } finally {
      setIsGeneratingRecovery(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto">
      <SEO 
        title={t('settings.title', 'Settings')}
        description={t('settings.description', 'Manage your account settings, security preferences, and active sessions.')}
      />
      <div className="mb-12">
        <h1 className="text-4xl md:text-5xl font-headline font-black tracking-tighter text-black dark:text-white mb-4">{t('settings.title', 'Security Configuration')}</h1>
        <p className="text-on-surface-variant text-lg max-w-2xl leading-relaxed">
          {t('settings.subtitle', 'Fine-tune your digital bastion. Adjust encryption strength, manage authentication protocols, and oversee active sessions from a central command center.')}
        </p>
      </div>

      <div className="space-y-16">
        {/* User Profile */}
        <section>
          <div className="flex items-center gap-3 mb-8">
            <User className="text-black dark:text-white" size={24} />
            <h2 className="text-2xl font-headline font-extrabold tracking-tight">{t('settings.userProfile', 'User Profile')}</h2>
          </div>
          <div className="bg-surface-container-low p-10 rounded-xl">
            <div className="grid grid-cols-12 gap-10">
              {/* Photo Upload */}
              <div className="col-span-12 md:col-span-4 lg:col-span-3">
                <div 
                  className={`relative group aspect-square rounded-2xl overflow-hidden border-2 border-dashed transition-all ${
                    isDragging ? 'border-black bg-black/5 scale-[1.02]' : 'border-outline-variant/30 hover:border-black/50'
                  }`}
                  onDragOver={onDragOver}
                  onDragLeave={onDragLeave}
                  onDrop={onDrop}
                >
                  <UserAvatar
                    firstName={localProfile.firstName}
                    lastName={localProfile.lastName}
                    photoUrl={localProfile.photoUrl}
                    className="w-full h-full object-cover transition-transform group-hover:scale-105"
                  />
                  <div className="absolute inset-0 bg-[#000000]/40 opacity-0 group-hover:opacity-100 transition-opacity flex flex-col items-center justify-center text-white cursor-pointer" onClick={() => fileInputRef.current?.click()}>
                    <Camera size={32} className="mb-2" />
                    <span className="text-[10px] font-black uppercase tracking-widest">{t('settings.changePhoto', 'Change Photo')}</span>
                    <span className="text-[8px] opacity-70 mt-1 uppercase">{t('settings.dragAndDrop', 'Drag & Drop')}</span>
                  </div>
                  <input 
                    type="file" 
                    ref={fileInputRef} 
                    className="hidden" 
                    accept=".jpg,.jpeg,.png,.heic"
                    onChange={(e) => e.target.files?.[0] && handlePhotoUpload(e.target.files[0])}
                  />
                </div>
                <p className="text-[10px] text-on-surface-variant uppercase tracking-widest mt-4 text-center font-bold">
                  {t('settings.photoFormat', 'JPG, PNG, HEIC accepted')}
                </p>
              </div>

              {/* Profile Fields */}
              <div className="col-span-12 md:col-span-8 lg:col-span-9 grid grid-cols-1 sm:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant ml-1">
                    {t('settings.firstName', 'First Name')}
                  </label>
                  <input
                    type="text"
                    value={localProfile.firstName}
                    onChange={(e) => handleLocalProfileChange('firstName', e.target.value)}
                    className="w-full px-5 py-3.5 bg-white dark:bg-surface-container-high rounded-xl border border-on-surface-variant/50 dark:border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/10 dark:focus:ring-white/10 outline-none transition-all"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant ml-1">
                    {t('settings.lastName', 'Last Name')}
                  </label>
                  <input
                    type="text"
                    value={localProfile.lastName}
                    onChange={(e) => handleLocalProfileChange('lastName', e.target.value)}
                    className="w-full px-5 py-3.5 bg-white dark:bg-surface-container-high rounded-xl border border-on-surface-variant/50 dark:border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/10 dark:focus:ring-white/10 outline-none transition-all"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant ml-1">
                    {t('settings.company', 'Company Name (Optional)')}
                  </label>
                  <input
                    type="text"
                    value={localProfile.company}
                    onChange={(e) => handleLocalProfileChange('company', e.target.value)}
                    placeholder={t('settings.companyPlaceholder', 'Enter company name...')}
                    className="w-full px-5 py-3.5 bg-white dark:bg-surface-container-high rounded-xl border border-on-surface-variant/50 dark:border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/10 dark:focus:ring-white/10 outline-none transition-all"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant ml-1">
                    {t('settings.country', 'Country')}
                  </label>
                  <div className="relative" ref={dropdownRef}>
                    <button
                      onClick={() => setIsCountryDropdownOpen(!isCountryDropdownOpen)}
                      className="w-full px-5 py-3.5 bg-white dark:bg-surface-container-high rounded-xl border border-on-surface-variant/50 dark:border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/10 dark:focus:ring-white/10 outline-none transition-all flex items-center justify-between"
                    >
                      <span>{localProfile.country}</span>
                      <ChevronDown size={18} className={`transition-transform duration-300 ${isCountryDropdownOpen ? 'rotate-180' : ''}`} />
                    </button>
                    <AnimatePresence>
                      {isCountryDropdownOpen && (
                        <motion.div
                          initial={{ opacity: 0, y: -10, scale: 0.95 }}
                          animate={{ opacity: 1, y: 0, scale: 1 }}
                          exit={{ opacity: 0, y: -10, scale: 0.95 }}
                          className="absolute top-full left-0 right-0 mt-2 bg-white dark:bg-surface-container-low rounded-xl shadow-2xl border border-outline-variant/10 overflow-hidden z-50"
                        >
                          <div className="px-3 py-2 border-b border-outline-variant/10 sticky top-0 bg-white dark:bg-surface-container-low">
                            <input
                              autoFocus
                              type="text"
                              value={countrySearch}
                              onChange={e => setCountrySearch(e.target.value)}
                              placeholder="Search countries..."
                              className="w-full px-3 py-1.5 text-sm bg-surface dark:bg-surface-container-high rounded-lg border border-on-surface-variant/50 dark:border-outline-variant/10 outline-none"
                            />
                          </div>
                          <div className="max-h-52 overflow-y-auto custom-scrollbar">
                            {COUNTRY_LIST.entities
                              .filter(c => c.toLowerCase().includes(countrySearch.toLowerCase()))
                              .map((country) => (
                                <button
                                  key={country}
                                  onClick={() => {
                                    handleLocalProfileChange('country', country);
                                    setIsCountryDropdownOpen(false);
                                    setCountrySearch('');
                                  }}
                                  className={`w-full text-left px-5 py-3 text-sm font-bold hover:bg-surface-container-low transition-colors ${localProfile.country === country ? 'bg-black text-white' : 'text-black dark:text-white'}`}
                                >
                                  {country}
                                </button>
                              ))}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                </div>
              </div>
            </div>

            <AnimatePresence>
              {hasChanges && (
                <motion.div 
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 20 }}
                  className="mt-10 pt-10 border-t border-outline-variant/10 flex items-center justify-end gap-4"
                >
                  <button 
                    onClick={() => setLocalProfile(profile)}
                    className="px-6 py-3 text-sm font-bold text-on-surface-variant hover:text-black transition-colors"
                  >
                    {t('common.cancel', 'Cancel')}
                  </button>
                  <button 
                    onClick={handleSaveProfile}
                    disabled={isSaving}
                    className="px-10 py-3 bg-black text-white rounded-xl text-sm font-black uppercase tracking-widest hover:bg-black/90 transition-all flex items-center gap-2 shadow-lg shadow-black/10 disabled:opacity-50"
                  >
                    {isSaving ? (
                      <RefreshCw size={16} className="animate-spin" />
                    ) : (
                      <Check size={16} />
                    )}
                    {t('common.save', 'Save Changes')}
                  </button>
                </motion.div>
              )}
            </AnimatePresence>

            <AnimatePresence>
              {showSaveSuccess && (
                <motion.div 
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.9 }}
                  className="mt-6 p-4 bg-green-50 border border-green-100 rounded-xl flex items-center gap-3 text-green-700"
                >
                  <CheckCircle size={18} />
                  <span className="text-sm font-bold">{t('settings.profileSuccessDesc', 'User profile successfully updated')}</span>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </section>

        {/* Appearance */}
        <section>
          <div className="flex items-center gap-3 mb-8">
            <Monitor className="text-black dark:text-white" size={24} />
            <h2 className="text-2xl font-headline font-extrabold tracking-tight">{t('settings.appearance', 'Appearance')}</h2>
          </div>
          <div className="bg-surface-container-low p-10 rounded-xl">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h3 className="font-bold text-xl mb-2">{t('settings.theme', 'Theme Preference')}</h3>
                <p className="text-on-surface-variant text-sm max-w-md">
                  {t('settings.themeDesc', 'Choose how PWDnow looks to you. Select a theme or sync with your system.')}
                </p>
              </div>
            </div>
            
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <button
                onClick={() => setTheme('light')}
                className={`p-6 rounded-xl border-2 transition-all flex flex-col items-center gap-4 ${theme === 'light' ? 'border-black dark:border-white bg-white dark:bg-white/10 shadow-lg' : 'border-outline-variant/20 bg-surface hover:border-outline-variant/50'}`}
              >
                <div className={`w-12 h-12 rounded-full flex items-center justify-center ${theme === 'light' ? 'bg-amber-100 dark:bg-amber-900/40' : 'bg-surface-container-low'}`}>
                  <Sun size={24} className={theme === 'light' ? 'text-amber-500' : 'text-on-surface-variant'} />
                </div>
                <span className={`font-bold ${theme === 'light' ? 'text-black dark:text-white' : 'text-on-surface-variant'}`}>{t('settings.themeLight', 'Light')}</span>
              </button>

              <button
                onClick={() => setTheme('dark')}
                className={`p-6 rounded-xl border-2 transition-all flex flex-col items-center gap-4 ${theme === 'dark' ? 'border-black dark:border-white bg-white dark:bg-white/10 shadow-lg' : 'border-outline-variant/20 bg-surface hover:border-outline-variant/50'}`}
              >
                <div className={`w-12 h-12 rounded-full flex items-center justify-center ${theme === 'dark' ? 'bg-indigo-100 dark:bg-indigo-900/40' : 'bg-surface-container-low'}`}>
                  <Moon size={24} className={theme === 'dark' ? 'text-indigo-500' : 'text-on-surface-variant'} />
                </div>
                <span className={`font-bold ${theme === 'dark' ? 'text-black dark:text-white' : 'text-on-surface-variant'}`}>{t('settings.themeDark', 'Dark')}</span>
              </button>

              <button
                onClick={() => setTheme('system')}
                className={`p-6 rounded-xl border-2 transition-all flex flex-col items-center gap-4 ${theme === 'system' ? 'border-black dark:border-white bg-white dark:bg-white/10 shadow-lg' : 'border-outline-variant/20 bg-surface hover:border-outline-variant/50'}`}
              >
                <div className={`w-12 h-12 rounded-full flex items-center justify-center ${theme === 'system' ? 'bg-teal-100 dark:bg-teal-900/40' : 'bg-surface-container-low'}`}>
                  <Monitor size={24} className={theme === 'system' ? 'text-teal-500' : 'text-on-surface-variant'} />
                </div>
                <span className={`font-bold ${theme === 'system' ? 'text-black dark:text-white' : 'text-on-surface-variant'}`}>{t('settings.themeSystem', 'System')}</span>
              </button>
            </div>
          </div>
        </section>

        {/* Account Security */}
        <section>
          <div className="flex items-center gap-3 mb-8">
            <User className="text-black dark:text-white" size={24} />
            <h2 className="text-2xl font-headline font-extrabold tracking-tight">{t('settings.accountSecurity', 'Account Security')}</h2>
          </div>
          <div className="grid grid-cols-12 gap-8">
            <div className="col-span-12 lg:col-span-5 bg-surface-container-low p-10 rounded-xl flex flex-col justify-between">
              <div>
                <h3 className="font-bold text-xl mb-3">{t('settings.accountPassword', 'Account Password')}</h3>
                <p className="text-sm text-on-surface-variant mb-8 leading-relaxed">
                  {t('settings.accountPasswordDesc', 'The primary key to your entire vault. Changing this will re-encrypt all stored data using the new key derivation function.')}
                </p>
              </div>
              <div className="flex items-center gap-6">
                <button 
                  onClick={handleOpenModal}
                  className="bg-black text-white px-8 py-4 rounded-md font-bold text-sm hover:opacity-90 transition-all flex items-center gap-3 shadow-lg"
                  aria-label={t('settings.changeAccountPassword', 'Change Account Password')}
                >
                  <Edit3 size={18} aria-hidden="true" />
                  {t('settings.changeAccountPassword', 'Change Account Password')}
                </button>
                <span className="text-[10px] uppercase tracking-[0.2em] text-on-surface-variant font-black">
                  {profile.passwordChangedAt ? (() => {
                    const days = Math.floor((Date.now() - profile.passwordChangedAt!) / (1000 * 60 * 60 * 24));
                    return days === 0
                      ? t('settings.changedToday', 'Changed today')
                      : t('settings.lastChanged', `Last changed ${days} day(s) ago`, { days });
                  })() : t('settings.neverChanged', 'Never changed')}
                </span>              </div>
            </div>

            <div className="col-span-12 lg:col-span-7 grid grid-cols-2 gap-8">
              <div
                className="bg-surface-container-high p-8 rounded-xl group hover:bg-surface-container-highest transition-colors cursor-pointer"
                role="button"
                tabIndex={0}
                aria-label={t('settings.auditLog', 'Security Audit Log')}
                onClick={() => setIsAuditLogOpen(true)}
              >
                <History className="text-black dark:text-white mb-6" size={32} aria-hidden="true" />
                <h4 className="font-bold text-lg mb-2">{t('settings.auditLog', 'Security Audit Log')}</h4>
                <p className="text-xs text-on-surface-variant mb-6 leading-relaxed">{t('settings.auditLogDesc', 'View every access attempt and configuration change.')}</p>
                <span className="text-xs font-black uppercase tracking-widest text-black dark:text-white hover:underline">{t('settings.viewConnections', 'View Connections')}</span>
              </div>
              <div 
                className="bg-surface-container-high p-8 rounded-xl group hover:bg-surface-container-highest transition-colors cursor-pointer"
                role="button"
                tabIndex={0}
                aria-label={t('settings.recoveryKit', 'Recovery Kit')}
              >
                <ShieldAlert className="text-black dark:text-white mb-6" size={32} aria-hidden="true" />
                <h4 className="font-bold text-lg mb-2">{t('settings.recoveryKit', 'Recovery Kit')}</h4>
                <p className="text-xs text-on-surface-variant mb-4 leading-relaxed">{t('settings.recoveryKitDesc', 'Essential for account recovery if master password is lost.')}</p>
                {profile.recoveryKeyGeneratedAt && (
                  <p className="text-[10px] text-green-600 dark:text-green-400 font-bold uppercase tracking-widest mb-4">
                    Last Generated: {new Date(profile.recoveryKeyGeneratedAt).toLocaleDateString()}
                  </p>
                )}
                <button 
                  onClick={handleRegenerateKit}
                  className="text-xs font-black uppercase tracking-widest text-black dark:text-white hover:underline" 
                  aria-label={t('settings.regenerateKit', 'Regenerate Kit')}
                >
                  {t('settings.regenerateKit', 'Regenerate Kit')}
                </button>
              </div>
              <div className="col-span-2 bg-primary-container p-8 rounded-xl flex items-center justify-between text-white overflow-hidden relative">
                <div className="flex items-center gap-6 relative z-10">
                  <div className="w-14 h-14 rounded-full bg-on-primary-container flex items-center justify-center">
                    <ShieldAlert size={28} className="text-black dark:text-white" aria-hidden="true" />
                  </div>
                  <div>
                    <h4 className="font-bold text-xl">{t('settings.emergencyAccess', 'Emergency Access')}</h4>
                    <p className="text-sm opacity-70">{t('settings.emergencyAccessDesc', 'Designate trusted contacts to access your vault in emergencies.')}</p>
                  </div>
                </div>
                <button
                  onClick={() => setIsEmergencyModalOpen(true)}
                  className="px-8 py-3 border border-white/20 rounded-md text-sm font-bold hover:bg-white/10 transition-all relative z-10"
                  aria-label={t('settings.configure', 'Configure')}
                >
                  {t('settings.configure', 'Configure')}
                </button>
                <div className="absolute right-0 top-0 w-64 h-64 bg-on-primary-container blur-[40px] opacity-40" aria-hidden="true"></div>
              </div>

              {/* Active Share Links card */}
              {isServerMode() && (
                <div
                  className="bg-surface-container-high p-8 rounded-xl group hover:bg-surface-container-highest transition-colors cursor-pointer"
                  role="button" tabIndex={0}
                  onClick={() => setIsSharesOpen(true)}
                  onKeyDown={e => e.key === 'Enter' && setIsSharesOpen(true)}
                  aria-label={t('settings.activeShares', 'Active Share Links')}
                >
                  <Share2 className="text-black dark:text-white mb-6" size={32} aria-hidden="true" />
                  <h4 className="font-bold text-lg mb-2">{t('settings.activeShares', 'Active Share Links')}</h4>
                  <p className="text-xs text-on-surface-variant mb-6 leading-relaxed">{t('settings.activeSharesDesc', 'View and revoke active credential share links.')}</p>
                  <span className="text-xs font-black uppercase tracking-widest text-black dark:text-white hover:underline">{t('settings.manage', 'Manage')}</span>
                </div>
              )}

            </div>
          </div>
        </section>

        {/* ── Import & Export ──────────────────────────────────────────────────── */}
        <section>
          <div className="flex items-center gap-3 mb-8">
            <Download className="text-black dark:text-white" size={24} aria-hidden="true" />
            <h2 className="text-2xl font-headline font-extrabold tracking-tight">{t('settings.importExport', 'Import & Export')}</h2>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

            {/* ── Import card ─────────────────────────────────────────────────── */}
            <div className="bg-surface-container-low rounded-2xl p-6 border border-outline-variant/20 flex flex-col gap-5">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-surface-container-high flex items-center justify-center shrink-0">
                  <Upload size={16} className="text-black dark:text-white" />
                </div>
                <div>
                  <h3 className="font-bold text-sm text-black dark:text-white">{t('settings.importVaultTitle', 'Import')}</h3>
                  <p className="text-[11px] text-on-surface-variant">{t('settings.importVaultDesc', 'Bring in credentials from any password manager')}</p>
                </div>
              </div>

              {/* Drag-and-drop zone */}
              {!pendingEncryptedFile && (
                <label
                  className={`relative flex flex-col items-center justify-center gap-3 rounded-2xl border-2 border-dashed p-10 cursor-pointer transition-all ${
                    isDragOver
                      ? 'border-black dark:border-white bg-black/5 dark:bg-white/5 scale-[0.99]'
                      : 'border-outline-variant/40 hover:border-outline-variant/70 hover:bg-surface-container-high/40'
                  }`}
                  onDragOver={e => { e.preventDefault(); setIsDragOver(true); }}
                  onDragEnter={e => { e.preventDefault(); setIsDragOver(true); }}
                  onDragLeave={() => setIsDragOver(false)}
                  onDrop={handleFileDrop}
                >
                  <input type="file" accept={Array.from(new Set(FORMATS.flatMap(f => f.importExts || []))).map(ext => `.${ext}`).join(',')} className="sr-only" onChange={handleFileSelect} />
                  <div className={`w-12 h-12 rounded-2xl flex items-center justify-center transition-colors ${isDragOver ? 'bg-black dark:bg-white' : 'bg-surface-container-high'}`}>
                    <FileUp size={22} className={isDragOver ? 'text-white dark:text-black' : 'text-on-surface-variant'} />
                  </div>
                  <div className="text-center">
                    <p className="text-sm font-bold text-black dark:text-white">
                      {isDragOver ? t('settings.dropHere', 'Drop to import') : t('settings.importDropzone', 'Drag & drop or click to browse')}
                    </p>
                    <p className="text-[11px] text-on-surface-variant mt-1">{t('settings.importAccepted', 'JSON · CSV · XML · KDBX · 1PUX auto-detected')}</p>
                  </div>
                </label>
              )}

              {/* Encrypted file passphrase prompt */}
              {pendingEncryptedFile && (() => {
                const isKdbx = pendingEncryptedFile.name.toLowerCase().endsWith('.kdbx');
                const headingText = isKdbx
                  ? t('settings.importKdbxDetected', 'KeePass database — enter your master password')
                  : t('settings.importEncryptedDetected', 'Encrypted export: enter passphrase to unlock');
                const placeholderText = isKdbx
                  ? t('settings.importKdbxPasswordPlaceholder', 'KeePass master password…')
                  : t('settings.importPassphrasePlaceholder', 'Export passphrase…');
                const buttonText = isKdbx
                  ? t('settings.importKdbxButton', 'Unlock & Import')
                  : t('settings.importDecryptButton', 'Decrypt & Import');
                return (
                  <div className="space-y-3 bg-surface-container-high/50 rounded-xl p-4 border border-outline-variant/20">
                    <div className="flex items-center gap-2">
                      <Lock size={13} className="text-black dark:text-white shrink-0" />
                      <p className="text-xs font-bold text-black dark:text-white">{headingText}</p>
                    </div>
                    <p className="text-[11px] text-on-surface-variant truncate">{pendingEncryptedFile.name}</p>
                    {isDecryptingKdbx ? (
                      <div className="flex items-center gap-2 py-2">
                        <Loader2 size={14} className="animate-spin text-on-surface-variant" />
                        <p className="text-[11px] text-on-surface-variant">
                          {t('settings.importKdbxDecrypting', 'Unlocking database… this may take 10–30 seconds')}
                        </p>
                      </div>
                    ) : (
                      <input
                        type="password"
                        value={importPassphrase}
                        onChange={e => { setImportPassphrase(e.target.value); setImportPassphraseError(''); }}
                        onKeyDown={e => e.key === 'Enter' && handleEncryptedImport()}
                        placeholder={placeholderText}
                        className="w-full bg-surface-container-highest rounded-lg px-3 py-2 text-xs text-black dark:text-white outline-none focus:ring-2 focus:ring-on-primary-container/20 border border-outline-variant/20"
                        autoFocus
                      />
                    )}
                    {importPassphraseError && <p className="text-[10px] text-error">{importPassphraseError}</p>}
                    <div className="flex gap-2">
                      <button
                        onClick={handleEncryptedImport}
                        disabled={isDecryptingKdbx}
                        className="flex-1 py-2.5 bg-black dark:bg-white text-white dark:text-black rounded-xl font-black text-xs uppercase tracking-widest hover:opacity-90 transition-all disabled:opacity-50"
                      >
                        {isDecryptingKdbx ? (
                          <span className="flex items-center justify-center gap-1.5">
                            <Loader2 size={11} className="animate-spin" />
                            {t('settings.importKdbxUnlocking', 'Unlocking…')}
                          </span>
                        ) : buttonText}
                      </button>
                      <button
                        onClick={() => { setPendingEncryptedFile(null); setImportPassphrase(''); setIsDecryptingKdbx(false); }}
                        disabled={isDecryptingKdbx}
                        className="px-4 py-2.5 rounded-xl font-black text-xs uppercase tracking-widest text-on-surface-variant hover:bg-surface-container-high transition-all disabled:opacity-50"
                      >
                        {t('common.cancel', 'Cancel')}
                      </button>
                    </div>
                  </div>
                );
              })()}

              {importError && (
                <p className="text-xs font-bold text-error flex items-center gap-1.5">
                  <AlertTriangle size={13} /> {importError}
                </p>
              )}

              <div className="mt-auto pt-4 border-t border-outline-variant/10">
                <p className="text-[10px] font-bold text-black dark:text-white mb-1.5">
                  {t('settings.importAutoDetect', 'Format is detected automatically. Supported formats:')}
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {Array.from(new Set(FORMATS.filter(f => f.canImport).map(f => f.manager))).map(manager => (
                    <span key={manager} className="text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 bg-surface-container-high text-on-surface-variant rounded-md">
                      {manager}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            {/* ── Export card ─────────────────────────────────────────────────── */}
            <div className="bg-surface-container-low rounded-2xl p-6 border border-outline-variant/20 flex flex-col gap-5">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-black dark:bg-white flex items-center justify-center shrink-0">
                  <Download size={16} className="text-white dark:text-black" />
                </div>
                <div>
                  <h3 className="font-bold text-sm text-black dark:text-white">{t('settings.exportVaultTitle', 'Export')}</h3>
                  <p className="text-[11px] text-on-surface-variant">{t('settings.exportVaultDesc', 'Download your credentials for backup or migration')}</p>
                </div>
              </div>

              {/* Category tabs */}
              <div className="flex gap-1 bg-surface-container-high rounded-xl p-1">
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
                      className={`flex-1 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${active ? 'bg-black dark:bg-white text-white dark:text-black shadow-sm' : 'text-on-surface-variant hover:text-black dark:hover:text-white'}`}
                    >
                      {gLabel.split(' ')[0]}
                    </button>
                  );
                })}
              </div>

              {/* Format buttons for current category */}
              <div className="grid grid-cols-2 gap-2">
                {categoryExportFormats.map(fmt => {
                  const active = selectedFormatId === fmt.id;
                  return (
                    <button
                      key={fmt.id}
                      onClick={() => { setSelectedFormatId(fmt.id); setExportPassphrase(''); setExportPassphraseConfirm(''); setExportPassphraseError(''); }}
                      className={`flex items-center gap-2 px-3 py-2.5 rounded-xl border-2 text-xs font-bold transition-all text-left ${
                        active
                          ? 'border-black dark:border-white bg-black dark:bg-white text-white dark:text-black'
                          : 'border-outline-variant/30 hover:border-outline-variant/60 text-on-surface-variant hover:text-black dark:hover:text-white'
                      }`}
                    >
                      {fmt.exportExt === 'json' || fmt.exportExt === '1pux' ? <FileJson size={12} /> : fmt.exportExt === 'xml' ? <FileText size={12} /> : <FileText size={12} />}
                      <span className="truncate">{fmt.label.replace(/^PWDnow /, '')}</span>
                    </button>
                  );
                })}
              </div>

              {/* Passphrase fields - only for encrypted formats */}
              {selectedFmt?.needsPassphrase && (
                <div className="space-y-2">
                  <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant flex items-center gap-1.5">
                    <Lock size={10} /> {t('settings.exportPassphraseLabel', 'Encryption passphrase')}
                  </label>
                  <input
                    type="password"
                    value={exportPassphrase}
                    onChange={e => { setExportPassphrase(e.target.value); setExportPassphraseError(''); }}
                    placeholder={t('settings.exportPassphrasePlaceholder', 'Enter a strong passphrase…')}
                    className="w-full bg-surface-container-highest rounded-lg px-3 py-2 text-xs text-black dark:text-white outline-none focus:ring-2 focus:ring-on-primary-container/20 border border-outline-variant/20"
                  />
                  <input
                    type="password"
                    value={exportPassphraseConfirm}
                    onChange={e => { setExportPassphraseConfirm(e.target.value); setExportPassphraseError(''); }}
                    placeholder={t('settings.exportPassphraseConfirmPlaceholder', 'Confirm passphrase…')}
                    className="w-full bg-surface-container-highest rounded-lg px-3 py-2 text-xs text-black dark:text-white outline-none focus:ring-2 focus:ring-on-primary-container/20 border border-outline-variant/20"
                  />
                  {exportPassphraseError && <p className="text-[10px] text-error">{exportPassphraseError}</p>}
                </div>
              )}

              {/* Export button */}
              <button
                onClick={handleExport}
                disabled={!selectedFmt?.canExport || credentials.length === 0}
                className="mt-auto w-full py-3 bg-black dark:bg-white text-white dark:text-black rounded-xl font-black uppercase tracking-widest text-xs hover:opacity-90 transition-all flex items-center justify-center gap-2 disabled:opacity-30"
              >
                <Download size={14} />
                {t('settings.exportButton', 'Export')}
                {credentials.length > 0 && <span className="opacity-60">({credentials.length})</span>}
              </button>

              {/* Contextual note */}
              <p className="text-[10px] text-on-surface-variant leading-relaxed">
                {selectedFmt?.needsPassphrase
                  ? t('settings.exportWarningEncrypted', 'AES-256-GCM · PBKDF2-SHA-256 · 600 000 iterations. Keep the passphrase - it is required to re-import.')
                  : t('settings.exportWarningCleartext', 'Credentials export in cleartext for compatibility. Delete the file after migration.')}
              </p>
            </div>

          </div>
        </section>

        {/* Authentication Protocols */}
        <section>
          <div className="flex items-center gap-3 mb-8">
            <Smartphone className="text-black dark:text-white" size={24} />
            <h2 className="text-2xl font-headline font-extrabold tracking-tight">{t('settings.authProtocols', 'Authentication Protocols')}</h2>
          </div>
          <div className="bg-surface-container-low rounded-xl p-10">
            <div className="flex items-center justify-between mb-10">
              <div>
                <h3 className="font-bold text-xl mb-2">{t('settings.mfa', 'Multi-Factor Authentication (MFA)')}</h3>
                <p className="text-sm text-on-surface-variant">{t('settings.twoFactorDesc', 'Recommended for all users to prevent unauthorized access.')}</p>
              </div>
              {countActiveMfaMethods(mfaConfig) > 0 && (
                <div className="bg-black text-white px-4 py-1.5 rounded text-[10px] font-black uppercase tracking-widest">{t('settings.statusActive', 'Status: Active')}</div>
              )}
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
              {/* TOTP */}
              {(() => {
                const active = mfaConfig.totp.enabled || (mfaConfig.hotp?.enabled ?? false);
                return (
                  <div
                    onClick={() => openMfaModal('totp')}
                    className={`p-8 rounded-xl border-2 transition-all cursor-pointer flex flex-col ${active ? 'border-black dark:border-on-primary-container bg-white dark:bg-surface-container-high shadow-lg' : 'border-outline-variant/40 bg-surface-container-high hover:border-outline-variant hover:bg-surface-container-highest'}`}
                  >
                    <div className="flex items-center justify-between mb-6">
                      <Smartphone size={32} className={active ? 'text-black dark:text-white' : 'text-on-surface-variant'} />
                      <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${active ? 'border-black bg-black dark:border-on-primary-container dark:bg-on-primary-container' : 'border-outline-variant'}`}>
                        {active && <div className="w-2 h-2 bg-white rounded-full" />}
                      </div>
                    </div>
                    <h4 className="font-bold text-lg mb-2">{t('settings.authAppTitle', 'Authenticator App')}</h4>
                    <p className="text-xs text-on-surface-variant leading-relaxed mb-4">{t('settings.authAppDesc2', 'Use apps like Authy or Google Authenticator for time-based codes.')}</p>
                    <div className="mt-auto flex items-center justify-between">
                      {active ? (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-green-700 bg-green-50 dark:bg-green-950/40 dark:text-green-400 px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-green-500" />Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-on-surface-variant bg-surface-container-highest px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-outline-variant" />Not set up
                        </span>
                      )}
                      {active && (
                        <button
                          type="button"
                          onClick={e => { e.stopPropagation(); handleTotpRemove(); }}
                          className="p-1.5 rounded-lg text-red-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20 transition-colors"
                          title="Remove authenticator app"
                        >
                          <Trash2 size={15} />
                        </button>
                      )}
                    </div>
                  </div>
                );
              })()}

              {/* WebAuthn */}
              {(() => {
                const active = mfaConfig.webauthn.enabled;
                return (
                  <div
                    onClick={() => openMfaModal('webauthn')}
                    className={`p-8 rounded-xl border-2 transition-all cursor-pointer flex flex-col ${active ? 'border-black dark:border-on-primary-container bg-white dark:bg-surface-container-high shadow-lg' : 'border-outline-variant/40 bg-surface-container-high hover:border-outline-variant hover:bg-surface-container-highest'}`}
                  >
                    <div className="flex items-center justify-between mb-6">
                      <Key size={32} className={active ? 'text-black dark:text-white' : 'text-on-surface-variant'} />
                      <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${active ? 'border-black bg-black dark:border-on-primary-container dark:bg-on-primary-container' : 'border-outline-variant'}`}>
                        {active && <div className="w-2 h-2 bg-white rounded-full" />}
                      </div>
                    </div>
                    <h4 className="font-bold text-lg mb-2">{t('settings.securityKeyTitle', 'Security Key')}</h4>
                    <p className="text-xs text-on-surface-variant leading-relaxed mb-4">{t('settings.securityKeyDesc', 'Physical YubiKey or Titan security key for hardware-level protection.')}</p>
                    <div className="mt-auto">
                      {active ? (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-green-700 bg-green-50 dark:bg-green-950/40 dark:text-green-400 px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-green-500" />{mfaConfig.webauthn.credentials.length} key{mfaConfig.webauthn.credentials.length !== 1 ? 's' : ''} registered
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-on-surface-variant bg-surface-container-highest px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-outline-variant" />Not set up
                        </span>
                      )}
                    </div>
                  </div>
                );
              })()}

              {/* Email OTP */}
              {(() => {
                const active = mfaConfig.email.enabled;
                return (
                  <div
                    onClick={() => openMfaModal('email')}
                    className={`p-8 rounded-xl border-2 transition-all cursor-pointer flex flex-col ${active ? 'border-black dark:border-on-primary-container bg-white dark:bg-surface-container-high shadow-lg' : 'border-outline-variant/40 bg-surface-container-high hover:border-outline-variant hover:bg-surface-container-highest'}`}
                  >
                    <div className="flex items-center justify-between mb-6">
                      <Mail size={32} className={active ? 'text-black dark:text-white' : 'text-on-surface-variant'} />
                      <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${active ? 'border-black bg-black dark:border-on-primary-container dark:bg-on-primary-container' : 'border-outline-variant'}`}>
                        {active && <div className="w-2 h-2 bg-white rounded-full" />}
                      </div>
                    </div>
                    <h4 className="font-bold text-lg mb-2">{t('settings.emailVerificationTitle', 'Email Verification')}</h4>
                    <p className="text-xs text-on-surface-variant leading-relaxed mb-4">{t('settings.emailVerificationDesc', 'Receive temporary codes via your registered email address.')}</p>
                    <div className="mt-auto flex items-center justify-between">
                      {active ? (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-green-700 bg-green-50 dark:bg-green-950/40 dark:text-green-400 px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-green-500" />Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-on-surface-variant bg-surface-container-highest px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-outline-variant" />Not set up
                        </span>
                      )}
                      {active && (
                        <button
                          type="button"
                          onClick={e => { e.stopPropagation(); handleEmailRemove(); }}
                          className="p-1.5 rounded-lg text-red-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20 transition-colors"
                          title="Remove email OTP"
                        >
                          <Trash2 size={15} />
                        </button>
                      )}
                    </div>
                  </div>
                );
              })()}

              {/* Passkey (synced) */}
              {(() => {
                const active = mfaConfig.passkey?.enabled ?? false;
                const count = mfaConfig.passkey?.credentials?.length ?? 0;
                const unavailable = platformAuthAvail === false;
                return (
                  <div
                    onClick={() => openMfaModal('passkey')}
                    className={`p-8 rounded-xl border-2 transition-all cursor-pointer flex flex-col ${active ? 'border-black dark:border-on-primary-container bg-white dark:bg-surface-container-high shadow-lg' : unavailable ? 'border-amber-300/60 dark:border-amber-700/40 bg-surface-container-high opacity-75' : 'border-outline-variant/40 bg-surface-container-high hover:border-outline-variant hover:bg-surface-container-highest'}`}
                  >
                    <div className="flex items-center justify-between mb-6">
                      <KeyRound size={32} className={active ? 'text-black dark:text-white' : 'text-on-surface-variant'} />
                      <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${active ? 'border-black bg-black dark:border-on-primary-container dark:bg-on-primary-container' : 'border-outline-variant'}`}>
                        {active && <div className="w-2 h-2 bg-white rounded-full" />}
                      </div>
                    </div>
                    <h4 className="font-bold text-lg mb-2">{t('settings.passkeyTitle', 'Passkey')}</h4>
                    <p className="text-xs text-on-surface-variant leading-relaxed mb-4">{t('settings.passkeyDesc', 'Synced passkey via iCloud Keychain or Google Password Manager. Works across your devices.')}</p>
                    <div className="mt-auto space-y-2">
                      {active ? (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-green-700 bg-green-50 dark:bg-green-950/40 dark:text-green-400 px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-green-500" />{t('settings.passkeyCount', '{{count}} passkey(s) registered', { count })}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-on-surface-variant bg-surface-container-highest px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-outline-variant" />{t('settings.notSetUp', 'Not set up')}
                        </span>
                      )}
                      {unavailable && (
                        <p className="text-[10px] text-amber-600 dark:text-amber-400 font-semibold flex items-center gap-1">
                          <AlertTriangle size={10} />Not available - no platform authenticator detected (VM environment)
                        </p>
                      )}
                    </div>
                  </div>
                );
              })()}

              {/* Platform Auth – Touch ID / Windows Hello / Face ID */}
              {(() => {
                const active = mfaConfig.platform?.enabled ?? false;
                const count = mfaConfig.platform?.credentials?.length ?? 0;
                const unavailable = platformAuthAvail === false;
                return (
                  <div
                    onClick={() => openMfaModal('platform')}
                    className={`p-8 rounded-xl border-2 transition-all cursor-pointer flex flex-col ${active ? 'border-black dark:border-on-primary-container bg-white dark:bg-surface-container-high shadow-lg' : unavailable ? 'border-amber-300/60 dark:border-amber-700/40 bg-surface-container-high opacity-75' : 'border-outline-variant/40 bg-surface-container-high hover:border-outline-variant hover:bg-surface-container-highest'}`}
                  >
                    <div className="flex items-center justify-between mb-6">
                      <Fingerprint size={32} className={active ? 'text-black dark:text-white' : 'text-on-surface-variant'} />
                      <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${active ? 'border-black bg-black dark:border-on-primary-container dark:bg-on-primary-container' : 'border-outline-variant'}`}>
                        {active && <div className="w-2 h-2 bg-white rounded-full" />}
                      </div>
                    </div>
                    <h4 className="font-bold text-lg mb-2">{t('settings.platformTitle', 'Touch ID / Windows Hello')}</h4>
                    <p className="text-xs text-on-surface-variant leading-relaxed mb-4">{t('settings.platformDesc', 'Device-bound biometric. Your fingerprint or face stays on this device - never synced.')}</p>
                    <div className="mt-auto space-y-2">
                      {active ? (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-green-700 bg-green-50 dark:bg-green-950/40 dark:text-green-400 px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-green-500" />{t('settings.platformCount', '{{count}} device(s) registered', { count })}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-on-surface-variant bg-surface-container-highest px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-outline-variant" />{t('settings.notSetUp', 'Not set up')}
                        </span>
                      )}
                      {unavailable && (
                        <p className="text-[10px] text-amber-600 dark:text-amber-400 font-semibold flex items-center gap-1">
                          <AlertTriangle size={10} />Not available - Touch ID / Windows Hello requires biometric hardware (not accessible in a VM)
                        </p>
                      )}
                    </div>
                  </div>
                );
              })()}
            </div>

            {/* Quick Unlock (Phase 4) */}
            <div className={`mt-8 p-6 rounded-xl border-2 flex items-center justify-between gap-6 transition-all ${quickUnlockEnabled ? 'border-black dark:border-on-primary-container bg-black/5 dark:bg-white/5' : 'border-outline-variant/30 bg-surface-container-high'}`}>
              <div className="flex gap-4 items-start">
                <div className={`mt-0.5 p-2 rounded-xl ${quickUnlockEnabled ? 'bg-blue-600 text-white' : 'bg-surface-container-highest text-on-surface-variant'}`}>
                  <Fingerprint size={24} />
                </div>
                <div>
                  <h4 className="font-bold text-base mb-1">Quick Unlock (Touch ID / Windows Hello)</h4>
                  <p className="text-sm text-on-surface-variant leading-relaxed">
                    {quickUnlockEnabled
                      ? 'Use your fingerprint or face to instantly unlock the vault on this device without typing your master password.'
                      : 'Enroll this device to quickly unlock using Windows Hello, Touch ID, or Face ID.'}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={handleToggleQuickUnlock}
                disabled={quickUnlockLoading}
                className={`shrink-0 flex items-center gap-2 px-4 py-2 rounded-lg font-bold text-sm transition-all shadow-sm active:scale-[0.98] ${
                  quickUnlockEnabled 
                    ? 'bg-black text-white hover:opacity-90 dark:bg-white dark:text-black' 
                    : 'bg-white text-black border-2 border-outline-variant hover:border-black dark:bg-[#1a1a1a] dark:text-white dark:border-white/20 dark:hover:border-white'
                }`}
              >
                {quickUnlockLoading ? <Loader2 size={16} className="animate-spin" /> : null}
                {quickUnlockEnabled
                  ? <><ToggleRight size={16} />Enabled</>
                  : <><ToggleLeft size={16} />Disabled</>}
              </button>
            </div>

            {/* Passwordless toggle - shown when ≥2 MFA methods are active */}
            {countActiveMfaMethods(mfaConfig) >= 2 && (
              <div className={`mt-8 p-6 rounded-xl border-2 flex items-center justify-between gap-6 transition-all ${mfaConfig.passwordlessEnabled ? 'border-black dark:border-on-primary-container bg-black/5 dark:bg-white/5' : 'border-outline-variant/30 bg-surface-container-high'}`}>
                <div className="flex items-start gap-4">
                  <div className={`mt-0.5 p-2 rounded-xl ${mfaConfig.passwordlessEnabled ? 'bg-black text-white' : 'bg-surface-container-highest text-on-surface-variant'}`}>
                    <Fingerprint size={20} />
                  </div>
                  <div>
                    <h4 className="font-bold text-base mb-1">{t('settings.passwordlessTitle', 'Go Passwordless')}</h4>
                    <p className="text-xs text-on-surface-variant leading-relaxed max-w-lg">
                      {mfaConfig.passwordlessEnabled
                        ? t('settings.passwordlessEnabledDesc', 'Password field is hidden at login. Sign in using your configured MFA method.')
                        : t('settings.passwordlessDisabledDesc', 'You have 2+ authentication methods. Disable the password field at login and sign in with your biometric or security key instead.')}
                    </p>
                  </div>
                </div>
                <button
                  onClick={handlePasswordlessToggle}
                  className="shrink-0 flex items-center gap-2 px-5 py-3 rounded-xl font-black text-xs uppercase tracking-widest transition-all"
                  style={mfaConfig.passwordlessEnabled
                    ? { background: 'black', color: 'white' }
                    : { background: 'var(--color-surface-container-highest)', color: 'var(--color-on-surface)' }}
                >
                  {mfaConfig.passwordlessEnabled
                    ? <><ToggleRight size={16} />{t('settings.passwordlessOn', 'Enabled')}</>
                    : <><ToggleLeft size={16} />{t('settings.passwordlessOff', 'Disabled')}</>}
                </button>
              </div>
            )}

            {/* Two-Factor Requirement toggle - shown when TOTP or email MFA is active */}
            {(mfaConfig.totp.enabled || mfaConfig.email.enabled) && !mfaConfig.passwordlessEnabled && (
              <div className={`mt-4 p-6 rounded-xl border-2 flex items-center justify-between gap-6 transition-all ${mfaConfig.passwordLoginEnabled === false ? 'border-amber-500 dark:border-amber-500 bg-amber-50/50 dark:bg-amber-900/10' : 'border-outline-variant/30 bg-surface-container-high'}`}>
                <div className="flex items-start gap-4">
                  <div className={`mt-0.5 p-2 rounded-xl ${mfaConfig.passwordLoginEnabled === false ? 'bg-amber-500 text-white' : 'bg-surface-container-highest text-on-surface-variant'}`}>
                    <KeyRound size={20} />
                  </div>
                  <div>
                    <h4 className="font-bold text-base mb-1">{t('settings.twoFactorTitle', 'Two-Factor Requirement')}</h4>
                    <p className="text-xs text-on-surface-variant leading-relaxed max-w-lg">
                      {mfaConfig.passwordLoginEnabled === false
                        ? t('settings.twoFactorOffDesc', 'Two-factor required. Every password-based login must be followed by an authenticator code or email OTP.')
                        : t('settings.twoFactorOnDesc', 'Password-only login is permitted. Users can sign in without a second factor.')}
                    </p>
                  </div>
                </div>
                <button
                  onClick={handlePasswordLoginToggle}
                  className="shrink-0 flex items-center gap-2 px-5 py-3 rounded-xl font-black text-xs uppercase tracking-widest transition-all"
                  style={mfaConfig.passwordLoginEnabled === false
                    ? { background: 'rgb(245 158 11)', color: 'white' }
                    : { background: 'var(--color-surface-container-highest)', color: 'var(--color-on-surface)' }}
                >
                  {mfaConfig.passwordLoginEnabled === false
                    ? <><ToggleLeft size={16} />{t('settings.passwordLoginOff', 'Disabled')}</>
                    : <><ToggleRight size={16} />{t('settings.passwordLoginOn', 'Enabled')}</>}
                </button>
              </div>
            )}
            {policyError && (
              <div className="mt-3 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/30 rounded-xl flex items-center gap-2">
                <AlertTriangle size={14} className="text-red-500 shrink-0" />
                <p className="text-red-600 dark:text-red-400 text-sm">{policyError}</p>
              </div>
            )}
          </div>
        </section>


        {/* Session Lock */}
        <section>
          <div className="flex items-center gap-3 mb-8">
            <Timer className="text-black dark:text-white" size={24} aria-hidden="true" />
            <h2 className="text-2xl font-headline font-extrabold tracking-tight">{t('settings.sessionLock', 'Session Lock')}</h2>
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
                aria-label={t('settings.autoLockLabel', 'Auto-lock timeout')}
              >
                <option value="30000">{t('settings.lock30s', '30 seconds')}</option>
                <option value="60000">{t('settings.lock1m', '1 minute')}</option>
                <option value="300000">{t('settings.lock5m', '5 minutes')}</option>
                <option value="600000">{t('settings.lock10m', '10 minutes')}</option>
                <option value="1500000">{t('settings.lock25m', '25 minutes')}</option>
                <option value="off">{t('settings.lockOff', 'Off')}</option>
              </select>
              <ChevronDown size={16} className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none text-on-surface-variant" aria-hidden="true" />
            </div>
          </div>
        </section>

        {/* Email Server */}
        <section>
          <div className="flex items-center gap-3 mb-8">
            <Server className="text-black dark:text-white" size={24} aria-hidden="true" />
            <h2 className="text-2xl font-headline font-extrabold tracking-tight">{t('settings.emailServer', 'Email Server')}</h2>
          </div>
          <div className="bg-surface-container-low p-10 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6">
            <div>
              <h3 className="font-bold text-xl mb-2">{t('settings.emailServerTitle', 'SMTP Configuration')}</h3>
              <p className="text-sm text-on-surface-variant leading-relaxed max-w-md">
                {t('settings.emailServerDesc', 'Configure your outgoing mail server for password resets and notifications. Supports SMTP, ESMTP, STARTTLS and SSL/TLS.')}
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
                setEmailServerForm(emailServerConfig ?? { ...DEFAULT_EMAIL_CONFIG });
                setEmailTestResult('idle');
                setShowSmtpPassword(false);
                setIsEmailServerModalOpen(true);
              }}
              className="shrink-0 px-8 py-4 bg-black dark:bg-white text-white dark:text-black rounded-xl font-bold text-sm hover:opacity-90 transition-all flex items-center gap-3 shadow-lg"
            >
              {emailServerConfig
                ? <><Edit3 size={18} />{t('settings.editEmailServer', 'Edit')}</>
                : <><Server size={18} />{t('settings.setupEmailServer', 'Setup Email Server')}</>
              }
            </button>
          </div>
        </section>

        {/* ── Travel Mode ───────────────────────────────────────────────────── */}
        <section>
          <div className="flex items-center gap-3 mb-8">
            <Plane className="text-black dark:text-white" size={24} aria-hidden="true" />
            <h2 className="text-2xl font-headline font-extrabold tracking-tight">{t('settings.offlineTravelMode', 'Travel Mode')}</h2>
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
                    ? t('settings.travelActiveDesc', '{{count}} folder(s) hidden - vault appears sanitized. Hidden data is AES-256-GCM encrypted locally and invisible to device inspection.', { count: travelConfig.hiddenFolderIds.length })
                    : t('settings.travelInactiveDesc', 'Hide designated vault folders when crossing borders or entering high-risk environments. Hidden data is encrypted on-device with your travel password - invisible to inspection, fully restorable with the travel password.')}
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

        {/* ── Offline Duress Mode ───────────────────────────────────────────── */}
        <section>
          <div className="flex items-center gap-3 mb-8">
            <Skull className="text-black dark:text-white" size={24} aria-hidden="true" />
            <h2 className="text-2xl font-headline font-extrabold tracking-tight">{t('settings.offlineDuressMode', 'Offline Duress Mode')}</h2>
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
                    ? t('settings.duressArmedDesc', 'Entering the duress password at login triggers an immediate forensic wipe. Auto-wipe after {{max}} failed attempt(s) ({{remaining}} remaining).', { max: duressConfig.maxAttempts, remaining: duressConfig.attemptsRemaining })
                    : t('settings.duressDisarmedDesc', 'A separate duress password entered at login silently wipes all vault data (3-pass CSPRNG overwrite). Also auto-triggers after a configurable number of failed login attempts.')}
                </p>

                {/* Max attempts selector */}
                <div className="flex items-center gap-4">
                  <label className={`text-[10px] font-black uppercase tracking-widest shrink-0 ${duressConfig.armed ? 'text-red-300' : 'text-on-surface-variant'}`}>
                    {t('settings.duressAutoWipeAfter', 'Auto-wipe after')}
                  </label>
                  <div className="relative">
                    <select
                      value={duressMaxAttempts}
                      onChange={e => setDuressMaxAttempts(Number(e.target.value))}
                      disabled={duressConfig.armed}
                      className={`appearance-none text-sm font-bold px-5 py-2.5 pr-9 rounded-lg cursor-pointer focus:outline-none focus:ring-2 disabled:opacity-60 disabled:cursor-not-allowed transition-all ${
                        duressConfig.armed
                          ? 'bg-red-900/50 text-red-100 border border-red-700 focus:ring-red-600'
                          : 'bg-surface-container-high focus:ring-black dark:focus:ring-white'
                      }`}
                    >
                      {[3, 5, 10, 35, 60].map(n => (
                        <option key={n} value={n}>{t('settings.duressFailedAttempts', '{{count}} failed attempt(s)', { count: n })}</option>
                      ))}
                    </select>
                    <ChevronDown size={14} className={`absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none ${duressConfig.armed ? 'text-red-400' : 'text-on-surface-variant'}`} />
                  </div>
                  {duressConfig.armed && (
                    <span className={`text-xs font-bold ${duressConfig.attemptsRemaining <= 2 ? 'text-red-400 animate-pulse' : 'text-red-300'}`}>
                      {t('settings.duressAttemptsRemaining', '{{remaining}} / {{max}} remaining', { remaining: duressConfig.attemptsRemaining, max: duressConfig.maxAttempts })}
                    </span>
                  )}
                </div>
              </div>

              <div className="flex flex-col gap-3 shrink-0">
                {duressConfig.armed ? (
                  <>
                    <button
                      onClick={() => { setIsDuressWipeOpen(true); }}
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

      </div>

      {/* Change Password Modal */}
      <AnimatePresence>
        {isChangeModalOpen && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40"
              onClick={() => setIsChangeModalOpen(false)}
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-lg bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl overflow-hidden border border-outline-variant/10"
            >
              <div className="p-10">
                <div className="flex items-center justify-between mb-8">
                  <div className="w-12 h-12 rounded-2xl bg-black flex items-center justify-center">
                    <Key className="text-white" size={24} />
                  </div>
                  <button 
                    onClick={() => setIsChangeModalOpen(false)}
                    className="p-2 hover:bg-surface-container-low rounded-full transition-colors"
                  >
                    <X size={20} />
                  </button>
                </div>

                {step === 4 ? (
                  <div className="text-center py-6">
                    <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('settings.successTitle', 'Success')}</h3>
                    <p className="text-on-surface-variant text-sm mb-10">{t('settings.successDesc', 'Account password successfully updated')}</p>
                    <button 
                      onClick={() => setIsChangeModalOpen(false)}
                      className="w-full py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all"
                    >
                      {t('settings.close', 'Close')}
                    </button>
                  </div>
                ) : step === 3 ? (
                  <div className="space-y-8">
                    <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('settings.confirmUpdateTitle', 'Are you sure?')}</h3>
                    <p className="text-on-surface-variant text-sm leading-relaxed">
                      {t('settings.confirmUpdateDesc', 'Are you sure you want to commit some updates? If lost you may lose your access.')}
                    </p>
                    <div className="flex gap-3 pt-4">
                      <button 
                        onClick={() => setStep(2)}
                        className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all"
                      >
                        {t('common.back', 'Back')}
                      </button>
                      <button 
                        onClick={handleConfirmUpdate}
                        disabled={isSavingPassword}
                        className="flex-1 flex items-center justify-center gap-2 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {isSavingPassword ? (
                          <>
                            <Loader2 size={16} className="animate-spin" />
                            {t('common.processing', 'Processing...')}
                          </>
                        ) : (
                          t('settings.accept', 'Accept')
                        )}
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">
                      {step === 1 ? t('settings.verifyIdentity', 'Verify Identity') : t('settings.setNewPassword', 'Set New Password')}
                    </h3>
                    <p className="text-on-surface-variant text-sm mb-8 leading-relaxed">
                      {step === 1 
                        ? t('settings.verifyDesc', 'To change your account password, please enter your current one first to ensure it\'s really you.')
                        : t('settings.setNewDesc', 'Create a new, highly secure password for your account. We recommend using our generator for maximum entropy.')}
                    </p>

                    {step === 1 ? (
                      <div className="space-y-6">
                        <div className="space-y-3">
                          <label htmlFor="old-password" className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">
                            {t('settings.oldPassword', 'Old Password')}
                          </label>
                          <div className="relative">
                            <input
                              id="old-password"
                              type={showOldPassword ? 'text' : 'password'}
                              value={oldPassword}
                              onChange={(e) => { setOldPassword(e.target.value); setOldPasswordError(''); }}
                              placeholder="••••••••••••••••"
                              className={`w-full px-6 py-4 bg-surface-container-low rounded-xl border text-black dark:text-white font-bold focus:ring-2 focus:ring-black/20 dark:focus:ring-white/20 outline-none transition-all ${oldPasswordError ? 'border-red-400' : 'border-outline-variant/10'}`}
                            />
                            <button
                              type="button"
                              tabIndex={-1}
                              onClick={() => setShowOldPassword(!showOldPassword)}
                              className="absolute right-4 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-black transition-colors"
                            >
                              {showOldPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                            </button>
                          </div>
                          {oldPasswordError && (
                            <p className="text-[10px] font-bold text-red-600 uppercase tracking-widest">{oldPasswordError}</p>
                          )}
                        </div>
                        <button
                          onClick={handleNextStep}
                          disabled={!oldPassword || isSavingPassword}
                          className="w-full flex items-center justify-center gap-2 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {isSavingPassword ? (
                            <>
                              <Loader2 size={16} className="animate-spin" />
                              {t('common.verifying', 'Verifying...')}
                            </>
                          ) : (
                            t('common.next', 'Next Step')
                          )}
                        </button>
                      </div>
                    ) : (
                      <div className="space-y-8">
                        <div className="space-y-6">
                          <div className="space-y-3">
                            <label htmlFor="new-password" className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">
                              {t('settings.newPassword', 'New Account Password')}
                            </label>
                            <div className="relative">
                              <input 
                                id="new-password"
                                type={showNewPassword ? 'text' : 'password'}
                                value={newPassword}
                                onChange={(e) => { setNewPassword(e.target.value); setNewPasswordError(''); }}
                                className="w-full px-6 py-4 pr-32 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-mono font-bold tracking-widest focus:ring-2 focus:ring-black/20 dark:focus:ring-white/20 outline-none transition-all"
                              />
                              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                                <button
                                  type="button"
                                  tabIndex={-1}
                                  onClick={() => setShowNewPassword(!showNewPassword)}
                                  className="p-2 text-on-surface-variant hover:text-black transition-colors"
                                >
                                  {showNewPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                                </button>
                                <button 
                                  type="button"
                                  onClick={generatePassword}
                                  title={t('addCredential.generate', 'Generate')}
                                  className="p-2 bg-black text-white rounded-lg hover:opacity-80 transition-all"
                                >
                                  <RefreshCw size={16} />
                                </button>
                              </div>
                            </div>
                          </div>

                          <div className="space-y-3">
                            <label htmlFor="confirm-password" className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">
                              {t('settings.confirmPassword', 'Confirm New Password')}
                            </label>
                            <div className="relative">
                              <input 
                                id="confirm-password"
                                type={showConfirmPassword ? 'text' : 'password'}
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                className="w-full px-6 py-4 pr-12 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-mono font-bold tracking-widest focus:ring-2 focus:ring-black/20 dark:focus:ring-white/20 outline-none transition-all"
                              />
                              <button
                                type="button"
                                tabIndex={-1}
                                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                className="absolute right-4 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-black transition-colors"
                              >
                                {showConfirmPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                              </button>
                            </div>
                            {confirmPassword && !passwordsMatch && (
                              <p className="text-[10px] font-bold text-red-600 uppercase tracking-widest">{t('addCredential.passwordMismatch', 'Passwords do not match')}</p>
                            )}
                            {newPassword.length > 0 && newPassword.length < 12 && (
                              <p className="text-[10px] font-bold text-orange-500 uppercase tracking-widest">{t('settings.minPasswordLength', 'Minimum 12 characters required')}</p>
                            )}
                            {newPasswordError && (
                              <p className="text-[10px] font-bold text-red-600 uppercase tracking-widest">{newPasswordError}</p>
                            )}
                          </div>
                        </div>

                        {/* Strength Indicator */}
                        <div className="p-6 bg-surface-container-low rounded-2xl border border-outline-variant/10">
                          <div className="flex items-center justify-between mb-4">
                            <div className="flex items-center gap-2">
                              <ShieldCheck size={16} className={strength.color} />
                              <span className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('addCredential.entropyAnalysis', 'Entropy Analysis')}</span>
                            </div>
                            <span className={`text-[10px] font-black uppercase tracking-widest ${strength.color}`}>{strength.label}</span>
                          </div>
                          <div className="h-2 bg-black/5 rounded-full overflow-hidden">
                            <motion.div 
                              initial={{ width: 0 }}
                              animate={{ width: strength.width }}
                              className={`h-full ${strength.bar} transition-all duration-500`}
                            />
                          </div>
                        </div>

                        <div className="flex gap-3">
                          <button 
                            onClick={() => setStep(1)}
                            className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all"
                          >
                            {t('common.back', 'Back')}
                          </button>
                          <button 
                            onClick={handleNextStep}
                            disabled={!isStrongEnough || !passwordsMatch}
                            className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            {t('settings.updatePassword', 'Update Password')}
                          </button>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Audit Log / Connections Modal */}
      <AnimatePresence>
        {isAuditLogOpen && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40"
              onClick={() => setIsAuditLogOpen(false)}
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-2xl bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl border border-outline-variant/10 flex flex-col max-h-[85vh]"
            >
              {/* Header */}
              <div className="flex items-center justify-between p-8 border-b border-outline-variant/10 shrink-0">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-2xl bg-black flex items-center justify-center">
                    <History className="text-white" size={22} />
                  </div>
                  <div>
                    <h3 className="text-xl font-headline font-black text-black dark:text-white">{t('settings.auditLog', 'Security Audit Log')}</h3>
                    <p className="text-xs text-on-surface-variant mt-0.5">
                      {auditTab === 'sessions'
                        ? `${sessions.length} session${sessions.length !== 1 ? 's' : ''} recorded`
                        : `${auditEventsTotal} event${auditEventsTotal !== 1 ? 's' : ''} recorded`}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setIsAuditLogOpen(false)}
                  className="p-2 hover:bg-surface-container-high rounded-full transition-colors"
                  aria-label="Close"
                >
                  <X size={20} />
                </button>
              </div>

              {/* Tab switcher */}
              <div className="flex gap-1 px-8 pt-4 shrink-0">
                <button
                  onClick={() => setAuditTab('sessions')}
                  className={`px-4 py-2 text-xs font-black uppercase tracking-widest rounded-lg transition-colors ${auditTab === 'sessions' ? 'bg-black text-white dark:bg-white dark:text-black' : 'text-on-surface-variant hover:bg-surface-container-high'}`}
                >
                  {t('settings.sessionsTab', 'Sessions')}
                </button>
                {isServerMode() && (
                  <button
                    onClick={() => setAuditTab('events')}
                    className={`px-4 py-2 text-xs font-black uppercase tracking-widest rounded-lg transition-colors ${auditTab === 'events' ? 'bg-black text-white dark:bg-white dark:text-black' : 'text-on-surface-variant hover:bg-surface-container-high'}`}
                  >
                    {t('settings.auditEventsTab', 'Audit Events')}
                  </button>
                )}
              </div>

              {/* Content area */}
              <div className="overflow-y-auto flex-1 p-8 space-y-3">
                {auditTab === 'sessions' ? (
                  sessions.length === 0 ? (
                    <div className="py-12 text-center text-on-surface-variant text-sm">
                      No sessions recorded yet. Log out and back in to see your session here.
                    </div>
                  ) : (
                    sessions.map((session) => (
                      <div key={session.id} className="flex items-center justify-between p-5 bg-surface-container-low dark:bg-surface-container-high rounded-xl group hover:bg-surface-container-high dark:hover:bg-surface-container-highest transition-all">
                        <div className="flex items-center gap-5">
                          <div className="w-12 h-12 bg-surface-container-high dark:bg-surface-container-highest rounded-xl flex items-center justify-center shrink-0">
                            <Monitor size={22} className="text-on-surface-variant" />
                          </div>
                          <div>
                            <div className="flex items-center gap-2 mb-0.5">
                              <p className="font-bold text-sm text-black dark:text-white">{session.deviceName}</p>
                              {session.isCurrent && (
                                <span className="text-[9px] px-2 py-0.5 bg-black dark:bg-white text-white dark:text-black rounded font-black uppercase tracking-widest">
                                  {t('settings.current', 'Current')}
                                </span>
                              )}
                            </div>
                            <p className="text-xs text-on-surface-variant">IP: {session.ip} · {formatSessionTime(session.timestamp)}</p>
                          </div>
                        </div>
                        {!session.isCurrent && (
                          <button
                            onClick={async () => {
                              const all = await getSessions();
                              const updated = all.filter(s => s.id !== session.id);
                              const { writeEncryptedLocal: wel } = await import('../utils/localCrypto');
                              await wel('login_sessions', JSON.stringify(updated));
                              setSessions(await getSessions());
                            }}
                            className="bg-error/10 text-error px-4 py-2 rounded-lg font-black text-xs uppercase tracking-widest shrink-0 hover:bg-error/20 transition-colors"
                            aria-label={`Revoke ${session.deviceName}`}
                          >
                            {t('settings.revoke', 'Revoke')}
                          </button>
                        )}
                      </div>
                    ))
                  )
                ) : auditEventsLoading ? (
                  <div className="py-12 flex justify-center"><Loader2 className="animate-spin text-on-surface-variant" size={24} /></div>
                ) : auditEvents.length === 0 ? (
                  <div className="py-12 text-center text-on-surface-variant text-sm">
                    {t('settings.noAuditEvents', 'No audit events recorded yet. Actions like login, logout, and credential changes will appear here.')}
                  </div>
                ) : (
                  <>
                    {auditEvents.map((event) => (
                      <div key={event.id} className="p-4 bg-surface-container-low dark:bg-surface-container-high rounded-xl">
                        <div className="flex items-center gap-3">
                          <div className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 ${event.success ? 'bg-green-500/10' : 'bg-red-500/10'}`}>
                            {getAuditActionIcon(event.action)}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-bold text-sm text-black dark:text-white">{getAuditActionLabel(event.action)}</span>
                              {event.riskFlags?.map((flag: string) => (
                                <span key={flag} className={`text-[9px] px-1.5 py-0.5 rounded font-black uppercase tracking-widest ${getRiskBadgeClass(flag)}`}>{flag}</span>
                              ))}
                              {event.resourceLabel && (
                                <span className="text-xs text-on-surface-variant truncate max-w-[140px]">· {event.resourceLabel}</span>
                              )}
                            </div>
                            {(() => {
                              const rawIp: string = event.ip || '';
                              const publicIp: string = event.publicIp || '';
                              const info = event.ipInfo;
                              const resolvedIp = publicIp || rawIp;
                              const { isLoopback, isPrivate, label } = classifyIp(resolvedIp);
                              const isIpv6 = resolvedIp.includes(':') && !/^::1$|^::ffff:127/.test(resolvedIp);
                              const location = [info?.city, info?.region, info?.country].filter(Boolean).join(', ');
                              return (
                                <div className="mt-1 space-y-1">
                                  {isPrivate && (
                                    <div className="flex items-center gap-1.5">
                                      <span className="inline-flex items-center gap-1 text-[9px] px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-600 dark:text-amber-400 font-black uppercase tracking-widest border border-amber-500/20">
                                        <Globe size={8} /> {label} · {rawIp}
                                      </span>
                                    </div>
                                  )}
                                  <p className="text-xs text-on-surface-variant flex items-center gap-1.5 flex-wrap">
                                    {info?.countryFlag && <span>{info.countryFlag}</span>}
                                    {isIpv6 && (
                                      <span className="font-mono text-[10px] bg-blue-500/10 text-blue-600 dark:text-blue-400 px-1.5 py-0.5 rounded truncate max-w-[180px]">{resolvedIp}</span>
                                    )}
                                    {location ? (
                                      <span>{location}</span>
                                    ) : (
                                      !isPrivate && !isLoopback && <span className="font-mono">{resolvedIp}</span>
                                    )}
                                    {info?.org && (
                                      <span className="text-on-surface-variant/60 truncate max-w-[180px]">· {info.org}</span>
                                    )}
                                  </p>
                                </div>
                              );
                            })()}
                          </div>
                          <p className="text-xs text-on-surface-variant shrink-0">{formatSessionTime(event.ts)}</p>
                        </div>
                      </div>
                    ))}
                    {auditEventsTotal > 50 && (
                      <p className="text-xs text-center text-on-surface-variant py-2">
                        {t('settings.showingOf', 'Showing 50 of {{total}} events', { total: auditEventsTotal })}
                      </p>
                    )}
                  </>
                )}
              </div>

              {/* Footer actions */}
              <div className="p-6 border-t border-outline-variant/10 bg-surface-container-low/50 flex flex-wrap items-center justify-between gap-3 shrink-0 rounded-b-3xl">
                {auditTab === 'sessions' ? (
                  <>
                    <button
                      onClick={() => { setIsAuditLogOpen(false); setIsRevokeModalOpen(true); setRevokeSuccess(false); }}
                      className="flex items-center gap-2 text-xs font-black uppercase tracking-widest text-error hover:underline"
                    >
                      <LogOut size={14} />
                      {t('settings.revokeAll', 'Revoke All Other Sessions')}
                    </button>
                    <button
                      onClick={() => {
                        const header = 'Device,IP Address,Last Active\n';
                        const rows = sessions.map(s => `"${s.deviceName}","${s.ip}","${formatSessionTime(s.timestamp)}"`).join('\n');
                        const blob = new Blob([header + rows], { type: 'text/csv' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url; a.download = 'session-audit-log.csv';
                        document.body.appendChild(a); a.click(); document.body.removeChild(a);
                        setTimeout(() => URL.revokeObjectURL(url), 10000);
                      }}
                      className="flex items-center gap-2 px-5 py-2.5 bg-black text-white rounded-xl text-xs font-black uppercase tracking-widest hover:bg-neutral-800 transition-all"
                    >
                      <Download size={14} />
                      {t('settings.downloadCsv', 'Download CSV')}
                    </button>
                  </>
                ) : (
                  <>
                    <button
                      onClick={async () => {
                        if (!confirm(t('settings.clearEventsConfirm', 'Clear all audit events? This cannot be undone.'))) return;
                        await fetch('/api/audit/events', { method: 'DELETE', credentials: 'include', headers: { 'X-CSRF-Token': getCsrfToken() } });
                        setAuditEvents([]); setAuditEventsTotal(0);
                      }}
                      className="flex items-center gap-2 text-xs font-black uppercase tracking-widest text-error hover:underline"
                    >
                      <Trash2 size={14} />
                      {t('settings.clearEvents', 'Clear Log')}
                    </button>
                    <button
                      onClick={() => {
                        const header = 'Time,Action,Location,Organization,Risk Flags,Resource\n';
                        const rows = auditEvents.map(e =>
                          `"${new Date(e.ts).toISOString()}","${getAuditActionLabel(e.action)}","${[e.ipInfo?.city, e.ipInfo?.country].filter(Boolean).join(', ')}","${e.ipInfo?.org || ''}","${(e.riskFlags || []).join('/')}","${e.resourceLabel || ''}"`
                        ).join('\n');
                        const blob = new Blob([header + rows], { type: 'text/csv' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url; a.download = 'audit-events.csv';
                        document.body.appendChild(a); a.click(); document.body.removeChild(a);
                        setTimeout(() => URL.revokeObjectURL(url), 10000);
                      }}
                      className="flex items-center gap-2 px-5 py-2.5 bg-black text-white rounded-xl text-xs font-black uppercase tracking-widest hover:bg-neutral-800 transition-all"
                    >
                      <Download size={14} />
                      {t('settings.downloadCsv', 'Download CSV')}
                    </button>
                  </>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Active Share Links Modal */}
      <AnimatePresence>
        {isSharesOpen && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="absolute inset-0 bg-[#000000]/40" onClick={() => setIsSharesOpen(false)} />
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95 }}
              className="relative w-full max-w-lg bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl border border-outline-variant/10 flex flex-col max-h-[80vh]"
            >
              <div className="flex items-center justify-between p-8 border-b border-outline-variant/10 shrink-0">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-2xl bg-black flex items-center justify-center"><Share2 className="text-white" size={22} /></div>
                  <div>
                    <h3 className="text-xl font-headline font-black text-black dark:text-white">{t('settings.activeShares', 'Active Share Links')}</h3>
                    <p className="text-xs text-on-surface-variant mt-0.5">{shares.length} active link{shares.length !== 1 ? 's' : ''}</p>
                  </div>
                </div>
                <button onClick={() => setIsSharesOpen(false)} className="p-2 hover:bg-surface-container-high rounded-full transition-colors"><X size={20} /></button>
              </div>

              <div className="overflow-y-auto flex-1 p-8 space-y-3">
                {sharesLoading ? (
                  <div className="py-12 flex justify-center"><Loader2 className="animate-spin text-on-surface-variant" size={24} /></div>
                ) : shares.length === 0 ? (
                  <div className="py-12 text-center text-on-surface-variant text-sm">
                    {t('settings.noActiveShares', 'No active share links. Share a credential from your vault to see it here.')}
                  </div>
                ) : shares.map(share => (
                  <div key={share.id} className="flex items-center justify-between p-4 bg-surface-container-low dark:bg-surface-container-high rounded-xl gap-3">
                    <div className="flex-1 min-w-0">
                      <p className="font-bold text-sm text-black dark:text-white truncate">{share.label || t('settings.unknownService', 'Unknown service')}</p>
                      <div className="flex items-center gap-3 mt-0.5">
                        <span className="text-xs text-on-surface-variant">{formatExpiry(share.expiresAt)}</span>
                        {share.singleView && <span className="text-[10px] px-2 py-0.5 bg-surface-container-highest rounded font-bold">{t('settings.viewOnce', 'View once')}</span>}
                        {share.viewed && <span className="text-[10px] px-2 py-0.5 bg-green-500/15 text-green-600 rounded font-bold">{t('settings.viewed', 'Viewed')}</span>}
                      </div>
                    </div>
                    <button
                      onClick={() => revokeShare(share.id)}
                      className="bg-error/10 text-error px-3 py-1.5 rounded-lg font-black text-xs uppercase tracking-widest shrink-0 hover:bg-error/20 transition-colors"
                    >
                      {t('settings.revoke', 'Revoke')}
                    </button>
                  </div>
                ))}
              </div>

              {shares.length > 0 && (
                <div className="p-6 border-t border-outline-variant/10 shrink-0 flex justify-end">
                  <button onClick={revokeAllShares} className="flex items-center gap-2 text-xs font-black uppercase tracking-widest text-error hover:underline">
                    <Trash2 size={14} />
                    {t('settings.revokeAllShares', 'Revoke All')}
                  </button>
                </div>
              )}
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Revoke Sessions Modal */}
      <AnimatePresence>
        {isRevokeModalOpen && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40"
              onClick={() => setIsRevokeModalOpen(false)}
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-md bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl overflow-hidden border border-outline-variant/10"
            >
              <div className="p-10">
                <div className="flex items-center justify-between mb-8">
                  <div className="w-12 h-12 rounded-2xl bg-error/10 flex items-center justify-center">
                    <LogOut className="text-error" size={24} />
                  </div>
                  <button 
                    onClick={() => setIsRevokeModalOpen(false)}
                    className="p-2 hover:bg-surface-container-low rounded-full transition-colors"
                  >
                    <X size={20} />
                  </button>
                </div>

                {revokeSuccess ? (
                  <div className="text-center py-6">
                    <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('settings.successTitle', 'Success')}</h3>
                    <p className="text-on-surface-variant text-sm mb-10">{t('settings.revokeAllSuccess', 'All other sessions have been successfully revoked.')}</p>
                    <button 
                      onClick={() => setIsRevokeModalOpen(false)}
                      className="w-full py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all"
                    >
                      {t('settings.close', 'Close')}
                    </button>
                  </div>
                ) : (
                  <div className="space-y-8">
                    <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('settings.revokeAll', 'Revoke All Other Sessions')}</h3>
                    <p className="text-on-surface-variant text-sm leading-relaxed">
                      {t('settings.revokeAllConfirm', 'Are you sure you want to revoke all other active sessions? You will be logged out on all devices except this one.')}
                    </p>
                    <div className="flex gap-3 pt-4">
                      <button 
                        onClick={() => setIsRevokeModalOpen(false)}
                        className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all"
                      >
                        {t('common.cancel', 'Cancel')}
                      </button>
                      <button 
                        onClick={handleRevokeAll}
                        disabled={isRevoking}
                        className="flex-1 py-4 bg-error text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-error/90 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                      >
                        {isRevoking ? <RefreshCw size={16} className="animate-spin" /> : null}
                        {isRevoking ? t('settings.revoking', 'Revoking...') : t('settings.revoke', 'Revoke')}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── MFA Modal ──────────────────────────────────────────────────────────── */}
      <AnimatePresence>
        {mfaModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40"
              onClick={closeMfaModal}
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-lg bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl overflow-hidden border border-outline-variant/10 max-h-[90vh] overflow-y-auto"
            >
              <div className="p-10">

                {/* Header */}
                <div className="flex items-center justify-between mb-8">
                  <div className="w-12 h-12 rounded-2xl bg-black flex items-center justify-center">
                    {mfaModal.type === 'totp'     && <Smartphone  className="text-white" size={22} />}
                    {mfaModal.type === 'webauthn' && <Key         className="text-white" size={22} />}
                    {mfaModal.type === 'email'    && <Mail        className="text-white" size={22} />}
                    {mfaModal.type === 'passkey'  && <KeyRound    className="text-white" size={22} />}
                    {mfaModal.type === 'platform' && <Fingerprint className="text-white" size={22} />}
                  </div>
                  <button onClick={closeMfaModal} className="p-2 hover:bg-surface-container-low rounded-full transition-colors">
                    <X size={20} />
                  </button>
                </div>

                {/* ════════════════════════════════════════════════════════════
                    TOTP – Authenticator App
                    Step 1 = scan QR / copy secret
                    Step 2 = enter 6-digit code to verify
                    Step 3 = success
                    Step 9 = already-enabled management screen
                ═══════════════════════════════════════════════════════════ */}
                {mfaModal.type === 'totp' && (
                  <>
                    {/* Already enabled: manage screen */}
                    {(mfaConfig.totp.enabled || mfaConfig.hotp?.enabled) && mfaModal.step === 1 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Authenticator App</h3>
                          <p className="text-on-surface-variant text-sm leading-relaxed">Your authenticator app is configured and active.</p>
                        </div>
                        <div className="p-5 bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800 rounded-2xl flex items-center gap-4">
                          <CheckCircle size={22} className="text-green-600 shrink-0" />
                          <div>
                            <p className="font-bold text-sm text-green-800 dark:text-green-300">
                              Active since {new Date((mfaConfig.hotp?.enabled ? mfaConfig.hotp.enabledAt : mfaConfig.totp.enabledAt) ?? 0).toLocaleDateString()}
                            </p>
                            <p className="text-xs text-green-700/70 dark:text-green-400/70 mt-0.5">
                              {mfaConfig.hotp?.enabled
                                ? 'HOTP · SHA-1 · 6 digits · Counter-based'
                                : `TOTP · ${mfaConfig.totp.algorithm || 'SHA-256'} · ${mfaConfig.totp.digits || 8} digits · 30 s period`}
                            </p>
                          </div>
                        </div>
                        <div className="flex gap-3 pt-2">
                          <button onClick={closeMfaModal} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Close</button>
                          <button
                            onClick={handleTotpRemove}
                            className="flex-1 py-4 bg-error/10 text-error rounded-xl font-black uppercase tracking-widest text-xs hover:bg-error/20 transition-all flex items-center justify-center gap-2"
                          >
                            <Trash2 size={14} />Remove
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Setup step 0 – choose TOTP vs HOTP */}
                    {!mfaConfig.totp.enabled && !mfaConfig.hotp?.enabled && mfaModal.step === 0 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Set up Authenticator App</h3>
                          <p className="text-on-surface-variant text-sm leading-relaxed">Choose the type of one-time password your app will generate.</p>
                        </div>
                        <div className="space-y-3">
                          <button
                            type="button"
                            onClick={() => setTotpType('totp')}
                            className={`w-full flex items-center gap-4 p-4 rounded-xl border-2 transition-all text-left ${totpType === 'totp' ? 'border-black dark:border-white bg-surface-container-high' : 'border-outline-variant/40 bg-surface-container-high hover:border-outline-variant'}`}
                          >
                            <div className={`w-10 h-10 rounded-full border-2 flex items-center justify-center shrink-0 ${totpType === 'totp' ? 'border-black bg-black dark:border-white dark:bg-white' : 'border-outline-variant'}`}>
                              {totpType === 'totp' && <div className="w-3 h-3 bg-white dark:bg-black rounded-full" />}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-0.5">
                                <p className="font-bold text-sm text-black dark:text-white">TOTP</p>
                                <span className="text-[10px] font-black uppercase tracking-widest bg-blue-600 text-white px-2 py-0.5 rounded-md">Recommended</span>
                              </div>
                              <p className="text-xs text-on-surface-variant">Time-based - new code every 30 seconds</p>
                            </div>
                          </button>
                          <button
                            type="button"
                            onClick={() => setTotpType('hotp')}
                            className={`w-full flex items-center gap-4 p-4 rounded-xl border-2 transition-all text-left ${totpType === 'hotp' ? 'border-black dark:border-white bg-surface-container-high' : 'border-outline-variant/40 bg-surface-container-high hover:border-outline-variant'}`}
                          >
                            <div className={`w-10 h-10 rounded-full border-2 flex items-center justify-center shrink-0 ${totpType === 'hotp' ? 'border-black bg-black dark:border-white dark:bg-white' : 'border-outline-variant'}`}>
                              {totpType === 'hotp' && <div className="w-3 h-3 bg-white dark:bg-black rounded-full" />}
                            </div>
                            <div className="flex-1 min-w-0">
                              <p className="font-bold text-sm text-black dark:text-white mb-0.5">HOTP</p>
                              <p className="text-xs text-on-surface-variant">Counter-based - new code on each button press</p>
                            </div>
                          </button>
                        </div>
                        <div className="flex gap-3">
                          <button onClick={closeMfaModal} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Cancel</button>
                          <button
                            onClick={handleTotpTypeConfirm}
                            className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2"
                          >
                            <ShieldCheck size={16} />Next
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Setup step 1 – QR code */}
                    {!mfaConfig.totp.enabled && !mfaConfig.hotp?.enabled && mfaModal.step === 1 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Set up Authenticator App</h3>
                          <p className="text-on-surface-variant text-sm leading-relaxed">
                            {totpType === 'hotp'
                              ? 'Scan the QR code with your authenticator app. Each press of the "next code" button generates a new code.'
                              : 'Scan the QR code with Google Authenticator, Authy, or any TOTP-compatible app.'}
                          </p>
                        </div>

                        {/* QR code – rendered directly into a <canvas> via QRCode.toCanvas() */}
                        <div className="flex justify-center p-6 bg-surface-container-low rounded-2xl border-2 border-dashed border-outline-variant/20">
                          <canvas
                            ref={qrCanvasCallback}
                            className="rounded-xl w-48 h-48"
                            aria-label="TOTP QR Code"
                          />
                        </div>

                        {/* Manual entry */}
                        <div>
                          <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-2">Can't scan? Enter manually</p>
                          <div className="flex items-center gap-3 p-4 bg-surface-container-low rounded-xl border border-outline-variant/10">
                            <code className="flex-1 text-xs font-mono font-bold tracking-widest break-all text-black dark:text-white select-all">{totpSecret}</code>
                            <button
                              onClick={() => { navigator.clipboard.writeText(totpSecret); setTotpSecretCopied(true); setTimeout(() => setTotpSecretCopied(false), 2000); }}
                              className="shrink-0 p-2 rounded-lg hover:bg-surface-container-high transition-colors"
                              title="Copy secret"
                            >
                              {totpSecretCopied ? <Check size={16} className="text-green-600" /> : <Copy size={16} className="text-on-surface-variant" />}
                            </button>
                          </div>
                        </div>

                        <div className="flex gap-3">
                          <button onClick={closeMfaModal} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Cancel</button>
                          <button
                            onClick={() => setMfaModal({ type: 'totp', step: 2 })}
                            className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2"
                          >
                            <ShieldCheck size={16} />Next: Verify
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Setup step 2 – verify code */}
                    {!mfaConfig.totp.enabled && !mfaConfig.hotp?.enabled && mfaModal.step === 2 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Verify the code</h3>
                          <p className="text-on-surface-variant text-sm leading-relaxed">Open your authenticator app and enter the 8-digit code shown for this account.</p>
                        </div>

                        <div className="flex items-center justify-center gap-2">
                          {[0,1,2,3].map(i => (
                            <input key={i} ref={el => { totpRefs.current[i] = el; }}
                              type="text" inputMode="numeric" maxLength={1} value={totpCode[i]}
                              onChange={e => totpHandlers.onChange(i, e.target.value)}
                              onKeyDown={e => { totpHandlers.onKeyDown(i, e); if (e.key === 'Enter' && !totpCode.some(c => !c)) handleTotpVerify(); }}
                              onPaste={i === 0 ? totpHandlers.onPaste : undefined}
                              className="w-12 h-14 text-center text-xl font-black bg-white dark:bg-[#1a1a1a] border-2 border-slate-400 dark:border-slate-400 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all text-black dark:text-white"
                            />
                          ))}
                          <div className="w-4 h-0.5 bg-slate-400 dark:bg-slate-400 rounded-full mx-1" />
                          {[4,5,6,7].map(i => (
                            <input key={i} ref={el => { totpRefs.current[i] = el; }}
                              type="text" inputMode="numeric" maxLength={1} value={totpCode[i]}
                              onChange={e => totpHandlers.onChange(i, e.target.value)}
                              onKeyDown={e => { totpHandlers.onKeyDown(i, e); if (e.key === 'Enter' && !totpCode.some(c => !c)) handleTotpVerify(); }}
                              className="w-12 h-14 text-center text-xl font-black bg-white dark:bg-[#1a1a1a] border-2 border-slate-400 dark:border-slate-400 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all text-black dark:text-white"
                            />
                          ))}
                        </div>

                        {totpError && (
                          <p className="text-xs font-bold text-error flex items-center gap-2"><AlertTriangle size={14} />{totpError}</p>
                        )}

                        <div className="flex gap-3">
                          <button onClick={() => setMfaModal({ type: 'totp', step: 1 })} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Back</button>
                          <button
                            onClick={handleTotpVerify}
                            disabled={totpCode.some(c => !c)}
                            className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                          >
                            <ShieldCheck size={16} />Confirm
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Success */}
                    {mfaModal.step === 3 && (
                      <div className="text-center py-6 space-y-6">
                        <div className="w-20 h-20 rounded-full bg-green-50 dark:bg-green-950/40 flex items-center justify-center mx-auto">
                          <CheckCircle size={40} className="text-green-600" />
                        </div>
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Authenticator active</h3>
                          <p className="text-on-surface-variant text-sm">
                            {totpType === 'hotp'
                              ? 'Your HOTP app is linked. Each login will prompt for a counter-based code from your app.'
                              : 'Your app is linked. From now on, every login will require an 8-digit TOTP code.'}
                          </p>
                        </div>
                        <button onClick={closeMfaModal} className="w-full py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all">Done</button>
                      </div>
                    )}
                  </>
                )}

                {/* ════════════════════════════════════════════════════════════
                    WEBAUTHN – Security Key
                    Step 1 = name input + register button (or manage if already set)
                    Step 3 = success
                ═══════════════════════════════════════════════════════════ */}
                {mfaModal.type === 'webauthn' && (
                  <>
                    {/* Manage existing keys */}
                    {mfaConfig.webauthn.enabled && mfaModal.step === 1 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Security Keys</h3>
                          <p className="text-on-surface-variant text-sm leading-relaxed">Registered hardware security keys (FIDO2 / WebAuthn).</p>
                        </div>

                        <div className="space-y-3">
                          {mfaConfig.webauthn.credentials.map(cred => (
                            <div key={cred.id} className="flex items-center justify-between p-4 bg-surface-container-low rounded-xl border border-outline-variant/10">
                              <div className="flex items-center gap-3">
                                <Key size={18} className="text-on-surface-variant" />
                                <div>
                                  <p className="font-bold text-sm">{cred.name}</p>
                                  <p className="text-[10px] text-on-surface-variant">Added {new Date(cred.createdAt).toLocaleDateString()}</p>
                                </div>
                              </div>
                              <button
                                onClick={() => handleWebAuthnRemove(cred.id)}
                                className="p-2 text-error hover:bg-error/10 rounded-lg transition-colors"
                                title="Remove key"
                              >
                                <Trash2 size={16} />
                              </button>
                            </div>
                          ))}
                        </div>

                        {/* Add another key */}
                        <div className="space-y-3">
                          <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">Add another key</label>
                          {!isSecureContext() && (
                            <p className="text-[10px] text-amber-700 dark:text-amber-400 flex items-center gap-1">
                              <AlertTriangle size={12} />May fail on plain HTTP - use HTTPS or localhost for best results.
                            </p>
                          )}
                          <div className="flex gap-3">
                            <input
                              type="text"
                              value={webAuthnKeyName}
                              onChange={e => setWebAuthnKeyName(e.target.value)}
                              placeholder="Key name (e.g. YubiKey 5C)"
                              className="flex-1 px-4 py-3 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-bold text-sm focus:ring-2 focus:ring-black/20 outline-none"
                            />
                            <button
                              onClick={handleWebAuthnRegister}
                              disabled={webAuthnBusy}
                              className="px-6 py-3 bg-black text-white rounded-xl font-black text-xs uppercase tracking-widest hover:bg-neutral-800 transition-all disabled:opacity-50 flex items-center gap-2"
                            >
                              {webAuthnBusy ? <RefreshCw size={14} className="animate-spin" /> : <Key size={14} />}Add
                            </button>
                          </div>
                        </div>

                        {webAuthnError && (
                          <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/40 rounded-xl">
                            <p className="text-xs font-bold text-error flex items-center gap-2 mb-1"><AlertTriangle size={13} />Registration failed</p>
                            <pre className="text-xs text-red-700 dark:text-red-300 whitespace-pre-wrap font-sans leading-relaxed">{webAuthnError}</pre>
                          </div>
                        )}
                        <button onClick={closeMfaModal} className="w-full py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Close</button>
                      </div>
                    )}

                    {/* First-time setup */}
                    {!mfaConfig.webauthn.enabled && mfaModal.step === 1 && (
                      <div className="space-y-6">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Register Security Key</h3>
                          <p className="text-on-surface-variant text-sm leading-relaxed">
                            Register a FIDO2-compatible security key (YubiKey, Titan Key, or your device's built-in authenticator).
                          </p>
                        </div>

                        {/* Linux / VM setup guide - shown proactively on Linux */}
                        {/Linux/.test(navigator.userAgent) && !/Android/.test(navigator.userAgent) && (
                          <details className="group">
                            <summary className="flex items-center gap-2 cursor-pointer text-xs font-bold text-amber-700 dark:text-amber-400 list-none">
                              <AlertTriangle size={13} />
                              Linux setup required before registering
                              <span className="ml-auto text-[10px] font-normal opacity-60 group-open:hidden">▼ show</span>
                              <span className="ml-auto text-[10px] font-normal opacity-60 hidden group-open:inline">▲ hide</span>
                            </summary>
                            <div className="mt-3 p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700/40 rounded-xl space-y-3 text-xs text-amber-800 dark:text-amber-300">
                              <p className="font-bold">Complete these steps once, then try registering:</p>
                              <ol className="space-y-3 list-decimal list-outside pl-4">
                                <li>
                                  <strong>Connect the key to this VM</strong> (if running in Parallels / VMware):<br />
                                  <span className="text-amber-700 dark:text-amber-400">Parallels menu bar → Devices → USB → [YubiKey] → <em>Connect to Ubuntu</em></span>
                                </li>
                                <li>
                                  <strong>Create udev permission rules</strong> - run this once in a terminal:<br />
                                  <code className="block mt-1.5 p-3 bg-amber-100 dark:bg-amber-900/40 rounded-lg font-mono text-[11px] leading-relaxed whitespace-pre select-all">
{`sudo tee /etc/udev/rules.d/70-fido-browser.rules > /dev/null << 'EOF'
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", GROUP="plugdev", MODE="0664"
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ENV{ID_SECURITY_TOKEN}=="1", GROUP="plugdev", MODE="0664"
EOF
sudo udevadm control --reload-rules && sudo udevadm trigger`}
                                  </code>
                                </li>
                                <li>
                                  <strong>Make sure your user is in the <code>plugdev</code> group:</strong><br />
                                  <code className="inline-block mt-1 px-2 py-0.5 bg-amber-100 dark:bg-amber-900/40 rounded font-mono text-[11px]">sudo adduser $USER plugdev</code>
                                  <span className="block text-amber-600 dark:text-amber-500 text-[10px] mt-0.5">Then log out and back in.</span>
                                </li>
                                <li><strong>Unplug and replug the YubiKey.</strong></li>
                              </ol>
                            </div>
                          </details>
                        )}

                        {!isWebAuthnSupported() ? (
                          <div className="p-5 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 rounded-xl flex items-start gap-3">
                            <AlertTriangle size={18} className="text-amber-600 shrink-0 mt-0.5" />
                            <p className="text-sm text-amber-800 dark:text-amber-300">WebAuthn is not supported in this browser.</p>
                          </div>
                        ) : (
                          <>
                            {!isSecureContext() && (
                              <div className="p-4 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-xl flex items-start gap-3">
                                <AlertTriangle size={16} className="text-amber-600 shrink-0 mt-0.5" />
                                <p className="text-xs text-amber-800 dark:text-amber-300 leading-relaxed">
                                  <strong>Note:</strong> Your browser may block key registration on plain HTTP. If registration fails, access the app over HTTPS or via <code>localhost</code>.
                                </p>
                              </div>
                            )}
                            <div className="space-y-4">
                              <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">Key name (for your reference)</label>
                              <input
                                type="text"
                                autoFocus
                                value={webAuthnKeyName}
                                onChange={e => setWebAuthnKeyName(e.target.value)}
                                onKeyDown={e => { if (e.key === 'Enter' && !webAuthnBusy) handleWebAuthnRegister(); }}
                                placeholder="e.g. YubiKey 5C Nano"
                                className="w-full px-5 py-3.5 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/20 outline-none transition-all"
                              />
                            </div>
                          </>
                        )}

                        {webAuthnError && (
                          <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/40 rounded-xl">
                            <div className="flex items-start gap-2 mb-1">
                              <AlertTriangle size={14} className="text-error shrink-0 mt-0.5" />
                              <p className="text-xs font-bold text-error">Registration failed</p>
                            </div>
                            <pre className="text-xs text-red-700 dark:text-red-300 whitespace-pre-wrap font-sans leading-relaxed ml-5">{webAuthnError}</pre>
                          </div>
                        )}

                        <div className="flex gap-3">
                          <button onClick={closeMfaModal} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Cancel</button>
                          <button
                            onClick={handleWebAuthnRegister}
                            disabled={webAuthnBusy || !isWebAuthnSupported()}
                            className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                          >
                            {webAuthnBusy ? <RefreshCw size={16} className="animate-spin" /> : <Key size={16} />}
                            {webAuthnBusy ? 'Touch your key…' : 'Register Key'}
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Success */}
                    {mfaModal.step === 3 && (
                      <div className="text-center py-6 space-y-6">
                        <div className="w-20 h-20 rounded-full bg-green-50 dark:bg-green-950/40 flex items-center justify-center mx-auto">
                          <CheckCircle size={40} className="text-green-600" />
                        </div>
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Key registered</h3>
                          <p className="text-on-surface-variant text-sm">"{webAuthnKeyName}" has been registered. Insert it and tap when prompted at login.</p>
                        </div>
                        <button onClick={closeMfaModal} className="w-full py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all">Done</button>
                      </div>
                    )}
                  </>
                )}

                {/* ════════════════════════════════════════════════════════════
                    EMAIL OTP
                    Step 1 = enter email address
                    Step 2 = enter code (simulated email preview shown)
                    Step 3 = success
                ═══════════════════════════════════════════════════════════ */}
                {mfaModal.type === 'email' && (
                  <>
                    {/* Manage / already active */}
                    {mfaConfig.email.enabled && mfaModal.step === 1 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Email Verification</h3>
                          <p className="text-on-surface-variant text-sm">OTP codes will be sent to:</p>
                        </div>
                        <div className="p-5 bg-surface-container-low rounded-xl border border-outline-variant/10 flex items-center gap-3">
                          <Mail size={18} className="text-on-surface-variant" />
                          <span className="font-bold text-sm">{mfaConfig.email.address}</span>
                        </div>
                        <div className="flex gap-3">
                          <button onClick={closeMfaModal} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Close</button>
                          <button
                            onClick={handleEmailRemove}
                            className="flex-1 py-4 bg-error/10 text-error rounded-xl font-black uppercase tracking-widest text-xs hover:bg-error/20 transition-all flex items-center justify-center gap-2"
                          >
                            <Trash2 size={14} />Remove
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Step 1 – enter email */}
                    {!mfaConfig.email.enabled && mfaModal.step === 1 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Set up Email Verification</h3>
                          <p className="text-on-surface-variant text-sm leading-relaxed">Enter the email address where you want to receive one-time login codes.</p>
                        </div>
                        <div className="space-y-3">
                          <label htmlFor="email-mfa" className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">Email address</label>
                          <input
                            id="email-mfa"
                            type="email"
                            autoFocus
                            value={emailInput}
                            onChange={e => setEmailInput(e.target.value.replace(/[^a-zA-Z0-9@.\-_+]/g, ''))}
                            onKeyDown={e => { if (e.key === 'Enter' && isEmailValid && !emailBusy) handleEmailSend(); }}
                            placeholder="you@example.com"
                            className="w-full px-5 py-3.5 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/20 outline-none transition-all"
                          />
                        </div>
                        <div className="flex gap-3">
                          <button onClick={closeMfaModal} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Cancel</button>
                          <button
                            onClick={handleEmailSend}
                            disabled={!isEmailValid || emailBusy}
                            className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                          >
                            {emailBusy ? <RefreshCw size={16} className="animate-spin" /> : <Mail size={16} />}
                            {emailBusy ? 'Sending…' : 'Send Code'}
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Step 2 – simulated email preview + code entry */}
                    {!mfaConfig.email.enabled && mfaModal.step === 2 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Enter the code</h3>
                          <p className="text-on-surface-variant text-sm">
                            In a production app the code would be emailed. Here is a simulated preview:
                          </p>
                        </div>

                        {/* Simulated email preview */}
                        <div className="rounded-2xl border border-outline-variant/20 overflow-hidden text-sm">
                          <div className="bg-surface-container-high px-5 py-3 flex items-center gap-3 border-b border-outline-variant/10">
                            <div className="w-8 h-8 rounded-full bg-black flex items-center justify-center shrink-0">
                              <ShieldCheck size={14} className="text-white" />
                            </div>
                            <div className="min-w-0">
                              <p className="font-bold text-xs truncate">PWDnow &lt;no-reply@pwdnow.app&gt;</p>
                              <p className="text-[10px] text-on-surface-variant truncate">To: {emailInput}</p>
                            </div>
                          </div>
                          <div className="px-6 py-5 bg-white dark:bg-surface-container-low">
                            <p className="font-bold mb-3">Your verification code</p>
                            <p className="text-on-surface-variant text-xs mb-4 leading-relaxed">Use the code below to complete your MFA setup. It expires in <strong>5 minutes</strong>.</p>
                            <div className="bg-surface-container-high rounded-xl py-4 text-center">
                              <span className="font-mono text-3xl font-black tracking-[0.4em] text-black dark:text-white">
                                {emailSimCode.slice(0,3)} {emailSimCode.slice(3)}
                              </span>
                            </div>
                            <p className="text-[10px] text-on-surface-variant mt-4">Do not share this code with anyone.</p>
                          </div>
                        </div>

                        {/* Code entry */}
                        <div className="flex items-center justify-center gap-2">
                          {[0,1,2].map(i => (
                            <input key={i} ref={el => { emailRefs.current[i] = el; }}
                              type="text" inputMode="numeric" maxLength={1} value={emailCode[i]}
                              onChange={e => emailHandlers.onChange(i, e.target.value)}
                              onKeyDown={e => { emailHandlers.onKeyDown(i, e); if (e.key === 'Enter' && !emailCode.some(c => !c)) handleEmailVerify(); }}
                              onPaste={i === 0 ? emailHandlers.onPaste : undefined}
                              className="w-12 h-14 text-center text-xl font-black bg-white dark:bg-[#1a1a1a] border-2 border-slate-400 dark:border-slate-400 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all text-black dark:text-white"
                            />
                          ))}
                          <div className="w-4 h-0.5 bg-slate-400 dark:bg-slate-400 rounded-full mx-1" />
                          {[3,4,5].map(i => (
                            <input key={i} ref={el => { emailRefs.current[i] = el; }}
                              type="text" inputMode="numeric" maxLength={1} value={emailCode[i]}
                              onChange={e => emailHandlers.onChange(i, e.target.value)}
                              onKeyDown={e => { emailHandlers.onKeyDown(i, e); if (e.key === 'Enter' && !emailCode.some(c => !c)) handleEmailVerify(); }}
                              className="w-12 h-14 text-center text-xl font-black bg-white dark:bg-[#1a1a1a] border-2 border-slate-400 dark:border-slate-400 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all text-black dark:text-white"
                            />
                          ))}
                        </div>

                        {emailError && (
                          <p className="text-xs font-bold text-error flex items-center gap-2"><AlertTriangle size={14} />{emailError}</p>
                        )}

                        <div className="flex gap-3">
                          <button onClick={() => { setMfaModal({ type: 'email', step: 1 }); setEmailCode(['','','','','','']); setEmailError(''); }} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Back</button>
                          <button
                            onClick={handleEmailVerify}
                            disabled={emailCode.some(c => !c)}
                            className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                          >
                            <ShieldCheck size={16} />Verify
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Success */}
                    {mfaModal.step === 3 && (
                      <div className="text-center py-6 space-y-6">
                        <div className="w-20 h-20 rounded-full bg-green-50 dark:bg-green-950/40 flex items-center justify-center mx-auto">
                          <CheckCircle size={40} className="text-green-600" />
                        </div>
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Email verification active</h3>
                          <p className="text-on-surface-variant text-sm">OTP codes will be sent to <strong className="text-black dark:text-white">{emailInput}</strong> at every login.</p>
                        </div>
                        <button onClick={closeMfaModal} className="w-full py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all">Done</button>
                      </div>
                    )}
                  </>
                )}

                {/* ════════════════════════════════════════════════════════════
                    PASSKEY – Synced Passkey (iCloud / Google)
                    Step 1 = name input + register (or manage if already set)
                    Step 3 = success
                ═══════════════════════════════════════════════════════════ */}
                {mfaModal.type === 'passkey' && (
                  <>
                    {/* Manage existing passkeys */}
                    {(mfaConfig.passkey?.enabled) && mfaModal.step === 1 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Passkeys</h3>
                          <p className="text-on-surface-variant text-sm leading-relaxed">Synced passkeys registered to this account.</p>
                        </div>

                        <div className="space-y-3">
                          {(mfaConfig.passkey?.credentials ?? []).map(cred => (
                            <div key={cred.id} className="flex items-center justify-between p-4 bg-surface-container-low rounded-xl border border-outline-variant/10">
                              <div className="flex items-center gap-3">
                                <KeyRound size={18} className="text-on-surface-variant" />
                                <div>
                                  <p className="font-bold text-sm">{cred.name}</p>
                                  <p className="text-[10px] text-on-surface-variant">Added {new Date(cred.createdAt).toLocaleDateString()}</p>
                                </div>
                              </div>
                              <button onClick={() => handlePasskeyRemove(cred.id)} className="p-2 text-error hover:bg-error/10 rounded-lg transition-colors" title="Remove passkey">
                                <Trash2 size={16} />
                              </button>
                            </div>
                          ))}
                        </div>

                        <div className="space-y-3">
                          <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">Add another passkey</label>
                          <div className="flex gap-3">
                            <input type="text" value={passkeyName} onChange={e => setPasskeyName(e.target.value)}
                              placeholder="e.g. MacBook Pro"
                              className="flex-1 px-4 py-3 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-bold text-sm focus:ring-2 focus:ring-black/20 outline-none" />
                            <button onClick={handlePasskeyRegister} disabled={passkeyBusy}
                              className="px-6 py-3 bg-black text-white rounded-xl font-black text-xs uppercase tracking-widest hover:bg-neutral-800 transition-all disabled:opacity-50 flex items-center gap-2">
                              {passkeyBusy ? <RefreshCw size={14} className="animate-spin" /> : <KeyRound size={14} />}Add
                            </button>
                          </div>
                          {passkeyError && <p className="text-xs font-bold text-error flex items-center gap-2"><AlertTriangle size={14} />{passkeyError}</p>}
                        </div>

                        <button onClick={closeMfaModal} className="w-full py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Close</button>
                      </div>
                    )}

                    {/* First-time setup */}
                    {!(mfaConfig.passkey?.enabled) && mfaModal.step === 1 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Register a Passkey</h3>
                          <p className="text-on-surface-variant text-sm leading-relaxed">
                            A passkey is stored in your iCloud Keychain (Mac/iPhone) or Google Password Manager (Android/Chrome) and syncs across your devices. On Mac, you'll be prompted for Touch ID.
                          </p>
                        </div>

                        {!isWebAuthnSupported() ? (
                          <div className="p-5 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 rounded-xl flex items-start gap-3">
                            <AlertTriangle size={18} className="text-amber-600 shrink-0 mt-0.5" />
                            <p className="text-sm text-amber-800 dark:text-amber-300">Passkeys are not supported in this browser.</p>
                          </div>
                        ) : (
                          <>
                            {!isSecureContext() && (
                              <div className="p-4 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-xl flex items-start gap-3">
                                <AlertTriangle size={16} className="text-amber-600 shrink-0 mt-0.5" />
                                <p className="text-xs text-amber-800 dark:text-amber-300 leading-relaxed"><strong>Note:</strong> Passkey registration requires HTTPS or <code>localhost</code>.</p>
                              </div>
                            )}
                            <div className="space-y-4">
                              <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">Passkey name</label>
                              <input type="text" autoFocus value={passkeyName} onChange={e => setPasskeyName(e.target.value)}
                                onKeyDown={e => { if (e.key === 'Enter' && !passkeyBusy) handlePasskeyRegister(); }}
                                placeholder="e.g. MacBook Pro"
                                className="w-full px-5 py-3.5 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/20 outline-none transition-all" />
                            </div>
                          </>
                        )}

                        {passkeyError && <p className="text-xs font-bold text-error flex items-center gap-2"><AlertTriangle size={14} />{passkeyError}</p>}

                        <div className="flex gap-3">
                          <button onClick={closeMfaModal} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Cancel</button>
                          <button onClick={handlePasskeyRegister} disabled={passkeyBusy || !isWebAuthnSupported()}
                            className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2 disabled:opacity-50">
                            {passkeyBusy ? <RefreshCw size={16} className="animate-spin" /> : <KeyRound size={16} />}
                            {passkeyBusy ? 'Waiting for Touch ID…' : 'Create Passkey'}
                          </button>
                        </div>
                      </div>
                    )}

                    {mfaModal.step === 3 && (
                      <div className="text-center py-6 space-y-6">
                        <div className="w-20 h-20 rounded-full bg-green-50 dark:bg-green-950/40 flex items-center justify-center mx-auto">
                          <CheckCircle size={40} className="text-green-600" />
                        </div>
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Passkey created</h3>
                          <p className="text-on-surface-variant text-sm">"{passkeyName}" is saved. You can now use Touch ID or your passkey provider to sign in.</p>
                        </div>
                        <button onClick={closeMfaModal} className="w-full py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all">Done</button>
                      </div>
                    )}
                  </>
                )}

                {/* ════════════════════════════════════════════════════════════
                    PLATFORM AUTH – Touch ID / Windows Hello / Face ID
                    Step 1 = name input + register (or manage if already set)
                    Step 3 = success
                ═══════════════════════════════════════════════════════════ */}
                {mfaModal.type === 'platform' && (
                  <>
                    {/* Manage existing */}
                    {(mfaConfig.platform?.enabled) && mfaModal.step === 1 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Touch ID / Windows Hello</h3>
                          <p className="text-on-surface-variant text-sm leading-relaxed">Device-bound biometric authenticators registered to this account.</p>
                        </div>

                        <div className="space-y-3">
                          {(mfaConfig.platform?.credentials ?? []).map(cred => (
                            <div key={cred.id} className="flex items-center justify-between p-4 bg-surface-container-low rounded-xl border border-outline-variant/10">
                              <div className="flex items-center gap-3">
                                <Fingerprint size={18} className="text-on-surface-variant" />
                                <div>
                                  <p className="font-bold text-sm">{cred.name}</p>
                                  <p className="text-[10px] text-on-surface-variant">Added {new Date(cred.createdAt).toLocaleDateString()}</p>
                                </div>
                              </div>
                              <button onClick={() => handlePlatformRemove(cred.id)} className="p-2 text-error hover:bg-error/10 rounded-lg transition-colors" title="Remove">
                                <Trash2 size={16} />
                              </button>
                            </div>
                          ))}
                        </div>

                        <div className="space-y-3">
                          <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">Add another device</label>
                          <div className="flex gap-3">
                            <input type="text" value={platformName} onChange={e => setPlatformName(e.target.value)}
                              placeholder="e.g. MacBook Pro"
                              className="flex-1 px-4 py-3 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-bold text-sm focus:ring-2 focus:ring-black/20 outline-none" />
                            <button onClick={handlePlatformRegister} disabled={platformBusy}
                              className="px-6 py-3 bg-black text-white rounded-xl font-black text-xs uppercase tracking-widest hover:bg-neutral-800 transition-all disabled:opacity-50 flex items-center gap-2">
                              {platformBusy ? <RefreshCw size={14} className="animate-spin" /> : <Fingerprint size={14} />}Add
                            </button>
                          </div>
                          {platformError && <p className="text-xs font-bold text-error flex items-center gap-2"><AlertTriangle size={14} />{platformError}</p>}
                        </div>

                        <button onClick={closeMfaModal} className="w-full py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Close</button>
                      </div>
                    )}

                    {/* First-time setup */}
                    {!(mfaConfig.platform?.enabled) && mfaModal.step === 1 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Register Touch ID / Windows Hello</h3>
                          <p className="text-on-surface-variant text-sm leading-relaxed">
                            This registers a device-bound biometric credential. Your fingerprint or face data stays on this device and is never synced or shared.
                          </p>
                        </div>

                        {!isWebAuthnSupported() ? (
                          <div className="p-5 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 rounded-xl flex items-start gap-3">
                            <AlertTriangle size={18} className="text-amber-600 shrink-0 mt-0.5" />
                            <p className="text-sm text-amber-800 dark:text-amber-300">Platform biometrics are not supported in this browser.</p>
                          </div>
                        ) : (
                          <>
                            {!isSecureContext() && (
                              <div className="p-4 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-xl flex items-start gap-3">
                                <AlertTriangle size={16} className="text-amber-600 shrink-0 mt-0.5" />
                                <p className="text-xs text-amber-800 dark:text-amber-300 leading-relaxed"><strong>Note:</strong> Biometric registration requires HTTPS or <code>localhost</code>.</p>
                              </div>
                            )}
                            <div className="space-y-4">
                              <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">Device name</label>
                              <input type="text" autoFocus value={platformName} onChange={e => setPlatformName(e.target.value)}
                                onKeyDown={e => { if (e.key === 'Enter' && !platformBusy) handlePlatformRegister(); }}
                                placeholder="e.g. MacBook Pro"
                                className="w-full px-5 py-3.5 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/20 outline-none transition-all" />
                            </div>
                          </>
                        )}

                        {platformError && <p className="text-xs font-bold text-error flex items-center gap-2"><AlertTriangle size={14} />{platformError}</p>}

                        <div className="flex gap-3">
                          <button onClick={closeMfaModal} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Cancel</button>
                          <button onClick={handlePlatformRegister} disabled={platformBusy || !isWebAuthnSupported()}
                            className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2 disabled:opacity-50">
                            {platformBusy ? <RefreshCw size={16} className="animate-spin" /> : <Fingerprint size={16} />}
                            {platformBusy ? 'Waiting for biometric…' : 'Register Biometric'}
                          </button>
                        </div>
                      </div>
                    )}

                    {mfaModal.step === 3 && (
                      <div className="text-center py-6 space-y-6">
                        <div className="w-20 h-20 rounded-full bg-green-50 dark:bg-green-950/40 flex items-center justify-center mx-auto">
                          <CheckCircle size={40} className="text-green-600" />
                        </div>
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Biometric registered</h3>
                          <p className="text-on-surface-variant text-sm">"{platformName}" can now be used to sign in on this device.</p>
                        </div>
                        <button onClick={closeMfaModal} className="w-full py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all">Done</button>
                      </div>
                    )}
                  </>
                )}

              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Email Server Modal */}
      <AnimatePresence>
        {isEmailServerModalOpen && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40"
              onClick={() => setIsEmailServerModalOpen(false)}
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-lg bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl border border-outline-variant/10 overflow-hidden"
            >
              <div className="p-10 max-h-[90vh] overflow-y-auto">
                {/* Header */}
                <div className="flex items-center justify-between mb-8">
                  <div className="w-12 h-12 rounded-2xl bg-black dark:bg-white flex items-center justify-center">
                    <Server className="text-white dark:text-black" size={24} />
                  </div>
                  <button
                    onClick={() => setIsEmailServerModalOpen(false)}
                    className="p-2 hover:bg-surface-container-low rounded-full transition-colors"
                  >
                    <X size={20} />
                  </button>
                </div>

                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">
                  {t('settings.emailServerSetupTitle', 'Email Server Setup')}
                </h3>
                <p className="text-on-surface-variant text-sm mb-8">
                  {t('settings.emailServerSetupSubtitle', 'Configure your outgoing mail (SMTP) settings.')}
                </p>

                {/* Protocol Selector */}
                <div className="mb-6">
                  <label className="block text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-3">
                    {t('settings.smtpProtocol', 'Security Protocol')}
                  </label>
                  <div className="grid grid-cols-2 gap-3">
                    {([
                      { key: 'smtp' as SmtpProtocol, label: t('settings.smtpProtoSmtp', 'SMTP'), desc: t('settings.smtpProtoSmtpDesc', 'Port 25 - Legacy plaintext') },
                      { key: 'esmtp' as SmtpProtocol, label: t('settings.smtpProtoEsmtp', 'ESMTP'), desc: t('settings.smtpProtoEsmtpDesc', 'Port 587 - Extended SMTP') },
                      { key: 'starttls' as SmtpProtocol, label: t('settings.smtpProtoStarttls', 'STARTTLS'), desc: t('settings.smtpProtoStarttlsDesc', 'Port 587 - Upgrades to TLS'), recommended: true },
                      { key: 'ssl_tls' as SmtpProtocol, label: t('settings.smtpProtoSslTls', 'SSL / TLS'), desc: t('settings.smtpProtoSslTlsDesc', 'Port 465 - Implicit TLS') },
                    ] as { key: SmtpProtocol; label: string; desc: string; recommended?: boolean }[]).map(({ key, label, desc, recommended }) => (
                      <button
                        key={key}
                        type="button"
                        onClick={() => handleEmailProtocolChange(key)}
                        className={`text-left p-4 rounded-xl border-2 transition-all ${
                          emailServerForm.protocol === key
                            ? 'border-black dark:border-white bg-black/5 dark:bg-white/10'
                            : 'border-outline-variant/30 hover:border-outline-variant'
                        }`}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-bold text-sm text-black dark:text-white">{label}</span>
                          {recommended && (
                            <span className="text-[9px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-400">
                              {t('settings.recommended', 'Recommended')}
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-on-surface-variant leading-snug">{desc}</p>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Host + Port */}
                <div className="grid grid-cols-3 gap-4 mb-4">
                  <div className="col-span-2">
                    <label className="block text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-2">
                      {t('settings.smtpHost', 'SMTP Host')}
                    </label>
                    <input
                      type="text"
                      value={emailServerForm.host}
                      onChange={e => { setEmailServerForm(p => ({ ...p, host: e.target.value })); setEmailTestResult('idle'); }}
                      placeholder={t('settings.smtpHostPlaceholder', 'mail.example.com')}
                      className="w-full px-4 py-3 rounded-xl border border-outline-variant/30 bg-surface-container-high text-black dark:text-white placeholder:text-on-surface-variant/50 focus:ring-2 focus:ring-black dark:focus:ring-white focus:border-transparent outline-none text-sm transition-all"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-2">
                      {t('settings.smtpPort', 'Port')}
                    </label>
                    <input
                      type="number"
                      value={emailServerForm.port}
                      onChange={e => { setEmailServerForm(p => ({ ...p, port: Number(e.target.value) })); setEmailTestResult('idle'); }}
                      className="w-full px-4 py-3 rounded-xl border border-outline-variant/30 bg-surface-container-high text-black dark:text-white focus:ring-2 focus:ring-black dark:focus:ring-white focus:border-transparent outline-none text-sm transition-all"
                    />
                  </div>
                </div>

                {/* Username */}
                <div className="mb-4">
                  <label className="block text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-2">
                    {t('settings.smtpUsername', 'Username')}
                  </label>
                  <input
                    type="email"
                    value={emailServerForm.username}
                    onChange={e => { setEmailServerForm(p => ({ ...p, username: e.target.value })); setEmailTestResult('idle'); }}
                    placeholder={t('settings.smtpUsernamePlaceholder', 'user@example.com')}
                    className="w-full px-4 py-3 rounded-xl border border-outline-variant/30 bg-surface-container-high text-black dark:text-white placeholder:text-on-surface-variant/50 focus:ring-2 focus:ring-black dark:focus:ring-white focus:border-transparent outline-none text-sm transition-all"
                  />
                </div>

                {/* Password */}
                <div className="mb-4">
                  <label className="block text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-2">
                    {t('settings.smtpPassword', 'Password')}
                  </label>
                  <div className="relative">
                    <input
                      type={showSmtpPassword ? 'text' : 'password'}
                      value={emailServerForm.password}
                      onChange={e => { setEmailServerForm(p => ({ ...p, password: e.target.value })); setEmailTestResult('idle'); }}
                      placeholder="••••••••"
                      className="w-full px-4 py-3 pr-12 rounded-xl border border-outline-variant/30 bg-surface-container-high text-black dark:text-white placeholder:text-on-surface-variant/50 focus:ring-2 focus:ring-black dark:focus:ring-white focus:border-transparent outline-none text-sm transition-all"
                    />
                    <button
                      type="button"
                      onClick={() => setShowSmtpPassword(p => !p)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-black dark:hover:text-white transition-colors"
                      aria-label={showSmtpPassword ? 'Hide password' : 'Show password'}
                    >
                      {showSmtpPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>
                </div>

                {/* From Name + From Address */}
                <div className="grid grid-cols-2 gap-4 mb-8">
                  <div>
                    <label className="block text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-2">
                      {t('settings.smtpFromName', 'From Name')}
                    </label>
                    <input
                      type="text"
                      value={emailServerForm.fromName}
                      onChange={e => setEmailServerForm(p => ({ ...p, fromName: e.target.value }))}
                      placeholder={t('settings.smtpFromNamePlaceholder', 'PWDnow')}
                      className="w-full px-4 py-3 rounded-xl border border-outline-variant/30 bg-surface-container-high text-black dark:text-white placeholder:text-on-surface-variant/50 focus:ring-2 focus:ring-black dark:focus:ring-white focus:border-transparent outline-none text-sm transition-all"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-2">
                      {t('settings.smtpFromAddress', 'From Email')}
                    </label>
                    <input
                      type="email"
                      value={emailServerForm.fromAddress}
                      onChange={e => setEmailServerForm(p => ({ ...p, fromAddress: e.target.value }))}
                      placeholder={t('settings.smtpFromAddressPlaceholder', 'noreply@example.com')}
                      className="w-full px-4 py-3 rounded-xl border border-outline-variant/30 bg-surface-container-high text-black dark:text-white placeholder:text-on-surface-variant/50 focus:ring-2 focus:ring-black dark:focus:ring-white focus:border-transparent outline-none text-sm transition-all"
                    />
                  </div>
                </div>

                {/* Test Connection */}
                <div className="flex items-center gap-4 mb-4">
                  <button
                    type="button"
                    onClick={handleTestConnection}
                    disabled={emailTestResult === 'testing' || !emailServerForm.host || !emailServerForm.username}
                    className="px-6 py-3 rounded-xl border-2 border-black dark:border-white font-bold text-sm text-black dark:text-white hover:bg-black hover:text-white dark:hover:bg-white dark:hover:text-black disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center gap-2"
                  >
                    {emailTestResult === 'testing'
                      ? <><Loader2 size={16} className="animate-spin" />{t('settings.testingConnection', 'Testing…')}</>
                      : t('settings.testConnection', 'Test Connection')
                    }
                  </button>
                  {emailTestResult === 'success' && (
                    <span className="flex items-center gap-1.5 text-sm font-bold text-green-600 dark:text-green-400">
                      <Check size={16} /> {t('settings.connectionOk', 'Connection successful')}
                    </span>
                  )}
                  {emailTestResult === 'failure' && (
                    <span className="flex items-center gap-1.5 text-sm font-bold text-red-600 dark:text-red-400">
                      <AlertTriangle size={16} /> {t('settings.connectionFailed', 'Connection failed')}
                    </span>
                  )}
                </div>

                {/* Save */}
                <button
                  type="button"
                  onClick={handleSaveEmailServer}
                  disabled={isSavingEmailServer || !emailServerForm.host || !emailServerForm.username}
                  className="w-full py-4 bg-black dark:bg-white text-white dark:text-black rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
                >
                  {isSavingEmailServer
                    ? <><Loader2 size={16} className="animate-spin" />{t('common.processing', 'Processing...')}</>
                    : t('common.save', 'Save')
                  }
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── Travel Mode Modal ─────────────────────────────────────────────────── */}
      <AnimatePresence>
        {isTravelModalOpen && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40"
              onClick={() => setIsTravelModalOpen(false)}
            />
            <motion.div initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-lg bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl border border-outline-variant/10 overflow-hidden max-h-[90vh] flex flex-col"
            >
              <div className="p-8 border-b border-outline-variant/10 flex items-center justify-between shrink-0">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-2xl bg-blue-600 flex items-center justify-center">
                    <Plane className="text-white" size={22} />
                  </div>
                  <div>
                    <h3 className="text-xl font-headline font-black text-black dark:text-white">{t('settings.enableTravelMode', 'Enable Travel Mode')}</h3>
                    <p className="text-xs text-on-surface-variant mt-0.5">{t('settings.travelStep', 'Step {{step}} of 4', { step: travelStep })}</p>
                  </div>
                </div>
                <button onClick={() => setIsTravelModalOpen(false)} className="p-2 hover:bg-surface-container-high rounded-full transition-colors"><X size={20} /></button>
              </div>

              <div className="overflow-y-auto flex-1 p-8">
                {travelStep === 1 && (
                  <div className="space-y-6">
                    <div>
                      <p className="text-sm text-on-surface-variant leading-relaxed mb-5">
                        {t('settings.travelStep1Desc', 'Select which folders to hide when Travel Mode is active. These folders will be AES-256-GCM encrypted and invisible until you disable Travel Mode with your travel password.')}
                      </p>
                      <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-3">{t('settings.travelSelectFolders', 'Select folders to hide')}</p>
                      {folders.length === 0 ? (
                        <p className="text-sm text-on-surface-variant text-center py-8">{t('settings.travelNoFolders', 'No folders found. Create folders in your vault first.')}</p>
                      ) : (
                        <div className="space-y-2">
                          {folders.map(folder => {
                            const selected = travelHiddenFolderIds.includes(folder.id);
                            return (
                              <button key={folder.id} type="button" onClick={() => toggleTravelFolder(folder.id)}
                                className={`w-full flex items-center justify-between p-4 rounded-xl border-2 transition-all text-left ${
                                  selected ? 'border-blue-600 bg-blue-50 dark:bg-blue-950/30' : 'border-outline-variant/20 hover:border-outline-variant/50'
                                }`}
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
                    </div>
                    {travelError && <p className="text-xs font-bold text-red-600 uppercase tracking-widest">{travelError}</p>}
                    <button onClick={() => { if (travelHiddenFolderIds.length === 0) { setTravelError(t('settings.travelSelectAtLeastOne', 'Select at least one folder to hide.')); return; } setTravelError(''); setTravelStep(2); }}
                      className="w-full py-4 bg-blue-600 text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-blue-700 transition-all"
                    >
                      {t('settings.travelNextStep', 'Next - Set Travel Password')}
                    </button>
                  </div>
                )}

                {travelStep === 2 && (
                  <div className="space-y-6">
                    <p className="text-sm text-on-surface-variant leading-relaxed">
                      {t('settings.travelPasswordDesc', 'This password is required to restore hidden folders. It is separate from your main vault password and is used only to decrypt the hidden vault.')}
                    </p>
                    <form onSubmit={e => e.preventDefault()} className="space-y-6">
                      <input type="text" name="username" value="user" readOnly autoComplete="username" className="hidden" aria-hidden="true" />
                      <div className="space-y-3">
                        <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('settings.travelPasswordLabel', 'Password')}</label>
                        <div className="relative">
                          <input type={showTravelPassword ? 'text' : 'password'} value={travelPassword}
                            onChange={e => { setTravelPassword(e.target.value); setTravelError(''); }}
                            placeholder={t('settings.travelPasswordMin', 'Minimum 8 characters')}
                            className="w-full px-5 py-4 pr-12 bg-surface-container-low rounded-xl border border-zinc-300 dark:border-zinc-600 text-black dark:text-white font-bold focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500 dark:focus:border-blue-400 outline-none transition-all"
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
                          className="w-full px-5 py-4 bg-surface-container-low rounded-xl border border-zinc-300 dark:border-zinc-600 text-black dark:text-white font-bold focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500 dark:focus:border-blue-400 outline-none transition-all"
                        />
                      </div>
                    </form>
                    {travelError && <p className="text-xs font-bold text-red-600 uppercase tracking-widest">{travelError}</p>}
                    <div className="flex gap-3">
                      <button onClick={() => setTravelStep(1)} className="flex-1 py-4 bg-surface-container-low rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Back</button>
                      <button onClick={() => { if (travelPassword.length < 8) { setTravelError(t('settings.travelPasswordMinError', 'Minimum 8 characters.')); return; } if (travelPassword !== confirmTravelPassword) { setTravelError(t('settings.travelPasswordMismatch', 'Passwords do not match.')); return; } setTravelError(''); setTravelStep(3); }}
                        className="flex-1 py-4 bg-blue-600 text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-blue-700 transition-all"
                      >
                        Continue
                      </button>
                    </div>
                  </div>
                )}

                {travelStep === 3 && (
                  <div className="space-y-6">
                    <div className="p-5 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-2xl flex items-start gap-3">
                      <AlertTriangle size={20} className="text-amber-600 shrink-0 mt-0.5" />
                      <div>
                        <p className="font-bold text-sm text-amber-800 dark:text-amber-300 mb-1">{t('settings.travelWarningTitle', 'Store your password safely')}</p>
                        <p className="text-xs text-amber-700/70 dark:text-amber-400/70 leading-relaxed">
                          {t('settings.travelWarningDesc', 'If you forget it, the hidden folders cannot be recovered - they are encrypted with your password. There is no backdoor.')}
                        </p>
                      </div>
                    </div>
                    <div className="space-y-3">
                      <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('settings.travelFoldersToHide', 'Folders that will be hidden')}</p>
                      {folders.filter(f => travelHiddenFolderIds.includes(f.id)).map(f => (
                        <div key={f.id} className="flex items-center gap-3 p-3 bg-surface-container-low rounded-xl">
                          <Plane size={16} className="text-blue-600 shrink-0" />
                          <span className="font-bold text-sm text-black dark:text-white">{f.label}</span>
                          <span className="text-xs text-on-surface-variant ml-auto">
                            {t('settings.travelCredentialCount', '{{count}} credential(s)', { count: credentials.filter(c => c.folderId === f.id).length })}
                          </span>
                        </div>
                      ))}
                    </div>
                    {travelError && <p className="text-xs font-bold text-red-600 uppercase tracking-widest">{travelError}</p>}
                    <div className="flex gap-3">
                      <button onClick={() => setTravelStep(2)} className="flex-1 py-4 bg-surface-container-low rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Back</button>
                      <button onClick={handleEnableTravel} disabled={isEnablingTravel}
                        className="flex-1 py-4 bg-blue-600 text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-blue-700 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                      >
                        {isEnablingTravel
                          ? (
                            <svg width="28" height="28" viewBox="0 0 28 28" fill="none" className="animate-spin">
                              <circle cx="14" cy="14" r="11" stroke="rgba(255,255,255,0.25)" strokeWidth="3"/>
                              <circle cx="14" cy="14" r="11" stroke="white" strokeWidth="3" strokeLinecap="round" strokeDasharray="17 52"/>
                            </svg>
                          )
                          : <><Plane size={16} />{t('settings.travelActivate', 'Activate Travel Mode')}</>
                        }
                      </button>
                    </div>
                  </div>
                )}

                {travelStep === 4 && (
                  <div className="text-center py-6 space-y-6">
                    <div className="w-20 h-20 rounded-full bg-blue-100 dark:bg-blue-950/50 flex items-center justify-center mx-auto">
                      <Plane size={40} className="text-blue-600" />
                    </div>
                    <div>
                      <h3 className="text-xl font-headline font-black text-black dark:text-white mb-2">{t('settings.travelActivateConfirmTitle', 'Travel Mode Active')}</h3>
                      <p className="text-sm text-on-surface-variant leading-relaxed">
                        {t('settings.travelActivateConfirmDesc', 'Hidden folders are encrypted and invisible. Your vault has been updated.')}
                      </p>
                    </div>
                    <button onClick={() => setIsTravelModalOpen(false)}
                      className="w-full py-4 bg-blue-600 text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-blue-700 transition-all"
                    >
                      Done
                    </button>
                  </div>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── Import Preview Modal ──────────────────────────────────────────────── */}
      <AnimatePresence>
        {isImportModalOpen && importResult && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40"
              onClick={() => !isImporting && setIsImportModalOpen(false)}
            />
            <motion.div initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-xl bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl border border-outline-variant/10 overflow-hidden max-h-[90vh] flex flex-col"
            >
              {/* Header */}
              <div className="flex items-center justify-between p-6 border-b border-outline-variant/10">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-black dark:bg-white flex items-center justify-center shrink-0">
                    <Upload size={18} className="text-white dark:text-black" />
                  </div>
                  <div>
                    <h3 className="text-lg font-headline font-black text-black dark:text-white">{t('settings.importPreviewTitle', 'Import Preview')}</h3>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[10px] px-2 py-0.5 bg-surface-container-high rounded-full font-black uppercase tracking-widest text-on-surface-variant">
                        {getFormat(importResult.detectedFormat)?.label ?? importResult.detectedFormat}
                      </span>
                      <span className="text-xs text-on-surface-variant">{importFileName}</span>
                    </div>
                  </div>
                </div>
                <button onClick={() => !isImporting && setIsImportModalOpen(false)} className="p-2 hover:bg-surface-container-high rounded-full transition-colors">
                  <X size={20} />
                </button>
              </div>

              {/* Body */}
              <div className="overflow-y-auto flex-1 p-6 space-y-5">
                {/* Count */}
                <div className="p-4 bg-surface-container-high rounded-xl flex items-center gap-3">
                  <CheckCircle size={18} className="text-green-600 shrink-0" />
                  <p className="text-sm font-bold text-black dark:text-white">
                    {t('settings.importCredentialsFound', '{{count}} credential(s) found', { count: importResult.credentials.length })}
                  </p>
                </div>

                {/* Preview table */}
                <div>
                  <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-2">{t('settings.importPreviewLabel', 'Preview (first 8)')}</p>
                  <div className="rounded-xl border border-outline-variant/20 overflow-hidden">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="bg-surface-container-high">
                          <th className="text-left px-3 py-2 font-black uppercase tracking-widest text-on-surface-variant text-[10px]">Service</th>
                          <th className="text-left px-3 py-2 font-black uppercase tracking-widest text-on-surface-variant text-[10px]">Username</th>
                          <th className="text-left px-3 py-2 font-black uppercase tracking-widest text-on-surface-variant text-[10px] hidden sm:table-cell">URL</th>
                        </tr>
                      </thead>
                      <tbody>
                        {importResult.credentials.slice(0, 8).map((c, i) => (
                          <tr key={i} className="border-t border-outline-variant/10 hover:bg-surface-container-high/50">
                            <td className="px-3 py-2 font-bold text-black dark:text-white truncate max-w-[120px]">{c.service}</td>
                            <td className="px-3 py-2 text-on-surface-variant truncate max-w-[120px]">{c.username}</td>
                            <td className="px-3 py-2 text-on-surface-variant truncate max-w-[140px] hidden sm:table-cell">{c.url}</td>
                          </tr>
                        ))}
                        {importResult.credentials.length > 8 && (
                          <tr className="border-t border-outline-variant/10">
                            <td colSpan={3} className="px-3 py-2 text-center text-on-surface-variant text-[11px]">
                              {t('settings.importMoreItems', '+{{count}} more', { count: importResult.credentials.length - 8 })}
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Import mode toggle */}
                <div>
                  <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-2">{t('settings.importModeLabel', 'Import mode')}</p>
                  <div className="grid grid-cols-2 gap-3">
                    <button
                      type="button"
                      onClick={() => setImportMode('merge')}
                      className={`px-4 py-3 rounded-xl border-2 text-sm font-bold transition-all text-left ${
                        importMode === 'merge'
                          ? 'border-black dark:border-white bg-black dark:bg-white text-white dark:text-black'
                          : 'border-outline-variant/30 hover:border-outline-variant/60 text-on-surface-variant'
                      }`}
                    >
                      <p className="font-black">{t('settings.importMergeName', 'Merge')}</p>
                      <p className={`text-[11px] mt-0.5 font-normal ${importMode === 'merge' ? 'text-white/70 dark:text-black/60' : 'text-on-surface-variant'}`}>{t('settings.importMergeDesc', 'Add alongside existing')}</p>
                    </button>
                    <button
                      type="button"
                      onClick={() => setImportMode('replace')}
                      className={`px-4 py-3 rounded-xl border-2 text-sm font-bold transition-all text-left ${
                        importMode === 'replace'
                          ? 'border-red-600 bg-red-600 text-white'
                          : 'border-outline-variant/30 hover:border-red-300 text-on-surface-variant'
                      }`}
                    >
                      <p className="font-black">{t('settings.importReplaceName', 'Replace All')}</p>
                      <p className={`text-[11px] mt-0.5 font-normal ${importMode === 'replace' ? 'text-white/70' : 'text-on-surface-variant'}`}>{t('settings.importReplaceDesc', 'Delete existing first')}</p>
                    </button>
                  </div>
                  {importMode === 'replace' && (
                    <div className="mt-3 p-3 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 rounded-xl flex items-start gap-2">
                      <AlertTriangle size={15} className="text-red-600 shrink-0 mt-0.5" />
                      <p className="text-xs text-red-700 dark:text-red-400 font-bold">
                        {t('settings.importReplaceWarning', 'This will permanently delete all {{count}} existing credential(s) before importing. This cannot be undone.', { count: credentials.length })}
                      </p>
                    </div>
                  )}
                </div>
              </div>

              {/* Footer */}
              <div className="flex gap-3 p-6 border-t border-outline-variant/10">
                <button
                  onClick={() => setIsImportModalOpen(false)}
                  disabled={isImporting}
                  className="flex-1 py-3.5 bg-surface-container-low rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleConfirmImport}
                  disabled={isImporting}
                  className={`flex-1 py-3.5 rounded-xl font-black uppercase tracking-widest text-xs transition-all flex items-center justify-center gap-2 disabled:opacity-50 ${
                    importMode === 'replace'
                      ? 'bg-red-600 hover:bg-red-700 text-white'
                      : 'bg-black dark:bg-white text-white dark:text-black hover:opacity-90'
                  }`}
                >
                  {isImporting
                    ? <svg width="20" height="20" viewBox="0 0 20 20" fill="none" className="animate-spin"><circle cx="10" cy="10" r="8" stroke="rgba(255,255,255,0.3)" strokeWidth="2.5"/><circle cx="10" cy="10" r="8" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeDasharray="12 38"/></svg>
                    : <><Upload size={14} />{t('settings.importButton', 'Import {{count}} credential(s)', { count: importResult.credentials.length })}</>
                  }
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── Disable Travel Mode Modal ─────────────────────────────────────────── */}
      <AnimatePresence>
        {isDisableTravelOpen && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40"
              onClick={() => setIsDisableTravelOpen(false)}
            />
            <motion.div initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-md bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl border border-outline-variant/10 p-8"
            >
              <div className="flex items-center justify-between mb-8">
                <div className="w-12 h-12 rounded-2xl bg-blue-600 flex items-center justify-center">
                  <Plane className="text-white" size={22} />
                </div>
                <button onClick={() => setIsDisableTravelOpen(false)} className="p-2 hover:bg-surface-container-high rounded-full transition-colors"><X size={20} /></button>
              </div>
              <h3 className="text-xl font-headline font-black text-black dark:text-white mb-2">{t('settings.travelDisableTitle', 'Disable Travel Mode')}</h3>
              <p className="text-sm text-on-surface-variant leading-relaxed mb-8">
                {t('settings.travelDisableDesc', 'Enter your travel password to decrypt and restore {{count}} hidden folder(s).', { count: travelConfig.hiddenFolderIds.length })}
              </p>
              <form onSubmit={e => { e.preventDefault(); handleDisableTravel(); }} className="space-y-3 mb-6">
                <input type="text" name="username" value="user" readOnly autoComplete="username" className="hidden" aria-hidden="true" />
                <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('settings.travelPasswordLabel', 'Password')}</label>
                <input type="password" value={disableTravelPw}
                  onChange={e => { setDisableTravelPw(e.target.value); setDisableTravelError(''); }}
                  placeholder={t('settings.travelPasswordPlaceholder', 'Enter your travel password')}
                  autoComplete="current-password"
                  className="w-full px-5 py-4 bg-surface-container-low rounded-xl border border-zinc-300 dark:border-zinc-600 text-black dark:text-white font-bold focus:ring-2 focus:ring-blue-600/20 focus:border-blue-600 outline-none transition-all"
                />
                {disableTravelError && <p className="text-xs font-bold text-red-600 uppercase tracking-widest">{disableTravelError}</p>}
              </form>
              <div className="flex gap-3">
                <button onClick={() => setIsDisableTravelOpen(false)} className="flex-1 py-4 bg-surface-container-low rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Cancel</button>
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

      {/* ── Arm Duress Mode Modal ─────────────────────────────────────────────── */}
      <AnimatePresence>
        {isDuressModalOpen && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40"
              onClick={() => setIsDuressModalOpen(false)}
            />
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
                      <h3 className="text-xl font-headline font-black text-black dark:text-white mb-2">{t('settings.duressArmedTitle', 'Duress Mode Armed')}</h3>
                      <p className="text-sm text-on-surface-variant">
                        {t('settings.duressArmedConfirmDesc', 'Entering the duress password at login will trigger an immediate forensic wipe. Auto-wipe activates after {{count}} failed attempt(s).', { count: duressMaxAttempts })}
                      </p>
                    </div>
                    <button onClick={() => setIsDuressModalOpen(false)}
                      className="w-full py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-neutral-800 transition-all"
                    >
                      Done
                    </button>
                  </div>
                ) : (
                  <>
                    <h3 className="text-xl font-headline font-black text-black dark:text-white mb-2">{t('settings.duressSetupTitle', 'Arm Duress Mode')}</h3>
                    <p className="text-sm text-on-surface-variant leading-relaxed mb-8">
                      {duressStep === 1
                        ? t('settings.duressStep1Desc', 'Set a duress password - different from your main password. Entering it at login triggers an immediate forensic wipe of all vault data.')
                        : t('settings.duressStep2Desc', 'Confirm your duress password. This cannot be recovered.')}
                    </p>

                    <form onSubmit={e => e.preventDefault()} className="space-y-5">
                      <input type="text" name="username" value="user" readOnly autoComplete="username" className="hidden" aria-hidden="true" />
                      {duressStep === 1 && (
                        <div className="space-y-3">
                          <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('settings.duressPasswordLabel', 'Duress Password')}</label>
                          <div className="relative">
                            <input type={showDuressPassword ? 'text' : 'password'} value={duressPassword}
                              onChange={e => { setDuressPassword(e.target.value); setDuressError(''); }}
                              placeholder={t('settings.duressPasswordMin', 'Minimum 8 characters')}
                              autoComplete="new-password"
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
                          <button onClick={() => setDuressStep(1)} className="flex-1 py-4 bg-surface-container-low rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Back</button>
                        )}
                        <button
                          type="submit"
                          onClick={() => {
                            if (duressStep === 1) {
                              if (duressPassword.length < 8) { setDuressError(t('settings.duressPasswordMinError', 'Duress password must be at least 8 characters.')); return; }
                              setDuressError('');
                              setDuressStep(2);
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
                    </form>
                  </>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── Trigger Wipe Confirmation Modal ──────────────────────────────────── */}
      <AnimatePresence>
        {isDuressWipeOpen && (
          <div className="fixed inset-0 z-[110] flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40"
              onClick={() => !isWiping && setIsDuressWipeOpen(false)}
            />
            <motion.div initial={{ opacity: 0, scale: 0.9, y: 30 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.9, y: 30 }}
              className="relative w-full max-w-sm bg-red-950 rounded-3xl shadow-2xl border border-red-800 p-8 text-white text-center"
            >
              <div className="w-20 h-20 rounded-full bg-red-900/60 border-2 border-red-700 flex items-center justify-center mx-auto mb-6">
                <Flame size={40} className="text-red-400" />
              </div>
              <h3 className="text-2xl font-headline font-black mb-3">Confirm Wipe</h3>
              <p className="text-red-200 text-sm leading-relaxed mb-8">
                This will immediately perform a 3-pass forensic overwrite and delete ALL vault data, sessions, and credentials. <strong className="text-white">This cannot be undone.</strong>
              </p>
              {isWiping ? (
                <div className="flex flex-col items-center gap-3">
                  <Loader2 size={32} className="animate-spin text-red-400" />
                  <p className="text-red-300 font-bold text-sm uppercase tracking-widest">Wiping…</p>
                </div>
              ) : (
                <div className="flex gap-3">
                  <button onClick={() => setIsDuressWipeOpen(false)}
                    className="flex-1 py-4 bg-red-900/50 border border-red-800 text-red-300 rounded-xl font-black uppercase tracking-widest text-xs hover:bg-red-900 transition-all"
                  >
                    Cancel
                  </button>
                  <button onClick={handleTriggerWipe}
                    className="flex-1 py-4 bg-red-600 text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-red-500 transition-all flex items-center justify-center gap-2"
                  >
                    <Flame size={16} />
                    Wipe Now
                  </button>
                </div>
              )}
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── Recovery Kit Modal ─────────────────────────────────────────── */}
      <AnimatePresence>
        {isRecoveryModalOpen && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40"
              onClick={() => setIsRecoveryModalOpen(false)}
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-lg bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl overflow-hidden border border-outline-variant/10"
            >
              <div className="p-10 text-center">
                <div className="w-16 h-16 rounded-2xl bg-black dark:bg-white flex items-center justify-center mx-auto mb-6 shadow-xl">
                  <ShieldAlert className="text-white dark:text-black" size={32} />
                </div>
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">
                  Recovery Kit
                </h3>
                <p className="text-on-surface-variant text-sm mb-8 leading-relaxed">
                  Save this key in a secure location. It can be used to recover your account if you lose your master password.
                </p>

                <div className="bg-surface-container-low p-6 rounded-2xl border-2 border-dashed border-outline-variant/30 mb-8 font-mono font-bold text-lg tracking-wider break-all select-all">
                  {recoveryKey}
                </div>

                <div className="flex gap-3">
                  <button 
                    onClick={() => setIsRecoveryModalOpen(false)}
                    className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all"
                  >
                    Cancel
                  </button>
                  <button 
                    onClick={saveRecoveryKey}
                    disabled={isGeneratingRecovery}
                    className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 dark:bg-white dark:text-black transition-all flex items-center justify-center gap-2"
                  >
                    {isGeneratingRecovery ? <Loader2 size={16} className="animate-spin" /> : <Download size={16} />}
                    Download & Save
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── Emergency Access Modal ──────────────────────────────────────── */}
      <AnimatePresence>
        {isEmergencyModalOpen && (
          <Suspense fallback={null}>
            <EmergencyAccessModal onClose={() => setIsEmergencyModalOpen(false)} />
          </Suspense>
        )}
      </AnimatePresence>

    </div>
  );
}
