import React, { useState, useCallback, useEffect, useRef } from 'react';
import { User, History, ShieldAlert, Smartphone, Key, Mail, Monitor, CheckCircle, LogOut, Edit3, RefreshCw, X, ShieldCheck, Check, Eye, EyeOff, Camera, ChevronDown, Copy, AlertTriangle, Trash2, Timer, Server, Loader2, Download, Upload, Plane, Skull, Flame, FileJson, FileText, FileUp, Fingerprint, KeyRound, ToggleLeft, ToggleRight } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import QRCode from 'qrcode';
import { useUser } from '../context/UserContext';
import { useVault } from '../context/VaultContext';
import {
  getDuressModeConfig, getTravelModeConfig,
  armDuressMode, disarmDuressMode,
  enableTravelMode, disableTravelMode,
  wipeVaultData,
  type DuressModeConfig, type TravelModeConfig,
} from '../utils/securityModes';
import { daemon } from '../utils/daemonClient';
import UserAvatar from '../components/UserAvatar';
import { useTheme } from '../context/ThemeContext';
import { generateUUID } from '../utils/crypto';
import { writeEncryptedLocal, readDecryptedLocal } from '../utils/localCrypto';
import {
  exportToPWDnow, exportToBitwarden, exportTo1Password, exportToNordPass,
  triggerDownload, importFromFile,
  type ExportFormat, type ImportResult, FORMAT_LABELS,
} from '../utils/importExport';
import { getSessions, clearOtherSessions, formatSessionTime, type LoginSession } from '../utils/sessionTracker';
import SEO from '../components/SEO';
import {
  getMfaConfig, saveMfaConfig,
  generateTotpSecret, buildTotpUri, verifyTotp,
  generateEmailCode, verifyEmailCode, clearPendingOtp,
  isWebAuthnSupported, isSecureContext,
  registerWebAuthn, authenticateWebAuthn,
  registerPasskey, registerPlatformAuth,
  countActiveMfaMethods,
  type MfaConfig, type WebAuthnCredentialMeta,
} from '../utils/mfa';
import COUNTRY_LIST from '../data/country-list.json';

export default function Settings() {
  const { t } = useTranslation();
  const { profile, updateProfile, reloadProfile } = useUser();
  const { theme, setTheme } = useTheme();
  const { credentials, folders, addCredential, deleteCredential, addFolder, reloadLocal } = useVault();
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
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 800));
    updateProfile(localProfile);
    setIsSaving(false);
    setShowSaveSuccess(true);
    setTimeout(() => setShowSaveSuccess(false), 3000);
  };

  // ── Modal open/close ──────────────────────────────────────────────────────
  const [isChangeModalOpen, setIsChangeModalOpen] = useState(false);
  const [isAuditLogOpen, setIsAuditLogOpen] = useState(false);
  const [isRevokeModalOpen, setIsRevokeModalOpen] = useState(false);
  const [isRevoking, setIsRevoking] = useState(false);
  const [revokeSuccess, setRevokeSuccess] = useState(false);

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

  const refreshMfa = () => setMfaConfig(getMfaConfig());

  // ── MFA modal state ────────────────────────────────────────────────────────
  type MfaType = 'totp' | 'webauthn' | 'email' | 'passkey' | 'platform';
  const [mfaModal, setMfaModal] = useState<{ type: MfaType; step: number } | null>(null);

  // TOTP
  const [totpSecret, setTotpSecret]     = useState('');
  const [totpCode, setTotpCode]         = useState(['', '', '', '', '', '']);
  const [totpError, setTotpError]       = useState('');
  const [totpSecretCopied, setTotpSecretCopied] = useState(false);
  const totpRefs = useRef<(HTMLInputElement | null)[]>([]);
  // Canvas ref: QRCode.toCanvas() is the reliable browser API — toDataURL() creates
  // an off-screen canvas internally and fails in some Vite/ESM environments.
  const qrCanvasRef = useRef<HTMLCanvasElement>(null);

  // Render QR code into the canvas as soon as the secret and canvas are both ready.
  useEffect(() => {
    if (!totpSecret || !qrCanvasRef.current) return;
    const uri = buildTotpUri(totpSecret, profile.email || 'user@pwdnow');
    QRCode.toCanvas(qrCanvasRef.current, uri, {
      width: 192,
      margin: 2,
      errorCorrectionLevel: 'M',
      color: { dark: '#000000', light: '#ffffff' },
    }, (err) => {
      if (err) console.error('[TOTP QR]', err);
    });
  }, [totpSecret]);

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

    // If already enabled, re-open at step 1 (remove option)
    setMfaModal({ type, step: 1 });

    if (type === 'totp' && !mfaConfig.totp.enabled) {
      const secret = generateTotpSecret();
      setTotpSecret(secret);
      // QR code is rendered by the useEffect above once totpSecret is set
      // and the canvas ref is mounted.
    }
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
      if (value && index < 5) refs.current[index + 1]?.focus();
      if (value && index === 5 && onComplete) onComplete();
    },
    onKeyDown(index: number, e: React.KeyboardEvent<HTMLInputElement>) {
      if (e.key === 'Backspace' && !code[index] && index > 0) refs.current[index - 1]?.focus();
    },
    onPaste(e: React.ClipboardEvent) {
      e.preventDefault();
      const digits = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6).split('');
      const next = [...code];
      digits.forEach((d, i) => { next[i] = d; });
      setCode(next);
      refs.current[Math.min(digits.length, 5)]?.focus();
    },
  });

  const totpHandlers  = makeDigitHandlers(totpCode,  setTotpCode,  totpRefs);
  const emailHandlers = makeDigitHandlers(emailCode, setEmailCode, emailRefs);

  // ── TOTP: verify and save ──────────────────────────────────────────────────
  const handleTotpVerify = async () => {
    const token = totpCode.join('');
    const ok = await verifyTotp(totpSecret, token);
    if (!ok) { setTotpError('Invalid code. Make sure your device clock is correct.'); return; }
    const cfg = getMfaConfig();
    cfg.totp = { enabled: true, secret: totpSecret, enabledAt: Date.now() };
    saveMfaConfig(cfg);
    refreshMfa();
    setMfaModal({ type: 'totp', step: 3 });
  };

  // ── TOTP: remove ──────────────────────────────────────────────────────────
  const handleTotpRemove = () => {
    const cfg = getMfaConfig();
    cfg.totp = { enabled: false };
    saveMfaConfig(cfg);
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
      setWebAuthnError(err instanceof Error ? err.message : 'Registration failed.');
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
      setPasskeyError(err instanceof Error ? err.message : 'Registration failed.');
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
      refreshMfa();
      setMfaModal({ type: 'platform', step: 3 });
    } catch (err) {
      setPlatformError(err instanceof Error ? err.message : 'Registration failed.');
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
    refreshMfa();
  };

  // ── Passwordless toggle ───────────────────────────────────────────────────
  const handlePasswordlessToggle = () => {
    const cfg = getMfaConfig();
    cfg.passwordlessEnabled = !cfg.passwordlessEnabled;
    saveMfaConfig(cfg);
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
    refreshMfa();
    setMfaModal({ type: 'email', step: 3 });
  };

  // ── Email OTP: remove ─────────────────────────────────────────────────────
  const handleEmailRemove = () => {
    const cfg = getMfaConfig();
    cfg.email = { enabled: false };
    saveMfaConfig(cfg);
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
  const [exportFormat, setExportFormat] = useState<ExportFormat>('pwdnow');
  const [importResult, setImportResult] = useState<ImportResult | null>(null);
  const [importFileName, setImportFileName] = useState('');
  const [isImportModalOpen, setIsImportModalOpen] = useState(false);
  const [importMode, setImportMode] = useState<'merge' | 'replace'>('merge');
  const [isImporting, setIsImporting] = useState(false);
  const [importError, setImportError] = useState('');

  const handleExport = useCallback(() => {
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    let content: string;
    let filename: string;
    let mime: string;
    switch (exportFormat) {
      case 'bitwarden':
        content  = exportToBitwarden(credentials, folders);
        filename = `bitwarden_export_${date}.json`;
        mime     = 'application/json';
        break;
      case '1password':
        content  = exportTo1Password(credentials);
        filename = `1password_export_${date}.csv`;
        mime     = 'text/csv';
        break;
      case 'nordpass':
        content  = exportToNordPass(credentials);
        filename = `nordpass_export_${date}.csv`;
        mime     = 'text/csv';
        break;
      default:
        content  = exportToPWDnow(credentials, folders);
        filename = `pwdnow_export_${date}.json`;
        mime     = 'application/json';
    }
    triggerDownload(content, filename, mime);
  }, [exportFormat, credentials, folders]);

  const handleFileSelect = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImportError('');
    try {
      const result = await importFromFile(file);
      if (result.credentials.length === 0) { setImportError('No credentials found in file.'); return; }
      setImportResult(result);
      setImportFileName(file.name);
      setImportMode('merge');
      setIsImportModalOpen(true);
    } catch (err) {
      setImportError(err instanceof Error ? err.message : 'Failed to parse file.');
    }
    e.target.value = '';
  }, []);

  const handleConfirmImport = useCallback(async () => {
    if (!importResult) return;
    setIsImporting(true);
    try {
      if (importMode === 'replace') {
        for (const cred of credentials) {
          await deleteCredential(cred.id);
        }
      }
      // Find or create 'Imported' folder
      let importFolderId = folders.find(f => f.label === 'Imported')?.id;
      if (!importFolderId) {
        const newFolder = { id: generateUUID(), label: 'Imported', description: 'Credentials imported from an external source', iconName: 'Download' };
        await addFolder(newFolder);
        importFolderId = newFolder.id;
      }
      for (const cred of importResult.credentials) {
        // For PWDnow format try to preserve folder assignment
        let folderId = importFolderId;
        if (importResult.detectedFormat === 'pwdnow' && cred.folderId) {
          const match = folders.find(f => f.id === cred.folderId || f.label === cred.folderId);
          if (match) folderId = match.id;
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
    if (duressPassword.length < 8) { setDuressError('Duress password must be at least 8 characters.'); return; }
    if (duressPassword !== confirmDuressPassword) { setDuressError('Passwords do not match.'); return; }
    setIsArmingDuress(true);
    await armDuressMode(duressPassword, duressMaxAttempts);
    setDuressConfig(getDuressModeConfig());
    setIsArmingDuress(false);
    setDuressStep(3);
  };

  const handleDisarmDuress = () => {
    disarmDuressMode();
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
    await enableTravelMode(travelPassword, travelHiddenFolderIds, credentials, folders);
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
      const reader = new FileReader();
      reader.onloadend = () => {
        setLocalProfile(prev => ({ ...prev, photoUrl: reader.result as string }));
      };
      reader.readAsDataURL(file);
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
        if (hasRestSession) {
          const res = await fetch('/api/auth/verify-password', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
            body: JSON.stringify({ password: oldPassword })
          });
          const data = await res.json().catch(() => ({ ok: false }));
          if (!res.ok || !data.ok) {
            setOldPasswordError(t('settings.wrongOldPassword', 'Incorrect password. Please try again.'));
            return;
          }
        } else if (daemon.isConnected) {
          const valid = await daemon.verifyPassword(oldPassword);
          if (!valid) {
            setOldPasswordError(t('settings.wrongOldPassword', 'Incorrect password. Please try again.'));
            return;
          }
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

        if (!res.ok) {
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
                <div className="w-12 h-12 rounded-full bg-surface-container-low flex items-center justify-center">
                  <Monitor size={24} className={theme === 'light' ? 'text-black dark:text-white' : 'text-on-surface-variant'} />
                </div>
                <span className={`font-bold ${theme === 'light' ? 'text-black dark:text-white' : 'text-on-surface-variant'}`}>{t('settings.themeLight', 'Light')}</span>
              </button>

              <button
                onClick={() => setTheme('dark')}
                className={`p-6 rounded-xl border-2 transition-all flex flex-col items-center gap-4 ${theme === 'dark' ? 'border-black dark:border-white bg-white dark:bg-white/10 shadow-lg' : 'border-outline-variant/20 bg-surface hover:border-outline-variant/50'}`}
              >
                <div className="w-12 h-12 rounded-full bg-surface-container-low flex items-center justify-center">
                  <Monitor size={24} className={theme === 'dark' ? 'text-black dark:text-white' : 'text-on-surface-variant'} />
                </div>
                <span className={`font-bold ${theme === 'dark' ? 'text-black dark:text-white' : 'text-on-surface-variant'}`}>{t('settings.themeDark', 'Dark')}</span>
              </button>

              <button
                onClick={() => setTheme('system')}
                className={`p-6 rounded-xl border-2 transition-all flex flex-col items-center gap-4 ${theme === 'system' ? 'border-black dark:border-white bg-white dark:bg-white/10 shadow-lg' : 'border-outline-variant/20 bg-surface hover:border-outline-variant/50'}`}
              >
                <div className="w-12 h-12 rounded-full bg-surface-container-low flex items-center justify-center">
                  <Monitor size={24} className={theme === 'system' ? 'text-black dark:text-white' : 'text-on-surface-variant'} />
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
                <p className="text-xs text-on-surface-variant mb-6 leading-relaxed">{t('settings.recoveryKitDesc', 'Essential for account recovery if master password is lost.')}</p>
                <button className="text-xs font-black uppercase tracking-widest text-black dark:text-white hover:underline" aria-label={t('settings.regenerateKit', 'Regenerate Kit')}>{t('settings.regenerateKit', 'Regenerate Kit')}</button>
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
                  className="px-8 py-3 border border-white/20 rounded-md text-sm font-bold hover:bg-white/10 transition-all relative z-10"
                  aria-label={t('settings.configure', 'Configure')}
                >
                  {t('settings.configure', 'Configure')}
                </button>
                <div className="absolute right-0 top-0 w-64 h-64 bg-on-primary-container blur-[40px] opacity-40" aria-hidden="true"></div>
              </div>
            </div>
          </div>
        </section>

        {/* ── Import & Export ──────────────────────────────────────────────────── */}
        <section>
          <div className="flex items-center gap-3 mb-8">
            <Download className="text-black dark:text-white" size={24} aria-hidden="true" />
            <h2 className="text-2xl font-headline font-extrabold tracking-tight">Import & Export</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Export card */}
            <div className="bg-surface-container-low rounded-2xl p-8 border border-outline-variant/20 flex flex-col gap-5">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-black dark:bg-white flex items-center justify-center shrink-0">
                  <Download size={18} className="text-white dark:text-black" />
                </div>
                <div>
                  <h3 className="font-bold text-base text-black dark:text-white">Export Vault</h3>
                  <p className="text-xs text-on-surface-variant mt-0.5">Download a copy of your credentials</p>
                </div>
              </div>

              <div className="space-y-3">
                <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">Format</label>
                <div className="grid grid-cols-2 gap-2">
                  {(['pwdnow', 'bitwarden', '1password', 'nordpass'] as ExportFormat[]).map(fmt => (
                    <button
                      key={fmt}
                      type="button"
                      onClick={() => setExportFormat(fmt)}
                      className={`flex items-center gap-2 px-3 py-2.5 rounded-xl border-2 text-xs font-bold transition-all text-left ${
                        exportFormat === fmt
                          ? 'border-black dark:border-white bg-black dark:bg-white text-white dark:text-black'
                          : 'border-outline-variant/30 hover:border-outline-variant/60 text-on-surface-variant'
                      }`}
                    >
                      {fmt === 'pwdnow' || fmt === 'bitwarden' ? <FileJson size={13} /> : <FileText size={13} />}
                      {FORMAT_LABELS[fmt]}
                    </button>
                  ))}
                </div>
              </div>

              <button
                onClick={handleExport}
                disabled={credentials.length === 0}
                className="w-full py-3.5 bg-black dark:bg-white text-white dark:text-black rounded-xl font-black uppercase tracking-widest text-xs hover:opacity-90 transition-all flex items-center justify-center gap-2 disabled:opacity-40"
              >
                <Download size={15} />
                Export {credentials.length} credential{credentials.length !== 1 ? 's' : ''}
              </button>

              <p className="text-[10px] text-on-surface-variant leading-relaxed">
                Exports are unencrypted. Store the file securely and delete it after use.
              </p>
            </div>

            {/* Import card */}
            <div className="bg-surface-container-low rounded-2xl p-8 border border-outline-variant/20 flex flex-col gap-5">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-black dark:bg-white flex items-center justify-center shrink-0">
                  <Upload size={18} className="text-white dark:text-black" />
                </div>
                <div>
                  <h3 className="font-bold text-base text-black dark:text-white">Import Vault</h3>
                  <p className="text-xs text-on-surface-variant mt-0.5">Bring in credentials from another manager</p>
                </div>
              </div>

              <label className="flex flex-col items-center justify-center gap-3 border-2 border-dashed border-outline-variant/40 hover:border-outline-variant/80 rounded-xl p-8 cursor-pointer transition-all group">
                <input
                  type="file"
                  accept=".json,.csv"
                  className="sr-only"
                  onChange={handleFileSelect}
                />
                <FileUp size={28} className="text-on-surface-variant group-hover:text-black dark:group-hover:text-white transition-colors" />
                <div className="text-center">
                  <p className="text-sm font-bold text-black dark:text-white">Drop file or click to browse</p>
                  <p className="text-xs text-on-surface-variant mt-1">Accepts .json and .csv</p>
                </div>
              </label>

              {importError && (
                <p className="text-xs font-bold text-red-600 uppercase tracking-widest">{importError}</p>
              )}

              <div className="space-y-1.5">
                <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">Supported sources</p>
                <div className="flex flex-wrap gap-2">
                  {['PWDnow JSON', 'Bitwarden JSON', '1Password CSV', 'NordPass CSV'].map(s => (
                    <span key={s} className="text-[10px] px-2.5 py-1 bg-surface-container-high rounded-lg font-bold text-on-surface-variant">{s}</span>
                  ))}
                </div>
              </div>
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
                const active = mfaConfig.totp.enabled;
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
                    <div className="mt-auto">
                      {active ? (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-green-700 bg-green-50 dark:bg-green-950/40 dark:text-green-400 px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-green-500" />Active
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
                    <div className="mt-auto">
                      {active ? (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-green-700 bg-green-50 dark:bg-green-950/40 dark:text-green-400 px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-green-500" />Active
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

              {/* Passkey (synced) */}
              {(() => {
                const active = mfaConfig.passkey?.enabled ?? false;
                const count = mfaConfig.passkey?.credentials?.length ?? 0;
                return (
                  <div
                    onClick={() => openMfaModal('passkey')}
                    className={`p-8 rounded-xl border-2 transition-all cursor-pointer flex flex-col ${active ? 'border-black dark:border-on-primary-container bg-white dark:bg-surface-container-high shadow-lg' : 'border-outline-variant/40 bg-surface-container-high hover:border-outline-variant hover:bg-surface-container-highest'}`}
                  >
                    <div className="flex items-center justify-between mb-6">
                      <KeyRound size={32} className={active ? 'text-black dark:text-white' : 'text-on-surface-variant'} />
                      <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${active ? 'border-black bg-black dark:border-on-primary-container dark:bg-on-primary-container' : 'border-outline-variant'}`}>
                        {active && <div className="w-2 h-2 bg-white rounded-full" />}
                      </div>
                    </div>
                    <h4 className="font-bold text-lg mb-2">{t('settings.passkeyTitle', 'Passkey')}</h4>
                    <p className="text-xs text-on-surface-variant leading-relaxed mb-4">{t('settings.passkeyDesc', 'Synced passkey via iCloud Keychain or Google Password Manager. Works across your devices.')}</p>
                    <div className="mt-auto">
                      {active ? (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-green-700 bg-green-50 dark:bg-green-950/40 dark:text-green-400 px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-green-500" />{t('settings.passkeyCount', '{{count}} passkey(s) registered', { count })}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-on-surface-variant bg-surface-container-highest px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-outline-variant" />{t('settings.notSetUp', 'Not set up')}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })()}

              {/* Platform Auth – Touch ID / Windows Hello / Face ID */}
              {(() => {
                const active = mfaConfig.platform?.enabled ?? false;
                const count = mfaConfig.platform?.credentials?.length ?? 0;
                return (
                  <div
                    onClick={() => openMfaModal('platform')}
                    className={`p-8 rounded-xl border-2 transition-all cursor-pointer flex flex-col ${active ? 'border-black dark:border-on-primary-container bg-white dark:bg-surface-container-high shadow-lg' : 'border-outline-variant/40 bg-surface-container-high hover:border-outline-variant hover:bg-surface-container-highest'}`}
                  >
                    <div className="flex items-center justify-between mb-6">
                      <Fingerprint size={32} className={active ? 'text-black dark:text-white' : 'text-on-surface-variant'} />
                      <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${active ? 'border-black bg-black dark:border-on-primary-container dark:bg-on-primary-container' : 'border-outline-variant'}`}>
                        {active && <div className="w-2 h-2 bg-white rounded-full" />}
                      </div>
                    </div>
                    <h4 className="font-bold text-lg mb-2">{t('settings.platformTitle', 'Touch ID / Windows Hello')}</h4>
                    <p className="text-xs text-on-surface-variant leading-relaxed mb-4">{t('settings.platformDesc', 'Device-bound biometric. Your fingerprint or face stays on this device — never synced.')}</p>
                    <div className="mt-auto">
                      {active ? (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-green-700 bg-green-50 dark:bg-green-950/40 dark:text-green-400 px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-green-500" />{t('settings.platformCount', '{{count}} device(s) registered', { count })}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-on-surface-variant bg-surface-container-highest px-2.5 py-1 rounded-md">
                          <div className="w-1.5 h-1.5 rounded-full bg-outline-variant" />{t('settings.notSetUp', 'Not set up')}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })()}
            </div>

            {/* Passwordless toggle — shown when ≥2 MFA methods are active */}
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
            <h2 className="text-2xl font-headline font-extrabold tracking-tight">Travel Mode</h2>
          </div>
          <div className={`rounded-xl p-10 border-2 transition-all ${travelConfig.active ? 'bg-blue-950 border-blue-700' : 'bg-surface-container-low border-transparent'}`}>
            <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-6">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-3">
                  <h3 className={`font-bold text-xl ${travelConfig.active ? 'text-white' : ''}`}>
                    {travelConfig.active ? 'Travel Mode Active' : 'Travel Mode'}
                  </h3>
                  {travelConfig.active
                    ? <span className="text-[9px] px-2.5 py-1 bg-blue-500 text-white rounded-full font-black uppercase tracking-widest animate-pulse">Active</span>
                    : <span className="text-[9px] px-2.5 py-1 bg-surface-container-high text-on-surface-variant rounded-full font-black uppercase tracking-widest">Inactive</span>
                  }
                </div>
                <p className={`text-sm leading-relaxed max-w-xl mb-4 ${travelConfig.active ? 'text-blue-200' : 'text-on-surface-variant'}`}>
                  {travelConfig.active
                    ? `${travelConfig.hiddenFolderIds.length} folder${travelConfig.hiddenFolderIds.length !== 1 ? 's' : ''} hidden — vault appears sanitized. Hidden data is AES-256-GCM encrypted locally and invisible to device inspection.`
                    : 'Hide designated vault folders when crossing borders or entering high-risk environments. Hidden data is encrypted on-device with your travel password — invisible to inspection, fully restorable with the travel password.'}
                </p>
              </div>
              <div className="shrink-0">
                {travelConfig.active ? (
                  <button
                    onClick={() => { setIsDisableTravelOpen(true); setDisableTravelPw(''); setDisableTravelError(''); }}
                    className="px-8 py-4 bg-blue-500 hover:bg-blue-400 text-white rounded-xl font-bold text-sm transition-all flex items-center gap-3 shadow-lg shadow-blue-900/50"
                  >
                    <Plane size={18} />
                    Disable Travel Mode
                  </button>
                ) : (
                  <button
                    onClick={() => { setIsTravelModalOpen(true); setTravelStep(1); setTravelHiddenFolderIds([]); setTravelPassword(''); setConfirmTravelPassword(''); setTravelError(''); }}
                    className="px-8 py-4 bg-black dark:bg-white text-white dark:text-black rounded-xl font-bold text-sm hover:opacity-90 transition-all flex items-center gap-3 shadow-lg"
                  >
                    <Plane size={18} />
                    Enable Travel Mode
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
            <h2 className="text-2xl font-headline font-extrabold tracking-tight">Offline Duress Mode</h2>
          </div>
          <div className={`rounded-xl p-10 border-2 transition-all ${duressConfig.armed ? 'bg-red-950 border-red-800' : 'bg-surface-container-low border-transparent'}`}>
            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-8">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-3">
                  <h3 className={`font-bold text-xl ${duressConfig.armed ? 'text-white' : ''}`}>
                    {duressConfig.armed ? 'Duress Mode Armed' : 'Duress Mode'}
                  </h3>
                  {duressConfig.armed
                    ? <span className="text-[9px] px-2.5 py-1 bg-red-600 text-white rounded-full font-black uppercase tracking-widest animate-pulse">Armed</span>
                    : <span className="text-[9px] px-2.5 py-1 bg-surface-container-high text-on-surface-variant rounded-full font-black uppercase tracking-widest">Disarmed</span>
                  }
                </div>
                <p className={`text-sm leading-relaxed max-w-xl mb-6 ${duressConfig.armed ? 'text-red-200' : 'text-on-surface-variant'}`}>
                  {duressConfig.armed
                    ? `Entering the duress password at login triggers an immediate forensic wipe. Auto-wipe after ${duressConfig.maxAttempts} failed attempt${duressConfig.maxAttempts !== 1 ? 's' : ''} (${duressConfig.attemptsRemaining} remaining).`
                    : 'A separate duress password entered at login silently wipes all vault data (3-pass CSPRNG overwrite). Also auto-triggers after a configurable number of failed login attempts.'}
                </p>

                {/* Max attempts selector — always visible when armed or when configuring */}
                <div className="flex items-center gap-4">
                  <label className={`text-[10px] font-black uppercase tracking-widest shrink-0 ${duressConfig.armed ? 'text-red-300' : 'text-on-surface-variant'}`}>
                    Auto-wipe after
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
                        <option key={n} value={n}>{n} failed attempt{n !== 1 ? 's' : ''}</option>
                      ))}
                    </select>
                    <ChevronDown size={14} className={`absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none ${duressConfig.armed ? 'text-red-400' : 'text-on-surface-variant'}`} />
                  </div>
                  {duressConfig.armed && (
                    <span className={`text-xs font-bold ${duressConfig.attemptsRemaining <= 2 ? 'text-red-400 animate-pulse' : 'text-red-300'}`}>
                      {duressConfig.attemptsRemaining} / {duressConfig.maxAttempts} remaining
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
                      Trigger Wipe Now
                    </button>
                    <button
                      onClick={handleDisarmDuress}
                      className="px-8 py-4 bg-red-950 hover:bg-red-900 border border-red-800 text-red-300 rounded-xl font-bold text-sm transition-all flex items-center gap-3"
                    >
                      <ShieldCheck size={18} />
                      Disarm
                    </button>
                  </>
                ) : (
                  <button
                    onClick={() => { setIsDuressModalOpen(true); setDuressStep(1); setDuressPassword(''); setConfirmDuressPassword(''); setDuressError(''); }}
                    className="px-8 py-4 bg-black dark:bg-white text-white dark:text-black rounded-xl font-bold text-sm hover:opacity-90 transition-all flex items-center gap-3 shadow-lg"
                  >
                    <Skull size={18} />
                    Arm Duress Mode
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
              className="absolute inset-0 bg-[#000000]/40 backdrop-blur-sm"
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
                        className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all"
                      >
                        {t('settings.accept', 'Accept')}
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
                          className="w-full py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {t('common.next', 'Next Step')}
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
              className="absolute inset-0 bg-[#000000]/40 backdrop-blur-sm"
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
                    <p className="text-xs text-on-surface-variant mt-0.5">{sessions.length} session{sessions.length !== 1 ? 's' : ''} recorded</p>
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

              {/* Session list */}
              <div className="overflow-y-auto flex-1 p-8 space-y-3">
                {sessions.length === 0 ? (
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
                )}
              </div>

              {/* Footer actions */}
              <div className="p-6 border-t border-outline-variant/10 bg-surface-container-low/50 flex flex-wrap items-center justify-between gap-3 shrink-0 rounded-b-3xl">
                <button
                  onClick={() => {
                    setIsAuditLogOpen(false);
                    setIsRevokeModalOpen(true);
                    setRevokeSuccess(false);
                  }}
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
                    a.href = url;
                    a.download = 'session-audit-log.csv';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    setTimeout(() => URL.revokeObjectURL(url), 10000);
                  }}
                  className="flex items-center gap-2 px-5 py-2.5 bg-black text-white rounded-xl text-xs font-black uppercase tracking-widest hover:bg-neutral-800 transition-all"
                >
                  <Download size={14} />
                  {t('settings.downloadCsv', 'Download CSV')}
                </button>
              </div>
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
              className="absolute inset-0 bg-[#000000]/40 backdrop-blur-sm"
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
              className="absolute inset-0 bg-[#000000]/40 backdrop-blur-sm"
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
                    {mfaConfig.totp.enabled && mfaModal.step === 1 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Authenticator App</h3>
                          <p className="text-on-surface-variant text-sm leading-relaxed">Your authenticator app is configured and active.</p>
                        </div>
                        <div className="p-5 bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800 rounded-2xl flex items-center gap-4">
                          <CheckCircle size={22} className="text-green-600 shrink-0" />
                          <div>
                            <p className="font-bold text-sm text-green-800 dark:text-green-300">Active since {new Date(mfaConfig.totp.enabledAt ?? 0).toLocaleDateString()}</p>
                            <p className="text-xs text-green-700/70 dark:text-green-400/70 mt-0.5">TOTP · SHA-1 · 6 digits · 30 s period</p>
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

                    {/* Setup step 1 – QR code */}
                    {!mfaConfig.totp.enabled && mfaModal.step === 1 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Set up Authenticator App</h3>
                          <p className="text-on-surface-variant text-sm leading-relaxed">Scan the QR code with Google Authenticator, Authy, or any TOTP-compatible app.</p>
                        </div>

                        {/* QR code – rendered directly into a <canvas> via QRCode.toCanvas() */}
                        <div className="flex justify-center p-6 bg-surface-container-low rounded-2xl border-2 border-dashed border-outline-variant/20">
                          <canvas
                            ref={qrCanvasRef}
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
                    {!mfaConfig.totp.enabled && mfaModal.step === 2 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Verify the code</h3>
                          <p className="text-on-surface-variant text-sm leading-relaxed">Open your authenticator app and enter the 6-digit code shown for this account.</p>
                        </div>

                        <div className="flex items-center justify-center gap-2">
                          {[0,1,2].map(i => (
                            <input key={i} ref={el => { totpRefs.current[i] = el; }}
                              type="text" inputMode="numeric" maxLength={1} value={totpCode[i]}
                              onChange={e => totpHandlers.onChange(i, e.target.value)}
                              onKeyDown={e => totpHandlers.onKeyDown(i, e)}
                              onPaste={i === 0 ? totpHandlers.onPaste : undefined}
                              className="w-12 h-14 text-center text-xl font-black bg-surface-container-low border border-outline-variant/10 rounded-xl focus:ring-2 focus:ring-black/20 outline-none transition-all"
                            />
                          ))}
                          <div className="w-4 h-0.5 bg-outline-variant/30 rounded-full mx-1" />
                          {[3,4,5].map(i => (
                            <input key={i} ref={el => { totpRefs.current[i] = el; }}
                              type="text" inputMode="numeric" maxLength={1} value={totpCode[i]}
                              onChange={e => totpHandlers.onChange(i, e.target.value)}
                              onKeyDown={e => totpHandlers.onKeyDown(i, e)}
                              className="w-12 h-14 text-center text-xl font-black bg-surface-container-low border border-outline-variant/10 rounded-xl focus:ring-2 focus:ring-black/20 outline-none transition-all"
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
                          <p className="text-on-surface-variant text-sm">Your app is linked. From now on, every login will require a 6-digit TOTP code.</p>
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
                              <AlertTriangle size={12} />May fail on plain HTTP — use HTTPS or localhost for best results.
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
                          <p className="text-xs font-bold text-error flex items-center gap-2"><AlertTriangle size={14} />{webAuthnError}</p>
                        )}
                        <button onClick={closeMfaModal} className="w-full py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Close</button>
                      </div>
                    )}

                    {/* First-time setup */}
                    {!mfaConfig.webauthn.enabled && mfaModal.step === 1 && (
                      <div className="space-y-8">
                        <div>
                          <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">Register Security Key</h3>
                          <p className="text-on-surface-variant text-sm leading-relaxed">
                            Register a FIDO2-compatible security key (YubiKey, Titan Key, or your device's built-in authenticator).
                          </p>
                        </div>

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
                          <p className="text-xs font-bold text-error flex items-center gap-2"><AlertTriangle size={14} />{webAuthnError}</p>
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
                              onKeyDown={e => emailHandlers.onKeyDown(i, e)}
                              onPaste={i === 0 ? emailHandlers.onPaste : undefined}
                              className="w-12 h-14 text-center text-xl font-black bg-surface-container-low border border-outline-variant/10 rounded-xl focus:ring-2 focus:ring-black/20 outline-none transition-all"
                            />
                          ))}
                          <div className="w-4 h-0.5 bg-outline-variant/30 rounded-full mx-1" />
                          {[3,4,5].map(i => (
                            <input key={i} ref={el => { emailRefs.current[i] = el; }}
                              type="text" inputMode="numeric" maxLength={1} value={emailCode[i]}
                              onChange={e => emailHandlers.onChange(i, e.target.value)}
                              onKeyDown={e => emailHandlers.onKeyDown(i, e)}
                              className="w-12 h-14 text-center text-xl font-black bg-surface-container-low border border-outline-variant/10 rounded-xl focus:ring-2 focus:ring-black/20 outline-none transition-all"
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
              className="absolute inset-0 bg-[#000000]/40 backdrop-blur-sm"
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
                      { key: 'smtp' as SmtpProtocol, label: t('settings.smtpProtoSmtp', 'SMTP'), desc: t('settings.smtpProtoSmtpDesc', 'Port 25 — Legacy plaintext') },
                      { key: 'esmtp' as SmtpProtocol, label: t('settings.smtpProtoEsmtp', 'ESMTP'), desc: t('settings.smtpProtoEsmtpDesc', 'Port 587 — Extended SMTP') },
                      { key: 'starttls' as SmtpProtocol, label: t('settings.smtpProtoStarttls', 'STARTTLS'), desc: t('settings.smtpProtoStarttlsDesc', 'Port 587 — Upgrades to TLS'), recommended: true },
                      { key: 'ssl_tls' as SmtpProtocol, label: t('settings.smtpProtoSslTls', 'SSL / TLS'), desc: t('settings.smtpProtoSslTlsDesc', 'Port 465 — Implicit TLS') },
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
              className="absolute inset-0 bg-[#000000]/60 backdrop-blur-sm"
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
                    <h3 className="text-xl font-headline font-black text-black dark:text-white">Enable Travel Mode</h3>
                    <p className="text-xs text-on-surface-variant mt-0.5">Step {travelStep} of 4</p>
                  </div>
                </div>
                <button onClick={() => setIsTravelModalOpen(false)} className="p-2 hover:bg-surface-container-high rounded-full transition-colors"><X size={20} /></button>
              </div>

              <div className="overflow-y-auto flex-1 p-8">
                {travelStep === 1 && (
                  <div className="space-y-6">
                    <div>
                      <p className="text-sm text-on-surface-variant leading-relaxed mb-5">
                        Select which folders to hide when Travel Mode is active. These folders will be AES-256-GCM encrypted and invisible until you disable Travel Mode with your travel password.
                      </p>
                      <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-3">Select folders to hide</p>
                      {folders.length === 0 ? (
                        <p className="text-sm text-on-surface-variant text-center py-8">No folders found. Create folders in your vault first.</p>
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
                    <button onClick={() => { if (travelHiddenFolderIds.length === 0) { setTravelError('Select at least one folder to hide.'); return; } setTravelError(''); setTravelStep(2); }}
                      className="w-full py-4 bg-blue-600 text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-blue-700 transition-all"
                    >
                      Next — Set Travel Password
                    </button>
                  </div>
                )}

                {travelStep === 2 && (
                  <div className="space-y-6">
                    <p className="text-sm text-on-surface-variant leading-relaxed">
                      This password is required to restore hidden folders. It is separate from your main vault password and is used only to decrypt the hidden vault.
                    </p>
                    <div className="space-y-3">
                      <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">Password</label>
                      <div className="relative">
                        <input type={showTravelPassword ? 'text' : 'password'} value={travelPassword}
                          onChange={e => { setTravelPassword(e.target.value); setTravelError(''); }}
                          placeholder="Minimum 8 characters"
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
                      <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">Confirm Password</label>
                      <input type="password" value={confirmTravelPassword}
                        onChange={e => { setConfirmTravelPassword(e.target.value); setTravelError(''); }}
                        placeholder="Repeat password"
                        className="w-full px-5 py-4 bg-surface-container-low rounded-xl border border-zinc-300 dark:border-zinc-600 text-black dark:text-white font-bold focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500 dark:focus:border-blue-400 outline-none transition-all"
                      />
                    </div>
                    {travelError && <p className="text-xs font-bold text-red-600 uppercase tracking-widest">{travelError}</p>}
                    <div className="flex gap-3">
                      <button onClick={() => setTravelStep(1)} className="flex-1 py-4 bg-surface-container-low rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Back</button>
                      <button onClick={() => { if (travelPassword.length < 8) { setTravelError('Minimum 8 characters.'); return; } if (travelPassword !== confirmTravelPassword) { setTravelError('Passwords do not match.'); return; } setTravelError(''); setTravelStep(3); }}
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
                        <p className="font-bold text-sm text-amber-800 dark:text-amber-300 mb-1">Store your password safely</p>
                        <p className="text-xs text-amber-700/70 dark:text-amber-400/70 leading-relaxed">
                          If you forget it, the hidden folders cannot be recovered — they are encrypted with your password. There is no backdoor.
                        </p>
                      </div>
                    </div>
                    <div className="space-y-3">
                      <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">Folders that will be hidden</p>
                      {folders.filter(f => travelHiddenFolderIds.includes(f.id)).map(f => (
                        <div key={f.id} className="flex items-center gap-3 p-3 bg-surface-container-low rounded-xl">
                          <Plane size={16} className="text-blue-600 shrink-0" />
                          <span className="font-bold text-sm text-black dark:text-white">{f.label}</span>
                          <span className="text-xs text-on-surface-variant ml-auto">
                            {credentials.filter(c => c.folderId === f.id).length} credential{credentials.filter(c => c.folderId === f.id).length !== 1 ? 's' : ''}
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
                          : <><Plane size={16} />Activate Travel Mode</>
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
                      <h3 className="text-xl font-headline font-black text-black dark:text-white mb-2">Travel Mode Active</h3>
                      <p className="text-sm text-on-surface-variant leading-relaxed">
                        Hidden folders are encrypted and invisible. Your vault has been updated.
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
              className="absolute inset-0 bg-[#000000]/60 backdrop-blur-sm"
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
                    <h3 className="text-lg font-headline font-black text-black dark:text-white">Import Preview</h3>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[10px] px-2 py-0.5 bg-surface-container-high rounded-full font-black uppercase tracking-widest text-on-surface-variant">
                        {FORMAT_LABELS[importResult.detectedFormat]}
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
                    {importResult.credentials.length} credential{importResult.credentials.length !== 1 ? 's' : ''} found
                  </p>
                </div>

                {/* Preview table */}
                <div>
                  <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-2">Preview (first 8)</p>
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
                              +{importResult.credentials.length - 8} more
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Import mode toggle */}
                <div>
                  <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-2">Import mode</p>
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
                      <p className="font-black">Merge</p>
                      <p className={`text-[11px] mt-0.5 font-normal ${importMode === 'merge' ? 'text-white/70 dark:text-black/60' : 'text-on-surface-variant'}`}>Add alongside existing</p>
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
                      <p className="font-black">Replace All</p>
                      <p className={`text-[11px] mt-0.5 font-normal ${importMode === 'replace' ? 'text-white/70' : 'text-on-surface-variant'}`}>Delete existing first</p>
                    </button>
                  </div>
                  {importMode === 'replace' && (
                    <div className="mt-3 p-3 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 rounded-xl flex items-start gap-2">
                      <AlertTriangle size={15} className="text-red-600 shrink-0 mt-0.5" />
                      <p className="text-xs text-red-700 dark:text-red-400 font-bold">
                        This will permanently delete all {credentials.length} existing credential{credentials.length !== 1 ? 's' : ''} before importing. This cannot be undone.
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
                    : <><Upload size={14} />Import {importResult.credentials.length} credential{importResult.credentials.length !== 1 ? 's' : ''}</>
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
              className="absolute inset-0 bg-[#000000]/60 backdrop-blur-sm"
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
              <h3 className="text-xl font-headline font-black text-black dark:text-white mb-2">Disable Travel Mode</h3>
              <p className="text-sm text-on-surface-variant leading-relaxed mb-8">
                Enter your password to decrypt and restore {travelConfig.hiddenFolderIds.length} hidden folder{travelConfig.hiddenFolderIds.length !== 1 ? 's' : ''}.
              </p>
              <div className="space-y-3 mb-6">
                <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">Password</label>
                <input type="password" value={disableTravelPw}
                  onChange={e => { setDisableTravelPw(e.target.value); setDisableTravelError(''); }}
                  placeholder="Enter your password"
                  className="w-full px-5 py-4 bg-surface-container-low rounded-xl border border-zinc-300 dark:border-zinc-600 text-black dark:text-white font-bold focus:ring-2 focus:ring-blue-600/20 focus:border-blue-600 outline-none transition-all"
                  onKeyDown={e => e.key === 'Enter' && handleDisableTravel()}
                />
                {disableTravelError && <p className="text-xs font-bold text-red-600 uppercase tracking-widest">{disableTravelError}</p>}
              </div>
              <div className="flex gap-3">
                <button onClick={() => setIsDisableTravelOpen(false)} className="flex-1 py-4 bg-surface-container-low rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Cancel</button>
                <button onClick={handleDisableTravel} disabled={isDisablingTravel || !disableTravelPw}
                  className="flex-1 py-4 bg-blue-600 text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-blue-700 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {isDisablingTravel ? <><Loader2 size={16} className="animate-spin" />Decrypting…</> : 'Restore Folders'}
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
              className="absolute inset-0 bg-[#000000]/70 backdrop-blur-sm"
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
                      <h3 className="text-xl font-headline font-black text-black dark:text-white mb-2">Duress Mode Armed</h3>
                      <p className="text-sm text-on-surface-variant">
                        Entering the duress password at login will trigger an immediate forensic wipe. Auto-wipe activates after {duressMaxAttempts} failed attempt{duressMaxAttempts !== 1 ? 's' : ''}.
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
                    <h3 className="text-xl font-headline font-black text-black dark:text-white mb-2">Arm Duress Mode</h3>
                    <p className="text-sm text-on-surface-variant leading-relaxed mb-8">
                      {duressStep === 1
                        ? 'Set a duress password — different from your main password. Entering it at login triggers an immediate forensic wipe of all vault data.'
                        : 'Confirm your duress password. This cannot be recovered.'}
                    </p>

                    <div className="space-y-5">
                      {duressStep === 1 && (
                        <div className="space-y-3">
                          <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">Duress Password</label>
                          <div className="relative">
                            <input type={showDuressPassword ? 'text' : 'password'} value={duressPassword}
                              onChange={e => { setDuressPassword(e.target.value); setDuressError(''); }}
                              placeholder="Minimum 8 characters"
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
                          <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">Confirm Duress Password</label>
                          <input type="password" value={confirmDuressPassword}
                            onChange={e => { setConfirmDuressPassword(e.target.value); setDuressError(''); }}
                            placeholder="Repeat duress password"
                            autoFocus
                            className="w-full px-5 py-4 bg-surface-container-low rounded-xl border border-outline-variant/20 text-black dark:text-white font-bold focus:ring-2 focus:ring-red-600/20 focus:border-red-600 outline-none transition-all"
                          />
                        </div>
                      )}

                      {duressError && <p className="text-xs font-bold text-red-600 uppercase tracking-widest">{duressError}</p>}

                      <div className="p-4 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900 rounded-xl flex items-start gap-3">
                        <AlertTriangle size={16} className="text-red-600 shrink-0 mt-0.5" />
                        <p className="text-xs text-red-700 dark:text-red-300 leading-relaxed">
                          Triggering wipe performs a 3-pass CSPRNG overwrite of all localStorage, sessionStorage, IndexedDB, and Cache Storage. This is irreversible.
                        </p>
                      </div>

                      <div className="flex gap-3">
                        {duressStep === 2 && (
                          <button onClick={() => setDuressStep(1)} className="flex-1 py-4 bg-surface-container-low rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">Back</button>
                        )}
                        <button
                          onClick={() => {
                            if (duressStep === 1) {
                              if (duressPassword.length < 8) { setDuressError('Minimum 8 characters.'); return; }
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
                            ? <><Loader2 size={16} className="animate-spin" />Arming…</>
                            : duressStep === 1 ? 'Next' : <><Skull size={16} />Arm Duress Mode</>
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

      {/* ── Trigger Wipe Confirmation Modal ──────────────────────────────────── */}
      <AnimatePresence>
        {isDuressWipeOpen && (
          <div className="fixed inset-0 z-[110] flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/80 backdrop-blur-md"
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

    </div>
  );
}
