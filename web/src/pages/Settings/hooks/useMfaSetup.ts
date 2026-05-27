import { useState, useRef, useCallback, useEffect } from 'react';
import QRCode from 'qrcode';
import {
  getMfaConfig, saveMfaConfig,
  generateTotpSecret, buildTotpUri, buildHotpUri, verifyTotp, verifyHotp,
  generateEmailCode, verifyEmailCode, clearPendingOtp,
  isWebAuthnSupported, isSecureContext,
  registerWebAuthn, authenticateWebAuthn,
  registerPasskey, registerPlatformAuth,
  countActiveMfaMethods, refreshLoginHints,
  isPlatformAuthAvailable, describeWebAuthnError,
  type MfaConfig, type WebAuthnCredentialMeta
} from '../../../utils/mfa';
import { logger } from '../../../utils/logger';
import { useTranslation } from 'react-i18next';
import { useNotification } from '../../../context/NotificationContext';
import { daemon } from '../../../utils/daemonClient';
import { hasLocalQuickUnlock, enrollQuickUnlock, revokeLocalQuickUnlock } from '../../../utils/quickUnlock';
import type { UserProfile } from '../../../context/UserContext';

export type MfaType = 'totp' | 'webauthn' | 'email' | 'passkey' | 'platform';
export interface MfaModalState { type: MfaType; step: number }

export function useMfaSetup(profile: UserProfile) {
  const { t } = useTranslation();
  const { addNotification } = useNotification();
  const [mfaConfig, setMfaConfig] = useState<MfaConfig>(getMfaConfig);
  const [policyError, setPolicyError] = useState('');
  const [platformAuthAvail, setPlatformAuthAvail] = useState<boolean | null>(null);

  const refreshMfa = () => setMfaConfig(getMfaConfig());

  useEffect(() => {
    isPlatformAuthAvailable().then(setPlatformAuthAvail);
  }, []);

  const [mfaModal, setMfaModal] = useState<MfaModalState | null>(null);

  // TOTP / HOTP
  const [totpSecret, setTotpSecret] = useState('');
  const [totpType, setTotpType] = useState<'totp' | 'hotp'>('totp');
  const [hotpCounter, setHotpCounter] = useState(0);
  const [totpCode, setTotpCode] = useState(Array(8).fill(''));
  const [totpError, setTotpError] = useState('');
  const [totpSecretCopied, setTotpSecretCopied] = useState(false);
  const totpRefs = useRef<(HTMLInputElement | null)[]>([]);

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
      if (err) logger.error('[TOTP QR]', err);
    });
  }, [totpSecret, totpType, hotpCounter, profile.email]);

  // WebAuthn
  const [webAuthnError, setWebAuthnError] = useState('');
  const [webAuthnBusy, setWebAuthnBusy] = useState(false);
  const [webAuthnKeyName, setWebAuthnKeyName] = useState(t('mfa.defaultKeyName', 'My Security Key'));

  // Passkey
  const [passkeyError, setPasskeyError] = useState('');
  const [passkeyBusy, setPasskeyBusy] = useState(false);
  const [passkeyName, setPasskeyName] = useState(t('mfa.defaultDeviceName', 'My Device'));

  // Platform auth
  const [platformError, setPlatformError] = useState('');
  const [platformBusy, setPlatformBusy] = useState(false);
  const [platformName, setPlatformName] = useState(t('mfa.defaultThisDevice', 'This Device'));

  // Email OTP
  const [emailInput, setEmailInput] = useState(profile.email || '');
  const [emailSimCode, setEmailSimCode] = useState<string | null>(null);
  const [emailCode, setEmailCode] = useState(Array(6).fill(''));
  const [emailError, setEmailError] = useState('');
  const [emailBusy, setEmailBusy] = useState(false);
  const emailRefs = useRef<(HTMLInputElement | null)[]>([]);

  // Quick Unlock
  const [quickUnlockEnabled, setQuickUnlockEnabled] = useState(() => hasLocalQuickUnlock());
  const [quickUnlockLoading, setQuickUnlockLoading] = useState(false);
  const [isPasswordPromptOpen, setIsPasswordPromptOpen] = useState(false);

  const closeMfaModal = () => {
    setMfaModal(null);
    clearPendingOtp();
  };

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

  const handleTotpRemove = () => {
    const cfg = getMfaConfig();
    cfg.totp = { enabled: false };
    cfg.hotp = undefined;
    saveMfaConfig(cfg);
    refreshLoginHints();
    refreshMfa();
    closeMfaModal();
  };

  const handleWebAuthnRegister = async () => {
    setWebAuthnError('');
    setWebAuthnBusy(true);
    try {
      const userEmail = profile.email || 'user@pwdnow';
      await registerWebAuthn(userEmail, userEmail, profile.firstName || 'User', webAuthnKeyName.trim() || t('mfa.defaultKeyName', 'My Security Key'));
      refreshMfa();
      setMfaModal({ type: 'webauthn', step: 3 });
    } catch (err) {
      setWebAuthnError(describeWebAuthnError(err, 'securitykey'));
    } finally {
      setWebAuthnBusy(false);
    }
  };

  const handleWebAuthnRemove = (credId: string) => {
    const cfg = getMfaConfig();
    cfg.webauthn.credentials = cfg.webauthn.credentials.filter(c => c.id !== credId);
    cfg.webauthn.enabled = cfg.webauthn.credentials.length > 0;
    saveMfaConfig(cfg);
    refreshMfa();
  };

  const handlePasskeyRegister = async () => {
    setPasskeyError('');
    setPasskeyBusy(true);
    try {
      const userEmail = profile.email || 'user@pwdnow';
      await registerPasskey(userEmail, userEmail, profile.firstName || 'User', passkeyName.trim() || t('mfa.defaultDeviceName', 'My Device'));
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

  const handlePlatformRegister = async () => {
    setPlatformError('');
    setPlatformBusy(true);
    try {
      const userEmail = profile.email || 'user@pwdnow';
      await registerPlatformAuth(userEmail, userEmail, profile.firstName || 'User', platformName.trim() || t('mfa.defaultThisDevice', 'This Device'));
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

  const handleToggleQuickUnlock = async () => {
    if (!quickUnlockEnabled) {
      setIsPasswordPromptOpen(true);
    } else {
      setQuickUnlockLoading(true);
      try {
        await daemon.quickUnlockRevoke();
        revokeLocalQuickUnlock();
        setQuickUnlockEnabled(false);
        addNotification({ title: 'Quick Unlock', message: t('settings.quickUnlockDisabled', 'Quick Unlock disabled for this device'), type: 'info' });
      } catch (e: any) {
        addNotification({ title: 'Error', message: e.message || 'Error revoking Quick Unlock', type: 'error' });
      } finally {
        setQuickUnlockLoading(false);
      }
    }
  };

  const handleQuickUnlockConfirm = async (pwd: string) => {
    setIsPasswordPromptOpen(false);
    setQuickUnlockLoading(true);
    try {
      const dbk = await enrollQuickUnlock(profile.email || 'user');
      if (dbk) {
        await daemon.quickUnlockEnroll(pwd, dbk);
        setQuickUnlockEnabled(true);
        addNotification({ title: 'Quick Unlock', message: t('settings.quickUnlockEnabled', 'Quick Unlock enabled successfully!'), type: 'success' });
      } else {
        addNotification({ title: 'Quick Unlock', message: t('settings.quickUnlockFailed', 'Touch ID / WebAuthn PRF enrollment failed'), type: 'error' });
      }
    } catch (e: any) {
      addNotification({ title: 'Error', message: e.message || 'Error managing Quick Unlock', type: 'error' });
    } finally {
      setQuickUnlockLoading(false);
    }
  };

  const handlePasswordlessToggle = () => {
    const cfg = getMfaConfig();
    cfg.passwordlessEnabled = !cfg.passwordlessEnabled;
    saveMfaConfig(cfg);
    refreshLoginHints();
    refreshMfa();
  };

  const handlePasswordLoginToggle = () => {
    const activeMethods = countActiveMfaMethods();
    const cfg = getMfaConfig();
    const currentEnabled = cfg.passwordLoginEnabled !== false;

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

  const handleEmailSend = async () => {
    setEmailBusy(true);
    setEmailError('');
    try {
      // Detect browser for email context
      const { isBraveBrowser } = await import('../../../utils/browser');
      const browserName = (await isBraveBrowser()) ? 'Brave' : undefined;

      const res = await fetch('/api/auth/send-setup-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          toEmail: emailInput,
          browser: browserName,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        if (data.error === 'smtp_not_configured') {
          setEmailError('Email server not configured. Set up SMTP in Security settings first.');
          setEmailBusy(false);
          return;
        }
        if (data.error === 'resend_too_soon') {
          setEmailError(`Please wait ${Math.ceil((data.waitMs || 30000) / 1000)}s before resending.`);
          setEmailBusy(false);
          return;
        }
        throw new Error(data.error || 'Failed to send code');
      }
      // Server sent a real email — no sim code needed
      setEmailSimCode(null);
      setEmailBusy(false);
      setMfaModal({ type: 'email', step: 2 });
    } catch (e: any) {
      setEmailError(e.message || 'Failed to send verification code.');
      setEmailBusy(false);
    }
  };

  const handleEmailVerify = async () => {
    const token = emailCode.join('');
    setEmailError('');
    try {
      const res = await fetch('/api/auth/verify-setup-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ code: token }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        if (data.error === 'expired_or_invalid') {
          setEmailError('Code expired. Please request a new one.');
        } else if (data.error === 'too_many_attempts') {
          setEmailError('Too many attempts. Please request a new code.');
        } else {
          setEmailError(`Incorrect code.${data.attemptsLeft != null ? ` ${data.attemptsLeft} attempt(s) left.` : ''}`);
        }
        return;
      }
      // Verified — enable email MFA
      const cfg = getMfaConfig();
      cfg.email = { enabled: true, address: data.email || emailInput, enabledAt: Date.now() };
      saveMfaConfig(cfg);
      refreshLoginHints();
      refreshMfa();
      setMfaModal({ type: 'email', step: 3 });
    } catch (e: any) {
      setEmailError(e.message || 'Verification failed.');
    }
  };

  const handleEmailRemove = () => {
    const cfg = getMfaConfig();
    cfg.email = { enabled: false };
    saveMfaConfig(cfg);
    refreshLoginHints();
    refreshMfa();
    closeMfaModal();
  };

  const openMfaModal = (type: MfaType) => {
    if (type === 'totp') {
      const secret = generateTotpSecret();
      setTotpSecret(secret);
      setTotpType('totp');
      setTotpCode(Array(8).fill(''));
      setTotpError('');
      setMfaModal({ type: 'totp', step: 1 });
    } else if (type === 'email') {
      setEmailSimCode(null);
      setEmailCode(Array(6).fill(''));
      setEmailError('');
      setMfaModal({ type: 'email', step: 1 });
    } else {
      setMfaModal({ type, step: 1 });
    }
  };

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
      const focusIndex = Math.min(digits.length, code.length - 1);
      if (focusIndex >= 0) refs.current[focusIndex]?.focus();
    },
  });

  const totpHandlers  = makeDigitHandlers(totpCode,  setTotpCode,  totpRefs, handleTotpVerify);
  const emailHandlers = makeDigitHandlers(emailCode, setEmailCode, emailRefs, handleEmailVerify);

  return {
    mfaConfig,
    policyError,
    platformAuthAvail,
    mfaModal,
    setMfaModal,
    totpSecret,
    setTotpSecret,
    totpType,
    setTotpType,
    hotpCounter,
    setHotpCounter,
    totpCode,
    setTotpCode,
    totpError,
    setTotpError,
    totpSecretCopied,
    setTotpSecretCopied,
    totpRefs,
    qrCanvasCallback,
    webAuthnError,
    setWebAuthnError,
    webAuthnBusy,
    setWebAuthnBusy,
    webAuthnKeyName,
    setWebAuthnKeyName,
    passkeyError,
    setPasskeyError,
    passkeyBusy,
    setPasskeyBusy,
    passkeyName,
    setPasskeyName,
    platformError,
    setPlatformError,
    platformBusy,
    setPlatformBusy,
    platformName,
    setPlatformName,
    emailInput,
    setEmailInput,
    emailSimCode,
    setEmailSimCode,
    emailCode,
    setEmailCode,
    emailError,
    setEmailError,
    emailBusy,
    setEmailBusy,
    emailRefs,
    quickUnlockEnabled,
    quickUnlockLoading,
    isPasswordPromptOpen,
    setIsPasswordPromptOpen,
    refreshMfa,
    closeMfaModal,
    openMfaModal,
    handleTotpVerify,
    handleTotpRemove,
    handleWebAuthnRegister,
    handleWebAuthnRemove,
    handlePasskeyRegister,
    handlePasskeyRemove,
    handlePlatformRegister,
    handlePlatformRemove,
    handleToggleQuickUnlock,
    handleQuickUnlockConfirm,
    handlePasswordlessToggle,
    handlePasswordLoginToggle,
    handleEmailSend,
    handleEmailVerify,
    handleEmailRemove,
    totpHandlers,
    emailHandlers
  };
}
