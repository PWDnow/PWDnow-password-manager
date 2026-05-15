import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Shield, ArrowRight, CheckCircle2, Loader2, ShieldAlert, Fingerprint, ChevronLeft, ShieldCheck, AlertTriangle, Smartphone, Key } from 'lucide-react';
import PublicHeader from '../components/PublicHeader';
import SEO from '../components/SEO';
import { daemon } from '../utils/daemonClient';
import { recordSession } from '../utils/sessionTracker';
import { keyStore, deriveLocalKey, deriveV1Only, getOrCreateLocalKeySalt, deriveArgon2idMaster, hkdfV2Bind } from '../crypto/keystore';
import {
  loadMfaConfig, getMfaConfig, saveMfaConfig,
  getPasskeyHint, loadPasskeyHint,
  authenticateWithPasskeyForLogin, getLoginHints,
  verifyTotp, verifyHotp, verifyEmailCode, generateEmailCode,
  authenticateWebAuthnForLogin, describeWebAuthnError,
  loadMfaConfigFromServer,
  type LoginHints,
} from '../utils/mfa';
import { checkIsDuressPassword, recordFailedLoginAttempt, wipeVaultData, getDuressModeConfig } from '../utils/securityModes';
import { generateUUID } from '../utils/crypto';
import { hasLocalQuickUnlock, getQuickUnlockDbk } from '../utils/quickUnlock';
import { LoginPerfTracker } from '../utils/perf';

export default function Login() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [step, setStep] = useState<'email' | 'method' | 'totp'>('email');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [passkeyLoading, setPasskeyLoading] = useState(false);
  const [webAuthnLoading, setWebAuthnLoading] = useState(false);
  const [quickUnlockLoading, setQuickUnlockLoading] = useState(false);
  const [selectedMfaChannel, setSelectedMfaChannel] = useState<'totp' | 'email' | null>(null);

  // Quick Unlock
  const [hasQuickUnlock] = useState(() => hasLocalQuickUnlock());

  const handleQuickUnlock = async () => {
    setError('');
    setQuickUnlockLoading(true);
    try {
      const dbk = await getQuickUnlockDbk();
      if (!dbk) {
        setError('Quick unlock failed or canceled. Please use your master password.');
        return;
      }
      if (!daemon.isConnected) await daemon.connect();
      await daemon.quickUnlock(dbk);

      window.dispatchEvent(new CustomEvent('daemonUnlocked'));
      try { await recordSession(); } catch { /* non-fatal */ }
      navigate('/vault');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Quick unlock failed');
    } finally {
      setQuickUnlockLoading(false);
    }
  };

  // Which MFA method to use in the TOTP step
  const [mfaMethod, setMfaMethod] = useState<'totp' | 'email'>('totp');
  // Track what authenticated (to complete login after TOTP)
  const [daemonWasUnlocked, setDaemonWasUnlocked] = useState(false);
  // D.1: partial token from server when MFA is required (S-01 server-side enforcement)
  const [serverPartialToken, setServerPartialToken] = useState<string | null>(null);
  // Simulated email OTP code (demo mode)
  const [emailSimCode, setEmailSimCode] = useState('');

  // Passkey hint is loaded from encrypted localStorage after the session key is
  // available (post-login on a previous session). Defaults to false; revealed
  // during the email step when daemon provides authoritative credential IDs.
  const [hasPasskeyHint, setHasPasskeyHint] = useState(false);

  // When the local _lk_salt differs from the server cryptoSalt at the email
  // step, we capture the old value here so the password step can derive a
  // decrypt-only "legacy" PBKDF2 key. This unblocks accounts whose vault data
  // was originally encrypted with the stale local salt.
  const [legacyLkSalt, setLegacyLkSalt] = useState<string | null>(null);

  // Track whether the server already has a cryptoSalt for this account.
  // When false, we MUST publish the local salt to the server after successful
  // login to prevent the "folders vanish after cache clear" bug.
  const [serverHasCryptoSalt, setServerHasCryptoSalt] = useState(false);

  // Login hints come live from daemon/server per email-step - never from localStorage.
  const [loginHints, setLoginHints] = useState<LoginHints>(getLoginHints());
  const hasMfaHint = loginHints.totp || loginHints.emailOtp;
  const isPasswordless = loginHints.passwordlessEnabled;
  const hasWebAuthnHint = loginHints.webauthn;

  // TOTP step state
  const [totpCode, setTotpCode] = useState(['', '', '', '', '', '']);
  const [totpError, setTotpError] = useState('');
  const totpRefs = useRef<(HTMLInputElement | null)[]>([]);

  const handleTotpDigit = (index: number, value: string) => {
    if (value.length > 1) value = value.slice(-1);
    if (!/^\d?$/.test(value)) return;
    const next = [...totpCode];
    next[index] = value;
    setTotpCode(next);
    if (value && index < 5) totpRefs.current[index + 1]?.focus();
  };
  const handleTotpKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !totpCode[index] && index > 0) totpRefs.current[index - 1]?.focus();
    if (e.key === 'Enter' && !totpCode.some(c => !c) && !loading) handleTotpSubmit();
  };
  const handleTotpPaste = (e: React.ClipboardEvent) => {
    e.preventDefault();
    const digits = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6).split('');
    const next = [...totpCode];
    digits.forEach((d, i) => { next[i] = d; });
    setTotpCode(next);
    totpRefs.current[Math.min(digits.length, 5)]?.focus();
  };

  // Redirect already-authenticated users straight to the vault.
  useEffect(() => {
    keyStore.restoreAsync().finally(() => {
      const hasServerSession = document.cookie.split(';').some(c => c.trim().startsWith('_pwd_csrf='));
      const hasLocalKeys = keyStore.getLocalKey(1) !== null || keyStore.getLocalKey(2) !== null;
      if (keyStore.hasToken || (hasServerSession && hasLocalKeys)) {
        navigate('/vault', { replace: true });
        return;
      }
      
      // If the user has a session but no local keys (e.g. after a page refresh in Server Mode),
      // pre-fill their email so they only need to enter their password to unlock the vault.
      if (hasServerSession && !hasLocalKeys) {
        fetch('/api/auth/me')
          .then(r => r.json())
          .then(data => {
            if (data.authenticated && data.user?.email) {
              setEmail(data.user.email);
            }
          })
          .catch(() => {});
      }

      // Attempt to load encrypted passkey hints (only succeeds if session key is in memory
      // from a prior unlock in the same tab - typically false on the login page, but
      // handles the edge case where the user navigates back without clearing the keystore).
      loadPasskeyHint().then(() => {
        setHasPasskeyHint(getPasskeyHint().length > 0);
      }).catch(() => {});
      // Remove legacy plaintext login hints and passkey hints if present.
      localStorage.removeItem('_pwdn_login_hints');
    });
  }, [navigate]);

  // Redirect to /setup if first-run setup has not been completed yet.
  useEffect(() => {
    fetch('/api/setup-status')
      .then(r => r.json())
      .then(({ completed }: { completed: boolean }) => {
        if (!completed) navigate('/setup', { replace: true });
      })
      .catch(() => { /* API unreachable - allow login to proceed */ });
  }, [navigate]);

  // ── Step 1 → Step 2: email continue ─────────────────────────────────────────
  const handleEmailContinue = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim()) return;
    setError('');
    
    setLoading(true);
    try {
      // ── Fetch hints from both daemon and server in parallel ────────────
      const daemonHintsPromise = (async () => {
        try {
          if (!daemon.isConnected) await daemon.connect();
          return await daemon.getLoginHints();
        } catch (e) {
          console.debug('Daemon hints failed:', e);
          return null;
        }
      })();

      const serverHintsPromise = (async () => {
        try {
          const url = `/api/auth/login-hints?email=${encodeURIComponent(email)}`;
          const res = await fetch(url);
          if (res.ok) return await res.json();
        } catch (e) {
          console.debug('Server hints failed:', e);
        }
        return null;
      })();

      const [dh, sh] = await Promise.all([daemonHintsPromise, serverHintsPromise]);

      let hints: LoginHints | null = null;
      
      // ── Senior Dev Fix: Prioritize user-specific server hints ───────────
      if (sh && sh.hints) {
        hints = sh.hints;
      } else if (dh) {
        hints = {
          totp:                dh.totp_enabled,
          emailOtp:            dh.email_otp_enabled,
          passwordEnabled:     dh.password_login_enabled,
          webauthn:            dh.fido2_ids.length > 0,
          passwordlessEnabled: !dh.password_login_enabled && dh.fido2_ids.length > 0,
        };
      }

      if (sh && sh.hints) {
        // Capture the server-stored salt - it is the AUTHORITATIVE PBKDF2 salt.
        // Always force `_lk_salt` to match. If a stale local salt was sitting
        // here from a pre-server-bridge era, capture it as the legacy salt so
        // the password step can derive a decrypt-only fallback key for any
        // data that was originally encrypted with it.
        if (sh.hints.cryptoSalt) {
          setServerHasCryptoSalt(true);
          const existingLk = localStorage.getItem('_lk_salt');
          if (existingLk && existingLk !== sh.hints.cryptoSalt) {
            // A pre-existing local salt that differs from the server's
            // cryptoSalt - capture it so the password step can derive a
            // decrypt-only fallback key for any data encrypted with it.
            setLegacyLkSalt(existingLk);
          } else {
            setLegacyLkSalt(null);
          }
          localStorage.setItem('_pwd_lks', sh.hints.cryptoSalt);
          // Force the canonical salt - overrides any stale value.
          localStorage.setItem('_lk_salt', sh.hints.cryptoSalt);
        } else {
          // Server has no cryptoSalt — we MUST publish our local salt after
          // successful login. Mark this so the login completion handler knows.
          setServerHasCryptoSalt(false);
        }
      }

      if (hints) {
        setLoginHints(hints);
        // Hints are held in React state only - never persisted to localStorage.

        // ── Auto-select the most secure MFA method ──────────────────────────
        // Ranking: Security Key > Passkey > TOTP > Email
        if (hints.webauthn) {
          // Keep as null to show "Security Key" button prominently
          setSelectedMfaChannel(null); 
        } else if (hints.passwordlessEnabled) {
          setSelectedMfaChannel(null);
        } else if (hints.totp) {
          setMfaMethod('totp');
          // If password is required, we still need to show the password field first
          // unless it's a pure MFA step.
        } else if (hints.emailOtp) {
          setMfaMethod('email');
        }
      }
    } catch (err) {
      console.debug('[Login] hints fetch error:', err);
    } finally {
      setLoading(false);
    }

    setStep('method');
  };

  // ── Passkey / biometric sign-in ───────────────────────────────────────────
  const handlePasskeyLogin = async () => {
    setError('');
    setPasskeyLoading(true);
    try {
      const ok = await authenticateWithPasskeyForLogin();
      if (!ok) { setError('Passkey authentication failed or no passkey found for this device.'); return; }

      window.dispatchEvent(new CustomEvent('daemonUnlocked'));
      try { await recordSession(); } catch { /* non-fatal */ }
      navigate('/vault');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Passkey authentication failed.');
    } finally {
      setPasskeyLoading(false);
    }
  };

  const handleWebAuthnLogin = async () => {
    setError('');
    setWebAuthnLoading(true);
    try {
      const ok = await authenticateWebAuthnForLogin();
      if (!ok) { setError(t('login.securityKeyFailed', 'Security key authentication failed. Make sure your key is connected.')); return; }
      
      window.dispatchEvent(new CustomEvent('daemonUnlocked'));
      try { await recordSession(); } catch { /* non-fatal */ }
      navigate('/vault');
    } catch (err) {
      setError(describeWebAuthnError(err, 'securitykey'));
    } finally {
      setWebAuthnLoading(false);
    }
  };

  // ── Publish cryptoSalt to server if missing ─────────────────────────────
  // This is the primary fix for the "folders vanish after cache clear" bug.
  // Without a server-stored salt, every cache-clear generates a new random
  // salt → different PBKDF2 key → can't decrypt existing vault data.
  const publishCryptoSaltIfNeeded = async () => {
    if (serverHasCryptoSalt) return; // Server already has it — nothing to do
    const salt = localStorage.getItem('_lk_salt');
    if (!salt) return; // No local salt to publish — shouldn't happen post-login
    const csrfMatch = document.cookie.match(/(?:^|;\s*)_pwd_csrf=([^;]*)/);
    const csrf = csrfMatch ? decodeURIComponent(csrfMatch[1]) : '';
    try {
      const res = await fetch('/api/auth/crypto-salt', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrf,
        },
        body: JSON.stringify({ cryptoSalt: salt }),
      });
      if (res.ok) {
        const data = await res.json();
        // Store the server's authoritative salt (which may be the one we just sent,
        // or the one that was already on the server if a race occurred)
        if (data.cryptoSalt) {
          localStorage.setItem('_pwd_lks', data.cryptoSalt);
          localStorage.setItem('_lk_salt', data.cryptoSalt);
        }
        console.log('[Login] Published cryptoSalt to server');
      }
    } catch (e) {
      console.warn('[Login] Failed to publish cryptoSalt:', e);
    }
  };

  // ── Complete login after successful password (and optional TOTP) ──────────
  // daemon.unlock() already stored the real session token; do not overwrite it.
  const completeDaemonLogin = async () => {
    try { await recordSession(); } catch { /* non-fatal */ }
    publishCryptoSaltIfNeeded(); // fire-and-forget, non-blocking
    window.dispatchEvent(new CustomEvent('daemonUnlocked'));
    navigate('/vault');
  };

  const completeServerLogin = async () => {
    // Note: session token was already stored in keyStore during handleLogin/server-path
    await publishCryptoSaltIfNeeded(); // MUST await here — salt must be published
    // before demoKeyAvailable triggers vault reload, to prevent a race where the
    // next login (after a cache clear) can't find the salt.
    window.dispatchEvent(new CustomEvent('demoKeyAvailable'));
    try { await recordSession(); } catch { /* non-fatal */ }
    navigate('/vault');
  };

  // ── TOTP / email OTP verification ─────────────────────────────────────────
  const handleTotpSubmit = async () => {
    setLoading(true);
    setTotpError('');

    const token = totpCode.join('');
    const cfg = getMfaConfig();

    let ok = false;
    try {
      if (mfaMethod === 'totp' && cfg.totp.secret) {
        ok = await verifyTotp(cfg.totp.secret, token, cfg.totp.algorithm || 'SHA-1', cfg.totp.digits || 6);
      } else if (mfaMethod === 'totp' && cfg.hotp?.enabled && cfg.hotp.secret) {
        const result = await verifyHotp(cfg.hotp.secret, cfg.hotp.counter, token, 10, cfg.hotp.algorithm || 'SHA-1', cfg.hotp.digits || 6);
        ok = result.ok;
        if (ok) {
          const updated = getMfaConfig();
          if (updated.hotp) { updated.hotp.counter = result.nextCounter; saveMfaConfig(updated); }
        }
      } else if (mfaMethod === 'email') {
        ok = verifyEmailCode(token);
      }
    } catch {
      ok = false;
    }

    if (!ok) {
      setTotpError(t('login.mfaInvalidCode', 'Incorrect code. Please try again.'));
      setTotpCode(['', '', '', '', '', '']);
      totpRefs.current[0]?.focus();
      setLoading(false);
      return;
    }

    // D.1 / S-01: if the server issued a partial token, complete the MFA gate
    // by calling /api/auth/login/finish before navigating to the vault.
    if (!daemonWasUnlocked && serverPartialToken) {
      try {
        const body: Record<string, string> = { partialToken: serverPartialToken };
        if (mfaMethod === 'totp') body.totpCode = token;
        else body.emailCode = token;
        const finishRes = await fetch('/api/auth/login/finish', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        const finishData = await finishRes.json().catch(() => ({ ok: false }));
        if (!finishRes.ok || !finishData.ok) {
          setTotpError(t('login.mfaInvalidCode', 'Incorrect code. Please try again.'));
          setServerPartialToken(null);
          setTotpCode(['', '', '', '', '', '']);
          totpRefs.current[0]?.focus();
          setLoading(false);
          return;
        }
      } catch {
        setTotpError(t('login.mfaInvalidCode', 'Server error. Please try again.'));
        setLoading(false);
        return;
      }
      setServerPartialToken(null);
    }

    if (daemonWasUnlocked) {
      await completeDaemonLogin();
    } else {
      await completeServerLogin();
    }
  };

  // ── Switch MFA method (TOTP ↔ email) ──────────────────────────────────────
  const handleSwitchMfaMethod = () => {
    const next = mfaMethod === 'totp' ? 'email' : 'totp';
    setMfaMethod(next);
    setTotpCode(['', '', '', '', '', '']);
    setTotpError('');
    if (next === 'email') {
      const code = generateEmailCode(email);
      setEmailSimCode(code);
    }
    setTimeout(() => totpRefs.current[0]?.focus(), 50);
  };

  // ── Password sign-in ──────────────────────────────────────────────────────
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const perf = LoginPerfTracker.get();
    perf.reset();
    perf.markStart('total');

    // ── Duress intercept ───────────────────────────────────────────────────────
    if (getDuressModeConfig().armed) {
      const isDuress = await checkIsDuressPassword(password);
      if (isDuress) {
        await new Promise(r => setTimeout(r, 900));
        await wipeVaultData(daemon.isConnected ? daemon : undefined);
        window.location.replace('/login');
        return;
      }
    }

    // ── Try daemon first ──────────────────────────────────────────────────────
    let daemonUnlocked = false;
    const salt = getOrCreateLocalKeySalt();
    perf.markStart('argon2idMaster');
    // Phase A: start v2 Argon2id AND v1 PBKDF2 concurrently with daemon.unlock
    // so both browser KDF costs overlap with the 6–8 s daemon Argon2id window.
    const browserMasterPromise = deriveArgon2idMaster(password, salt).catch(e => {
      console.warn('[Login] Argon2id master derivation failed:', e);
      return null;
    });
    perf.markStart('pbkdf2V1');
    const v1Promise = deriveV1Only(password, salt).catch(e => {
      console.warn('[Login] V1 key derivation failed:', e);
      return null as { encKey: CryptoKey; sigKey: CryptoKey } | null;
    });

    try {
      if (!daemon.isConnected) await daemon.connect();
      perf.markStart('daemonUnlock');
      await daemon.unlock(password);
      perf.markEnd('daemonUnlock');
      daemonUnlocked = true;
    } catch { /* daemon unavailable - fall through to offline auth */ }

    if (daemonUnlocked) {
      let v1KeyAvailable = false;
      try {
        const token = keyStore.get() || '';
        // v1 PBKDF2 was started before daemon.unlock — awaiting an already-resolved promise
        perf.markStart('deriveKeys');
        const v1 = await v1Promise;
        perf.markEnd('deriveKeys');
        perf.markEnd('pbkdf2V1');
        if (v1) {
          keyStore.storeLocalKey(v1.encKey, 1);
          keyStore.storeSigningKey(v1.sigKey, 1);
          v1KeyAvailable = true;
        }

        // Phase 2: Defer v2 and MFA into background
        keyStore.v2Pending = browserMasterPromise.then(async (master) => {
          if (master) {
            const v2 = await hkdfV2Bind(master, salt, token);
            keyStore.storeLocalKey(v2.encKey, 2);
            keyStore.storeSigningKey(v2.sigKey, 2);
            const saltBytes = Uint8Array.from(salt.match(/../g)!.map(h => parseInt(h, 16)));
            keyStore.setV2Salt(saltBytes);
          }
        }).catch(e => console.warn('[Login] Background v2 failed:', e));

      } catch (e) {
        // crypto.subtle is missing on plain HTTP for non-localhost — known limitation,
        // documented as "non-fatal" historically. Anything else is a real bug:
        // log it loudly so it cannot hide behind a swallowed catch again.
        console.error('[Login] Local key derivation failed:', e);
      }

      // Post-unlock work in parallel: MFA config, passkey hint, legacy key.
      const backgroundTasks: Promise<unknown>[] = [
        loadMfaConfig().catch(e => console.warn('MFA load failed', e)),
        loadPasskeyHint().then(() => {
          setHasPasskeyHint(getPasskeyHint().length > 0);
        }).catch(e => console.warn('Passkey hint load failed', e))
      ];
      if (legacyLkSalt) {
        backgroundTasks.push(
          deriveLocalKey(password, legacyLkSalt)
            .then(k => keyStore.storeLegacyKey(k))
            .catch(e => console.warn('[Login] legacy key derivation failed', e))
        );
      }

      if (v1KeyAvailable) window.dispatchEvent(new CustomEvent('demoKeyAvailable'));

      await completeDaemonLogin();
      perf.markEnd('total');
      perf.log();
      return;
    }

    // ── Offline / demo-mode fallback ─────────────────────────────────────────
    // Reuse v1Promise + browserMasterPromise from the daemon section above — they
    // have been running concurrently with the failed daemon connect attempt, so
    // by the time the server fetch resolves they are likely already done.
    // No new derivations are started here; only a token is generated.
    const serverModeToken = generateUUID();

    try {
      const browser = await (async () => {
        try {
          if ((navigator as any).brave && typeof (navigator as any).brave.isBrave === 'function' && await (navigator as any).brave.isBrave()) return 'Brave';
        } catch { /* ignore */ }
        return 'Unknown';
      })();

      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, browser })
      });

      const data = await res.json().catch(() => ({ ok: false }));

      if (res.ok && data.ok !== false) {
        // D.1 / S-01: server returned a partial token - MFA required server-side.
        if (data.partialToken) {
          setServerPartialToken(data.partialToken);
          const method = (data.methods?.includes('totp') ? 'totp' : 'email') as 'totp' | 'email';
          setMfaMethod(method);
          setDaemonWasUnlocked(false);
          if (method === 'email') {
            const code = generateEmailCode(email);
            setEmailSimCode(code);
          }
          setStep('totp');
          setLoading(false);
          return;
        }

        try {
          // Await v1 (likely already resolved — it ran during daemon connect + server fetch).
          // Bind v2 via cheap HKDF once the Argon2id master is ready (background).
          keyStore.store(serverModeToken);
          const v1 = await v1Promise;
          if (v1) {
            keyStore.storeLocalKey(v1.encKey, 1);
            keyStore.storeSigningKey(v1.sigKey, 1);
          }

          keyStore.v2Pending = browserMasterPromise.then(async (master) => {
            if (master) {
              const v2 = await hkdfV2Bind(master, salt, serverModeToken);
              keyStore.storeLocalKey(v2.encKey, 2);
              keyStore.storeSigningKey(v2.sigKey, 2);
              const saltBytes = Uint8Array.from(salt.match(/../g)!.map(h => parseInt(h, 16)));
              keyStore.setV2Salt(saltBytes);
            }
          }).catch(e => console.warn('[Login] Background server-mode v2 failed:', e));

          // Run remaining post-unlock work in parallel: legacy-key derivation,
          // MFA config load (local + server), passkey hint load.
          const tasks: Promise<unknown>[] = [
            loadMfaConfig(),
            loadPasskeyHint(),
            loadMfaConfigFromServer(),
          ];
          if (legacyLkSalt) {
            tasks.push(
              deriveLocalKey(password, legacyLkSalt)
                .then(k => keyStore.storeLegacyKey(k))
                .catch(e => console.warn('[Login] legacy key derivation failed', e)),
            );
          }
          await Promise.all(tasks);
          setHasPasskeyHint(getPasskeyHint().length > 0);
          if (v1) window.dispatchEvent(new CustomEvent('demoKeyAvailable'));
        } catch (e) {
          console.error('[Login] Key derivation failed:', e);
        }

        const cfg = getMfaConfig();
        if (cfg.totp.enabled || cfg.email.enabled) {
          const method = cfg.totp.enabled ? 'totp' : 'email';
          setMfaMethod(method);
          setDaemonWasUnlocked(false);
          if (method === 'email') {
            const code = generateEmailCode(email);
            setEmailSimCode(code);
          }
          setStep('totp');
          setLoading(false);
          return;
        }

        await completeServerLogin();
        return;
      }
    } catch (err) {
      console.error('[Login] offline auth error:', err);
    }

    // Both daemon and offline auth failed
    const shouldWipe = recordFailedLoginAttempt();
    if (shouldWipe) {
      await wipeVaultData(daemon.isConnected ? daemon : undefined);
      window.location.replace('/login');
      return;
    }
    const cfg = getDuressModeConfig();
    const remaining = cfg.armed ? ` (${cfg.attemptsRemaining} attempt${cfg.attemptsRemaining !== 1 ? 's' : ''} remaining)` : '';
    setError(t('login.invalidCredentials', 'Invalid master password.') + remaining);
    setLoading(false);
    perf.markEnd('total');
    perf.log();
  };


  return (
    <main className="min-h-screen flex bg-white dark:bg-[#0a0a0a]">
      <SEO
        title={t('login.title', 'Login')}
        description={t('login.heroSubtitle', 'Military-grade encryption, seamless access control, and comprehensive audit logs designed for modern teams.')}
      />
      <PublicHeader />

      {/* Left Pane - Branding & Value Prop (Hidden on mobile) */}
      <section className="hidden lg:flex lg:w-[45%] bg-slate-900 relative overflow-hidden flex-col justify-between p-12 xl:p-16 text-white">
        <div className="absolute top-0 left-0 w-full h-full overflow-hidden pointer-events-none">
          <div className="absolute -top-[20%] -left-[10%] w-[70%] h-[70%] rounded-full bg-blue-600/20 blur-[120px]" />
          <div className="absolute bottom-[10%] -right-[20%] w-[60%] h-[60%] rounded-full bg-emerald-500/10 blur-[100px]" />
        </div>

        <div className="relative z-10 flex items-center gap-3">
          <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-600/20">
            <Shield className="text-white" size={24} />
          </div>
          <span className="text-2xl font-headline font-black tracking-tight text-white">PWDnow</span>
        </div>

        <div className="relative z-10 max-w-lg mt-12">
          <h2 className="text-4xl xl:text-5xl font-headline font-bold mb-6 leading-[1.1] tracking-tight text-white">
            {t('login.heroTitle', 'Secure your enterprise digital assets.')}
          </h2>
          <p className="text-slate-400 text-lg leading-relaxed mb-12">
            {t('login.heroSubtitle', 'Military-grade encryption, seamless access control, and comprehensive audit logs designed for modern teams.')}
          </p>

          <div className="space-y-4">
            {[
              t('login.feature1', 'Zero-knowledge architecture'),
              t('login.feature2', 'SOC2 Type II Certified'),
              t('login.feature3', 'End-to-end encryption')
            ].map((feature, idx) => (
              <div key={idx} className="flex items-center gap-3 text-slate-300">
                <CheckCircle2 className="text-blue-500" size={20} />
                <span className="font-medium">{feature}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="relative z-10 mt-12">
          <p className="text-slate-400 text-sm font-medium">
            © {new Date().getFullYear()} PWDnow. {t('login.allRightsReserved', 'All rights reserved.')}
          </p>
        </div>
      </section>

      {/* Right Pane - Login Form */}
      <section className="w-full lg:w-[55%] flex flex-col justify-center px-6 sm:px-12 md:px-24 xl:px-32 py-12 relative bg-white dark:bg-[#0a0a0a]">
        {/* Mobile Logo */}
        <div className="lg:hidden flex items-center gap-3 mb-12">
          <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-600/20">
            <Shield className="text-white" size={20} />
          </div>
          <span className="text-xl font-headline font-black tracking-tight text-black dark:text-white">PWDnow</span>
        </div>

        <div className="w-full max-w-md mx-auto lg:mx-0">

          {/* Insecure connection warning */}
          {window.location.protocol === 'http:' &&
           window.location.hostname !== 'localhost' &&
           window.location.hostname !== '127.0.0.1' && (
            <div className="mb-6 p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800/30 rounded-xl flex items-start gap-3" role="alert">
              <ShieldAlert className="text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" size={16} />
              <p className="text-amber-700 dark:text-amber-300 text-sm leading-snug">
                <strong>Insecure connection (HTTP)</strong> - passkeys and biometrics require HTTPS or localhost.
              </p>
            </div>
          )}

          {error && (
            <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/30 rounded-xl flex items-start gap-3" role="alert">
              <div className="text-red-600 dark:text-red-400 font-medium text-sm">{error}</div>
            </div>
          )}

          {/* ── STEP 1: email ──────────────────────────────────────────────── */}
          {step === 'email' && (
            <>
              <div className="mb-10">
                <h1 className="text-3xl sm:text-4xl font-headline font-bold text-black dark:text-white mb-3 tracking-tight">
                  {t('login.title', 'Welcome back')}
                </h1>
                <p className="text-on-surface-variant text-base">
                  {t('login.subtitle', 'Enter your email to continue.')}
                </p>
              </div>

              <form onSubmit={handleEmailContinue} className="space-y-6">
                <div>
                  <label htmlFor="email" className="block text-sm font-semibold text-black dark:text-white mb-2">
                    {t('login.emailLabel', 'Work Email')}
                  </label>
                  <input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full px-4 py-3.5 rounded-xl border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#141414] text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-white/30 focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all outline-none text-base"
                    placeholder="name@company.com"
                    required
                    autoFocus
                    autoComplete="email"
                  />
                </div>

                <button
                  type="submit"
                  disabled={!email.trim()}
                  className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white py-4 rounded-xl font-bold text-base transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 active:scale-[0.98]"
                >
                  {t('login.continue', 'Continue')}<ArrowRight size={18} />
                </button>
              </form>

              <div className="mt-10 pt-8 border-t border-outline-variant/30 dark:border-white/10 text-center">
                <p className="text-base text-on-surface-variant">
                  {t('login.noAccount', "Don't have an enterprise account?")}{' '}
                  <Link to="/register" className="text-black dark:text-white font-bold hover:text-blue-600 dark:hover:text-blue-400 transition-colors">
                    {t('login.createAccount', 'Request access')}
                  </Link>
                </p>
              </div>
            </>
          )}

          {/* ── STEP 2: password ─────────────────────────────────────────── */}
          {step === 'method' && (
            <>
              <div className="mb-10">
                <button
                  type="button"
                  onClick={() => { setStep('email'); setError(''); }}
                  className="flex items-center gap-1 text-sm text-on-surface-variant hover:text-black dark:hover:text-white transition-colors mb-6"
                >
                  <ChevronLeft size={16} />{email}
                </button>
                <h1 className="text-3xl sm:text-4xl font-headline font-bold text-black dark:text-white mb-3 tracking-tight">
                  Sign in as
                </h1>
                <p className="text-on-surface-variant text-base font-semibold truncate">{email}</p>
              </div>

              <div className="space-y-4">
                {selectedMfaChannel ? (
                  <form onSubmit={handleLogin} className="space-y-4">
                    <button type="button" onClick={() => setSelectedMfaChannel(null)} className="flex items-center gap-1 text-sm text-on-surface-variant hover:text-black dark:hover:text-white transition-colors mb-2">
                      <ChevronLeft size={16} /> Back to options
                    </button>
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <label htmlFor="password" className="block text-sm font-semibold text-black dark:text-white">
                          {t('login.passwordLabel', 'Password')}
                        </label>
                        <Link to="/forgot-password" tabIndex={-1} className="text-sm font-semibold text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors">
                          {t('login.forgotPassword', 'Forgot password?')}
                        </Link>
                      </div>
                      <input type="text" name="username" value={email} readOnly autoComplete="username" className="hidden" aria-hidden="true" />
                      <input
                        id="password"
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="w-full px-4 py-3.5 rounded-xl border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#141414] text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-white/30 focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all outline-none text-base"
                        placeholder="••••••••"
                        required
                        autoFocus
                        autoComplete="current-password"
                        aria-invalid={!!error}
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={loading || passkeyLoading || webAuthnLoading}
                      className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-60 disabled:cursor-not-allowed text-white py-4 rounded-xl font-bold text-base transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 active:scale-[0.98]"
                    >
                      {loading
                        ? <><Loader2 size={18} className="animate-spin" />{t('login.submitting', 'Signing in…')}</>
                        : <>{t('login.submit', 'Sign In')}<ArrowRight size={18} /></>
                      }
                    </button>
                  </form>
                ) : (
                  <>
                    {/* MOST SECURE - shown first */}
                    {hasPasskeyHint && (
                      <button
                        type="button"
                        onClick={handlePasskeyLogin}
                        disabled={passkeyLoading || loading || webAuthnLoading}
                        className="w-full flex items-center gap-4 px-5 py-4 rounded-xl border-2 border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#141414] hover:border-blue-600 dark:hover:border-blue-500 hover:bg-white dark:hover:bg-[#1a1a1a] transition-all text-left group disabled:opacity-60 disabled:cursor-not-allowed"
                      >
                        <div className="w-10 h-10 rounded-xl bg-black dark:bg-white flex items-center justify-center shrink-0">
                          {passkeyLoading
                            ? <Loader2 size={20} className="text-white dark:text-black animate-spin" />
                            : <Fingerprint size={20} className="text-white dark:text-black" />}
                        </div>
                        <div className="min-w-0">
                          <p className="font-bold text-sm text-black dark:text-white">Passkey / Touch ID / Windows Hello</p>
                          <p className="text-xs text-on-surface-variant mt-0.5">Use your fingerprint, face, or device PIN</p>
                        </div>
                        <ArrowRight size={16} className="ml-auto shrink-0 text-on-surface-variant group-hover:text-black dark:group-hover:text-white transition-colors" />
                      </button>
                    )}

                    {hasWebAuthnHint && (
                      <button
                        type="button"
                        onClick={handleWebAuthnLogin}
                        disabled={webAuthnLoading || loading || passkeyLoading}
                        className="w-full flex items-center gap-4 px-5 py-4 rounded-xl border-2 border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#141414] hover:border-blue-600 dark:hover:border-blue-500 hover:bg-white dark:hover:bg-[#1a1a1a] transition-all text-left group disabled:opacity-60 disabled:cursor-not-allowed"
                      >
                        <div className="w-10 h-10 rounded-xl bg-slate-900 dark:bg-white flex items-center justify-center shrink-0">
                          {webAuthnLoading
                            ? <Loader2 size={20} className="text-white dark:text-black animate-spin" />
                            : <Key size={20} className="text-white dark:text-black" />}
                        </div>
                        <div className="min-w-0">
                          <p className="font-bold text-sm text-black dark:text-white">{t('login.securityKeyCard', 'Security Key (YubiKey)')}</p>
                          <p className="text-xs text-on-surface-variant mt-0.5">{t('login.securityKeyDesc', 'Insert your hardware security key')}</p>
                        </div>
                        <ArrowRight size={16} className="ml-auto shrink-0 text-on-surface-variant group-hover:text-black dark:group-hover:text-white transition-colors" />
                      </button>
                    )}

                    {isPasswordless && !hasPasskeyHint && !hasWebAuthnHint && (
                      <div className="p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800/30 rounded-xl flex items-start gap-3">
                        <ShieldAlert className="text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" size={16} />
                        <p className="text-amber-700 dark:text-amber-300 text-sm leading-snug">
                          {t('login.passwordlessLocked', 'Passwordless login requires a registered hardware key. Go to Settings → Security to add one.')}
                        </p>
                      </div>
                    )}

                    {/* SECOND FACTOR & WEAKEST - shown when NOT passwordless */}
                    {!isPasswordless && (
                      <>
                        {hasQuickUnlock && (
                          <div className="mb-6 space-y-4">
                            <button
                              type="button"
                              onClick={handleQuickUnlock}
                              disabled={quickUnlockLoading || loading}
                              className="w-full flex items-center gap-4 px-5 py-4 rounded-xl border-2 border-blue-200 dark:border-blue-900/50 bg-blue-50 dark:bg-blue-900/20 hover:border-blue-600 dark:hover:border-blue-500 transition-all text-left group disabled:opacity-60 disabled:cursor-not-allowed"
                            >
                              <div className="w-10 h-10 rounded-xl bg-blue-600 dark:bg-blue-500 flex items-center justify-center shrink-0">
                                {quickUnlockLoading
                                  ? <Loader2 size={20} className="text-white animate-spin" />
                                  : <Fingerprint size={20} className="text-white" />}
                              </div>
                              <div className="min-w-0">
                                <p className="font-bold text-sm text-blue-900 dark:text-blue-100">Unlock with Touch ID / Windows Hello</p>
                                <p className="text-xs text-blue-700/80 dark:text-blue-300/80 mt-0.5">Quickly unlock this device</p>
                              </div>
                              <ArrowRight size={16} className="ml-auto shrink-0 text-blue-600 dark:text-blue-400 group-hover:translate-x-1 transition-transform" />
                            </button>
                            
                            <div className="flex items-center gap-4">
                              <div className="h-px bg-slate-200 dark:bg-white/10 flex-1"></div>
                              <span className="text-xs font-semibold text-slate-400 dark:text-white/40 uppercase tracking-wider">or</span>
                              <div className="h-px bg-slate-200 dark:bg-white/10 flex-1"></div>
                            </div>
                          </div>
                        )}
                        {!hasMfaHint ? (
                          <form onSubmit={handleLogin} className="space-y-4">
                            <div>
                              <div className="flex items-center justify-between mb-2">
                                <label htmlFor="password" className="block text-sm font-semibold text-black dark:text-white">
                                  {t('login.passwordLabel', 'Password')}
                                </label>
                                <Link to="/forgot-password" tabIndex={-1} className="text-sm font-semibold text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors">
                                  {t('login.forgotPassword', 'Forgot password?')}
                                </Link>
                              </div>
                              <input type="text" name="username" value={email} readOnly autoComplete="username" className="hidden" aria-hidden="true" />
                              <input
                                id="password"
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                className="w-full px-4 py-3.5 rounded-xl border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#141414] text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-white/30 focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all outline-none text-base"
                                placeholder="••••••••"
                                required
                                autoFocus
                                autoComplete="current-password"
                                aria-invalid={!!error}
                              />
                            </div>
                            <button
                              type="submit"
                              disabled={loading || passkeyLoading || webAuthnLoading}
                              className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-60 disabled:cursor-not-allowed text-white py-4 rounded-xl font-bold text-base transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 active:scale-[0.98]"
                            >
                              {loading
                                ? <><Loader2 size={18} className="animate-spin" />{t('login.submitting', 'Signing in…')}</>
                                : <>{t('login.submit', 'Sign In')}<ArrowRight size={18} /></>
                              }
                            </button>
                          </form>
                        ) : (
                          <>
                            {loginHints.totp && (
                              <button
                                type="button"
                                onClick={() => setSelectedMfaChannel('totp')}
                                className="w-full flex items-center gap-4 px-5 py-4 rounded-xl border-2 border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#141414] hover:border-blue-600 dark:hover:border-blue-500 hover:bg-white dark:hover:bg-[#1a1a1a] transition-all text-left group"
                              >
                                <div className="w-10 h-10 rounded-xl bg-slate-200 dark:bg-[#2a2a2a] flex items-center justify-center shrink-0">
                                  <Smartphone size={20} className="text-black dark:text-white" />
                                </div>
                                <div className="min-w-0">
                                  <p className="font-bold text-sm text-black dark:text-white">{t('login.methodPasswordTotp', 'Password + Authenticator App')}</p>
                                  <p className="text-xs text-on-surface-variant mt-0.5">{t('login.mfaAuthDesc', 'Enter your password, then a 6-digit code from your app')}</p>
                                </div>
                                <ArrowRight size={16} className="ml-auto shrink-0 text-on-surface-variant group-hover:text-black dark:group-hover:text-white transition-colors" />
                              </button>
                            )}
                            {loginHints.emailOtp && (
                              <button
                                type="button"
                                onClick={() => setSelectedMfaChannel('email')}
                                className="w-full flex items-center gap-4 px-5 py-4 rounded-xl border-2 border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#141414] hover:border-blue-600 dark:hover:border-blue-500 hover:bg-white dark:hover:bg-[#1a1a1a] transition-all text-left group"
                              >
                                <div className="w-10 h-10 rounded-xl bg-slate-200 dark:bg-[#2a2a2a] flex items-center justify-center shrink-0">
                                  <Smartphone size={20} className="text-black dark:text-white" />
                                </div>
                                <div className="min-w-0">
                                  <p className="font-bold text-sm text-black dark:text-white">{t('login.methodPasswordEmail', 'Password + Email OTP')}</p>
                                  <p className="text-xs text-on-surface-variant mt-0.5">{t('login.mfaEmailSubtitle', 'Enter the 6-digit code sent to your email.')}</p>
                                </div>
                                <ArrowRight size={16} className="ml-auto shrink-0 text-on-surface-variant group-hover:text-black dark:group-hover:text-white transition-colors" />
                              </button>
                            )}
                          </>
                        )}
                      </>
                    )}
                  </>
                )}
              </div>

              <div className="mt-10 pt-8 border-t border-outline-variant/30 dark:border-white/10 text-center">
                <p className="text-base text-on-surface-variant">
                  {t('login.noAccount', "Don't have an enterprise account?")}{' '}
                  <Link to="/register" className="text-black dark:text-white font-bold hover:text-blue-600 dark:hover:text-blue-400 transition-colors">
                    {t('login.createAccount', 'Request access')}
                  </Link>
                </p>
              </div>
            </>
          )}

          {/* ── STEP 3: TOTP / email OTP verification ────────────────────── */}
          {step === 'totp' && (
            <>
              <div className="mb-10">
                <button
                  type="button"
                  onClick={() => {
                    setStep('method');
                    setTotpCode(['', '', '', '', '', '']);
                    setTotpError('');
                    setDaemonWasUnlocked(false);
                    setEmailSimCode('');
                  }}
                  className="flex items-center gap-1 text-sm text-on-surface-variant hover:text-black dark:hover:text-white transition-colors mb-6"
                >
                  <ChevronLeft size={16} />{email}
                </button>

                <div className="flex items-center gap-3 mb-4">
                  <div className="w-11 h-11 rounded-xl bg-blue-600 flex items-center justify-center shrink-0">
                    <ShieldCheck size={22} className="text-white" />
                  </div>
                  <h1 className="text-3xl sm:text-4xl font-headline font-bold text-black dark:text-white tracking-tight">
                    {t('login.mfaTotpTitle', 'Two-Step Verification')}
                  </h1>
                </div>

                <p className="text-on-surface-variant text-base">
                  {mfaMethod === 'email'
                    ? t('login.mfaEmailSubtitle', 'Enter the 6-digit code sent to your email.')
                    : t('login.mfaTotpSubtitle', 'Open your authenticator app and enter the 6-digit code shown for this account.')}
                </p>
              </div>

              {/* Email OTP demo preview */}
              {mfaMethod === 'email' && emailSimCode && (
                <div className="mb-6 p-4 bg-slate-50 dark:bg-[#141414] border border-slate-200 dark:border-white/10 rounded-xl">
                  <p className="text-xs font-bold text-on-surface-variant uppercase tracking-widest mb-1">Simulated Email Preview</p>
                  <p className="text-sm text-on-surface-variant">Your one-time code:</p>
                  <p className="text-3xl font-black text-black dark:text-white tracking-[0.3em] mt-1">{emailSimCode}</p>
                  <p className="text-[10px] text-on-surface-variant mt-2">Valid for 5 minutes. Do not share.</p>
                </div>
              )}

              {/* 6-digit input boxes */}
              <div className="flex items-center justify-center gap-2 mb-6">
                {[0, 1, 2].map(i => (
                  <input
                    key={i}
                    ref={el => { totpRefs.current[i] = el; }}
                    type="text"
                    inputMode="numeric"
                    maxLength={1}
                    value={totpCode[i]}
                    onChange={e => handleTotpDigit(i, e.target.value)}
                    onKeyDown={e => handleTotpKeyDown(i, e)}
                    onPaste={i === 0 ? handleTotpPaste : undefined}
                    autoFocus={i === 0}
                    className="w-14 h-16 text-center text-2xl font-black bg-white dark:bg-[#1a1a1a] text-black dark:text-white border-2 border-slate-400 dark:border-slate-400 rounded-xl focus:ring-2 focus:ring-blue-600 focus:border-blue-600 outline-none transition-all"
                  />
                ))}
                <div className="w-4 h-0.5 bg-slate-400 dark:bg-slate-400 rounded-full mx-1" />
                {[3, 4, 5].map(i => (
                  <input
                    key={i}
                    ref={el => { totpRefs.current[i] = el; }}
                    type="text"
                    inputMode="numeric"
                    maxLength={1}
                    value={totpCode[i]}
                    onChange={e => handleTotpDigit(i, e.target.value)}
                    onKeyDown={e => handleTotpKeyDown(i, e)}
                    className="w-14 h-16 text-center text-2xl font-black bg-white dark:bg-[#1a1a1a] text-black dark:text-white border-2 border-slate-400 dark:border-slate-400 rounded-xl focus:ring-2 focus:ring-blue-600 focus:border-blue-600 outline-none transition-all"
                  />
                ))}
              </div>

              {totpError && (
                <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/30 rounded-xl flex items-center gap-2">
                  <AlertTriangle size={14} className="text-red-500 shrink-0" />
                  <p className="text-red-600 dark:text-red-400 text-sm font-medium">{totpError}</p>
                </div>
              )}

              <button
                type="button"
                onClick={handleTotpSubmit}
                disabled={totpCode.some(c => !c) || loading}
                className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white py-4 rounded-xl font-bold text-base transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 active:scale-[0.98]"
              >
                {loading
                  ? <><Loader2 size={18} className="animate-spin" />{t('login.mfaVerifying', 'Verifying…')}</>
                  : <><ShieldCheck size={18} />{t('login.mfaVerify', 'Verify')}</>
                }
              </button>

              {/* Switch between TOTP and email OTP if both are enabled */}
              {loginHints.totp && loginHints.emailOtp && (
                <button
                  type="button"
                  onClick={handleSwitchMfaMethod}
                  className="mt-4 w-full text-sm text-on-surface-variant hover:text-black dark:hover:text-white transition-colors text-center py-2"
                >
                  {mfaMethod === 'totp'
                    ? t('login.mfaSwitchToEmail', 'Use Email OTP instead')
                    : t('login.mfaSwitchToApp', 'Use Authenticator App instead')}
                </button>
              )}
            </>
          )}
        </div>
      </section>
    </main>
  );
}
