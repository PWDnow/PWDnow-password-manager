import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Shield, ArrowRight, CheckCircle2, Loader2, ShieldAlert, Fingerprint, KeyRound, ChevronLeft } from 'lucide-react';
import PublicHeader from '../components/PublicHeader';
import SEO from '../components/SEO';
import { daemon } from '../utils/daemonClient';
import { recordSession } from '../utils/sessionTracker';
import { keyStore, deriveLocalKey, getOrCreateLocalKeySalt } from '../crypto/keystore';
import { loadMfaConfig, getMfaConfig, getPasskeyHint, isWebAuthnSupported, isSecureContext, authenticateWithPasskeyForLogin } from '../utils/mfa';
import { checkIsDuressPassword, recordFailedLoginAttempt, wipeVaultData, getDuressModeConfig } from '../utils/securityModes';
import { generateUUID } from '../utils/crypto';

export default function Login() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [step, setStep] = useState<'email' | 'method'>('email');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [passkeyLoading, setPasskeyLoading] = useState(false);

  // Detect whether any passkeys/biometrics are registered for this browser.
  // Checked when moving to the method step so we know which options to offer.
  const hasPasskeyHint = getPasskeyHint().length > 0;
  const passkeyAvailable = isWebAuthnSupported() && isSecureContext();

  // Redirect to /setup if first-run setup has not been completed yet.
  useEffect(() => {
    fetch('/api/setup-status')
      .then(r => r.json())
      .then(({ completed }: { completed: boolean }) => {
        if (!completed) navigate('/setup', { replace: true });
      })
      .catch(() => { /* API unreachable — allow login to proceed */ });
  }, [navigate]);

  // ── Step 1 → Step 2: email continue ─────────────────────────────────────────
  const handleEmailContinue = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim()) return;
    setError('');
    setStep('method');
  };

  // ── Passkey / biometric sign-in ───────────────────────────────────────────
  const handlePasskeyLogin = async () => {
    setError('');
    setPasskeyLoading(true);
    try {
      const ok = await authenticateWithPasskeyForLogin();
      if (!ok) { setError('Passkey authentication failed or no passkey found for this device.'); return; }

      keyStore.store(generateUUID());
      try { await recordSession(); } catch { /* non-fatal */ }
      navigate('/vault');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Passkey authentication failed.');
    } finally {
      setPasskeyLoading(false);
    }
  };

  // ── Password sign-in ──────────────────────────────────────────────────────
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    // ── Duress intercept — check before any authentication attempt ────────────
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
    try {
      if (!daemon.isConnected) await daemon.connect();
      await daemon.unlock(password);
      daemonUnlocked = true;
    } catch { /* daemon unavailable — fall through to offline auth */ }

    if (daemonUnlocked) {
      try {
        const salt = getOrCreateLocalKeySalt();
        const localKey = await deriveLocalKey(password, salt);
        keyStore.storeLocalKey(localKey);
        await loadMfaConfig();
        window.dispatchEvent(new CustomEvent('demoKeyAvailable'));
      } catch { /* non-fatal on plain HTTP */ }
      try { await recordSession(); } catch { /* non-fatal */ }
      window.dispatchEvent(new CustomEvent('daemonUnlocked'));
      navigate('/vault');
      return;
    }

    // ── Offline / demo-mode fallback ─────────────────────────────────────────
    // Daemon unreachable — verify credentials via /api/auth/login.
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
        // In-memory sentinel — AppLayout checks keyStore.hasToken
        keyStore.store(generateUUID());
        try {
          const salt = getOrCreateLocalKeySalt();
          const localKey = await deriveLocalKey(password, salt);
          keyStore.storeLocalKey(localKey);
          await loadMfaConfig();
          window.dispatchEvent(new CustomEvent('demoKeyAvailable'));
        } catch { /* expected on plain HTTP */ }
        
        try { await recordSession(); } catch { /* non-fatal */ }
        navigate('/vault');
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
        {/* Background Decorative Elements */}
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
          <p className="text-slate-500 text-sm font-medium">
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
                <strong>Insecure connection (HTTP)</strong> — passkeys and biometrics require HTTPS or localhost.
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

          {/* ── STEP 2: choose sign-in method ────────────────────────────── */}
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
                {/* Passkey / Touch ID / Windows Hello — shown when registered or WebAuthn available */}
                {(hasPasskeyHint || passkeyAvailable) && (
                  <button
                    type="button"
                    onClick={handlePasskeyLogin}
                    disabled={passkeyLoading || loading}
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

                {/* Password — always shown unless passwordlessEnabled AND 2+ MFA active */}
                {(() => {
                  const cfg = getMfaConfig();
                  const hidePassword = cfg.passwordlessEnabled && (
                    cfg.passkey?.enabled || cfg.platform?.enabled || cfg.webauthn?.enabled
                  );
                  if (hidePassword) return null;
                  return (
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
                        disabled={loading || passkeyLoading}
                        className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-60 disabled:cursor-not-allowed text-white py-4 rounded-xl font-bold text-base transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 active:scale-[0.98]"
                      >
                        {loading
                          ? <><Loader2 size={18} className="animate-spin" />{t('login.submitting', 'Signing in…')}</>
                          : <>{t('login.submit', 'Sign In')}<ArrowRight size={18} /></>
                        }
                      </button>
                    </form>
                  );
                })()}
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
        </div>
      </section>
    </main>
  );
}
