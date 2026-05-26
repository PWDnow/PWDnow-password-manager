import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Shield, ArrowRight, Building2, Users, Loader2, Check, X, Minus } from 'lucide-react';
import PublicHeader from '../components/PublicHeader';
import SEO from '../components/SEO';
import { keyStore, deriveLocalKey, getOrCreateLocalKeySalt } from '../crypto/keystore';
import { daemon } from '../utils/daemonClient';
import { generateUUID } from '../utils/crypto';
import { apiFetch, ApiError, hasServerSession as _hasServerSession } from '../utils/api';
import { logger } from '../utils/logger';

export default function Register() {
  const { t } = useTranslation();
  const navigate = useNavigate();

  useEffect(() => {
    const hasServerSession = _hasServerSession();
    if (keyStore.hasToken || hasServerSession) {
      navigate('/vault', { replace: true });
    }
  }, [navigate]);

  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    company: '',
    email: '',
    password: ''
  });
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [passwordFocused, setPasswordFocused] = useState(false);
  const [passwordTouched, setPasswordTouched] = useState(false);

  const WEAK_PATTERNS_RULE = [/^(.)\1+$/, /^(0123456789|12345678901|abcdefghij)/i, /^(password|letmein|welcome|qwerty)/i];

  const passwordRules = [
    {
      key: 'rule1',
      label: t('register.passwordRule1', 'At least 12 characters'),
      met: formData.password.length >= 12,
    },
    {
      key: 'rule2',
      label: t('register.passwordRule2', 'At least one special character (!@#$%^&* etc.)'),
      met: /[^A-Za-z0-9]/.test(formData.password),
    },
    {
      key: 'rule3',
      label: t('register.passwordRule3', 'Not a common or predictable pattern'),
      met: formData.password.length > 0 && !WEAK_PATTERNS_RULE.some(re => re.test(formData.password)),
    },
    {
      key: 'rule4',
      label: t('register.passwordRule4', 'Not found in known data breaches'),
      met: null,
    },
  ];

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const validateEmail = (email: string) => {
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return regex.test(email);
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!validateEmail(formData.email)) {
      setError(t('register.errorEmail', 'Please enter a valid work email address.'));
      return;
    }

    if (!formData.firstName || !formData.lastName || !formData.password) {
      setError(t('register.errorRequired', 'Please fill in all required fields.'));
      return;
    }

    if (formData.password.length < 12) {
      setError(t('register.errorPasswordLength', 'Password must be at least 12 characters long.'));
      return;
    }
    if (!/[^A-Za-z0-9]/.test(formData.password)) {
      setError(t('register.errorPasswordSpecial', 'Password must contain at least one special character (!@#$%^&* etc.).'));
      return;
    }
    const WEAK_PATTERNS = [/^(.)\1+$/, /^(0123456789|12345678901|abcdefghij)/i, /^(password|letmein|welcome|qwerty)/i];
    if (WEAK_PATTERNS.some(re => re.test(formData.password))) {
      setError(t('register.errorPasswordWeak', 'This password is too common or predictable. Please choose a stronger one.'));
      return;
    }
    if (formData.password !== confirmPassword) {
      setError(t('register.errorPasswordMatch', 'Passwords do not match.'));
      return;
    }

    try {
      const { pwned } = await daemon.checkPasswordBreached(formData.password);
      if (pwned) {
        setError(t('register.errorPasswordPwned', 'This password was found in a known data breach. Please choose a different one.'));
        return;
      }
    } catch { /* daemon unavailable - skip HIBP check */ }

    setLoading(true);

    // ── Try daemon first ──────────────────────────────────────────────────────
    let daemonOk = false;
    try {
      await daemon.register(formData.password, formData.firstName, formData.lastName, formData.email);
      daemonOk = true;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : '';
      if (msg.includes('already exists') || msg.includes('409') || msg.includes('Item already exists')) {
        setError(t('register.errorEmailTaken', 'An account with this email already exists.'));
        setLoading(false);
        return;
      }
      // Daemon unavailable - fall through to offline registration
    }

    if (daemonOk) {
      try {
        const salt = getOrCreateLocalKeySalt();
        const localKey = await deriveLocalKey(formData.password, salt);
        keyStore.storeLocalKey(localKey);
      } catch { /* non-fatal on plain HTTP */ }
      window.dispatchEvent(new CustomEvent('daemonUnlocked'));
      navigate('/vault');
      return;
    }

    // ── Offline / demo-mode registration ─────────────────────────────────────
    try {
      const lkSalt = getOrCreateLocalKeySalt();
      await apiFetch('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          email: formData.email,
          password: formData.password,
          firstName: formData.firstName,
          lastName: formData.lastName,
          cryptoSalt: lkSalt
        })
      });

      // Mark this tab as authenticated
      keyStore.store(generateUUID());

      // Derive local encryption key
      try {
        const localKey = await deriveLocalKey(formData.password, lkSalt);
        keyStore.storeLocalKey(localKey);
      } catch { /* expected on plain HTTP */ }

      navigate('/vault');
    } catch (err) {
      if (err instanceof ApiError) {
        const errData = (err.data as { error?: string }) ?? {};
        if (errData.error === 'email_taken') {
          setError(t('register.errorEmailTaken', 'An account with this email already exists.'));
        } else {
          setError(errData.error || t('register.errorUnexpected', 'An unexpected error occurred. Please try again.'));
        }
      } else {
        logger.error('[Register] offline registration failed:', err);
        setError(t('register.errorUnexpected', 'An unexpected error occurred. Please try again.'));
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen flex bg-white dark:bg-[#0a0a0a]">
      <SEO 
        title={t('register.title', 'Create your account')} 
        description={t('register.heroSubtitle', 'Deploy enterprise-grade credential management across your entire organization in minutes, not months.')} 
      />
      <PublicHeader />
      
      {/* Left Pane - Branding & Value Prop (Hidden on mobile) */}
      <section className="hidden lg:flex lg:w-[45%] bg-slate-900 relative overflow-hidden flex-col justify-between p-12 xl:p-16 text-white">
        {/* Background Decorative Elements */}
        <div className="absolute top-0 left-0 w-full h-full overflow-hidden pointer-events-none">
          <div className="absolute top-[10%] -right-[10%] w-[60%] h-[60%] rounded-full bg-blue-600/20 blur-[120px]" />
          <div className="absolute -bottom-[20%] -left-[20%] w-[70%] h-[70%] rounded-full bg-indigo-500/10 blur-[100px]" />
        </div>

        <div className="relative z-10 flex items-center gap-3">
          <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-600/20">
            <Shield className="text-white" size={24} />
          </div>
          <span className="text-2xl font-headline font-black tracking-tight text-white">PWDnow</span>
        </div>

        <div className="relative z-10 max-w-lg mt-12">
          <h2 className="text-4xl xl:text-5xl font-headline font-bold mb-6 leading-[1.1] tracking-tight text-white">
            {t('register.heroTitle', 'Secure your digital life with open source.')}
          </h2>
          <p className="text-slate-400 text-lg leading-relaxed mb-12">
            {t('register.heroSubtitle', 'High-security vault with zero-knowledge architecture, designed for individuals and teams who value privacy.')}
          </p>

          <div className="grid grid-cols-2 gap-6">
            <div className="bg-white/5 p-6 rounded-2xl border border-white/10 backdrop-blur-sm">
              <Building2 className="text-blue-400 mb-4" size={28} />
              <div className="text-2xl font-bold text-white mb-1">100%</div>
              <div className="text-sm text-slate-400 font-medium">{t('register.openSourceLabel', 'Open Source')}</div>
            </div>
            <div className="bg-white/5 p-6 rounded-2xl border border-white/10 backdrop-blur-sm">
              <Users className="text-indigo-400 mb-4" size={28} />
              <div className="text-2xl font-bold text-white mb-1">{t('register.communityValue', 'Community')}</div>
              <div className="text-sm text-slate-400 font-medium">{t('register.communityLabel', 'Driven')}</div>
            </div>
          </div>
        </div>

        <div className="relative z-10 mt-12">
          <p className="text-slate-400 text-sm font-medium">
            © {new Date().getFullYear()} PWDnow. {t('register.allRightsReserved', 'All rights reserved.')}
          </p>
        </div>
      </section>

      {/* Right Pane - Register Form */}
      <section className="w-full lg:w-[55%] flex flex-col justify-center px-6 sm:px-12 md:px-24 xl:px-32 py-12 relative overflow-y-auto bg-white dark:bg-[#0a0a0a]">
        {/* Mobile Logo */}
        <div className="lg:hidden flex items-center gap-3 mb-12 mt-8">
          <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-600/20">
            <Shield className="text-white" size={20} />
          </div>
          <span className="text-xl font-headline font-black tracking-tight text-black dark:text-white">PWDnow</span>
        </div>

        <div className="w-full max-w-md mx-auto lg:mx-0">
          <div className="mb-10">
            <h1 className="text-3xl sm:text-4xl font-headline font-bold text-black dark:text-white mb-3 tracking-tight">
              {t('register.title', 'Create your account')}
            </h1>
            <p className="text-on-surface-variant text-base">
              {t('register.subtitle', 'Set up your enterprise workspace to get started.')}
            </p>
          </div>

          {error && (
            <div className="mb-8 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/30 rounded-xl flex items-start gap-3" role="alert">
              <div className="text-red-600 dark:text-red-400 font-medium text-sm">
                {error}
              </div>
            </div>
          )}

          <form onSubmit={handleRegister} className="space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
              <div>
                <label htmlFor="firstName" className="block text-sm font-semibold text-black dark:text-white mb-2">
                  {t('register.firstName', 'First Name')}
                </label>
                <input
                  id="firstName"
                  type="text"
                  name="firstName"
                  value={formData.firstName}
                  onChange={handleChange}
                  className="w-full px-4 py-3.5 rounded-xl border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#141414] text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-white/30 focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all outline-none text-base"
                  placeholder={t('register.firstNamePlaceholder', 'Jane')}
                  required
                  autoComplete="off"
                />
              </div>

              <div>
                <label htmlFor="lastName" className="block text-sm font-semibold text-black dark:text-white mb-2">
                  {t('register.lastName', 'Last Name')}
                </label>
                <input
                  id="lastName"
                  type="text"
                  name="lastName"
                  value={formData.lastName}
                  onChange={handleChange}
                  className="w-full px-4 py-3.5 rounded-xl border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#141414] text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-white/30 focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all outline-none text-base"
                  placeholder={t('register.lastNamePlaceholder', 'Doe')}
                  required
                  autoComplete="off"
                />
              </div>
            </div>

            <div>
              <label htmlFor="company" className="block text-sm font-semibold text-black dark:text-white mb-2 flex items-center gap-2">
                {t('register.company', 'Company Name')}
                <span className="text-xs font-normal text-slate-400 dark:text-white/40 normal-case tracking-normal">
                  ({t('register.optional', 'optional')})
                </span>
              </label>
              <input
                id="company"
                type="text"
                name="company"
                value={formData.company}
                onChange={handleChange}
                className="w-full px-4 py-3.5 rounded-xl border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#141414] text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-white/30 focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all outline-none text-base"
                placeholder={t('register.companyPlaceholder', 'Acme Corp')}
                autoComplete="off"
              />
            </div>

            <div>
              <label htmlFor="email" className="block text-sm font-semibold text-black dark:text-white mb-2">
                {t('register.email', 'Work Email')}
              </label>
              <input
                id="email"
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                className="w-full px-4 py-3.5 rounded-xl border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#141414] text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-white/30 focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all outline-none text-base"
                placeholder={t('register.emailPlaceholder', 'jane@example.com')}
                required
                autoComplete="off"
                aria-invalid={!!error}
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-semibold text-black dark:text-white mb-2">
                {t('register.password', 'Password')}
              </label>
              <input
                id="password"
                type="password"
                name="password"
                value={formData.password}
                onChange={(e) => { handleChange(e); setPasswordTouched(true); }}
                onFocus={() => setPasswordFocused(true)}
                onBlur={() => setPasswordFocused(false)}
                className="w-full px-4 py-3.5 rounded-xl border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#141414] text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-white/30 focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all outline-none text-base"
                placeholder="••••••••"
                required
                autoComplete="new-password"
              />
              {(passwordFocused || passwordTouched) && (
                <ul className="mt-3 space-y-1.5">
                  {passwordRules.map((rule) => {
                    const neutral = !passwordTouched || (formData.password.length === 0 && rule.met === null);
                    const isNeutral = formData.password.length === 0;
                    const status = isNeutral ? 'neutral' : rule.met === null ? 'neutral' : rule.met ? 'met' : 'unmet';
                    return (
                      <li key={rule.key} className="flex items-center gap-2 text-xs">
                        <span className={`flex-shrink-0 w-4 h-4 rounded-full flex items-center justify-center ${
                          status === 'met' ? 'bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400' :
                          status === 'unmet' ? 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400' :
                          'bg-slate-100 dark:bg-white/10 text-slate-400 dark:text-white/30'
                        }`}>
                          {status === 'met' ? <Check size={10} strokeWidth={3} /> :
                           status === 'unmet' ? <X size={10} strokeWidth={3} /> :
                           <Minus size={10} strokeWidth={3} />}
                        </span>
                        <span className={
                          status === 'met' ? 'text-green-700 dark:text-green-400' :
                          status === 'unmet' ? 'text-red-600 dark:text-red-400' :
                          'text-slate-500 dark:text-white/40'
                        }>
                          {rule.label}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>

            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-semibold text-black dark:text-white mb-2">
                {t('register.passwordConfirm', 'Confirm Password')}
              </label>
              <input
                id="confirmPassword"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full px-4 py-3.5 rounded-xl border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#141414] text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-white/30 focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all outline-none text-base"
                placeholder="••••••••"
                required
                autoComplete="new-password"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-6 bg-blue-600 hover:bg-blue-700 disabled:opacity-60 disabled:cursor-not-allowed text-white py-4 rounded-xl font-bold text-base transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 active:scale-[0.98]"
            >
              {loading
                ? <><Loader2 size={18} className="animate-spin" />{t('register.submitting', 'Creating…')}</>
                : <>{t('register.submit', 'Create Workspace')}<ArrowRight size={18} /></>
              }
            </button>
          </form>

          <div className="mt-10 pt-8 border-t border-outline-variant/30 dark:border-white/10 text-center">
            <p className="text-base text-on-surface-variant">
              {t('register.alreadyHaveAccount', 'Already have an account?')}{' '}
              <Link to="/login" className="text-black dark:text-white font-bold hover:text-blue-600 dark:hover:text-blue-400 transition-colors">
                {t('register.signIn', 'Sign in')}
              </Link>
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
