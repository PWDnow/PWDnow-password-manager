import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { keyStore } from '../crypto/keystore';
import { Shield, ArrowRight, CheckCircle2, Loader2, MailCheck } from 'lucide-react';
import PublicHeader from '../components/PublicHeader';
import SEO from '../components/SEO';

export default function ForgotPassword() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [view, setView] = useState<'form' | 'success'>('form');

  useEffect(() => {
    const hasServerSession = document.cookie.split(';').some(c => c.trim().startsWith('_pwd_csrf='));
    if (keyStore.hasToken || hasServerSession) {
      navigate('/vault', { replace: true });
    }
  }, [navigate]);
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!emailRegex.test(email)) {
        setError(t('forgotPassword.errorInvalidEmail', 'Please enter a valid email address.'));
        return;
      }
      if (!localStorage.getItem('email_server_config')) {
        setError(t('forgotPassword.errorNoSmtp', 'No email server has been configured yet. Please contact your administrator.'));
        return;
      }
      setView('success');
    } catch {
      setError(t('forgotPassword.errorUnexpected', 'An unexpected error occurred. Please try again.'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen flex bg-white dark:bg-[#0a0a0a]">
      <SEO
        title={t('forgotPassword.pageTitle', 'Forgot Password')}
        description={t('forgotPassword.heroSub', 'Enter your registered email and we\'ll send secure reset instructions.')}
      />
      <PublicHeader />

      {/* Left Pane */}
      <section className="hidden lg:flex lg:w-[45%] bg-slate-900 relative overflow-hidden flex-col justify-between p-12 xl:p-16 text-white">
        <div className="absolute top-0 left-0 w-full h-full overflow-hidden pointer-events-none">
          <div className="absolute top-[5%] -right-[15%] w-[65%] h-[65%] rounded-full bg-violet-600/20 blur-[120px]" />
          <div className="absolute -bottom-[15%] -left-[15%] w-[65%] h-[65%] rounded-full bg-purple-500/10 blur-[100px]" />
        </div>

        <div className="relative z-10 flex items-center gap-3">
          <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-600/20">
            <Shield className="text-white" size={24} />
          </div>
          <span className="text-2xl font-headline font-black tracking-tight text-white">PWDnow</span>
        </div>

        <div className="relative z-10 max-w-lg mt-12">
          <h2 className="text-4xl xl:text-5xl font-headline font-bold mb-6 leading-[1.1] tracking-tight text-white">
            {t('forgotPassword.heroTitle', 'Regain access to your vault securely.')}
          </h2>
          <p className="text-slate-400 text-lg leading-relaxed mb-12">
            {t('forgotPassword.heroSub', 'Enter your registered email and we\'ll send secure reset instructions.')}
          </p>

          <div className="space-y-4">
            {[
              t('forgotPassword.feature1', 'Encrypted one-time reset tokens'),
              t('forgotPassword.feature2', 'Link expires in 15 minutes'),
              t('forgotPassword.feature3', 'Secure, audited reset flow'),
            ].map((feature, idx) => (
              <div key={idx} className="flex items-center gap-3 text-slate-300">
                <CheckCircle2 className="text-violet-400" size={20} />
                <span className="font-medium">{feature}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="relative z-10 mt-12">
          <p className="text-slate-400 text-sm font-medium">
            © {new Date().getFullYear()} PWDnow. {t('forgotPassword.allRightsReserved', 'All rights reserved.')}
          </p>
        </div>
      </section>

      {/* Right Pane */}
      <section className="w-full lg:w-[55%] flex flex-col justify-center px-6 sm:px-12 md:px-24 xl:px-32 py-12 relative bg-white dark:bg-[#0a0a0a]">
        {/* Mobile Logo */}
        <div className="lg:hidden flex items-center gap-3 mb-12">
          <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-600/20">
            <Shield className="text-white" size={20} />
          </div>
          <span className="text-xl font-headline font-black tracking-tight text-black dark:text-white">PWDnow</span>
        </div>

        <div className="w-full max-w-md mx-auto lg:mx-0">
          {view === 'form' ? (
            <>
              <div className="mb-10">
                <h1 className="text-3xl sm:text-4xl font-headline font-bold text-black dark:text-white mb-3 tracking-tight">
                  {t('forgotPassword.title', 'Forgot your password?')}
                </h1>
                <p className="text-on-surface-variant text-base">
                  {t('forgotPassword.subtitle', 'Enter your registered email address and we\'ll send reset instructions.')}
                </p>
              </div>

              {error && (
                <div className="mb-8 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/30 rounded-xl" role="alert">
                  <div className="text-red-600 dark:text-red-400 font-medium text-sm">{error}</div>
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                  <label htmlFor="email" className="block text-sm font-semibold text-black dark:text-white mb-2">
                    {t('forgotPassword.emailLabel', 'Work Email')}
                  </label>
                  <input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full px-4 py-3.5 rounded-xl border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#141414] text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-white/30 focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all outline-none text-base"
                    placeholder="name@company.com"
                    required
                    autoComplete="off"
                    aria-invalid={!!error}
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full mt-4 bg-blue-600 hover:bg-blue-700 disabled:opacity-60 disabled:cursor-not-allowed text-white py-4 rounded-xl font-bold text-base transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 active:scale-[0.98]"
                >
                  {loading
                    ? <><Loader2 size={18} className="animate-spin" />{t('forgotPassword.submitting', 'Sending…')}</>
                    : <>{t('forgotPassword.submit', 'Send Reset Link')}<ArrowRight size={18} /></>
                  }
                </button>
              </form>

              <div className="mt-10 pt-8 border-t border-outline-variant/30 dark:border-white/10 text-center">
                <p className="text-base text-on-surface-variant">
                  {t('forgotPassword.rememberedIt', 'Remembered it?')}{' '}
                  <Link to="/login" className="text-black dark:text-white font-bold hover:text-blue-600 dark:hover:text-blue-400 transition-colors">
                    {t('forgotPassword.signIn', 'Sign in')}
                  </Link>
                </p>
              </div>
            </>
          ) : (
            <>
              <div className="flex flex-col items-center text-center">
                <div className="w-20 h-20 rounded-2xl bg-green-100 dark:bg-green-900/30 flex items-center justify-center mb-8">
                  <MailCheck className="text-green-600 dark:text-green-400" size={40} />
                </div>
                <h1 className="text-3xl sm:text-4xl font-headline font-bold text-black dark:text-white mb-4 tracking-tight">
                  {t('forgotPassword.successTitle', 'Check your inbox')}
                </h1>
                <p className="text-on-surface-variant text-base mb-3 max-w-sm">
                  {t('forgotPassword.successMsg', 'If an account exists for {{email}}, reset instructions are on their way.', { email })}
                </p>
                <p className="text-sm text-on-surface-variant/70 mb-10">
                  {t('forgotPassword.successNote', "Didn't receive it? Check your spam folder.")}
                </p>
                <Link
                  to="/login"
                  className="w-full max-w-xs bg-blue-600 hover:bg-blue-700 text-white py-4 rounded-xl font-bold text-base transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 active:scale-[0.98]"
                >
                  {t('forgotPassword.backToLogin', 'Back to Login')}
                </Link>
              </div>
            </>
          )}
        </div>
      </section>
    </main>
  );
}
