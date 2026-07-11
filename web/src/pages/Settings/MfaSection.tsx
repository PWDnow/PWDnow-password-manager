import React from 'react';
import { Key, Mail, KeyRound, Fingerprint, ToggleRight, ToggleLeft, Loader2, Trash2, AlertTriangle, ShieldCheck, X, Check, Copy, RefreshCw, Smartphone, Smartphone as SmartphoneIcon, Mail as MailIcon, Key as KeyIcon, ShieldCheck as ShieldCheckIcon } from 'lucide-react';

const FbShieldLock = ({ size = 20, className = '' }: { size?: number; className?: string }) => (
  <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <rect x="9" y="11" width="6" height="5" rx="1"/>
    <path d="M10 11V9.5a2 2 0 1 1 4 0V11"/>
  </svg>
);
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { useMfaSetup } from './hooks/useMfaSetup';
import { countActiveMfaMethods } from '../../utils/mfa';
import PasswordPromptModal from '../../components/PasswordPromptModal';
import MfaModalContent from './MfaModalContent';

import type { UserProfile } from '../../context/UserContext';

interface Props {
  profile: UserProfile;
  emailServerConfig: import('../../types').EmailServerConfig | null;
}

export default function MfaSection({ profile, emailServerConfig }: Props) {
  const { t } = useTranslation();
  const {
    mfaConfig,
    policyError,
    platformAuthAvail,
    mfaModal,
    setMfaModal,
    totpSecret,
    totpType,
    setTotpType,
    totpCode,
    totpError,
    totpSecretCopied,
    setTotpSecretCopied,
    totpRefs,
    qrCanvasCallback,
    webAuthnError,
    webAuthnBusy,
    webAuthnKeyName,
    setWebAuthnKeyName,
    handleWebAuthnRegister,
    webAuthnBusy: _webAuthnBusy, // avoid naming collision if any
    handleWebAuthnRemove,
    handleEmailRemove,
    emailInput,
    setEmailInput,
    emailSimCode,
    emailCode,
    setEmailCode,
    emailError,
    setEmailError,
    emailBusy,
    emailRefs,
    quickUnlockEnabled,
    quickUnlockLoading,
    isPasswordPromptOpen,
    setIsPasswordPromptOpen,
    closeMfaModal,
    openMfaModal,
    handleTotpVerify,
    handleTotpRemove,
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
    totpHandlers,
    emailHandlers,
    passkeyName,
    setPasskeyName,
    passkeyBusy,
    passkeyError,
    platformName,
    setPlatformName,
    platformBusy,
    platformError
  } = useMfaSetup(profile);

  return (
    <>
      <section>
        <div className="mb-6">
          <h2 className="text-[15px] font-semibold text-neutral-900 dark:text-white leading-snug">{t('settings.authProtocols', 'Authentication Protocols')}</h2>
          <p className="mt-1 text-[13px] text-neutral-600 dark:text-neutral-300">{t('settings.authProtocolsDesc', 'Manage multi-factor authentication and login methods.')}</p>
          <div className="mt-4 h-px bg-neutral-200 dark:bg-white/8" />
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
                        <div className="w-1.5 h-1.5 rounded-full bg-green-500" />{t('mfa.statusActive', 'Active')}
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-on-surface-variant bg-surface-container-highest px-2.5 py-1 rounded-md">
                        <div className="w-1.5 h-1.5 rounded-full bg-outline-variant" />{t('settings.notSetUp', 'Not set up')}
                      </span>
                    )}
                    {active && (
                      <button
                        type="button"
                        onClick={e => { e.stopPropagation(); handleTotpRemove(); }}
                        className="p-1.5 rounded-lg text-red-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20 transition-colors"
                        title={t('settings.removeAuthApp', 'Remove authenticator app')}
                        aria-label={t('settings.removeAuthApp', 'Remove authenticator app')}
                      >
                        <Trash2 size={15} aria-hidden="true" />
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
                        <div className="w-1.5 h-1.5 rounded-full bg-green-500" />{t('mfa.keysRegistered', '{{count}} key(s) registered', { count: mfaConfig.webauthn.credentials.length })}
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
                        <div className="w-1.5 h-1.5 rounded-full bg-green-500" />{t('mfa.statusActive', 'Active')}
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-on-surface-variant bg-surface-container-highest px-2.5 py-1 rounded-md">
                        <div className="w-1.5 h-1.5 rounded-full bg-outline-variant" />{t('settings.notSetUp', 'Not set up')}
                      </span>
                    )}
                    {active && (
                      <button
                        type="button"
                        onClick={e => { e.stopPropagation(); handleEmailRemove(); }}
                        className="p-1.5 rounded-lg text-red-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20 transition-colors"
                        title={t('settings.removeEmailOtp', 'Remove email OTP')}
                        aria-label={t('settings.removeEmailOtp', 'Remove email OTP')}
                      >
                        <Trash2 size={15} aria-hidden="true" />
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
                  className={`p-8 rounded-xl border-2 transition-all cursor-pointer flex flex-col ${active ? 'border-black dark:border-on-primary-container bg-white dark:bg-surface-container-high shadow-lg' : unavailable ? 'border-amber-300/60 dark:border-amber-700/40 bg-surface-container-high' : 'border-outline-variant/40 bg-surface-container-high hover:border-outline-variant hover:bg-surface-container-highest'}`}
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
                      <p className="text-[10px] text-black dark:text-amber-200 font-semibold flex items-center gap-1">
                        <AlertTriangle size={10} />{t('mfa.noAuthenticatorVM', 'Not available — no platform authenticator detected (VM environment)')}
                      </p>
                    )}
                  </div>
                </div>
              );
            })()}

            {/* Platform Auth */}
            {(() => {
              const active = mfaConfig.platform?.enabled ?? false;
              const count = mfaConfig.platform?.credentials?.length ?? 0;
              const unavailable = platformAuthAvail === false;
              return (
                <div
                  onClick={() => openMfaModal('platform')}
                  className={`p-8 rounded-xl border-2 transition-all cursor-pointer flex flex-col ${active ? 'border-black dark:border-on-primary-container bg-white dark:bg-surface-container-high shadow-lg' : unavailable ? 'border-amber-300/60 dark:border-amber-700/40 bg-surface-container-high' : 'border-outline-variant/40 bg-surface-container-high hover:border-outline-variant hover:bg-surface-container-highest'}`}
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
                      <p className="text-[10px] text-black dark:text-amber-200 font-semibold flex items-center gap-1">
                        <AlertTriangle size={10} />{t('mfa.noBiometricHardware', 'Not available — Touch ID / Windows Hello requires biometric hardware')}
                      </p>
                    )}
                  </div>
                </div>
              );
            })()}
          </div>

          {/* Quick Unlock */}
          <div className={`mt-8 p-6 rounded-xl border-2 flex items-center justify-between gap-6 transition-all ${quickUnlockEnabled ? 'border-black dark:border-on-primary-container bg-black/5 dark:bg-white/5' : 'border-outline-variant/30 bg-surface-container-high'}`}>
            <div className="flex gap-4 items-start">
              <div className={`mt-0.5 p-2 rounded-xl ${quickUnlockEnabled ? 'bg-blue-600 text-white' : 'bg-surface-container-highest text-on-surface-variant'}`}>
                <Fingerprint size={24} />
              </div>
              <div>
                <h4 className="font-bold text-base mb-1">{t('mfa.quickUnlockTitle', 'Quick Unlock (Touch ID / Windows Hello)')}</h4>
                <p className="text-sm text-on-surface-variant leading-relaxed">
                  {quickUnlockEnabled
                    ? t('mfa.quickUnlockEnabledDesc', 'Use your fingerprint or face to instantly unlock the vault on this device without typing your master password.')
                    : t('mfa.quickUnlockDisabledDesc', 'Enroll this device to quickly unlock using Windows Hello, Touch ID, or Face ID.')}
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={handleToggleQuickUnlock}
              disabled={quickUnlockLoading}
              aria-label={quickUnlockEnabled
                ? t('mfa.quickUnlockDisable', 'Disable Quick Unlock')
                : t('mfa.quickUnlockEnable', 'Enable Quick Unlock')}
              aria-pressed={quickUnlockEnabled}
              className={`shrink-0 flex items-center gap-2 px-4 py-2 rounded-lg font-bold text-sm transition-all shadow-sm active:scale-[0.98] ${
                quickUnlockEnabled
                  ? 'bg-black text-white hover:opacity-90 dark:bg-white dark:text-black'
                  : 'bg-white text-black border-2 border-outline-variant hover:border-black dark:bg-[#1a1a1a] dark:text-white dark:border-white/20 dark:hover:border-white'
              }`}
            >
              {quickUnlockLoading ? <Loader2 size={16} aria-hidden="true" className="animate-spin" /> : null}
              {quickUnlockEnabled
                ? <><ToggleRight size={16} aria-hidden="true" />{t('common.enabled', 'Enabled')}</>
                : <><ToggleLeft size={16} aria-hidden="true" />{t('common.disabled', 'Disabled')}</>}
            </button>
          </div>

          {/* Passwordless toggle */}
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
                      : t('settings.passwordlessDisabledDesc', 'You have 2+ authentication methods. Disable the password field at login.')}
                  </p>
                </div>
              </div>
              <button
                onClick={handlePasswordlessToggle}
                aria-label={mfaConfig.passwordlessEnabled
                  ? t('settings.passwordlessDisable', 'Disable passwordless login')
                  : t('settings.passwordlessEnable', 'Enable passwordless login')}
                aria-pressed={mfaConfig.passwordlessEnabled}
                className="shrink-0 flex items-center gap-2 px-5 py-3 rounded-xl font-black text-xs uppercase tracking-widest transition-all"
                style={mfaConfig.passwordlessEnabled
                  ? { background: 'black', color: 'white' }
                  : { background: 'var(--color-surface-container-highest)', color: 'var(--color-on-surface)' }}
              >
                {mfaConfig.passwordlessEnabled
                  ? <><ToggleRight size={16} aria-hidden="true" />{t('settings.passwordlessOn', 'Enabled')}</>
                  : <><ToggleLeft size={16} aria-hidden="true" />{t('settings.passwordlessOff', 'Disabled')}</>}
              </button>
            </div>
          )}

          {/* Two-Factor Requirement toggle */}
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
                aria-label={mfaConfig.passwordLoginEnabled === false
                  ? t('settings.twoFactorEnable', 'Enable password-only login')
                  : t('settings.twoFactorDisable', 'Disable password-only login (require two-factor)')}
                aria-pressed={mfaConfig.passwordLoginEnabled !== false}
                className="shrink-0 flex items-center gap-2 px-5 py-3 rounded-xl font-black text-xs uppercase tracking-widest transition-all"
                style={mfaConfig.passwordLoginEnabled === false
                  ? { background: 'rgb(245 158 11)', color: 'white' }
                  : { background: 'var(--color-surface-container-highest)', color: 'var(--color-on-surface)' }}
              >
                {mfaConfig.passwordLoginEnabled === false
                  ? <><ToggleLeft size={16} aria-hidden="true" />{t('settings.passwordLoginOff', 'Disabled')}</>
                  : <><ToggleRight size={16} aria-hidden="true" />{t('settings.passwordLoginOn', 'Enabled')}</>}
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

      {/* MFA Modal */}
      <AnimatePresence>
        {mfaModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-black/60 backdrop-blur-sm"
              onClick={closeMfaModal}
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-xl bg-white dark:bg-[#1a1a1a] rounded-3xl shadow-2xl overflow-hidden border border-slate-200 dark:border-white/10"
            >
              <div className="absolute top-6 right-6 z-10">
                <button aria-label="Close" onClick={closeMfaModal} className="p-2 hover:bg-slate-100 dark:hover:bg-white/5 rounded-full transition-colors">
  <X aria-hidden="true" size={20} className="text-slate-500" />
</button>
              </div>

              <MfaModalContent
                mfaModal={mfaModal}
                mfaConfig={mfaConfig}
                closeMfaModal={closeMfaModal}
                handleTotpRemove={handleTotpRemove}
                setTotpType={setTotpType}
                totpType={totpType}
                handleTotpTypeConfirm={() => setMfaModal({ type: 'totp', step: 1 })}
                qrCanvasCallback={qrCanvasCallback}
                totpSecret={totpSecret}
                totpSecretCopied={totpSecretCopied}
                setTotpSecretCopied={setTotpSecretCopied}
                totpCode={totpCode}
                totpRefs={totpRefs}
                totpHandlers={totpHandlers}
                handleTotpVerify={handleTotpVerify}
                totpError={totpError}
                handleWebAuthnRemove={handleWebAuthnRemove}
                webAuthnKeyName={webAuthnKeyName}
                setWebAuthnKeyName={setWebAuthnKeyName}
                handleWebAuthnRegister={handleWebAuthnRegister}
                webAuthnBusy={webAuthnBusy}
                webAuthnError={webAuthnError}
                handleEmailRemove={handleEmailRemove}
                emailInput={emailInput}
                setEmailInput={setEmailInput}
                isEmailValid={emailInput.includes('@')}
                emailBusy={emailBusy}
                handleEmailSend={handleEmailSend}
                emailSimCode={emailSimCode}
                emailCode={emailCode}
                emailRefs={emailRefs}
                emailHandlers={emailHandlers}
                handleEmailVerify={handleEmailVerify}
                emailError={emailError}
                setMfaModal={setMfaModal}
                setEmailCode={setEmailCode}
                setEmailError={setEmailError}
                emailServerConfig={emailServerConfig}
                handlePasskeyRemove={handlePasskeyRemove}
                passkeyName={passkeyName}
                setPasskeyName={setPasskeyName}
                handlePasskeyRegister={handlePasskeyRegister}
                passkeyBusy={passkeyBusy}
                passkeyError={passkeyError}
                handlePlatformRemove={handlePlatformRemove}
                platformName={platformName}
                setPlatformName={setPlatformName}
                handlePlatformRegister={handlePlatformRegister}
                platformBusy={platformBusy}
                platformError={platformError}
                platformAuthAvail={platformAuthAvail}
              />
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      <PasswordPromptModal
        isOpen={isPasswordPromptOpen}
        onClose={() => setIsPasswordPromptOpen(false)}
        onConfirm={handleQuickUnlockConfirm}
        title={t('settings.enableQuickUnlock', 'Enable Quick Unlock')}
        message={t('settings.quickUnlockPrompt', 'Enter your master password to enable Touch ID / Windows Hello unlock for this device:')}
        loading={quickUnlockLoading}
      />
    </>
  );
}
