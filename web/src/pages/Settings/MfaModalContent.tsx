import React from 'react';
import {
  Smartphone,
  Key,
  Mail,
  CheckCircle,
  Trash2,
  ShieldCheck,
  RefreshCw,
  KeyRound,
  Fingerprint,
  AlertTriangle,
  Loader2,
  Check,
  Copy
} from 'lucide-react';
import { motion } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { isWebAuthnSupported, isSecureContext, type MfaConfig } from '../../utils/mfa';
import type { MfaModalState } from './hooks/useMfaSetup';
import type { EmailServerConfig } from '../../types';

interface DigitInputHandlers {
  onChange(index: number, value: string): void;
  onKeyDown(index: number, e: React.KeyboardEvent<HTMLInputElement>): void;
  onPaste(e: React.ClipboardEvent): void;
}

interface Props {
  mfaModal: MfaModalState;
  mfaConfig: MfaConfig;
  closeMfaModal: () => void;
  handleTotpRemove: () => void;
  setTotpType: (type: 'totp' | 'hotp') => void;
  totpType: 'totp' | 'hotp';
  handleTotpTypeConfirm: () => void;
  qrCanvasCallback: (canvas: HTMLCanvasElement | null) => void;
  totpSecret: string;
  totpSecretCopied: boolean;
  setTotpSecretCopied: (v: boolean) => void;
  totpCode: string[];
  totpRefs: React.MutableRefObject<(HTMLInputElement | null)[]>;
  totpHandlers: DigitInputHandlers;
  handleTotpVerify: () => void;
  totpError: string;
  handleWebAuthnRemove: (id: string) => void;
  webAuthnKeyName: string;
  setWebAuthnKeyName: (v: string) => void;
  handleWebAuthnRegister: () => void;
  webAuthnBusy: boolean;
  webAuthnError: string;
  handleEmailRemove: () => void;
  emailInput: string;
  setEmailInput: (v: string) => void;
  isEmailValid: boolean;
  emailBusy: boolean;
  handleEmailSend: () => void;
  emailSimCode: string | null;
  emailCode: string[];
  emailRefs: React.MutableRefObject<(HTMLInputElement | null)[]>;
  emailHandlers: DigitInputHandlers;
  handleEmailVerify: () => void;
  emailError: string;
  setMfaModal: (v: MfaModalState | null) => void;
  setEmailCode: (v: string[]) => void;
  setEmailError: (v: string) => void;
  handlePasskeyRemove: (id: string) => void;
  passkeyName: string;
  setPasskeyName: (v: string) => void;
  handlePasskeyRegister: () => void;
  passkeyBusy: boolean;
  passkeyError: string;
  handlePlatformRemove: (id: string) => void;
  platformName: string;
  setPlatformName: (v: string) => void;
  handlePlatformRegister: () => void;
  platformBusy: boolean;
  platformError: string;
  platformAuthAvail: boolean | null;
  emailServerConfig: EmailServerConfig | null;
}

export default function MfaModalContent(props: Props) {
  const { t } = useTranslation();
  const {
    mfaModal,
    mfaConfig,
    closeMfaModal,
    handleTotpRemove,
    setTotpType,
    totpType,
    handleTotpTypeConfirm,
    qrCanvasCallback,
    totpSecret,
    totpSecretCopied,
    setTotpSecretCopied,
    totpCode,
    totpRefs,
    totpHandlers,
    handleTotpVerify,
    totpError,
    handleWebAuthnRemove,
    webAuthnKeyName,
    setWebAuthnKeyName,
    handleWebAuthnRegister,
    webAuthnBusy,
    webAuthnError,
    handleEmailRemove,
    emailInput,
    setEmailInput,
    isEmailValid,
    emailBusy,
    handleEmailSend,
    emailSimCode,
    emailCode,
    emailRefs,
    emailHandlers,
    handleEmailVerify,
    emailError,
    setMfaModal,
    setEmailCode,
    setEmailError,
    handlePasskeyRemove,
    passkeyName,
    setPasskeyName,
    handlePasskeyRegister,
    passkeyBusy,
    passkeyError,
    handlePlatformRemove,
    platformName,
    setPlatformName,
    handlePlatformRegister,
    platformBusy,
    platformError,
    platformAuthAvail,
    emailServerConfig,
  } = props;

  return (
    <div className="p-8">
      {mfaModal.type === 'totp' && (
        <>
          {/* Already enabled: manage screen */}
          {(mfaConfig.totp.enabled || mfaConfig.hotp?.enabled) && mfaModal.step === 1 && (
            <div className="space-y-8">
              <div>
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('mfa.authenticatorApp', 'Authenticator App')}</h3>
                <p className="text-on-surface-variant text-sm leading-relaxed">{t('mfa.authAppConfigured', 'Your authenticator app is configured and active.')}</p>
              </div>
              <div className="p-5 bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800 rounded-2xl flex items-center gap-4">
                <CheckCircle size={22} className="text-green-600 shrink-0" />
                <div>
                  <p className="font-bold text-sm text-green-800 dark:text-green-300">
                    {t('mfa.activeSince', 'Active since {{date}}', { date: new Date((mfaConfig.hotp?.enabled ? mfaConfig.hotp.enabledAt : mfaConfig.totp.enabledAt) ?? 0).toLocaleDateString() })}
                  </p>
                  <p className="text-xs text-green-700/70 dark:text-green-400/70 mt-0.5">
                    {mfaConfig.hotp?.enabled
                      ? t('mfa.hotpDetails', 'HOTP · SHA-1 · 6 digits · Counter-based')
                      : t('mfa.totpDetails', 'TOTP · {{algorithm}} · {{digits}} digits · 30 s period', { algorithm: mfaConfig.totp.algorithm || 'SHA-256', digits: mfaConfig.totp.digits || 8 })}
                  </p>
                </div>
              </div>
              <div className="flex gap-3 pt-2">
                <button onClick={closeMfaModal} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.close', 'Close')}</button>
                <button
                  onClick={handleTotpRemove}
                  className="flex-1 py-4 bg-error/10 text-error rounded-xl font-black uppercase tracking-widest text-xs hover:bg-error/20 transition-all flex items-center justify-center gap-2"
                >
                  <Trash2 size={14} />{t('common.remove', 'Remove')}
                </button>
              </div>
            </div>
          )}

          {/* Setup step 0 – choose TOTP vs HOTP */}
          {!mfaConfig.totp.enabled && !mfaConfig.hotp?.enabled && mfaModal.step === 0 && (
            <div className="space-y-8">
              <div>
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('mfa.setupAuthApp', 'Set up Authenticator App')}</h3>
                <p className="text-on-surface-variant text-sm leading-relaxed">{t('mfa.chooseOtpType', 'Choose the type of one-time password your app will generate.')}</p>
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
                      <span className="text-[10px] font-black uppercase tracking-widest bg-blue-600 text-white px-2 py-0.5 rounded-md">{t('common.recommended', 'Recommended')}</span>
                    </div>
                    <p className="text-xs text-on-surface-variant">{t('mfa.totpOptionDesc', 'Time-based - new code every 30 seconds')}</p>
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
                    <p className="text-xs text-on-surface-variant">{t('mfa.hotpOptionDesc', 'Counter-based - new code on each button press')}</p>
                  </div>
                </button>
              </div>
              <div className="flex gap-3">
                <button onClick={closeMfaModal} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.cancel', 'Cancel')}</button>
                <button
                  onClick={handleTotpTypeConfirm}
                  className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2"
                >
                  <ShieldCheck size={16} />{t('common.next', 'Next')}
                </button>
              </div>
            </div>
          )}

          {/* Setup step 1 – QR code */}
          {!mfaConfig.totp.enabled && !mfaConfig.hotp?.enabled && mfaModal.step === 1 && (
            <div className="space-y-8">
              <div>
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('mfa.setupAuthApp', 'Set up Authenticator App')}</h3>
                <p className="text-on-surface-variant text-sm leading-relaxed">
                  {totpType === 'hotp'
                    ? t('mfa.hotpScanDesc', 'Scan the QR code with your authenticator app. Each press of the "next code" button generates a new code.')
                    : t('mfa.totpScanDesc', 'Scan the QR code with Google Authenticator, Authy, or any TOTP-compatible app.')}
                </p>
              </div>

              <div className="flex flex-col md:flex-row items-center gap-10">
                <div className="p-4 bg-white rounded-2xl shadow-xl border border-outline-variant/10">
                  <canvas ref={qrCanvasCallback} />
                </div>
                <div className="flex-1 space-y-6">
                  <div>
                    <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-2">{t('mfa.manualEntryKey', 'Manual Entry Key')}</p>
                    <div className="flex items-center gap-3">
                      <code className="bg-surface-container-high px-4 py-2.5 rounded-xl font-mono text-sm font-bold text-black dark:text-white break-all flex-1">
                        {totpSecret}
                      </code>
                      <button
                        onClick={() => { navigator.clipboard.writeText(totpSecret); setTotpSecretCopied(true); setTimeout(() => setTotpSecretCopied(false), 2000); }}
                        className="p-3 bg-surface-container-high hover:bg-surface-container-highest rounded-xl transition-colors text-on-surface-variant hover:text-black"
                      >
                        {totpSecretCopied ? <Check size={18} className="text-green-600" /> : <Copy size={18} />}
                      </button>
                    </div>
                  </div>
                  <div className="p-4 bg-blue-50 dark:bg-blue-950/30 border border-blue-100 dark:border-blue-900 rounded-xl">
                    <p className="text-xs text-blue-700 dark:text-blue-300 leading-relaxed font-medium">
                      <strong>{t('mfa.securityTipLabel', 'Security Tip:')}</strong> {t('mfa.securityTip', 'Print a backup of this QR code or manual key and store it in a safe place.')}
                    </p>
                  </div>
                </div>
              </div>

              <div className="flex gap-3">
                <button onClick={() => setMfaModal({ type: 'totp', step: 0 })} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.back', 'Back')}</button>
                <button
                  onClick={() => setMfaModal({ type: 'totp', step: 2 })}
                  className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2"
                >
                  <ShieldCheck size={16} />{t('common.next', 'Next')}
                </button>
              </div>
            </div>
          )}

          {/* Setup step 2 – verify */}
          {!mfaConfig.totp.enabled && !mfaConfig.hotp?.enabled && mfaModal.step === 2 && (
            <div className="space-y-8">
              <div>
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('mfa.verifyCode', 'Verify the code')}</h3>
                <p className="text-on-surface-variant text-sm leading-relaxed">{t('mfa.enterEightDigitCode', 'Enter the 8-digit code from your app to complete setup.')}</p>
              </div>

              <div className="flex items-center justify-center gap-2">
                {[0,1,2,3].map(i => (
                  <input key={i} ref={el => { totpRefs.current[i] = el; }}
                    type="text" inputMode="numeric" maxLength={1} value={totpCode[i]}
                    onChange={e => totpHandlers.onChange(i, e.target.value)}
                    onKeyDown={e => totpHandlers.onKeyDown(i, e)}
                    onPaste={i === 0 ? totpHandlers.onPaste : undefined}
                    className="w-10 h-14 text-center text-xl font-black bg-white dark:bg-[#1a1a1a] border-2 border-slate-400 dark:border-slate-400 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all text-black dark:text-white"
                  />
                ))}
                <div className="w-4 h-0.5 bg-slate-400 dark:bg-slate-400 rounded-full mx-1" />
                {[4,5,6,7].map(i => (
                  <input key={i} ref={el => { totpRefs.current[i] = el; }}
                    type="text" inputMode="numeric" maxLength={1} value={totpCode[i]}
                    onChange={e => totpHandlers.onChange(i, e.target.value)}
                    onKeyDown={e => totpHandlers.onKeyDown(i, e)}
                    className="w-10 h-14 text-center text-xl font-black bg-white dark:bg-[#1a1a1a] border-2 border-slate-400 dark:border-slate-400 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all text-black dark:text-white"
                  />
                ))}
              </div>

              {totpError && (
                <p className="text-xs font-bold text-error flex items-center gap-2"><AlertTriangle size={14} />{totpError}</p>
              )}

              <div className="flex gap-3">
                <button onClick={() => setMfaModal({ type: 'totp', step: 1 })} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.back', 'Back')}</button>
                <button
                  onClick={handleTotpVerify}
                  disabled={totpCode.some(c => !c)}
                  className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  <ShieldCheck size={16} />{t('common.verify', 'Verify')}
                </button>
              </div>
            </div>
          )}

          {/* Setup step 3 – success */}
          {mfaModal.step === 3 && (
            <div className="text-center py-6 space-y-6">
              <div className="w-20 h-20 rounded-full bg-green-50 dark:bg-green-950/40 flex items-center justify-center mx-auto">
                <CheckCircle size={40} className="text-green-600" />
              </div>
              <div>
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('mfa.authAppActive', 'Authenticator app active')}</h3>
                <p className="text-on-surface-variant text-sm">{t('mfa.totpSynced', 'Your {{type}} {{mode}} is synced. Use it at next login.', { type: totpType.toUpperCase(), mode: totpType === 'hotp' ? t('mfa.counter', 'counter') : t('mfa.timer', 'timer') })}</p>
              </div>
              <button onClick={closeMfaModal} className="w-full py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all">{t('common.done', 'Done')}</button>
            </div>
          )}
        </>
      )}

      {/* WebAuthn */}
      {mfaModal.type === 'webauthn' && (
        <>
          {/* Manage existing keys */}
          {(mfaConfig.webauthn.enabled) && mfaModal.step === 1 && (
            <div className="space-y-8">
              <div>
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('mfa.securityKeys', 'Security Keys')}</h3>
                <p className="text-on-surface-variant text-sm leading-relaxed">{t('mfa.securityKeysManageDesc', 'Physical hardware security keys registered to this account.')}</p>
              </div>

              <div className="space-y-3">
                {(mfaConfig.webauthn.credentials ?? []).map(cred => (
                  <div key={cred.id} className="flex items-center justify-between p-4 bg-surface-container-low rounded-xl border border-outline-variant/10">
                    <div className="flex items-center gap-3">
                      <Key size={18} className="text-on-surface-variant" />
                      <div>
                        <p className="font-bold text-sm">{cred.name}</p>
                        <p className="text-[10px] text-on-surface-variant">{t('mfa.addedOn', 'Added {{date}}', { date: new Date(cred.createdAt).toLocaleDateString() })}</p>
                      </div>
                    </div>
                    <button onClick={() => handleWebAuthnRemove(cred.id)} className="p-2 text-error hover:bg-error/10 rounded-lg transition-colors" title={t('common.remove', 'Remove')}>
                      <Trash2 size={16} />
                    </button>
                  </div>
                ))}
              </div>

              <div className="space-y-3">
                <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('mfa.addAnotherKey', 'Add another security key')}</label>
                <div className="flex gap-3">
                  <input type="text" value={webAuthnKeyName} onChange={e => setWebAuthnKeyName(e.target.value)}
                    placeholder="e.g. Blue YubiKey"
                    className="flex-1 px-4 py-3 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-bold text-sm focus:ring-2 focus:ring-black/20 outline-none" />
                  <button onClick={handleWebAuthnRegister} disabled={webAuthnBusy}
                    className="px-6 py-3 bg-black text-white rounded-xl font-black text-xs uppercase tracking-widest hover:bg-neutral-800 transition-all disabled:opacity-50 flex items-center gap-2">
                    {webAuthnBusy ? <RefreshCw size={14} className="animate-spin" /> : <Key size={14} />}{t('common.add', 'Add')}
                  </button>
                </div>
                {webAuthnError && <p className="text-xs font-bold text-error flex items-center gap-2"><AlertTriangle size={14} />{webAuthnError}</p>}
              </div>

              <button onClick={closeMfaModal} className="w-full py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.close', 'Close')}</button>
            </div>
          )}

          {/* First-time setup */}
          {!(mfaConfig.webauthn.enabled) && mfaModal.step === 1 && (
            <div className="space-y-8">
              <div>
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('mfa.registerKeyTitle', 'Register a Security Key')}</h3>
                <p className="text-on-surface-variant text-sm leading-relaxed">
                  {t('mfa.registerKeyDesc', 'Use a physical YubiKey, Google Titan, or other FIDO2-compliant hardware key.')}
                </p>
              </div>

              {!isWebAuthnSupported() ? (
                <div className="p-5 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 rounded-xl flex items-start gap-3">
                  <AlertTriangle size={18} className="text-amber-600 shrink-0 mt-0.5" />
                  <p className="text-sm text-amber-800 dark:text-amber-300">{t('mfa.keyNotSupported', 'Security keys are not supported in this browser.')}</p>
                </div>
              ) : (
                <>
                  {!isSecureContext() && (
                    <div className="p-4 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-xl flex items-start gap-3">
                      <AlertTriangle size={16} className="text-amber-600 shrink-0 mt-0.5" />
                      <p className="text-xs text-amber-800 dark:text-amber-300 leading-relaxed"><strong>{t('mfa.noteLabel', 'Note:')}</strong> {t('mfa.webauthnRequiresHttps', 'WebAuthn requires HTTPS or localhost.')}</p>
                    </div>
                  )}
                  <div className="space-y-4">
                    <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('mfa.giveKeyName', 'Give this key a name')}</label>
                    <input type="text" autoFocus value={webAuthnKeyName} onChange={e => setWebAuthnKeyName(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter' && !webAuthnBusy) handleWebAuthnRegister(); }}
                      placeholder="e.g. YubiKey 5C"
                      className="w-full px-5 py-3.5 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/20 outline-none transition-all" />
                  </div>
                </>
              )}

              {webAuthnError && <p className="text-xs font-bold text-error flex items-center gap-2"><AlertTriangle size={14} />{webAuthnError}</p>}

              <div className="flex gap-3">
                <button onClick={closeMfaModal} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.cancel', 'Cancel')}</button>
                <button onClick={handleWebAuthnRegister} disabled={webAuthnBusy || !isWebAuthnSupported()}
                  className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2 disabled:opacity-50">
                  {webAuthnBusy ? <RefreshCw size={16} className="animate-spin" /> : <Key size={16} />}
                  {webAuthnBusy ? t('mfa.waitingForKey', 'Waiting for key…') : t('mfa.registerKeyBtn', 'Register Key')}
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
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('mfa.keyRegistered', 'Key registered')}</h3>
                <p className="text-on-surface-variant text-sm">{t('mfa.keyRegisteredDesc', '"{{name}}" has been registered. Insert it and tap when prompted at login.', { name: webAuthnKeyName })}</p>
              </div>
              <button onClick={closeMfaModal} className="w-full py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all">{t('common.done', 'Done')}</button>
            </div>
          )}
        </>
      )}

      {/* Email OTP */}
      {mfaModal.type === 'email' && (
        <>
          {/* Manage / already active */}
          {mfaConfig.email.enabled && mfaModal.step === 1 && (
            <div className="space-y-8">
              <div>
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('mfa.emailVerification', 'Email Verification')}</h3>
                <p className="text-on-surface-variant text-sm">{t('mfa.otpSentTo', 'OTP codes will be sent to:')}</p>
              </div>
              <div className="p-5 bg-surface-container-low rounded-xl border border-outline-variant/10 flex items-center gap-3">
                <Mail size={18} className="text-on-surface-variant" />
                <span className="font-bold text-sm">{mfaConfig.email.address}</span>
              </div>
              <div className="flex gap-3">
                <button onClick={closeMfaModal} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.close', 'Close')}</button>
                <button
                  onClick={handleEmailRemove}
                  className="flex-1 py-4 bg-error/10 text-error rounded-xl font-black uppercase tracking-widest text-xs hover:bg-error/20 transition-all flex items-center justify-center gap-2"
                >
                  <Trash2 size={14} />{t('common.remove', 'Remove')}
                </button>
              </div>
            </div>
          )}

          {/* Step 1 – enter email */}
          {!mfaConfig.email.enabled && mfaModal.step === 1 && (
            <div className="space-y-8">
              <div>
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('mfa.setupEmailVerification', 'Set up Email Verification')}</h3>
                <p className="text-on-surface-variant text-sm leading-relaxed">{t('mfa.setupEmailVerifyDesc', 'Enter the email address where you want to receive one-time login codes.')}</p>
              </div>
              <div className="space-y-3">
                <label htmlFor="email-mfa" className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('mfa.emailAddressLabel', 'Email address')}</label>
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
                <button onClick={closeMfaModal} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.cancel', 'Cancel')}</button>
                <button
                  onClick={handleEmailSend}
                  disabled={!isEmailValid || emailBusy}
                  className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {emailBusy ? <RefreshCw size={16} className="animate-spin" /> : <Mail size={16} />}
                  {emailBusy ? t('mfa.sending', 'Sending…') : t('mfa.sendCode', 'Send Code')}
                </button>
              </div>
            </div>
          )}

          {/* Step 2 – simulated email preview + code entry */}
          {!mfaConfig.email.enabled && mfaModal.step === 2 && (
            <div className="space-y-8">
              <div>
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('mfa.enterCode', 'Enter the code')}</h3>
                <p className="text-on-surface-variant text-sm">
                  {t('mfa.simEmailNote', 'In a production app the code would be emailed. Here is a simulated preview:')}
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
                  <p className="font-bold mb-3">{t('mfa.verificationCode', 'Your verification code')}</p>
                  <p className="text-on-surface-variant text-xs mb-4 leading-relaxed">{t('mfa.codeExpiry', 'Use the code below to complete your MFA setup. It expires in 5 minutes.')}</p>
                  <div className="bg-surface-container-high rounded-xl py-4 text-center">
                    <span className="font-mono text-3xl font-black tracking-[0.4em] text-black dark:text-white">
                      {emailSimCode ? `${emailSimCode.slice(0,3)} ${emailSimCode.slice(3)}` : '--- ---'}
                    </span>
                  </div>
                  <p className="text-[10px] text-on-surface-variant mt-4">{t('mfa.doNotShare', 'Do not share this code with anyone.')}</p>
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
                <button onClick={() => { setMfaModal({ type: 'email', step: 1 }); setEmailCode(['','','','','','']); setEmailError(''); }} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.back', 'Back')}</button>
                <button
                  onClick={handleEmailVerify}
                  disabled={emailCode.some(c => !c)}
                  className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  <ShieldCheck size={16} />{t('common.verify', 'Verify')}
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
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('mfa.emailVerificationActive', 'Email verification active')}</h3>
                <p className="text-on-surface-variant text-sm">{t('mfa.emailActiveDesc', 'OTP codes will be sent to {{email}} at every login.', { email: emailInput })}</p>
              </div>
              <button onClick={closeMfaModal} className="w-full py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all">{t('common.done', 'Done')}</button>
            </div>
          )}
        </>
      )}

      {/* Passkey */}
      {mfaModal.type === 'passkey' && (
        <>
          {/* Manage existing passkeys */}
          {(mfaConfig.passkey?.enabled) && mfaModal.step === 1 && (
            <div className="space-y-8">
              <div>
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('mfa.passkeys', 'Passkeys')}</h3>
                <p className="text-on-surface-variant text-sm leading-relaxed">{t('mfa.passkeysManageDesc', 'Synced passkeys registered to this account.')}</p>
              </div>

              <div className="space-y-3">
                {(mfaConfig.passkey?.credentials ?? []).map((cred) => (
                  <div key={cred.id} className="flex items-center justify-between p-4 bg-surface-container-low rounded-xl border border-outline-variant/10">
                    <div className="flex items-center gap-3">
                      <KeyRound size={18} className="text-on-surface-variant" />
                      <div>
                        <p className="font-bold text-sm">{cred.name}</p>
                        <p className="text-[10px] text-on-surface-variant">{t('mfa.addedOn', 'Added {{date}}', { date: new Date(cred.createdAt).toLocaleDateString() })}</p>
                      </div>
                    </div>
                    <button onClick={() => handlePasskeyRemove(cred.id)} className="p-2 text-error hover:bg-error/10 rounded-lg transition-colors" title={t('common.remove', 'Remove passkey')}>
                      <Trash2 size={16} />
                    </button>
                  </div>
                ))}
              </div>

              <div className="space-y-3">
                <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('settings.addAnotherPasskey', 'Add another passkey')}</label>
                <div className="flex gap-3">
                  <input type="text" value={passkeyName} onChange={e => setPasskeyName(e.target.value)}
                    placeholder="e.g. MacBook Pro"
                    className="flex-1 px-4 py-3 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-bold text-sm focus:ring-2 focus:ring-black/20 outline-none" />
                  <button onClick={handlePasskeyRegister} disabled={passkeyBusy}
                    className="px-6 py-3 bg-black text-white rounded-xl font-black text-xs uppercase tracking-widest hover:bg-neutral-800 transition-all disabled:opacity-50 flex items-center gap-2">
                    {passkeyBusy ? <RefreshCw size={14} className="animate-spin" /> : <KeyRound size={14} />}{t('common.add', 'Add')}
                  </button>
                </div>
                {passkeyError && <p className="text-xs font-bold text-error flex items-center gap-2"><AlertTriangle size={14} />{passkeyError}</p>}
              </div>

              <button onClick={closeMfaModal} className="w-full py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.close', 'Close')}</button>
            </div>
          )}

          {/* First-time setup */}
          {!(mfaConfig.passkey?.enabled) && mfaModal.step === 1 && (
            <div className="space-y-8">
              <div>
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('mfa.registerPasskeyTitle', 'Register a Passkey')}</h3>
                <p className="text-on-surface-variant text-sm leading-relaxed">
                  {t('mfa.registerPasskeyDesc', 'A passkey is stored in your iCloud Keychain (Mac/iPhone) or Google Password Manager (Android/Chrome) and syncs across your devices.')}
                </p>
              </div>

              {!isWebAuthnSupported() ? (
                <div className="p-5 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 rounded-xl flex items-start gap-3">
                  <AlertTriangle size={18} className="text-amber-600 shrink-0 mt-0.5" />
                  <p className="text-sm text-amber-800 dark:text-amber-300">{t('mfa.passkeysNotSupported', 'Passkeys are not supported in this browser.')}</p>
                </div>
              ) : (
                <>
                  {!isSecureContext() && (
                    <div className="p-4 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-xl flex items-start gap-3">
                      <AlertTriangle size={16} className="text-amber-600 shrink-0 mt-0.5" />
                      <p className="text-xs text-amber-800 dark:text-amber-300 leading-relaxed"><strong>{t('mfa.noteLabel', 'Note:')}</strong> {t('mfa.passkeyRequiresHttps', 'Passkey registration requires HTTPS or localhost.')}</p>
                    </div>
                  )}
                  <div className="space-y-4">
                    <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('settings.passkeyRegisterName', 'Passkey name')}</label>
                    <input type="text" autoFocus value={passkeyName} onChange={e => setPasskeyName(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter' && !passkeyBusy) handlePasskeyRegister(); }}
                      placeholder="e.g. MacBook Pro"
                      className="w-full px-5 py-3.5 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/20 outline-none transition-all" />
                  </div>
                </>
              )}

              {passkeyError && <p className="text-xs font-bold text-error flex items-center gap-2"><AlertTriangle size={14} />{passkeyError}</p>}

              <div className="flex gap-3">
                <button onClick={closeMfaModal} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.cancel', 'Cancel')}</button>
                <button onClick={handlePasskeyRegister} disabled={passkeyBusy || !isWebAuthnSupported()}
                  className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2 disabled:opacity-50">
                  {passkeyBusy ? <RefreshCw size={16} className="animate-spin" /> : <KeyRound size={16} />}
                  {passkeyBusy ? t('settings.passkeyWaiting', 'Waiting for Touch ID…') : t('settings.createPasskey', 'Create Passkey')}
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
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('settings.passkeyCreatedTitle', 'Passkey created')}</h3>
                <p className="text-on-surface-variant text-sm">{t('settings.passkeyCreatedDesc', '"{{name}}" is saved. You can now use Touch ID or your passkey provider to sign in.', { name: passkeyName })}</p>
              </div>
              <button onClick={closeMfaModal} className="w-full py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all">{t('common.done', 'Done')}</button>
            </div>
          )}
        </>
      )}

      {/* Platform Auth */}
      {mfaModal.type === 'platform' && (
        <>
          {/* Manage existing */}
          {(mfaConfig.platform?.enabled) && mfaModal.step === 1 && (
            <div className="space-y-8">
              <div>
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('settings.platformTitle', 'Touch ID / Windows Hello')}</h3>
                <p className="text-on-surface-variant text-sm leading-relaxed">{t('mfa.platformBiometricDesc', 'Device-bound biometric authenticators registered to this account.')}</p>
              </div>

              <div className="space-y-3">
                {(mfaConfig.platform?.credentials ?? []).map((cred) => (
                  <div key={cred.id} className="flex items-center justify-between p-4 bg-surface-container-low rounded-xl border border-outline-variant/10">
                    <div className="flex items-center gap-3">
                      <Fingerprint size={18} className="text-on-surface-variant" />
                      <div>
                        <p className="font-bold text-sm">{cred.name}</p>
                        <p className="text-[10px] text-on-surface-variant">{t('mfa.addedOn', 'Added {{date}}', { date: new Date(cred.createdAt).toLocaleDateString() })}</p>
                      </div>
                    </div>
                    <button onClick={() => handlePlatformRemove(cred.id)} className="p-2 text-error hover:bg-error/10 rounded-lg transition-colors" title={t('common.remove', 'Remove')}>
                      <Trash2 size={16} />
                    </button>
                  </div>
                ))}
              </div>

              <div className="space-y-3">
                <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('settings.addAnotherDevice', 'Add another device')}</label>
                <div className="flex gap-3">
                  <input type="text" value={platformName} onChange={e => setPlatformName(e.target.value)}
                    placeholder="e.g. MacBook Pro"
                    className="flex-1 px-4 py-3 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-bold text-sm focus:ring-2 focus:ring-black/20 outline-none" />
                  <button onClick={handlePlatformRegister} disabled={platformBusy}
                    className="px-6 py-3 bg-black text-white rounded-xl font-black text-xs uppercase tracking-widest hover:bg-neutral-800 transition-all disabled:opacity-50 flex items-center gap-2">
                    {platformBusy ? <RefreshCw size={14} className="animate-spin" /> : <Fingerprint size={14} />}{t('common.add', 'Add')}
                  </button>
                </div>
                {platformError && <p className="text-xs font-bold text-error flex items-center gap-2"><AlertTriangle size={14} />{platformError}</p>}
              </div>

              <button onClick={closeMfaModal} className="w-full py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.close', 'Close')}</button>
            </div>
          )}

          {/* First-time setup */}
          {!(mfaConfig.platform?.enabled) && mfaModal.step === 1 && (
            <div className="space-y-8">
              <div>
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('mfa.registerBiometricTitle', 'Register Touch ID / Windows Hello')}</h3>
                <p className="text-on-surface-variant text-sm leading-relaxed">
                  {t('mfa.biometricRegisterDesc', 'This registers a device-bound biometric credential.')}
                </p>
              </div>

              {!isWebAuthnSupported() ? (
                <div className="p-5 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 rounded-xl flex items-start gap-3">
                  <AlertTriangle size={18} className="text-amber-600 shrink-0 mt-0.5" />
                  <p className="text-sm text-amber-800 dark:text-amber-300">{t('mfa.biometricNotSupported', 'Platform biometrics are not supported in this browser.')}</p>
                </div>
              ) : (
                <>
                  {!isSecureContext() && (
                    <div className="p-4 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-xl flex items-start gap-3">
                      <AlertTriangle size={16} className="text-amber-600 shrink-0 mt-0.5" />
                      <p className="text-xs text-amber-800 dark:text-amber-300 leading-relaxed"><strong>{t('mfa.noteLabel', 'Note:')}</strong> {t('mfa.biometricRequiresHttps', 'Biometric registration requires HTTPS or localhost.')}</p>
                    </div>
                  )}
                  <div className="space-y-4">
                    <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('settings.platformRegisterName', 'Device name')}</label>
                    <input type="text" autoFocus value={platformName} onChange={e => setPlatformName(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter' && !platformBusy) handlePlatformRegister(); }}
                      placeholder="e.g. MacBook Pro"
                      className="w-full px-5 py-3.5 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/20 outline-none transition-all" />
                  </div>
                </>
              )}

              {platformError && <p className="text-xs font-bold text-error flex items-center gap-2"><AlertTriangle size={14} />{platformError}</p>}

              <div className="flex gap-3">
                <button onClick={closeMfaModal} className="flex-1 py-4 bg-surface-container-low text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-surface-container-high transition-all">{t('common.cancel', 'Cancel')}</button>
                <button onClick={handlePlatformRegister} disabled={platformBusy || !isWebAuthnSupported()}
                  className="flex-1 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all flex items-center justify-center gap-2 disabled:opacity-50">
                  {platformBusy ? <RefreshCw size={16} className="animate-spin" /> : <Fingerprint size={16} />}
                  {platformBusy ? t('settings.biometricWaiting', 'Waiting for biometric…') : t('settings.registerBiometric', 'Register Biometric')}
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
                <h3 className="text-2xl font-headline font-black text-black dark:text-white mb-2">{t('settings.biometricCreatedTitle', 'Biometric registered')}</h3>
                <p className="text-on-surface-variant text-sm">{t('settings.biometricCreatedDesc', '"{{name}}" can now be used to sign in on this device.', { name: platformName })}</p>
              </div>
              <button onClick={closeMfaModal} className="w-full py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-lg hover:bg-neutral-800 transition-all">{t('common.done', 'Done')}</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
