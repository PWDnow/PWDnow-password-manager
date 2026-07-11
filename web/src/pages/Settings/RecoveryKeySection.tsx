import React from 'react';
import { RefreshCw, Download, ShieldCheck, AlertTriangle } from 'lucide-react';

const FbKey = ({ size = 20, className = '' }: { size?: number; className?: string }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <circle cx="7.5" cy="15.5" r="5.5"/>
    <path d="m21 2-9.6 9.6"/>
    <path d="m15.5 7.5 3 3L22 7l-3-3"/>
  </svg>
);
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { Eye, EyeOff, Lock } from 'lucide-react';
import type { UserProfile } from '../../context/UserContext';

interface Props {
  profile: UserProfile;
  setIsRecoveryModalOpen: (v: boolean) => void;
  isGeneratingRecovery: boolean;
  handleGenerateRecovery: () => void;
  recoveryAuthPassword: string;
  setRecoveryAuthPassword: (v: string) => void;
  recoveryAuthError: string;
}

export default function RecoveryKeySection({ 
  profile, setIsRecoveryModalOpen, isGeneratingRecovery, handleGenerateRecovery,
  recoveryAuthPassword, setRecoveryAuthPassword, recoveryAuthError
}: Props) {
  const { t } = useTranslation();
  const [showPw, setShowPw] = React.useState(false);
  const [isVerifying, setIsVerifying] = React.useState(false);

  return (
    <section>
      <div className="mb-6">
        <h2 className="text-[15px] font-semibold text-neutral-900 dark:text-white leading-snug">{t('settings.recoveryKey', 'Emergency Recovery')}</h2>
        <p className="mt-1 text-[13px] text-neutral-600 dark:text-neutral-300">{t('settings.recoveryKeySubtitle', 'Generate a recovery key for offline vault access.')}</p>
        <div className="mt-4 h-px bg-neutral-200 dark:bg-white/8" />
      </div>
      <div className="bg-surface-container-low p-10 rounded-xl">
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-10">
          <div className="flex-1">
            <h3 className="font-bold text-xl mb-4">{t('settings.recoveryKeyTitle', 'Vault Recovery Key')}</h3>
            <p className="text-sm text-on-surface-variant leading-relaxed mb-8">
              {t('settings.recoveryKeyDesc', 'A recovery key allows you to regain access to your vault if you lose your password and MFA devices. Keep it offline in a secure location.')}
            </p>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-start">
              {profile.recoveryKeyGeneratedAt ? (
                <div className="flex items-center gap-4 p-5 bg-green-50 dark:bg-green-950/20 border border-green-100 dark:border-green-800/30 rounded-2xl">
                  <div className="w-10 h-10 rounded-xl bg-green-600 flex items-center justify-center shrink-0 shadow-lg shadow-green-900/20">
                    <ShieldCheck className="text-white" size={20} />
                  </div>
                  <div>
                    <p className="text-sm font-bold text-green-800 dark:text-green-300">{t('settings.keyActive', 'Recovery Key Active')}</p>
                    <p className="text-[10px] text-green-700/70 dark:text-green-400/70 font-bold uppercase tracking-widest mt-0.5">
                      {t('settings.lastGenerated', 'Last generated {{date}}', { date: new Date(profile.recoveryKeyGeneratedAt).toLocaleDateString() })}
                    </p>
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-4 p-5 bg-amber-50 dark:bg-amber-950/20 border border-amber-100 dark:border-amber-800/30 rounded-2xl">
                  <div className="w-10 h-10 rounded-xl bg-amber-500 flex items-center justify-center shrink-0 shadow-lg shadow-amber-900/20">
                    <AlertTriangle className="text-white" size={20} />
                  </div>
                  <div>
                    <p className="text-sm font-bold text-amber-900 dark:text-amber-200">{t('settings.noKey', 'No Recovery Key')}</p>
                    <p className="text-[10px] text-amber-900 dark:text-amber-200 font-bold uppercase tracking-widest mt-0.5">
                      {t('settings.keyWarning', 'Highly recommended for account safety')}
                    </p>
                  </div>
                </div>
              )}

              {isVerifying ? (
                <div className="space-y-3">
                  <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant px-1">{t('settings.verifyToGenerate', 'Enter Master Password to confirm')}</label>
                  <div className="relative">
                    <input
                      type={showPw ? 'text' : 'password'}
                      autoFocus
                      value={recoveryAuthPassword}
                      onChange={e => setRecoveryAuthPassword(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && handleGenerateRecovery()}
                      placeholder="••••••••••••"
                      className="w-full pl-11 pr-12 py-3.5 bg-surface-container-high rounded-xl border-2 border-outline-variant/20 text-sm font-bold focus:ring-2 focus:ring-black/10 dark:focus:ring-white/10 outline-none transition-all"
                    />
                    <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-on-surface-variant" />
                    <button type="button" onClick={() => setShowPw(!showPw)} className="absolute right-4 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-black dark:hover:text-white transition-colors">
                      {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                  {recoveryAuthError && <p className="text-[11px] font-bold text-red-600 px-1">{recoveryAuthError}</p>}
                  <div className="flex gap-2 pt-1">
                    <button
                      onClick={handleGenerateRecovery}
                      disabled={isGeneratingRecovery || !recoveryAuthPassword}
                      className="flex-1 py-3 bg-black dark:bg-white text-white dark:text-black rounded-xl font-bold text-xs hover:opacity-90 transition-all flex items-center justify-center gap-2 disabled:opacity-50 shadow-lg shadow-black/10 dark:shadow-white/10"
                    >
                      {isGeneratingRecovery ? <RefreshCw size={14} className="animate-spin" /> : <ShieldCheck size={14} />}
                      {t('settings.confirmAndGenerate', 'Confirm & Generate')}
                    </button>
                    <button onClick={() => setIsVerifying(false)} className="px-4 py-3 bg-surface-container-highest rounded-xl font-bold text-xs hover:bg-outline-variant/10 transition-all">
                      {t('common.cancel', 'Cancel')}
                    </button>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col gap-3">
                  <button
                    onClick={() => setIsVerifying(true)}
                    className="px-8 py-4 bg-black dark:bg-white text-white dark:text-black rounded-xl font-bold text-sm hover:opacity-90 transition-all flex items-center justify-center gap-3 shadow-lg shadow-black/10 dark:shadow-white/10"
                  >
                    <RefreshCw size={18} />
                    {profile.recoveryKeyGeneratedAt ? t('settings.rotateKey', 'Rotate Recovery Key') : t('settings.generateKey', 'Generate Recovery Key')}
                  </button>
                  {profile.recoveryKeyGeneratedAt && (
                    <button
                      onClick={() => setIsRecoveryModalOpen(true)}
                      className="px-8 py-4 bg-surface-container-high hover:bg-surface-container-highest text-black dark:text-white rounded-xl font-bold text-sm transition-all flex items-center justify-center gap-3 border border-outline-variant/10"
                    >
                      <Download size={18} />
                      {t('settings.viewAndDownload', 'View & Download')}
                    </button>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
