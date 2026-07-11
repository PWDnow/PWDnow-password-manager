import React, { useState } from 'react';
import { motion } from 'motion/react';
import { X, Copy, Download, CheckCircle, Shield, AlertTriangle } from 'lucide-react';
import { useTranslation } from 'react-i18next';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  recoveryKey: string;
}

export default function RecoveryKeyModal({ isOpen, onClose, recoveryKey }: Props) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(recoveryKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([`PWDnow Vault Recovery Key\nGenerated: ${new Date().toLocaleString()}\n\nKey: ${recoveryKey}\n\nKeep this file in a secure, offline location.`], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pwdnow-recovery-key-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        className="absolute inset-0 bg-[#000000]/60 backdrop-blur-sm"
        onClick={onClose}
      />
      <motion.div initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95, y: 20 }}
        className="relative w-full max-w-xl bg-white dark:bg-surface-container-low rounded-[32px] shadow-2xl border border-outline-variant/10 overflow-hidden"
      >
        <div className="flex items-center justify-between p-8 border-b border-outline-variant/10 bg-slate-50 dark:bg-black/20">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-2xl bg-yellow-500 text-white flex items-center justify-center shadow-lg shadow-yellow-500/20">
              <Shield size={24} />
            </div>
            <div>
              <h3 className="text-xl font-headline font-black text-black dark:text-white">{t('settings.recoveryKeyTitle', 'Your Recovery Key')}</h3>
              <p className="text-sm text-on-surface-variant mt-0.5">{t('settings.recoveryKeySubtitle', 'Generated and encrypted successfully')}</p>
            </div>
          </div>
          <button aria-label="Close" onClick={onClose} className="p-2 hover:bg-surface-container-high rounded-full transition-colors">
  <X aria-hidden="true" size={24} />
</button>
        </div>

        <div className="p-8 space-y-8">
          <div className="p-6 bg-amber-50 dark:bg-amber-950/20 border-2 border-dashed border-amber-200 dark:border-amber-800/30 rounded-3xl flex items-start gap-4">
            <AlertTriangle className="text-amber-600 dark:text-amber-400 shrink-0 mt-1" size={20} />
            <div>
              <p className="text-sm font-bold text-amber-900 dark:text-amber-100 mb-1">
                {t('settings.recoveryWarning', 'Important: This is the only time you will see this key.')}
              </p>
              <p className="text-xs text-amber-800/70 dark:text-amber-400/70 leading-relaxed font-medium">
                {t('settings.recoveryWarningDesc', 'If you lose this key and your password, your vault data will be permanently inaccessible. We recommend printing it or saving it to a secure offline drive.')}
              </p>
            </div>
          </div>

          <div className="space-y-3">
            <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant px-1">{t('settings.recoveryKeyLabel', 'Recovery Key')}</label>
            <div className="relative group">
              <div className="w-full px-6 py-8 bg-surface-container-high rounded-[24px] border-2 border-outline-variant/20 font-mono text-xl sm:text-2xl font-black text-center tracking-wider text-black dark:text-white shadow-inner">
                {recoveryKey}
              </div>
              <button 
                onClick={handleCopy}
                className="absolute right-4 top-4 p-3 bg-white dark:bg-black border border-outline-variant/20 rounded-xl shadow-sm hover:scale-105 transition-transform active:scale-95"
              >
                {copied ? <CheckCircle size={18} className="text-green-500" /> : <Copy size={18} />}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <button
              onClick={handleDownload}
              className="flex items-center justify-center gap-3 py-4 bg-surface-container-high hover:bg-surface-container-highest text-black dark:text-white rounded-2xl font-bold text-sm transition-all border border-outline-variant/10 shadow-sm"
            >
              <Download size={18} />
              {t('settings.downloadAsTxt', 'Download .txt')}
            </button>
            <button
              onClick={() => window.print()}
              className="flex items-center justify-center gap-3 py-4 bg-surface-container-high hover:bg-surface-container-highest text-black dark:text-white rounded-2xl font-bold text-sm transition-all border border-outline-variant/10 shadow-sm"
            >
              <Copy size={18} />
              {t('settings.printKey', 'Print Key')}
            </button>
          </div>
        </div>

        <div className="p-8 pt-0">
          <button 
            onClick={onClose}
            className="w-full py-4 bg-black dark:bg-white text-white dark:text-black rounded-2xl font-black uppercase tracking-widest text-xs hover:opacity-90 transition-all shadow-lg"
          >
            {t('settings.iHaveSavedKey', 'I have saved my recovery key')}
          </button>
        </div>
      </motion.div>
    </div>
  );
}
