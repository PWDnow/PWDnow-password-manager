import React, { useState } from 'react';
import { X, Lock, Loader2, ShieldCheck } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (password: string) => void;
  title: string;
  message: string;
  loading?: boolean;
}

export default function PasswordPromptModal({ isOpen, onClose, onConfirm, title, message, loading }: Props) {
  const { t } = useTranslation();
  const [password, setPassword] = useState('');

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          className="bg-white dark:bg-[#1a1a1a] w-full max-w-md rounded-2xl shadow-2xl overflow-hidden border border-slate-200 dark:border-white/10"
        >
          <div className="p-6">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-blue-600/10 flex items-center justify-center">
                  <Lock size={20} className="text-blue-600" />
                </div>
                <h2 className="text-xl font-bold text-slate-900 dark:text-white">{title}</h2>
              </div>
              <button aria-label="Close" onClick={onClose} className="p-2 hover:bg-slate-100 dark:hover:bg-white/5 rounded-lg transition-colors">
  <X aria-hidden="true" size={20} className="text-slate-500" />
</button>
            </div>

            <p className="text-slate-600 dark:text-slate-300 text-sm mb-6 leading-relaxed">
              {message}
            </p>

            <form onSubmit={(e) => { e.preventDefault(); onConfirm(password); }} className="space-y-6">
              <div>
                <label htmlFor="input-jfy6bo31a" className="block text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-300 mb-2">
                  {t('settings.masterPassword', 'Master Password')}
                </label>
<input id="input-jfy6bo31a"
                  type="password"
                  autoFocus
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-4 py-3 rounded-xl border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#141414] text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-600 outline-none transition-all"
                  placeholder="••••••••"
                />
              </div>

              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={onClose}
                  className="flex-1 px-4 py-3 rounded-xl font-bold text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-white/5 transition-colors"
                >
                  {t('common.cancel', 'Cancel')}
                </button>
                <button
                  type="submit"
                  disabled={!password || loading}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white py-3 rounded-xl font-bold transition-all flex items-center justify-center gap-2"
                >
                  {loading ? <Loader2 size={18} className="animate-spin" /> : <ShieldCheck size={18} />}
                  {t('common.confirm', 'Confirm')}
                </button>
              </div>
            </form>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
