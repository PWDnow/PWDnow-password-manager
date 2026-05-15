import React, { useEffect, useState } from 'react';
import { Download, X } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';

const DISMISSED_KEY = 'pwa_install_dismissed';

export default function InstallPrompt() {
  const { t } = useTranslation();
  const [prompt, setPrompt] = useState<any>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    // Already installed as PWA
    if (window.matchMedia('(display-mode: standalone)').matches) return;
    // Previously dismissed
    if (localStorage.getItem(DISMISSED_KEY)) return;

    const handler = (e: Event) => {
      e.preventDefault();
      setPrompt(e);
      setVisible(true);
    };
    window.addEventListener('beforeinstallprompt', handler);
    return () => window.removeEventListener('beforeinstallprompt', handler);
  }, []);

  function dismiss() {
    localStorage.setItem(DISMISSED_KEY, '1');
    setVisible(false);
  }

  async function install() {
    if (!prompt) return;
    prompt.prompt();
    const { outcome } = await prompt.userChoice;
    if (outcome === 'accepted') setVisible(false);
  }

  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          initial={{ opacity: 0, y: 80 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 80 }}
          className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 w-full max-w-sm mx-4"
        >
          <div className="bg-surface-container-low border border-outline-variant/20 rounded-2xl shadow-2xl p-5 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-black flex items-center justify-center shrink-0">
              <Download size={18} className="text-white" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="font-bold text-sm text-black dark:text-white">{t('pwa.installTitle', 'Install PWDnow')}</p>
              <p className="text-xs text-on-surface-variant mt-0.5">{t('pwa.installDesc', 'Add to home screen for offline access')}</p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={install}
                className="px-4 py-2 bg-black text-white rounded-xl text-xs font-black uppercase tracking-widest hover:bg-neutral-800 transition-colors"
              >
                {t('pwa.install', 'Install')}
              </button>
              <button
                onClick={dismiss}
                className="p-2 hover:bg-surface-container-high rounded-full transition-colors"
                aria-label={t('common.close', 'Close')}
              >
                <X size={16} className="text-on-surface-variant" />
              </button>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
