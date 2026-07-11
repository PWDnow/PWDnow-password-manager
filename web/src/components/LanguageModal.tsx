import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { X, Globe } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { SUPPORTED_LANGUAGES } from '../i18n';

interface LanguageModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function LanguageModal({ isOpen, onClose }: LanguageModalProps) {
  const { t, i18n } = useTranslation();

  const handleSelect = (code: string) => {
    i18n.changeLanguage(code);
    onClose();
  };

  const activeLang = i18n.resolvedLanguage ?? i18n.language;

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-[#000000]/40 backdrop-blur-sm z-50"
          />
          <div className="fixed inset-0 flex items-center justify-center p-4 z-50 pointer-events-none">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="bg-surface w-full max-w-md rounded-3xl shadow-2xl overflow-hidden pointer-events-auto"
            >
              <div className="p-6 border-b border-outline-variant/10 flex justify-between items-center bg-surface-container-lowest">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-primary-container flex items-center justify-center">
                    <Globe size={20} className="text-on-primary-container" />
                  </div>
                  <h2 className="text-xl font-headline font-black tracking-tight">{t('language.title', 'Select Language')}</h2>
                </div>
                <button aria-label="Close"
                  onClick={onClose}
                  className="p-2 hover:bg-surface-container-high rounded-full transition-colors"
                >
  <X aria-hidden="true" size={20} />
</button>
              </div>

              <div className="p-6 space-y-2 max-h-[60vh] overflow-y-auto">
                {SUPPORTED_LANGUAGES.map((lang) => (
                  <button
                    key={lang.code}
                    onClick={() => handleSelect(lang.code)}
                    className={`w-full flex items-center justify-between p-4 rounded-xl transition-all ${
                      activeLang === lang.code
                        ? 'bg-black dark:bg-white text-white dark:text-black'
                        : 'bg-surface-container-low hover:bg-surface-container-high text-black dark:text-white'
                    }`}
                  >
                    <span className="font-bold">{lang.nativeName}</span>
                    <span className={`text-xs uppercase tracking-widest font-black ${
                      activeLang === lang.code ? 'text-white/70 dark:text-black/70' : 'text-on-surface-variant'
                    }`}>
                      {lang.name}
                    </span>
                  </button>
                ))}
              </div>
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  );
}
