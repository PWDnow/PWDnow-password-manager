import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Sun, Moon, Globe } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import LanguageModal from './LanguageModal';

export default function PublicHeader() {
  const { i18n } = useTranslation();
  const { theme, setTheme, isDark } = useTheme();
  const [isLanguageModalOpen, setIsLanguageModalOpen] = useState(false);

  const toggleTheme = () => {
    setTheme(isDark ? 'light' : 'dark');
  };

  return (
    <>
      <div className="absolute top-0 right-0 p-6 z-50 flex items-center gap-3">
        <button
          onClick={toggleTheme}
          className="p-2.5 bg-white/80 dark:bg-black/80 hover:bg-white dark:hover:bg-black backdrop-blur-md border border-black/10 dark:border-white/10 rounded-full transition-all text-black dark:text-white shadow-sm"
          aria-label="Toggle Theme"
        >
          {isDark ? <Sun size={18} /> : <Moon size={18} />}
        </button>

        <button
          onClick={() => setIsLanguageModalOpen(true)}
          className="flex items-center gap-2 px-4 py-2.5 bg-white/80 dark:bg-black/80 hover:bg-white dark:hover:bg-black backdrop-blur-md border border-black/10 dark:border-white/10 rounded-full transition-all text-xs font-bold uppercase tracking-wider text-black dark:text-white shadow-sm"
        >
          <Globe size={16} />
          <span>{i18n.language === 'fr' ? 'FR' : 'EN'}</span>
        </button>
      </div>

      <LanguageModal 
        isOpen={isLanguageModalOpen} 
        onClose={() => setIsLanguageModalOpen(false)} 
      />
    </>
  );
}
