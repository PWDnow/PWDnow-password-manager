import React, { useState, useEffect } from 'react';
import { WifiOff } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';

export default function NetworkStatus() {
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const { t } = useTranslation();

  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  return (
    <AnimatePresence>
      {!isOnline && (
        <motion.div
          initial={{ y: -100, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: -100, opacity: 0 }}
          transition={{ type: 'spring', stiffness: 300, damping: 30 }}
          className="fixed top-0 left-0 w-full z-[9999] bg-error text-white px-4 py-3 shadow-lg flex items-center justify-center gap-3"
          role="alert"
          aria-live="assertive"
        >
          <WifiOff size={20} className="shrink-0" />
          <span className="font-headline font-semibold text-sm sm:text-base tracking-tight">
            {t('common.offline', 'Internet connection lost. Please check your network.')}
          </span>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
