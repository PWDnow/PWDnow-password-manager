import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { Check, Trash2, Folder, ShieldCheck, Clock, ShieldAlert } from 'lucide-react';
import { useNotification } from '../context/NotificationContext';

interface NotificationDropdownProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function NotificationDropdown({ isOpen, onClose }: NotificationDropdownProps) {
  const { t } = useTranslation();
  const { notifications, unreadCount, markAsRead, markAllAsRead, clearNotifications } = useNotification();

  const getTimeAgo = (timestamp: number) => {
    const minutes = Math.floor((Date.now() - timestamp) / 60000);
    if (minutes < 1) return 'Just now';
    return t('notifications.timeAgo', { count: minutes, defaultValue: `${minutes}m ago` });
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0, y: 10, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 10, scale: 0.95 }}
          className="fixed sm:absolute top-16 sm:top-auto right-4 sm:right-0 sm:mt-3 w-[calc(100vw-32px)] sm:w-80 max-w-sm bg-surface rounded-[2rem] shadow-[0_20px_60px_-15px_rgba(0,0,0,0.3)] border border-outline-variant/10 z-50 overflow-hidden ring-1 ring-black/5"
        >
          <div className="p-4 border-b border-outline-variant/5 bg-surface-container-low/30 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-black uppercase tracking-widest text-black dark:text-white">{t('notifications.title', 'Notifications')}</h3>
                {unreadCount > 0 && (
                  <span className="bg-error text-white text-[10px] font-black px-1.5 py-0.5 rounded-full">
                    {unreadCount}
                  </span>
                )}
              </div>
              <div className="flex gap-2">
                <button 
                  onClick={markAllAsRead}
                  className="p-2 hover:bg-surface-container-high rounded-xl transition-colors text-on-surface-variant hover:text-black dark:hover:text-white"
                  title={t('notifications.markAllRead', 'Mark all as read')}
                >
                  <Check size={16} />
                </button>
                <button 
                  onClick={clearNotifications}
                  className="p-2 hover:bg-surface-container-high rounded-xl transition-colors text-on-surface-variant hover:text-red-600"
                  title={t('notifications.clearAll', 'Clear all')}
                >
                  <Trash2 size={16} />
                </button>
              </div>
            </div>

            <div className="max-h-[400px] overflow-y-auto no-scrollbar">
              {notifications.length > 0 ? (
                <div className="divide-y divide-outline-variant/5">
                  {notifications.slice(0, 4).map((n) => (
                    <div 
                      key={n.id}
                      onClick={() => {
                        markAsRead(n.id);
                        onClose();
                      }}
                      className={`p-4 hover:bg-surface-container-low transition-colors cursor-pointer relative group ${!n.read ? 'bg-surface-container-low/50' : ''}`}
                    >
                      <div className="flex gap-3">
                        <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${
                          n.type === 'folder_created' ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 border border-blue-100 dark:border-blue-800' : 
                          n.type === 'credential_added' ? 'bg-green-50 dark:bg-green-900/20 text-green-600 dark:text-green-400 border border-green-100 dark:border-green-800' :
                          'bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 border border-red-100 dark:border-red-800'
                        }`}>
                          {n.type === 'folder_created' ? <Folder size={18} strokeWidth={2.5} /> : 
                           n.type === 'credential_added' ? <ShieldCheck size={18} strokeWidth={2.5} /> :
                           <ShieldAlert size={18} strokeWidth={2.5} />}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-black text-black dark:text-white truncate">{n.title}</p>
                          <p className="text-[11px] text-on-surface-variant font-medium mt-0.5 line-clamp-2 leading-relaxed">
                            {n.message}
                          </p>
                          <div className="flex items-center gap-1.5 mt-2 text-[9px] font-black uppercase tracking-widest text-on-surface-variant/40">
                            <Clock size={10} />
                            {getTimeAgo(n.timestamp)}
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-12 text-center">
                  <div className="w-12 h-12 bg-surface-container-low rounded-2xl flex items-center justify-center mx-auto mb-4 text-on-surface-variant/20">
                    <ShieldCheck size={24} />
                  </div>
                  <p className="text-xs font-bold text-on-surface-variant">
                    {t('notifications.empty', 'No new notifications')}
                  </p>
                </div>
              )}
            </div>
          </motion.div>
      )}
    </AnimatePresence>
  );
}
