import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { Check, Trash2, Folder, ShieldCheck, Clock, ShieldAlert, TimerReset } from 'lucide-react';
import { useNotification } from '../context/NotificationContext';

interface NotificationDropdownProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function NotificationDropdown({ isOpen, onClose }: NotificationDropdownProps) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { notifications, unreadCount, markAsRead, markAllAsRead, clearNotifications } = useNotification();

  const getTimeAgo = (timestamp: number) => {
    const diff = Date.now() - timestamp;
    const mins  = Math.floor(diff / 60_000);
    const hours = Math.floor(diff / 3_600_000);
    const days  = Math.floor(diff / 86_400_000);
    const weeks = Math.floor(diff / 604_800_000);
    if (mins  < 1)  return t('notifications.justNow',  'Just now');
    if (mins  < 60) return t('notifications.minsAgo',  '{{n}}m ago',   { n: mins });
    if (hours < 24) return t('notifications.hoursAgo', '{{n}}h ago',   { n: hours });
    if (days  < 7)  return t('notifications.daysAgo',  '{{n}} day{{s}} ago', { n: days,  s: days  === 1 ? '' : 's' });
    return              t('notifications.weeksAgo', '{{n}} week{{s}} ago', { n: weeks, s: weeks === 1 ? '' : 's' });
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
                  {notifications.slice(0, 8).map((n) => (
                    <div
                      key={n.id}
                      onClick={() => { markAsRead(n.id); onClose(); }}
                      className={`p-4 hover:bg-surface-container-low transition-colors cursor-pointer relative group ${!n.read ? 'bg-surface-container-low/50' : ''}`}
                    >
                      <div className="flex gap-3">
                        <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${
                          n.type === 'folder_created'     ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 border border-blue-100 dark:border-blue-800' :
                          n.type === 'credential_added'   ? 'bg-green-50 dark:bg-green-900/20 text-green-600 dark:text-green-400 border border-green-100 dark:border-green-800' :
                          n.type === 'credential_expiring'? 'bg-orange-50 dark:bg-orange-900/20 text-orange-500 dark:text-orange-400 border border-orange-100 dark:border-orange-800' :
                          'bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 border border-red-100 dark:border-red-800'
                        }`}>
                          {n.type === 'folder_created'      ? <Folder size={18} strokeWidth={2.5} /> :
                           n.type === 'credential_added'    ? <ShieldCheck size={18} strokeWidth={2.5} /> :
                           n.type === 'credential_expiring' ? <TimerReset size={18} strokeWidth={2.5} /> :
                           <ShieldAlert size={18} strokeWidth={2.5} />}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-black text-black dark:text-white truncate">{n.title}</p>
                          <p className="text-[11px] text-on-surface-variant font-medium mt-0.5 line-clamp-2 leading-relaxed">
                            {n.message}
                          </p>
                          <div className="flex items-center gap-2 mt-2">
                            <div className="flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-on-surface-variant/40">
                              <Clock size={10} />
                              {getTimeAgo(n.timestamp)}
                            </div>
                            {n.type === 'credential_expiring' && n.data?.credentialId && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  markAsRead(n.id);
                                  onClose();
                                  const folder = n.data.folderId && n.data.folderId !== 'vault'
                                    ? `/vault/${n.data.folderId}`
                                    : '/vault';
                                  navigate(folder, { state: { editCredentialId: n.data.credentialId } });
                                }}
                                className="ml-auto text-[9px] font-black uppercase tracking-widest px-2.5 py-1 rounded-lg bg-orange-500 hover:bg-orange-600 text-white transition-colors shrink-0"
                              >
                                {t('notifications.update', 'Update')}
                              </button>
                            )}
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
                  <p className="text-xs font-bold text-on-surface-variant text-center">
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
