import React, { useEffect, useState } from 'react';
import {
  X,
  Share2,
  Clock,
  Trash2,
  Globe,
  Loader2,
  AlertTriangle,
  Link,
  Check
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { useAuditLog } from './hooks/useAuditLog';
import { apiFetch } from '../../utils/api';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export default function SharesModal({ isOpen, onClose }: Props) {
  const { t } = useTranslation();
  const [confirmingRevokeAll, setConfirmingRevokeAll] = useState(false);
  const {
    shares,
    sharesLoading,
    refreshShares,
    setShares
  } = useAuditLog();

  useEffect(() => {
    if (isOpen) refreshShares();
    else setConfirmingRevokeAll(false);
  }, [isOpen]);

  const handleRevoke = async (id: string) => {
    try {
      await apiFetch(`/api/vault/shares/${id}`, { method: 'DELETE' });
      setShares(prev => prev.filter(s => s.id !== id));
    } catch {
      // ignore
    }
  };

  const handleRevokeAll = async () => {
    if (!confirmingRevokeAll) { setConfirmingRevokeAll(true); return; }
    setConfirmingRevokeAll(false);
    try {
      await Promise.all(shares.map(s => apiFetch(`/api/vault/shares/${s.id}`, { method: 'DELETE' })));
      setShares([]);
    } catch {
      // ignore
    }
  };

  function formatExpiry(expiresAt: number) {
    const diff = expiresAt - Date.now();
    if (diff <= 0) return t('settings.shareExpired', 'Expired');
    const h = Math.floor(diff / 3600000);
    if (h < 24) return t('shares.hoursRemaining', '{{h}}h remaining', { h });
    return t('shares.daysRemaining', '{{d}}d remaining', { d: Math.floor(h / 24) });
  }

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      <motion.div 
        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />
      <motion.div 
        initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95, y: 20 }}
        className="relative w-full max-w-2xl bg-white dark:bg-[#1a1a1a] rounded-3xl shadow-2xl overflow-hidden border border-slate-200 dark:border-white/10 flex flex-col max-h-[80vh]"
      >
        <div className="p-8 border-b border-slate-100 dark:border-white/5 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-2xl bg-blue-600/10 flex items-center justify-center">
              <Share2 className="text-blue-600" />
            </div>
            <div>
              <h3 className="text-2xl font-bold text-slate-900 dark:text-white">{t('settings.shareLinks', 'Shared Links')}</h3>
              <p className="text-sm text-slate-500">{t('settings.shareLinksDesc', 'Manage and revoke your active credential shares.')}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-slate-100 dark:hover:bg-white/5 rounded-full transition-colors">
            <X size={20} className="text-slate-500" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-8 custom-scrollbar">
          {sharesLoading ? (
            <div className="py-20 flex justify-center"><Loader2 className="animate-spin text-blue-600" /></div>
          ) : shares.length === 0 ? (
            <div className="text-center py-20">
              <div className="w-16 h-16 rounded-full bg-slate-50 dark:bg-white/5 flex items-center justify-center mx-auto mb-4">
                <Link size={24} className="text-slate-300" />
              </div>
              <p className="text-slate-500 font-bold">{t('settings.noActiveShares', 'No active share links')}</p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-xs font-black uppercase tracking-widest text-slate-400">{t('shares.activeLinkCount', '{{count}} active link(s)', { count: shares.length })}</h4>
                <button
                  onClick={handleRevokeAll}
                  className={`text-xs font-bold transition-colors ${confirmingRevokeAll ? 'text-red-700 underline' : 'text-red-600 hover:underline'}`}
                >
                  {confirmingRevokeAll
                    ? t('settings.revokeAllSharesConfirm', 'Confirm — revoke all?')
                    : t('settings.revokeAll', 'Revoke all')}
                </button>
              </div>
              <div className="grid gap-3">
                {shares.map(s => (
                  <div key={s.id} className="p-5 bg-slate-50 dark:bg-white/[0.03] rounded-2xl border border-slate-100 dark:border-white/5 flex items-center justify-between group">
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 rounded-xl bg-white dark:bg-white/5 shadow-sm flex items-center justify-center">
                        <Share2 size={18} className="text-slate-600" />
                      </div>
                      <div>
                        <p className="font-bold text-sm text-slate-900 dark:text-white">{s.label || t('shares.sharedCredential', 'Shared Credential')}</p>
                        <div className="flex items-center gap-3 mt-0.5">
                           <span className="flex items-center gap-1 text-[10px] text-slate-500">
                             <Clock size={12} /> {formatExpiry(s.expiresAt)}
                           </span>
                           <span className="flex items-center gap-1 text-[10px] text-slate-500">
                             <Globe size={12} /> {s.viewCount} {t('shares.views', 'views')}
                           </span>
                           {s.viewed && <span className="text-[10px] px-2 py-0.5 bg-green-500/15 text-green-600 rounded font-bold">{t('shares.viewed', 'Viewed')}</span>}
                        </div>
                      </div>
                    </div>
                    <button onClick={() => handleRevoke(s.id)} className="p-2 text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20 rounded-lg transition-all opacity-0 group-hover:opacity-100">
                      <Trash2 size={16} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="p-8 border-t border-slate-100 dark:border-white/5 bg-slate-50/50 dark:bg-white/[0.01]">
           <button onClick={onClose} className="w-full py-4 bg-black dark:bg-white dark:text-black text-white rounded-xl font-bold text-sm hover:opacity-90 transition-all">
             {t('common.done', 'Done')}
           </button>
        </div>
      </motion.div>
    </div>
  );
}
