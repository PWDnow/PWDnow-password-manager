import React, { useEffect } from 'react';
import { 
  X, 
  History, 
  Monitor, 
  LogOut, 
  ShieldAlert, 
  RefreshCw, 
  CheckCircle, 
  Trash2, 
  Globe,
  Loader2
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { useAuditLog } from './hooks/useAuditLog';
import { formatSessionTime } from '../../utils/sessionTracker';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export default function AuditLogModal({ isOpen, onClose }: Props) {
  const { t } = useTranslation();
  const {
    auditTab,
    setAuditTab,
    auditEvents,
    auditEventsTotal,
    auditEventsLoading,
    sessions,
    sessionsLoading,
    isRevoking,
    revokeSuccess,
    refreshSessions,
    refreshAuditEvents,
    handleRevokeAll
  } = useAuditLog();

  useEffect(() => {
    if (isOpen) {
      if (auditTab === 'sessions') refreshSessions();
      else refreshAuditEvents();
    }
  }, [isOpen, auditTab]);

  if (!isOpen) return null;

  const getActionInfo = (action: string) => {
    switch (action) {
      case 'login': return { icon: <CheckCircle className="text-green-500" size={16} />, label: t('audit.actionLogin', 'Login') };
      case 'login_failed': return { icon: <ShieldAlert className="text-red-500" size={16} />, label: t('audit.actionLoginFailed', 'Login Failed') };
      case 'logout': return { icon: <LogOut className="text-slate-400" size={16} />, label: t('audit.actionLogout', 'Logout') };
      case 'password_changed': return { icon: <RefreshCw className="text-blue-500" size={16} />, label: t('audit.actionPasswordChanged', 'Password Changed') };
      case 'mfa_changed': return { icon: <ShieldAlert className="text-blue-500" size={16} />, label: t('audit.actionMfaChanged', 'MFA Settings Changed') };
      case 'share_created': return { icon: <Globe className="text-indigo-500" size={16} />, label: t('audit.actionShareCreated', 'Secure Share Created') };
      case 'share_revoked': return { icon: <Trash2 className="text-slate-500" size={16} />, label: t('audit.actionShareRevoked', 'Secure Share Revoked') };
      case 'duress_wipe_triggered': return { icon: <ShieldAlert className="text-red-600" size={16} />, label: t('audit.actionDuressWipe', 'Duress Wipe Triggered') };
      default: return { icon: <History className="text-slate-400" size={16} />, label: action };
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      <motion.div 
        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />
      <motion.div 
        initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95, y: 20 }}
        className="relative w-full max-w-4xl bg-white dark:bg-[#1a1a1a] rounded-3xl shadow-2xl overflow-hidden border border-slate-200 dark:border-white/10 flex flex-col max-h-[80vh]"
      >
        <div className="p-8 border-b border-slate-100 dark:border-white/5 flex items-center justify-between bg-white/50 dark:bg-white/[0.02] backdrop-blur-md">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-2xl bg-blue-600/10 flex items-center justify-center">
              <History className="text-blue-600" />
            </div>
            <div>
              <h3 className="text-2xl font-bold text-slate-900 dark:text-white">{t('settings.auditLog', 'Security Audit Log')}</h3>
              <p className="text-sm text-slate-500">{t('settings.auditLogDesc', 'Review recent account activity and active sessions.')}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-slate-100 dark:hover:bg-white/5 rounded-full transition-colors">
            <X size={20} className="text-slate-500" />
          </button>
        </div>

        <div className="flex border-b border-slate-100 dark:border-white/5 px-8">
          <button
            onClick={() => setAuditTab('sessions')}
            className={`px-6 py-4 text-sm font-bold transition-all border-b-2 ${auditTab === 'sessions' ? 'border-blue-600 text-blue-600' : 'border-transparent text-slate-500 hover:text-slate-700'}`}
          >
            {t('audit.activeSessions', 'Active Sessions')}
          </button>
          <button
            onClick={() => setAuditTab('events')}
            className={`px-6 py-4 text-sm font-bold transition-all border-b-2 ${auditTab === 'events' ? 'border-blue-600 text-blue-600' : 'border-transparent text-slate-500 hover:text-slate-700'}`}
          >
            {t('audit.auditEvents', 'Audit Events')}
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-8 custom-scrollbar">
          {auditTab === 'sessions' ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-xs font-black uppercase tracking-widest text-slate-400">{t('audit.currentActiveSessions', 'Current active sessions')}</h4>
                <button
                  onClick={handleRevokeAll}
                  disabled={isRevoking || sessions.length <= 1}
                  className="text-xs font-bold text-red-600 hover:underline disabled:opacity-50"
                >
                  {t('audit.revokeAllOthers', 'Revoke all others')}
                </button>
              </div>

              {sessionsLoading ? (
                <div className="py-20 flex justify-center"><Loader2 className="animate-spin text-blue-600" /></div>
              ) : (
                <div className="grid gap-3">
                  {sessions.map(s => (
                    <div key={s.id} className="p-5 bg-slate-50 dark:bg-white/[0.03] rounded-2xl border border-slate-100 dark:border-white/5 flex items-center justify-between group hover:border-blue-600/30 transition-all">
                      <div className="flex items-center gap-4">
                        <div className="w-10 h-10 rounded-xl bg-white dark:bg-white/5 shadow-sm flex items-center justify-center">
                          <Monitor size={18} className="text-slate-600" />
                        </div>
                        <div>
                          <p className="font-bold text-sm text-slate-900 dark:text-white flex items-center gap-2">
                            {s.deviceName}
                            {s.id === 'current' && <span className="px-2 py-0.5 bg-blue-600 text-[8px] font-black uppercase text-white rounded-full">{t('audit.thisDevice', 'This Device')}</span>}
                          </p>
                          <p className="text-[10px] text-slate-500 mt-0.5">{s.ip} · {formatSessionTime(s.timestamp)}</p>
                        </div>
                      </div>
                      {s.id !== 'current' && (
                        <button className="p-2 text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20 rounded-lg transition-all opacity-0 group-hover:opacity-100">
                          <LogOut size={16} />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-xs font-black uppercase tracking-widest text-slate-400">{t('audit.recentActivity', 'Recent activity')}</h4>
                <p className="text-[10px] font-bold text-slate-500">{t('audit.showingLastEvents', 'Showing last {{count}} events', { count: auditEvents.length })}</p>
              </div>

              {auditEventsLoading ? (
                <div className="py-20 flex justify-center"><Loader2 className="animate-spin text-blue-600" /></div>
              ) : auditEvents.length === 0 ? (
                <div className="py-20 text-center">
                  <History size={48} className="mx-auto text-slate-200 dark:text-white/5 mb-4" />
                  <p className="text-sm font-medium text-slate-400">{t('audit.noEvents', 'No security events recorded yet.')}</p>
                </div>
              ) : (
                <div className="divide-y divide-slate-100 dark:divide-white/5 border border-slate-100 dark:border-white/5 rounded-2xl overflow-hidden bg-slate-50/50 dark:bg-white/[0.01]">
                  {auditEvents.map(e => {
                    const info = getActionInfo(e.action);
                    return (
                      <div key={e.id} className="p-4 flex items-start justify-between hover:bg-slate-100/50 dark:hover:bg-white/[0.02] transition-colors">
                        <div className="flex items-start gap-4">
                          <div className="w-8 h-8 rounded-lg bg-white dark:bg-white/5 shadow-sm flex items-center justify-center shrink-0 mt-0.5">
                            {info.icon}
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <p className="font-bold text-sm text-slate-900 dark:text-white">{info.label}</p>
                              {!e.success && <span className="px-1.5 py-0.5 bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 text-[8px] font-black uppercase rounded">{t('audit.failed', 'Failed')}</span>}
                            </div>
                            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-1">
                              <p className="text-[10px] text-slate-500 flex items-center gap-1">
                                <Globe size={10} />
                                {e.ip} {e.ipInfo?.countryFlag} {e.ipInfo?.city && `(${e.ipInfo.city}, ${e.ipInfo.countryCode})`}
                              </p>
                              <p className="text-[10px] text-slate-500 font-medium">
                                {new Date(e.ts).toLocaleString()}
                              </p>
                              {e.resourceLabel && (
                                <p className="text-[10px] text-blue-600 dark:text-blue-400 font-bold bg-blue-50 dark:bg-blue-900/20 px-1.5 rounded truncate max-w-[120px]">
                                  {e.resourceLabel}
                                </p>
                              )}
                            </div>
                          </div>
                        </div>
                        {e.riskFlags && e.riskFlags.length > 0 && (
                          <div className="flex gap-1">
                            {e.riskFlags.map(f => (
                              <span key={f} className="w-2 h-2 rounded-full bg-amber-500" title={f} />
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="p-8 border-t border-slate-100 dark:border-white/5 bg-slate-50/50 dark:bg-white/[0.01] flex items-center justify-between">
           <div className="flex items-center gap-3 text-slate-400">
             <ShieldAlert size={14} />
             <p className="text-[10px] font-black uppercase tracking-widest">{t('audit.e2eEncrypted', 'End-to-end encrypted audit logs')}</p>
           </div>
           <button onClick={onClose} className="px-8 py-3 bg-black dark:bg-white dark:text-black text-white rounded-xl font-bold text-sm hover:opacity-90 transition-all">
             {t('common.close', 'Close')}
           </button>
        </div>
      </motion.div>
    </div>
  );
}
