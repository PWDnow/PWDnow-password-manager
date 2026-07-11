import React, { useState, useEffect } from 'react';
import { X, ShieldAlert, Clock, Mail, Check, Copy, Users, CheckCircle2, XCircle, Loader2, Trash2, ChevronLeft, Info, ExternalLink } from 'lucide-react';
import { motion } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { apiFetch } from '../utils/api';

interface EmergencyConfig {
  enabled: boolean;
  contactEmail: string;
  waitPeriodHours: number;
  token: string;
  createdAt: number;
}

interface EmergencyRequest {
  id: string;
  requesterName: string;
  requesterEmail: string;
  requestedAt: number;
  status: 'pending' | 'granted' | 'denied';
  grantExpiresAt: number;
}

interface Props {
  onClose: () => void;
}

const WAIT_OPTIONS = [
  { hours: 24,  key: 'wait24h', fallback: '24 h' },
  { hours: 48,  key: 'wait48h', fallback: '48 h' },
  { hours: 72,  key: 'wait3d',  fallback: '3 days' },
  { hours: 168, key: 'wait7d',  fallback: '7 days' },
];


export default function EmergencyAccessModal({ onClose }: Props) {
  const { t } = useTranslation();
  const [step, setStep] = useState<'loading' | 'setup' | 'configured' | 'requests'>('loading');
  const [config, setConfig] = useState<EmergencyConfig | null>(null);
  const [requests, setRequests] = useState<EmergencyRequest[]>([]);
  const [email, setEmail] = useState('');
  const [waitHours, setWaitHours] = useState(48);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [respondingId, setRespondingId] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const [cfgRes, reqRes] = await Promise.all([
          apiFetch<{ config: EmergencyConfig | null }>('/api/vault/emergency', { method: 'GET' }),
          apiFetch<{ requests: EmergencyRequest[] }>('/api/vault/emergency/requests', { method: 'GET' }),
        ]);
        setConfig(cfgRes.config);
        setRequests(reqRes.requests ?? []);
        setStep(cfgRes.config?.enabled ? 'configured' : 'setup');
      } catch {
        setStep('setup');
      }
    })();
  }, []);

  async function handleSave() {
    if (!email.trim() || !email.includes('@')) { setError(t('emergency.invalidEmail', 'Enter a valid email address.')); return; }
    setError('');
    setBusy(true);
    try {
      const res = await apiFetch<{ config: EmergencyConfig }>('/api/vault/emergency', {
        method: 'POST',
        body: JSON.stringify({ contactEmail: email, waitPeriodHours: waitHours }),
      });
      setConfig(res.config);
      setStep('configured');
    } catch (e: any) {
      setError(e.message ?? t('emergency.failedToSave', 'Failed to save.'));
    } finally {
      setBusy(false);
    }
  }

  async function handleDisable() {
    setBusy(true);
    try {
      await apiFetch('/api/vault/emergency', { method: 'DELETE' });
      setConfig(null);
      setEmail('');
      setStep('setup');
    } finally {
      setBusy(false);
    }
  }

  async function handleRespond(reqId: string, action: 'grant' | 'deny') {
    setRespondingId(reqId);
    try {
      await apiFetch('/api/vault/emergency/respond', {
        method: 'POST',
        body: JSON.stringify({ requestId: reqId, action }),
      });
      setRequests(prev => prev.map(r => r.id === reqId ? { ...r, status: action === 'grant' ? 'granted' : 'denied' } : r));
    } finally {
      setRespondingId(null);
    }
  }

  function copyLink() {
    if (!config) return;
    const link = `${window.location.origin}/emergency/request/${config.token}`;
    navigator.clipboard.writeText(link);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const shareLink = config ? `${window.location.origin}/emergency/request/${config.token}` : '';
  const pendingCount = requests.filter(r => r.status === 'pending').length;

  return (
    <div className="fixed inset-0 z-[200] flex justify-end">
      {/* Background Overlay - No Blur */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="absolute inset-0 bg-black/40"
        onClick={onClose}
      />

      {/* Side Drawer Panel */}
      <motion.div
        initial={{ x: '100%' }}
        animate={{ x: 0 }}
        exit={{ x: '100%' }}
        transition={{ type: 'spring', damping: 25, stiffness: 200 }}
        className="relative w-full max-w-lg bg-white dark:bg-[#0a0a0a] shadow-2xl flex flex-col h-full border-l border-outline-variant/10"
      >
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-outline-variant/10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-black dark:bg-white flex items-center justify-center">
              <ShieldAlert className="text-white dark:text-black" size={20} />
            </div>
            <div>
              <h3 className="text-lg font-black text-black dark:text-white uppercase tracking-tight">
                {t('emergency.title', 'Emergency Access')}
              </h3>
              <p className="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">
                {t('emergency.subtitle', 'Account Recovery Protocol')}
              </p>
            </div>
          </div>
          <button aria-label="Close" 
            onClick={onClose} 
            className="w-10 h-10 flex items-center justify-center hover:bg-surface-container-low rounded-full transition-colors text-on-surface-variant hover:text-black dark:hover:text-white"
          >
  <X aria-hidden="true" size={20} />
</button>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto custom-scrollbar">
          <div className="p-8">

            {/* ── Loading State ─────────────────────────────────────────── */}
            {step === 'loading' && (
              <div className="flex flex-col items-center justify-center py-24 gap-4">
                <Loader2 size={32} className="animate-spin text-black dark:text-white" />
                <p className="text-xs font-bold text-on-surface-variant uppercase tracking-widest">
                  {t('emergency.initializing', 'Initializing secure channel...')}
                </p>
              </div>
            )}

            {/* ── Setup State ───────────────────────────────────────────── */}
            {step === 'setup' && (
              <div className="space-y-10">
                <section>
                  <h4 className="text-xl font-headline font-bold text-black dark:text-white mb-4">
                    {t('emergency.setupTitle', 'Secure Account Handover')}
                  </h4>
                  <p className="text-on-surface-variant text-sm leading-relaxed mb-6">
                    {t('emergency.setupDesc', 'Designate a trusted individual who can request access to your vault in the event of an emergency. This protocol uses a zero-knowledge wait period: any request triggers an immediate alert to you, giving you time to deny it. Silence during the wait period constitutes authorization.')}
                  </p>

                  <div className="bg-blue-50 dark:bg-blue-900/10 border border-blue-100 dark:border-blue-800/20 p-5 rounded-2xl flex gap-4">
                    <Info className="text-blue-600 shrink-0" size={20} />
                    <p className="text-xs text-blue-800 dark:text-blue-300 leading-relaxed">
                      {t('emergency.setupInfo', "Your trusted contact will only be able to decrypt your vault after the waiting period expires and only if you haven't denied the request.")}
                    </p>
                  </div>
                </section>

                <div className="space-y-8">
                  {/* Email Input */}
                  <div className="space-y-3">
                    <label htmlFor="input-0bz6u6yj6" className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant flex items-center gap-2">
                      <Mail size={12} /> {t('emergency.trustedContactEmail', 'Trusted Contact Email')}
                    </label>
<input id="input-0bz6u6yj6"
                      type="email"
                      value={email}
                      onChange={e => { setEmail(e.target.value); setError(''); }}
                      onKeyDown={e => e.key === 'Enter' && handleSave()}
                      placeholder="trusted-contact@secure.com"
                      className="w-full px-6 py-4 bg-surface-container-low rounded-2xl border border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/20 dark:focus:ring-white/20 outline-none transition-all placeholder:font-normal placeholder:text-on-surface-variant/50"
                    />
                    {error && (
                      <p className="text-[10px] font-bold text-red-600 uppercase tracking-widest ml-2">{error}</p>
                    )}
                  </div>

                  {/* Wait period selector */}
                  <div className="space-y-3">
                    <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant flex items-center gap-2">
                      <Clock size={12} /> {t('emergency.securityWaitPeriod', 'Security Wait Period')}
                    </label>
                    <div className="grid grid-cols-2 gap-3">
                      {WAIT_OPTIONS.map(({ hours, key, fallback }) => (
                        <button
                          key={hours}
                          onClick={() => setWaitHours(hours)}
                          className={`flex items-center justify-between px-5 py-4 rounded-2xl border-2 transition-all ${
                            waitHours === hours
                              ? 'border-black dark:border-white bg-black dark:bg-white text-white dark:text-black shadow-lg shadow-black/10'
                              : 'border-outline-variant/10 text-on-surface-variant hover:border-outline-variant/30 bg-surface-container-low'
                          }`}
                        >
                          <span className="text-sm font-black uppercase tracking-widest">{t(`emergency.${key}`, fallback)}</span>
                          {waitHours === hours && <Check size={16} />}
                        </button>
                      ))}
                    </div>
                  </div>

                  <button
                    onClick={handleSave}
                    disabled={busy || !email.trim()}
                    className="w-full py-5 bg-black text-white dark:bg-white dark:text-black rounded-2xl font-black uppercase tracking-widest text-xs shadow-xl hover:scale-[1.01] active:scale-[0.99] transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-3"
                  >
                    {busy ? <Loader2 size={18} className="animate-spin" /> : <ShieldAlert size={18} />}
                    {t('emergency.authorizeProtocol', 'Authorize Emergency Protocol')}
                  </button>
                </div>
              </div>
            )}

            {/* ── Configured State ──────────────────────────────────────── */}
            {step === 'configured' && config && (
              <div className="space-y-10">
                <section>
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="text-xl font-headline font-bold text-black dark:text-white">
                      {t('emergency.activeConfig', 'Active Configuration')}
                    </h4>
                    <span className="px-3 py-1 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 text-[10px] font-black uppercase tracking-widest rounded-full flex items-center gap-1.5">
                      <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                      {t('emergency.live', 'Live')}
                    </span>
                  </div>
                  
                  <div className="p-6 bg-surface-container-low rounded-3xl border border-outline-variant/10 space-y-4">
                    <div className="flex items-start gap-4">
                      <div className="w-10 h-10 rounded-xl bg-black dark:bg-[#1a1a1a] flex items-center justify-center shrink-0">
                        <Mail className="text-white" size={18} />
                      </div>
                      <div className="min-w-0">
                        <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('emergency.trustedContact', 'Trusted Contact')}</p>
                        <p className="font-bold text-black dark:text-white truncate">{config.contactEmail}</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-4">
                      <div className="w-10 h-10 rounded-xl bg-black dark:bg-[#1a1a1a] flex items-center justify-center shrink-0">
                        <Clock className="text-white" size={18} />
                      </div>
                      <div className="min-w-0">
                        <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('emergency.waitPeriod', 'Wait Period')}</p>
                        <p className="font-bold text-black dark:text-white">
                          {(() => { const o = WAIT_OPTIONS.find(x => x.hours === config.waitPeriodHours); return o ? t(`emergency.${o.key}`, o.fallback) : ''; })()}
                        </p>
                      </div>
                    </div>
                  </div>
                </section>

                {/* Requests Navigation */}
                <button
                  onClick={() => setStep('requests')}
                  className="w-full flex items-center justify-between p-6 bg-surface-container-low rounded-3xl border border-outline-variant/10 hover:bg-surface-container-high transition-all group"
                >
                  <div className="flex items-center gap-4">
                    <div className="w-12 h-12 rounded-2xl bg-black dark:bg-white flex items-center justify-center relative">
                      <Users className="text-white dark:text-black" size={20} />
                      {pendingCount > 0 && (
                        <span className="absolute -top-2 -right-2 w-6 h-6 bg-red-600 text-white text-[10px] font-black rounded-full flex items-center justify-center border-4 border-white dark:border-[#0a0a0a]">
                          {pendingCount}
                        </span>
                      )}
                    </div>
                    <div className="text-left">
                      <p className="font-black text-black dark:text-white uppercase tracking-tight">{t('emergency.accessRequests', 'Access Requests')}</p>
                      <p className="text-xs text-on-surface-variant">{t('emergency.pendingReview', '{{count}} pending review', { count: pendingCount })}</p>
                    </div>
                  </div>
                  <ChevronLeft className="rotate-180 text-on-surface-variant group-hover:text-black dark:group-hover:text-white transition-colors" size={20} />
                </button>

                {/* Share URL */}
                <section className="space-y-3">
                  <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant flex items-center gap-2">
                    <ExternalLink size={12} /> {t('emergency.secureRequestUrl', 'Secure Request URL')}
                  </label>
                  <div className="flex items-center gap-3">
                    <div className="flex-1 px-5 py-4 bg-surface-container-low rounded-2xl border border-outline-variant/10 text-[11px] font-mono text-on-surface-variant truncate">
                      {shareLink}
                    </div>
                    <button
                      onClick={copyLink}
                      className="shrink-0 w-14 h-14 flex items-center justify-center rounded-2xl bg-black dark:bg-white text-white dark:text-black hover:scale-[1.05] transition-all shadow-lg active:scale-95"
                      title={t('emergency.copyUrl', 'Copy URL')}
                    >
                      {copied ? <Check size={18} /> : <Copy size={18} />}
                    </button>
                  </div>
                  <p className="text-[10px] text-on-surface-variant text-center px-4 leading-relaxed">
                    {t('emergency.urlDesc', 'Provide this link to your trusted contact. They must visit this URL to initiate the access protocol.')}
                  </p>
                </section>

                <div className="pt-8 mt-8 border-t border-outline-variant/10">
                  <button
                    onClick={handleDisable}
                    disabled={busy}
                    className="w-full py-4 text-red-600 dark:text-red-400 font-black uppercase tracking-widest text-[10px] flex items-center justify-center gap-2 hover:bg-red-50 dark:hover:bg-red-900/10 rounded-xl transition-all disabled:opacity-40"
                  >
                    {busy ? <Loader2 size={14} className="animate-spin" /> : <Trash2 size={14} />}
                    {t('emergency.deactivate', 'Deactivate Emergency Access')}
                  </button>
                </div>
              </div>
            )}

            {/* ── Requests State ────────────────────────────────────────── */}
            {step === 'requests' && (
              <div className="space-y-8">
                <button
                  onClick={() => setStep('configured')}
                  className="flex items-center gap-2 text-xs font-black uppercase tracking-widest text-on-surface-variant hover:text-black dark:hover:text-white transition-colors"
                >
                  <ChevronLeft size={16} /> {t('emergency.backToConfig', 'Back to Config')}
                </button>

                <div>
                  <h4 className="text-xl font-headline font-bold text-black dark:text-white mb-2">
                    {t('emergency.auditLogTitle', 'Access Audit Log')}
                  </h4>
                  <p className="text-on-surface-variant text-sm leading-relaxed">
                    {t('emergency.auditLogDesc', 'Below are all recorded attempts to activate the emergency protocol for your account.')}
                  </p>
                </div>

                {requests.length === 0 ? (
                  <div className="flex flex-col items-center py-20 text-on-surface-variant border-2 border-dashed border-outline-variant/10 rounded-3xl">
                    <Users size={32} className="opacity-20 mb-4" />
                    <p className="text-[10px] font-black uppercase tracking-widest">{t('emergency.cleanAuditLog', 'Clean Audit Log')}</p>
                    <p className="text-xs mt-1 opacity-60">{t('emergency.noRequests', 'No access requests recorded')}</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {[...requests].reverse().map(req => (
                      <div
                        key={req.id}
                        className={`p-6 rounded-3xl border-2 transition-all ${
                          req.status === 'pending'
                            ? 'border-amber-500 bg-amber-50 dark:bg-amber-950/20 shadow-lg shadow-amber-500/5'
                            : 'border-outline-variant/10 bg-surface-container-low'
                        }`}
                      >
                        <div className="flex items-start justify-between mb-4">
                          <div className="min-w-0">
                            <p className="font-black text-black dark:text-white truncate">{req.requesterName}</p>
                            <p className="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest mt-1">
                              {new Date(req.requestedAt).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                            </p>
                          </div>
                          <span className={`text-[9px] font-black uppercase tracking-widest px-3 py-1.5 rounded-full shrink-0 ${
                            req.status === 'pending'
                              ? 'bg-amber-500 text-white animate-pulse'
                              : req.status === 'granted'
                              ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400'
                              : 'bg-neutral-100 dark:bg-neutral-800 text-on-surface-variant'
                          }`}>
                            {t(`emergency.status_${req.status}`, req.status)}
                          </span>
                        </div>

                        {req.status === 'pending' ? (
                          <div className="space-y-3">
                            <div className="flex items-center gap-2 p-3 bg-white/50 dark:bg-black/50 rounded-xl mb-4">
                              <Clock size={14} className="text-amber-600" />
                              <p className="text-[10px] font-bold text-amber-800 dark:text-amber-300">
                                {t('emergency.waitingPeriodExpires', 'Waiting period expires: {{date}}', { date: new Date(req.grantExpiresAt).toLocaleDateString() })}
                              </p>
                            </div>
                            <div className="flex gap-2">
                              <button
                                onClick={() => handleRespond(req.id, 'grant')}
                                disabled={respondingId === req.id}
                                className="flex-1 py-4 bg-black text-white dark:bg-white dark:text-black rounded-xl font-black uppercase tracking-widest text-[10px] hover:scale-[1.02] active:scale-[0.98] transition-all flex items-center justify-center gap-2"
                              >
                                {respondingId === req.id ? <Loader2 size={12} className="animate-spin" /> : <CheckCircle2 size={12} />}
                                {t('emergency.authorize', 'Authorize')}
                              </button>
                              <button
                                onClick={() => handleRespond(req.id, 'deny')}
                                disabled={respondingId === req.id}
                                className="flex-1 py-4 bg-surface-container-high border border-outline-variant/10 text-black dark:text-white rounded-xl font-black uppercase tracking-widest text-[10px] hover:bg-neutral-200 dark:hover:bg-neutral-800 transition-all flex items-center justify-center gap-2"
                              >
                                <XCircle size={12} />
                                {t('emergency.deny', 'Deny')}
                              </button>
                            </div>
                          </div>
                        ) : (
                          <div className="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">
                            {req.status === 'granted'
                              ? t('emergency.resolvedGranted', 'Resolved: Access Provided')
                              : t('emergency.resolvedDenied', 'Resolved: Access Denied')}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

          </div>
        </div>

        {/* Footer */}
        <div className="p-8 border-t border-outline-variant/10 bg-surface-container-low/30">
          <div className="flex items-center gap-3 text-on-surface-variant opacity-60">
            <ShieldAlert size={14} />
            <p className="text-[10px] font-bold uppercase tracking-[0.2em]">
              {t('emergency.encryptedLogsActive', 'Encrypted Audit Logs Active')}
            </p>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
