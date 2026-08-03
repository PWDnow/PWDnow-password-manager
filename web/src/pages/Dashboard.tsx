import React, { useMemo, useState, useEffect } from 'react';
import { Shield, Lock, Key, AlertTriangle, CheckCircle, Activity, ArrowUpRight, ShieldAlert, Loader2, ExternalLink } from 'lucide-react';
import { motion } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import SEO from '../components/SEO';
import { useVault } from '../context/VaultContext';
import { getMfaConfig } from '../utils/mfa';
import { passwordScore } from '../utils/passwordStrength';
import { apiFetch, hasServerSession } from '../utils/api';
import type { AuditEvent } from '../types';

// ── Security score computation (mirrors VaultHealth logic) ────────────────────
function computeSecurityScore(credentials: { password?: string; status?: string; otpSecret?: string }[]): {
  score: number;
  weakCount: number;
  reusedCount: number;
  twoFaCoverage: number;
} {
  const withPasswords = credentials.filter(c => c.password && c.password.length > 0);
  if (withPasswords.length === 0) return { score: 100, weakCount: 0, reusedCount: 0, twoFaCoverage: 0 };

  // Reuse detection by hash
  const seen = new Map<string, number>();
  for (const c of withPasswords) {
    let h = 5381;
    for (let i = 0; i < c.password!.length; i++) h = ((h << 5) + h) ^ c.password!.charCodeAt(i);
    const key = (h >>> 0).toString(16);
    seen.set(key, (seen.get(key) ?? 0) + 1);
  }

  const weakCount = withPasswords.filter(c => passwordScore(c.password!) <= 1).length;
  const reusedCount = withPasswords.filter(c => {
    let h = 5381;
    for (let i = 0; i < c.password!.length; i++) h = ((h << 5) + h) ^ c.password!.charCodeAt(i);
    return (seen.get((h >>> 0).toString(16)) ?? 1) > 1;
  }).length;
  seen.clear();

  const withOtp = credentials.filter(c => c.otpSecret && c.otpSecret.length > 0).length;
  const twoFaCoverage = credentials.length > 0 ? Math.round((withOtp / credentials.length) * 100) : 0;

  const total = withPasswords.length;
  const weakPen   = Math.min(40, (weakCount   / total) * 40);
  const reusedPen = Math.min(30, (reusedCount / total) * 30);
  const score = Math.round(Math.max(0, 100 - weakPen - reusedPen));

  return { score, weakCount, reusedCount, twoFaCoverage };
}

// ── Activity icon map ─────────────────────────────────────────────────────────
function activityIcon(action: string) {
  if (action === 'login')          return { icon: CheckCircle,  color: 'text-green-900 bg-green-100 dark:text-green-400 dark:bg-green-950/30' };
  if (action === 'login_failed')   return { icon: ShieldAlert,  color: 'text-red-900 bg-red-100 dark:text-red-400 dark:bg-red-950/30' };
  if (action === 'logout')         return { icon: Activity,     color: 'text-slate-900 bg-slate-100 dark:text-slate-400 dark:bg-white/5' };
  if (action === 'mfa_changed')    return { icon: Shield,       color: 'text-blue-900 bg-blue-100 dark:text-blue-400 dark:bg-blue-950/30' };
  if (action === 'share_created')  return { icon: ArrowUpRight, color: 'text-indigo-900 bg-indigo-100 dark:text-indigo-400 dark:bg-indigo-950/30' };
  return                                  { icon: Key,          color: 'text-purple-900 bg-purple-100 dark:text-purple-400 dark:bg-purple-950/30' };
}

function timeAgo(ts: number | string): string {
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 2)   return 'Just now';
  if (mins < 60)  return `${mins} mins ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)   return `${hrs} hour${hrs > 1 ? 's' : ''} ago`;
  const days = Math.floor(hrs / 24);
  return `${days} day${days > 1 ? 's' : ''} ago`;
}

export default function Dashboard() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { credentials, isLoading } = useVault();

  const [recentEvents, setRecentEvents] = useState<AuditEvent[]>([]);
  const [eventsLoading, setEventsLoading] = useState(false);

  // Load recent audit events (server session only; daemon-only sessions don't have a server audit log).
  useEffect(() => {
    if (!hasServerSession()) return;
    setEventsLoading(true);
    apiFetch<{ ok?: boolean; events?: AuditEvent[] }>('/api/audit/events?limit=4')
      .then(d => { if (d?.events) setRecentEvents(d.events); })
      .catch(() => {})
      .finally(() => setEventsLoading(false));
  }, []);

  const mfaCfg = useMemo(() => getMfaConfig(), []);

  const { score, weakCount, reusedCount, twoFaCoverage } = useMemo(
    () => computeSecurityScore(credentials),
    [credentials],
  );

  const mfaEnabled =
    mfaCfg.totp.enabled ||
    mfaCfg.email.enabled ||
    (mfaCfg.webauthn?.credentials?.length ?? 0) > 0 ||
    (mfaCfg.passkey?.credentials?.length ?? 0) > 0 ||
    (mfaCfg.platform?.credentials?.length ?? 0) > 0;

  const compromisedCount = weakCount + reusedCount; // conservative overlap; exact comes from VaultHealth

  const stats = [
    {
      label:  t('dashboard.totalItems', 'Total Items'),
      value:  isLoading ? '—' : String(credentials.length),
      icon:   Lock,
      color:  'bg-black text-white',
      href:   '/vault',
    },
    {
      label:  t('dashboard.securityScore', 'Security Score'),
      value:  isLoading ? '—' : `${score}/100`,
      icon:   Shield,
      color:  score >= 80 ? 'bg-green-100 text-green-900 dark:bg-green-950/30 dark:text-green-400' : score >= 50 ? 'bg-amber-100 text-amber-900 dark:bg-amber-950/30 dark:text-amber-400' : 'bg-red-100 text-red-900 dark:bg-red-950/30 dark:text-red-400',
      href:   '/health',
    },
    {
      label:  t('dashboard.compromised', 'At Risk'),
      value:  isLoading ? '—' : String(compromisedCount),
      icon:   ShieldAlert,
      color:  compromisedCount === 0 ? 'bg-green-100 text-green-900 dark:bg-green-950/30 dark:text-green-400' : 'bg-red-100 text-red-900 dark:bg-red-950/30 dark:text-red-400',
      href:   '/health',
    },
    {
      label:  t('dashboard.mfaStatus', 'MFA'),
      value:  mfaEnabled ? t('dashboard.mfaEnabled', 'Enabled') : t('dashboard.mfaDisabled', 'Off'),
      icon:   Activity,
      color:  mfaEnabled ? 'bg-blue-100 text-blue-900 dark:bg-blue-950/30 dark:text-blue-400' : 'bg-orange-100 text-orange-900 dark:bg-orange-950/30 dark:text-orange-400',
      href:   '/settings',
    },
  ];

  return (
    <div className="max-w-7xl mx-auto">
      <SEO
        title={t('dashboard.title', 'Sanctuary Overview')}
        description={t('dashboard.subtitle', 'Your digital assets are secured with PWDnow zero-knowledge encryption.')}
      />
      <div className="mb-12">
        <h1 className="text-4xl md:text-5xl font-headline font-black tracking-tighter text-black dark:text-white">
          {t('dashboard.title', 'Sanctuary Overview')}
        </h1>
        <p className="text-on-surface-variant text-lg mt-2 font-medium">
          {t('dashboard.subtitle', 'Your digital assets are secured with PWDnow zero-knowledge encryption.')}
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
        {stats.map((stat, i) => (
          <motion.button
            key={i}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            onClick={() => navigate(stat.href)}
            aria-label={`${stat.label}: ${stat.value}. Click to view details.`}
            className="w-full text-left bg-white dark:bg-surface-container-low p-8 rounded-2xl shadow-sm border border-outline-variant/5 group hover:shadow-xl transition-all duration-500 cursor-pointer focus-visible:outline focus-visible:outline-2 focus-visible:outline-theme-primary focus-visible:outline-offset-2"
          >
            <div className="flex justify-between items-start mb-6">
              <div className={`p-4 rounded-2xl ${stat.color} transition-transform group-hover:scale-110 duration-500`}>
                <stat.icon size={24} aria-hidden="true" />
              </div>
              <ArrowUpRight size={20} className="text-outline-variant opacity-0 group-hover:opacity-100 transition-opacity" aria-hidden="true" />
            </div>
            {isLoading ? (
              <div className="h-9 w-16 bg-surface-container-high rounded-lg animate-pulse mb-1" />
            ) : (
              <div className="text-3xl md:text-4xl font-black tracking-tighter mb-1">{stat.value}</div>
            )}
            <div className="text-xs font-black uppercase tracking-[0.2em] text-on-surface-variant">{stat.label}</div>
          </motion.button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Security Health Card */}
        <div className="lg:col-span-2 bg-black text-white rounded-3xl p-6 sm:p-8 md:p-12 relative overflow-hidden">
          <div className="relative z-10">
            <div className="flex items-center gap-4 mb-8">
              <div className="w-12 h-12 rounded-full bg-white/10 flex items-center justify-center">
                <Shield size={24} className="text-white" />
              </div>
              <h2 className="text-2xl font-headline font-black tracking-tight">
                {t('dashboard.securityHealth', 'Security Health Analysis')}
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-12">
              <div className="space-y-8">
                {/* Master password strength gauge uses overall score */}
                <div className="space-y-4">
                  <div className="flex justify-between items-end">
                    <span className="text-xs font-black uppercase tracking-widest opacity-60">
                      {t('dashboard.vaultScore', 'Vault Security Score')}
                    </span>
                    <span className="text-xl font-black">{isLoading ? '—' : `${score}%`}</span>
                  </div>
                  <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${score}%`, backgroundColor: score >= 80 ? '#4ade80' : score >= 50 ? '#fb923c' : '#f87171' }}
                    />
                  </div>
                </div>
                {/* 2FA coverage */}
                <div className="space-y-4">
                  <div className="flex justify-between items-end">
                    <span className="text-xs font-black uppercase tracking-widest opacity-60">
                      {t('dashboard.twoFactorCoverage', '2FA Coverage')}
                    </span>
                    <span className="text-xl font-black">{isLoading ? '—' : `${twoFaCoverage}%`}</span>
                  </div>
                  <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-white/40 rounded-full transition-all duration-700"
                      style={{ width: `${twoFaCoverage}%` }}
                    />
                  </div>
                </div>
              </div>

              <div className="bg-white/5 rounded-2xl p-8 border border-white/10">
                <h3 id="recommendations-heading" className="text-sm font-black uppercase tracking-widest mb-6 flex items-center gap-3">
                  <AlertTriangle size={16} className="text-yellow-400" aria-hidden="true" />
                  {t('dashboard.criticalRecommendations', 'Recommendations')}
                </h3>
                {isLoading ? (
                  <div className="space-y-3">
                    {[...Array(2)].map((_, i) => (
                      <div key={i} className="h-4 bg-white/10 rounded animate-pulse" />
                    ))}
                  </div>
                ) : (
                  <ul aria-labelledby="recommendations-heading" className="space-y-4">
                    {weakCount > 0 && (
                      <li className="flex gap-4 text-sm opacity-80">
                        <div className="w-1.5 h-1.5 rounded-full bg-yellow-400 mt-1.5 shrink-0" />
                        {t('dashboard.recWeak', { count: weakCount, defaultValue: `Replace ${weakCount} weak password${weakCount > 1 ? 's' : ''}` })}
                      </li>
                    )}
                    {reusedCount > 0 && (
                      <li className="flex gap-4 text-sm opacity-80">
                        <div className="w-1.5 h-1.5 rounded-full bg-yellow-400 mt-1.5 shrink-0" />
                        {t('dashboard.recReused', { count: reusedCount, defaultValue: `${reusedCount} reused password${reusedCount > 1 ? 's' : ''} detected` })}
                      </li>
                    )}
                    {!mfaEnabled && (
                      <li className="flex gap-4 text-sm opacity-80">
                        <div className="w-1.5 h-1.5 rounded-full bg-yellow-400 mt-1.5 shrink-0" />
                        {t('dashboard.recMfa', 'Enable multi-factor authentication for your account')}
                      </li>
                    )}
                    {twoFaCoverage < 50 && credentials.length > 0 && (
                      <li className="flex gap-4 text-sm opacity-80">
                        <div className="w-1.5 h-1.5 rounded-full bg-amber-400 mt-1.5 shrink-0" />
                        {t('dashboard.recTwoFa', { pct: twoFaCoverage, defaultValue: `Only ${twoFaCoverage}% of credentials have TOTP 2FA` })}
                      </li>
                    )}
                    {weakCount === 0 && reusedCount === 0 && mfaEnabled && twoFaCoverage >= 50 && (
                      <li className="flex gap-4 text-sm opacity-80">
                        <div className="w-1.5 h-1.5 rounded-full bg-green-400 mt-1.5 shrink-0" />
                        {t('dashboard.allGood', 'No critical issues detected. Vault looks great!')}
                      </li>
                    )}
                  </ul>
                )}
                <button
                  onClick={() => navigate('/health')}
                  className="mt-6 text-xs font-black uppercase tracking-widest text-slate-300 hover:text-white flex items-center gap-2 transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-white focus-visible:outline-offset-2"
                >
                  {t('dashboard.viewFullReport', 'Full Report')}
                  <ExternalLink size={11} aria-hidden="true" />
                </button>
              </div>
            </div>
          </div>
          <Shield size={400} className="absolute -right-20 -bottom-20 text-white/[0.03] rotate-12" />
        </div>

        {/* Recent Activity */}
        <div className="bg-white dark:bg-surface-container-low rounded-3xl p-6 sm:p-8 md:p-10 border border-outline-variant/5 shadow-sm">
          <h2 className="text-xl font-headline font-black tracking-tight mb-8">
            {t('dashboard.recentActivity', 'Recent Activity')}
          </h2>

          {eventsLoading ? (
            <div className="space-y-6">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-xl bg-surface-container-high animate-pulse shrink-0" />
                  <div className="flex-1 space-y-2">
                    <div className="h-3 bg-surface-container-high rounded animate-pulse w-3/4" />
                    <div className="h-2 bg-surface-container-high/60 rounded animate-pulse w-1/2" />
                  </div>
                </div>
              ))}
            </div>
          ) : recentEvents.length > 0 ? (
            <div className="space-y-6" role="list" aria-label="Recent activity">
              {recentEvents.map(event => {
                const { icon: Icon, color } = activityIcon(event.action);
                return (
                  <div key={event.id} className="flex items-center gap-4" role="listitem">
                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${color} shrink-0`} aria-hidden="true">
                      <Icon size={18} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-bold text-black dark:text-white capitalize truncate">
                        {event.action.replace(/_/g, ' ')}
                      </p>
                      <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant mt-0.5">
                        {timeAgo(event.ts)} · {event.ip}
                      </p>
                    </div>
                    {!event.success && (
                      <span className="text-[8px] font-black uppercase px-1.5 py-0.5 bg-red-100 dark:bg-red-900/30 text-red-700 rounded">
                        Failed
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            // Daemon-only / no server session: show vault-local stats instead
            <div className="space-y-6" role="list" aria-label="Vault stats">
              {[
                { action: t('dashboard.activityVaultAccessed', 'Vault Accessed'), time: t('dashboard.timeNow', 'Now'), icon: Lock, color: 'text-blue-700 bg-blue-50 dark:bg-blue-950/30' },
                { action: t('dashboard.credentialsTotal', `${credentials.length} Credentials`), time: t('dashboard.inVault', 'In vault'), icon: Key, color: 'text-purple-700 bg-purple-50 dark:bg-purple-950/30' },
                { action: t('dashboard.mfaStatus', `MFA ${mfaEnabled ? 'Enabled' : 'Disabled'}`), time: t('dashboard.accountSecurity', 'Account security'), icon: Activity, color: mfaEnabled ? 'text-green-700 bg-green-50 dark:bg-green-950/30' : 'text-orange-700 bg-orange-50 dark:bg-orange-950/30' },
                { action: t('dashboard.activityAudit', 'Security Audit'), time: t('dashboard.runAudit', 'Run for details'), icon: CheckCircle, color: 'text-neutral-700 dark:text-neutral-300 bg-surface-container-low' },
              ].map((item, i) => (
                <div key={i} className="flex items-center gap-4" role="listitem">
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${item.color}`} aria-hidden="true">
                    <item.icon size={18} />
                  </div>
                  <div>
                    <p className="text-sm font-bold text-black dark:text-white">{item.action}</p>
                    <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant mt-0.5">{item.time}</p>
                  </div>
                </div>
              ))}
            </div>
          )}

          <button
            onClick={() => navigate('/settings')}
            className="w-full mt-10 py-4 border border-outline-variant/20 rounded-2xl text-xs font-black uppercase tracking-widest hover:bg-surface-container-low transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-theme-primary focus-visible:outline-offset-2 text-black dark:text-white"
            aria-label="View full audit log"
          >
            {t('dashboard.viewAuditLog', 'View Full Audit Log')}
          </button>
        </div>
      </div>
    </div>
  );
}
