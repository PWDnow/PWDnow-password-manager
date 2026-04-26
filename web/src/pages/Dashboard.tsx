import React from 'react';
import { Shield, Lock, Key, AlertTriangle, CheckCircle, Activity, ArrowUpRight, ShieldAlert } from 'lucide-react';
import { motion } from 'motion/react';
import { useTranslation } from 'react-i18next';
import SEO from '../components/SEO';

export default function Dashboard() {
  const { t } = useTranslation();

  const stats = [
    { label: t('dashboard.totalItems', 'Total Items'), value: '142', icon: Lock, color: 'bg-black text-white' },
    { label: t('dashboard.securityScore', 'Security Score'), value: '94/100', icon: Shield, color: 'bg-green-100 text-green-700' },
    { label: t('dashboard.compromised', 'Compromised'), value: '2', icon: ShieldAlert, color: 'bg-red-100 text-red-700' },
    { label: t('dashboard.activeSessions', 'Active Sessions'), value: '4', icon: Activity, color: 'bg-blue-100 text-blue-700' },
  ];

  return (
    <div className="max-w-7xl mx-auto">
      <SEO 
        title={t('dashboard.title', 'Sanctuary Overview')}
        description={t('dashboard.subtitle', 'Your digital assets are secured with PWDnow zero-knowledge encryption.')}
      />
      <div className="mb-12">
        <h1 className="text-4xl md:text-5xl font-headline font-black tracking-tighter text-black dark:text-white">{t('dashboard.title', 'Sanctuary Overview')}</h1>
        <p className="text-on-surface-variant text-lg mt-2 font-medium">{t('dashboard.subtitle', 'Your digital assets are secured with PWDnow zero-knowledge encryption.')}</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
        {stats.map((stat, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            className="bg-white dark:bg-surface-container-low p-8 rounded-2xl shadow-sm border border-outline-variant/5 group hover:shadow-xl transition-all duration-500"
          >
            <div className="flex justify-between items-start mb-6">
              <div className={`p-4 rounded-2xl ${stat.color} transition-transform group-hover:scale-110 duration-500`}>
                <stat.icon size={24} />
              </div>
              <ArrowUpRight size={20} className="text-outline-variant opacity-0 group-hover:opacity-100 transition-opacity" />
            </div>
            <div className="text-3xl md:text-4xl font-black tracking-tighter mb-1">{stat.value}</div>
            <div className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{stat.label}</div>
          </motion.div>
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
              <h2 className="text-2xl font-headline font-black tracking-tight">{t('dashboard.securityHealth', 'Security Health Analysis')}</h2>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-12">
              <div className="space-y-8">
                <div className="space-y-4">
                  <div className="flex justify-between items-end">
                    <span className="text-xs font-black uppercase tracking-widest opacity-60">{t('dashboard.masterPasswordStrength', 'Master Password Strength')}</span>
                    <span className="text-xl font-black">98%</span>
                  </div>
                  <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                    <div className="h-full w-[98%] bg-white rounded-full"></div>
                  </div>
                </div>
                <div className="space-y-4">
                  <div className="flex justify-between items-end">
                    <span className="text-xs font-black uppercase tracking-widest opacity-60">{t('dashboard.twoFactorCoverage', '2FA Coverage')}</span>
                    <span className="text-xl font-black">85%</span>
                  </div>
                  <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                    <div className="h-full w-[85%] bg-white/40 rounded-full"></div>
                  </div>
                </div>
              </div>

              <div className="bg-white/5 rounded-2xl p-8 border border-white/10">
                <h3 className="text-sm font-black uppercase tracking-widest mb-6 flex items-center gap-3">
                  <AlertTriangle size={16} className="text-yellow-400" />
                  {t('dashboard.criticalRecommendations', 'Critical Recommendations')}
                </h3>
                <ul className="space-y-4">
                  <li className="flex gap-4 text-sm opacity-80">
                    <div className="w-1.5 h-1.5 rounded-full bg-yellow-400 mt-1.5 shrink-0"></div>
                    {t('dashboard.recommendation1', 'Rotate Fidelity investment password (reused)')}
                  </li>
                  <li className="flex gap-4 text-sm opacity-80">
                    <div className="w-1.5 h-1.5 rounded-full bg-yellow-400 mt-1.5 shrink-0"></div>
                    {t('dashboard.recommendation2', 'Enable hardware key for primary email')}
                  </li>
                </ul>
              </div>
            </div>
          </div>
          <Shield size={400} className="absolute -right-20 -bottom-20 text-white/[0.03] rotate-12" />
        </div>

        {/* Recent Activity */}
        <div className="bg-white dark:bg-surface-container-low rounded-3xl p-6 sm:p-8 md:p-10 border border-outline-variant/5 shadow-sm">
          <h2 className="text-xl font-headline font-black tracking-tight mb-8">{t('dashboard.recentActivity', 'Recent Activity')}</h2>
          <div className="space-y-8" role="list" aria-label="Recent activity">
            {[
              { action: t('dashboard.activityAccessed', 'Vault Accessed'), time: t('dashboard.time2mins', '2 mins ago'), icon: Lock, color: 'text-blue-600 bg-blue-50' },
              { action: t('dashboard.activityGenerated', 'Password Generated'), time: t('dashboard.time1hour', '1 hour ago'), icon: Key, color: 'text-purple-600 bg-purple-50' },
              { action: t('dashboard.activityLinked', 'New Device Linked'), time: t('dashboard.time4hours', '4 hours ago'), icon: Activity, color: 'text-green-600 bg-green-50' },
              { action: t('dashboard.activityAudit', 'Security Audit'), time: t('dashboard.timeYesterday', 'Yesterday'), icon: CheckCircle, color: 'text-black bg-surface-container-low' },
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
          <button 
            className="w-full mt-10 py-4 border border-outline-variant/20 rounded-2xl text-xs font-black uppercase tracking-widest hover:bg-surface-container-low transition-colors"
            aria-label="View full audit log"
          >
            {t('dashboard.viewAuditLog', 'View Full Audit Log')}
          </button>
        </div>
      </div>
    </div>
  );
}
