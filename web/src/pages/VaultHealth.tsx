import React, { useMemo } from 'react';
import { Shield, ShieldAlert, RefreshCw, Copy, AlertTriangle, CheckCircle2, ArrowRight } from 'lucide-react';
import { motion } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import SEO from '../components/SEO';
import { useVault } from '../context/VaultContext';
import { passwordScore } from '../utils/passwordStrength';
import { COMMON_PASSWORDS } from '../data/common-passwords';
import type { Credential } from '../types';

interface HealthEntry {
  credential: Credential;
  score: number;
  isWeak: boolean;
  isReused: boolean;
  isCommon: boolean;
}

function computeHealth(credentials: Credential[]): {
  entries: HealthEntry[];
  weakCount: number;
  reusedCount: number;
  commonCount: number;
  healthScore: number;
} {
  const withPasswords = credentials.filter(c => c.password && c.password.length > 0);

  // Detect reused passwords: group by password string (all already in-memory)
  const passwordGroups = new Map<string, number>();
  for (const c of withPasswords) {
    const p = c.password!;
    passwordGroups.set(p, (passwordGroups.get(p) ?? 0) + 1);
  }

  const entries: HealthEntry[] = withPasswords.map(c => {
    const p = c.password!;
    const score = passwordScore(p);
    return {
      credential: c,
      score,
      isWeak:   score <= 1,
      isReused: (passwordGroups.get(p) ?? 1) > 1,
      isCommon: COMMON_PASSWORDS.has(p),
    };
  });

  const weakCount   = entries.filter(e => e.isWeak).length;
  const reusedCount = entries.filter(e => e.isReused).length;
  const commonCount = entries.filter(e => e.isCommon).length;

  const total = withPasswords.length;
  if (total === 0) return { entries, weakCount, reusedCount, commonCount, healthScore: 100 };

  const weakPenalty   = Math.min(40, (weakCount   / total) * 40);
  const reusedPenalty = Math.min(30, (reusedCount / total) * 30);
  const commonPenalty = Math.min(30, (commonCount / total) * 30);
  const healthScore   = Math.round(Math.max(0, 100 - weakPenalty - reusedPenalty - commonPenalty));

  return { entries, weakCount, reusedCount, commonCount, healthScore };
}

function ScoreGauge({ score }: { score: number }) {
  const radius = 54;
  const circ   = 2 * Math.PI * radius;
  const fill   = (score / 100) * circ;
  const color  = score >= 80 ? '#16a34a' : score >= 50 ? '#ea580c' : '#dc2626';

  return (
    <svg width="144" height="144" viewBox="0 0 144 144" className="mx-auto">
      <circle cx="72" cy="72" r={radius} fill="none" stroke="currentColor" strokeWidth="12" className="text-surface-container-high" />
      <circle
        cx="72" cy="72" r={radius} fill="none"
        stroke={color} strokeWidth="12"
        strokeDasharray={`${fill} ${circ - fill}`}
        strokeLinecap="round"
        transform="rotate(-90 72 72)"
        style={{ transition: 'stroke-dasharray 0.6s ease' }}
      />
      <text x="72" y="68" textAnchor="middle" fontSize="28" fontWeight="900" fill={color} fontFamily="sans-serif">
        {score}
      </text>
      <text x="72" y="88" textAnchor="middle" fontSize="10" fill="#888" fontFamily="sans-serif" fontWeight="700" letterSpacing="2">
        /100
      </text>
    </svg>
  );
}

function CredentialRow({ entry, navigate }: { entry: HealthEntry; navigate: ReturnType<typeof useNavigate> }) {
  const issues: string[] = [];
  if (entry.isCommon) issues.push('Breached');
  if (entry.isWeak)   issues.push('Weak');
  if (entry.isReused) issues.push('Reused');

  const severity = entry.isCommon ? 'critical' : entry.isWeak ? 'high' : 'medium';
  const borderColor = severity === 'critical' ? 'border-red-200 dark:border-red-900/50 bg-red-50 dark:bg-red-950/20'
    : severity === 'high' ? 'border-orange-200 dark:border-orange-900/50 bg-orange-50 dark:bg-orange-950/20'
    : 'border-amber-200 dark:border-amber-900/50 bg-amber-50 dark:bg-amber-950/20';

  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      className={`flex items-center gap-4 p-4 rounded-xl border ${borderColor}`}
    >
      <ShieldAlert size={18} className={severity === 'critical' ? 'text-red-600 shrink-0' : severity === 'high' ? 'text-orange-600 shrink-0' : 'text-amber-600 shrink-0'} />
      <div className="flex-1 min-w-0">
        <p className="font-bold text-sm truncate text-black dark:text-white">{entry.credential.service}</p>
        {entry.credential.username && entry.credential.username !== 'No username' && (
          <p className="text-xs text-on-surface-variant truncate">{entry.credential.username}</p>
        )}
      </div>
      <div className="flex items-center gap-2 shrink-0">
        {issues.map(issue => (
          <span key={issue} className={`text-[9px] font-black uppercase tracking-widest px-2 py-1 rounded-full ${
            issue === 'Breached' ? 'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300' :
            issue === 'Weak'     ? 'bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-300' :
            'bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300'
          }`}>
            {issue}
          </span>
        ))}
        <button
          onClick={() => navigate('/vault')}
          className="w-8 h-8 flex items-center justify-center rounded-lg bg-surface-container-high hover:bg-surface-container-highest transition-colors text-on-surface-variant"
          title="Go to vault"
        >
          <ArrowRight size={14} />
        </button>
      </div>
    </motion.div>
  );
}

export default function VaultHealth() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { credentials } = useVault();

  const { entries, weakCount, reusedCount, commonCount, healthScore } = useMemo(
    () => computeHealth(credentials),
    [credentials],
  );

  const issueEntries = entries.filter(e => e.isWeak || e.isReused || e.isCommon);
  const cleanCount   = entries.length - issueEntries.length;

  const scoreLabel = healthScore >= 90 ? 'Excellent' : healthScore >= 75 ? 'Good' : healthScore >= 50 ? 'Fair' : 'Poor';
  const scoreColor = healthScore >= 75 ? 'text-green-600' : healthScore >= 50 ? 'text-orange-600' : 'text-red-600';

  return (
    <div className="max-w-5xl mx-auto">
      <SEO
        title="Vault Health"
        description="Password health dashboard for your PWDnow vault."
      />

      <div className="mb-10">
        <h1 className="text-4xl font-headline font-black tracking-tighter text-black dark:text-white mb-2">
          {t('health.title', 'Vault Health')}
        </h1>
        <p className="text-on-surface-variant">
          {t('health.subtitle', 'A real-time audit of your vault passwords - weak, reused, and known-compromised passwords.')}
        </p>
      </div>

      {/* ── Score + Summary ─────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
        {/* Score gauge */}
        <div className="md:col-span-1 bg-surface-container-low rounded-2xl p-8 flex flex-col items-center justify-center border border-outline-variant/20">
          <ScoreGauge score={healthScore} />
          <p className={`font-headline font-black text-lg mt-3 ${scoreColor}`}>{t(`health.${scoreLabel.toLowerCase()}`, scoreLabel)}</p>
          <p className="text-xs text-on-surface-variant mt-1 text-center">
            {t('health.basedOn', { count: entries.length, defaultValue: `Based on ${entries.length} credential${entries.length !== 1 ? 's' : ''} with passwords` })}
          </p>
        </div>

        {/* Stats */}
        <div className="md:col-span-2 grid grid-cols-2 gap-4">
          {[
            { labelKey: 'compromised', label: 'Compromised', value: commonCount,  color: 'text-red-600',    bg: 'bg-red-50 dark:bg-red-950/20',    border: 'border-red-200 dark:border-red-900/50',    descKey: 'compromisedDesc', desc: 'Found in known breach lists' },
            { labelKey: 'weak',        label: 'Weak',        value: weakCount,    color: 'text-orange-600', bg: 'bg-orange-50 dark:bg-orange-950/20', border: 'border-orange-200 dark:border-orange-900/50', descKey: 'weakDesc', desc: 'Short or simple passwords' },
            { labelKey: 'reused',      label: 'Reused',      value: reusedCount,  color: 'text-amber-600',  bg: 'bg-amber-50 dark:bg-amber-950/20',  border: 'border-amber-200 dark:border-amber-900/50',  descKey: 'reusedDesc', desc: 'Same password across accounts' },
            { labelKey: 'healthy',     label: 'Healthy',     value: cleanCount,   color: 'text-green-600',  bg: 'bg-green-50 dark:bg-green-950/20',  border: 'border-green-200 dark:border-green-900/50',  descKey: 'healthyDesc', desc: 'No issues detected' },
          ].map(({ labelKey, label, value, color, bg, border, descKey, desc }) => (
            <div key={label} className={`rounded-2xl p-5 border ${bg} ${border}`}>
              <p className={`text-3xl font-black font-headline ${color}`}>{value}</p>
              <p className="text-xs font-black uppercase tracking-widest text-on-surface-variant mt-0.5">{t(`health.${labelKey}`, label)}</p>
              <p className="text-xs text-on-surface-variant mt-1 opacity-70">{t(`health.${descKey}`, desc)}</p>
            </div>
          ))}
        </div>
      </div>

      {/* ── Issues list ─────────────────────────────────────────────────────── */}
      {issueEntries.length > 0 ? (
        <section className="mb-12">
          <div className="flex items-center justify-between mb-5">
            <h2 className="text-xl font-headline font-extrabold tracking-tight">
              {t('health.issuesFound', { count: issueEntries.length, defaultValue: `Issues Found (${issueEntries.length})` })}
            </h2>
            <button
              onClick={() => navigate('/vault')}
              className="flex items-center gap-2 text-xs font-bold text-on-surface-variant hover:text-black dark:hover:text-white transition-colors"
            >
              {t('health.goToVault', 'Go to Vault')} <ArrowRight size={14} />
            </button>
          </div>
          <div className="space-y-3">
            {issueEntries.map(entry => (
              <CredentialRow key={String(entry.credential.id)} entry={entry} navigate={navigate} />
            ))}
          </div>
        </section>
      ) : entries.length > 0 ? (
        <section className="mb-12 flex flex-col items-center py-16 text-center gap-4">
          <div className="w-16 h-16 rounded-full bg-green-100 dark:bg-green-950/40 flex items-center justify-center">
            <CheckCircle2 size={32} className="text-green-600" />
          </div>
          <div>
            <h2 className="font-headline font-black text-2xl text-black dark:text-white mb-2">{t('health.allClear', 'All Clear')}</h2>
            <p className="text-on-surface-variant text-sm">{t('health.allClearDesc', 'No weak, reused, or compromised passwords detected.')}</p>
          </div>
        </section>
      ) : (
        <section className="mb-12 flex flex-col items-center py-16 text-center gap-3 text-on-surface-variant">
          <Shield size={40} className="opacity-30" />
          <p className="font-bold text-sm">{t('health.noCredentials', 'No credentials with passwords found.')}</p>
        </section>
      )}

      {/* ── What we check ──────────────────────────────────────────────────── */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-4 bg-surface-container-low/50 rounded-2xl p-8 border border-outline-variant/10">
        <div>
          <h3 className="font-bold text-sm mb-1 text-black dark:text-white">{t('health.compromisedCheck', 'Compromised Check')}</h3>
          <p className="text-xs text-on-surface-variant">{t('health.compromisedCheckDesc', 'Matches against 500+ passwords from the rockyou.txt top entries and HIBP research. Run the Breach Monitor for a deeper scan using the full 900M+ HIBP dataset.')}</p>
        </div>
        <div>
          <h3 className="font-bold text-sm mb-1 text-black dark:text-white">{t('health.strengthAnalysis', 'Strength Analysis')}</h3>
          <p className="text-xs text-on-surface-variant">{t('health.strengthAnalysisDesc', 'Evaluates length, character diversity (uppercase, lowercase, numbers, symbols). Passwords scoring ≤ 1/5 are flagged as weak.')}</p>
        </div>
        <div>
          <h3 className="font-bold text-sm mb-1 text-black dark:text-white">{t('health.reuseDetection', 'Reuse Detection')}</h3>
          <p className="text-xs text-on-surface-variant">{t('health.reuseDetectionDesc', 'Identifies passwords shared across multiple accounts. All comparisons happen locally - your passwords never leave this page.')}</p>
        </div>
      </section>
    </div>
  );
}
