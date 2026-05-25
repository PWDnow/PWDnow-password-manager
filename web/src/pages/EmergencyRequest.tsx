import { apiFetch, ApiError } from '../utils/api';
import React, { useState } from 'react';
import { useParams } from 'react-router-dom';
import { ShieldAlert, Mail, User, Clock, CheckCircle2, AlertTriangle, Loader2 } from 'lucide-react';
import { motion } from 'motion/react';

type PageState = 'form' | 'submitting' | 'success' | 'error';

export default function EmergencyRequest() {
  const { token } = useParams<{ token: string }>();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [state, setState] = useState<PageState>('form');
  const [waitHours, setWaitHours] = useState<number | null>(null);
  const [errorMsg, setErrorMsg] = useState('');

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setState('submitting');
    try {
      const data = await apiFetch<{ ok: boolean; waitPeriodHours?: number; error?: string }>(
        `/api/emergency/request/${token}`,
        {
          method: 'POST',
          body: JSON.stringify({ requesterName: name.trim(), requesterEmail: email.trim() }),
        }
      );
      if (!data.ok) throw new Error(data.error ?? 'request_failed');
      setWaitHours(data.waitPeriodHours ?? null);
      setState('success');
    } catch (err: unknown) {
      const isNotFound =
        (err instanceof ApiError && (err.data as { error?: string })?.error === 'not_found') ||
        (err instanceof Error && err.message === 'not_found');
      setErrorMsg(isNotFound ? 'This emergency access link is invalid or has been revoked.' : 'Something went wrong. Please try again.');
      setState('error');
    }
  }

  return (
    <div className="min-h-screen bg-surface flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md"
      >
        {/* Header */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-primary-container flex items-center justify-center mx-auto mb-4">
            <ShieldAlert size={32} className="text-white" />
          </div>
          <h1 className="text-2xl font-headline font-black tracking-tight text-black dark:text-white mb-2">
            Emergency Vault Access
          </h1>
          <p className="text-sm text-on-surface-variant">
            The vault owner has granted you the ability to request emergency access.
          </p>
        </div>

        <div className="bg-surface-container rounded-2xl p-8 shadow-lg">
          {state === 'form' && (
            <form onSubmit={handleSubmit} className="space-y-5">
              <div className="p-4 rounded-xl border border-amber-200 bg-amber-50 dark:bg-amber-950/20 dark:border-amber-900/50">
                <div className="flex items-start gap-3">
                  <Clock size={16} className="text-amber-600 shrink-0 mt-0.5" />
                  <p className="text-xs text-amber-800 dark:text-amber-200 leading-relaxed">
                    Your request will be sent to the vault owner. They'll have a waiting period to deny it.
                    If they don't respond, access may be granted after that period.
                  </p>
                </div>
              </div>

              <div>
                <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant block mb-2">
                  Your Full Name <span className="text-error">*</span>
                </label>
                <div className="relative">
                  <User size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant" />
                  <input
                    type="text"
                    value={name}
                    onChange={e => setName(e.target.value)}
                    placeholder="Jane Smith"
                    required
                    className="w-full pl-9 pr-4 py-3 rounded-xl bg-surface-container-high border border-outline-variant/30 text-sm text-black dark:text-white placeholder:text-on-surface-variant focus:outline-none focus:border-black dark:focus:border-white transition-colors"
                  />
                </div>
              </div>

              <div>
                <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant block mb-2">
                  Your Email (optional)
                </label>
                <div className="relative">
                  <Mail size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant" />
                  <input
                    type="email"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    placeholder="you@example.com"
                    className="w-full pl-9 pr-4 py-3 rounded-xl bg-surface-container-high border border-outline-variant/30 text-sm text-black dark:text-white placeholder:text-on-surface-variant focus:outline-none focus:border-black dark:focus:border-white transition-colors"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={!name.trim()}
                className="w-full py-3 bg-black dark:bg-white text-white dark:text-black rounded-xl font-bold text-sm hover:opacity-90 transition-opacity disabled:opacity-50 flex items-center justify-center gap-2"
              >
                <ShieldAlert size={16} />
                Submit Emergency Request
              </button>
            </form>
          )}

          {state === 'submitting' && (
            <div className="flex flex-col items-center py-10 gap-4">
              <Loader2 size={32} className="animate-spin text-on-surface-variant" />
              <p className="text-sm text-on-surface-variant font-semibold">Submitting your request…</p>
            </div>
          )}

          {state === 'success' && (
            <div className="flex flex-col items-center text-center gap-4 py-4">
              <div className="w-16 h-16 rounded-full bg-green-100 dark:bg-green-950/40 flex items-center justify-center">
                <CheckCircle2 size={32} className="text-green-600" />
              </div>
              <div>
                <h2 className="font-bold text-lg text-black dark:text-white mb-2">Request Submitted</h2>
                <p className="text-sm text-on-surface-variant leading-relaxed">
                  Your request has been sent to the vault owner. They have been notified and have
                  {waitHours ? ` ${waitHours} hours` : ' a waiting period'} to respond.
                </p>
              </div>
              <div className="p-4 rounded-xl bg-surface-container-high w-full text-left">
                <p className="text-xs font-black uppercase tracking-widest text-on-surface-variant mb-1">What happens next</p>
                <ul className="text-xs text-on-surface-variant space-y-1 list-disc list-inside">
                  <li>The owner reviews your request and can grant or deny it</li>
                  <li>If they don't respond in time, the system may allow access</li>
                  <li>You'll need to contact the owner directly for any credentials</li>
                </ul>
              </div>
            </div>
          )}

          {state === 'error' && (
            <div className="flex flex-col items-center text-center gap-4 py-4">
              <div className="w-16 h-16 rounded-full bg-red-100 dark:bg-red-950/40 flex items-center justify-center">
                <AlertTriangle size={32} className="text-red-600" />
              </div>
              <div>
                <h2 className="font-bold text-lg text-black dark:text-white mb-2">Request Failed</h2>
                <p className="text-sm text-on-surface-variant">{errorMsg}</p>
              </div>
              <button
                onClick={() => setState('form')}
                className="px-6 py-2 border border-outline-variant/30 rounded-xl text-sm font-bold hover:bg-surface-container-high transition-colors"
              >
                Try Again
              </button>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
