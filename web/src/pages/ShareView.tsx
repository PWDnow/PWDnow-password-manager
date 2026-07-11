import { apiFetch, ApiError } from '../utils/api';
import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { Share2, Copy, Check, AlertTriangle, Clock, Loader2, Eye } from 'lucide-react';
import { motion } from 'motion/react';
import type { Credential } from '../types';

type PageState = 'loading' | 'decrypting' | 'success' | 'expired' | 'already_viewed' | 'error';

async function decryptCredential(encryptedBlob: string, ivBase64: string, keyBase64: string): Promise<Credential> {
  const rawKey = Uint8Array.from(atob(keyBase64), c => c.charCodeAt(0));
  const iv     = Uint8Array.from(atob(ivBase64),  c => c.charCodeAt(0));
  const ct     = Uint8Array.from(atob(encryptedBlob), c => c.charCodeAt(0));
  const key    = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt     = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

function MaskedField({ label, value }: { label: string; value: string }) {
  const [visible, setVisible] = useState(false);
  const [copied, setCopied] = useState(false);

  function copy() {
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="space-y-1">
      <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{label}</p>
      <div className="flex items-center gap-2">
        <span className="flex-1 font-mono text-sm text-black dark:text-white break-all">
          {visible ? value : '•'.repeat(Math.min(value.length, 20))}
        </span>
        <button
          onClick={() => setVisible(v => !v)}
          className="w-7 h-7 flex items-center justify-center rounded-lg bg-surface-container-high text-on-surface-variant hover:text-black dark:hover:text-white transition-colors"
        >
          <Eye size={13} />
        </button>
        <button
          onClick={copy}
          className="w-7 h-7 flex items-center justify-center rounded-lg bg-surface-container-high text-on-surface-variant hover:text-black dark:hover:text-white transition-colors"
        >
          {copied ? <Check size={13} className="text-green-600" /> : <Copy size={13} />}
        </button>
      </div>
    </div>
  );
}

function PlainField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }
  return (
    <div className="space-y-1">
      <p className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{label}</p>
      <div className="flex items-center gap-2">
        <span className="flex-1 text-sm text-black dark:text-white break-all">{value}</span>
        <button onClick={copy} className="w-7 h-7 flex items-center justify-center rounded-lg bg-surface-container-high text-on-surface-variant hover:text-black dark:hover:text-white transition-colors">
          {copied ? <Check size={13} className="text-green-600" /> : <Copy size={13} />}
        </button>
      </div>
    </div>
  );
}

export default function ShareView() {
  const { shareId } = useParams<{ shareId: string }>();
  const [state, setState] = useState<PageState>('loading');
  const [credential, setCredential] = useState<Credential | null>(null);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [isSingleView, setIsSingleView] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const keyBase64 = decodeURIComponent(window.location.hash.slice(1));
        if (!keyBase64) { setState('error'); return; }

        let data: { ok?: boolean; error?: string; expiresAt?: number; singleView?: boolean; encryptedBlob?: string; iv?: string };
        try {
          data = await apiFetch(`/api/share/${shareId}`);
        } catch (e) {
          if (e instanceof ApiError && e.status === 410) {
            setState((e.data as { error?: string })?.error === 'already_viewed' ? 'already_viewed' : 'expired');
            return;
          }
          setState('error');
          return;
        }
        if (!data.ok) { setState('error'); return; }

        setExpiresAt(data.expiresAt);
        setIsSingleView(data.singleView ?? false);
        setState('decrypting');

        const cred = await decryptCredential(data.encryptedBlob!, data.iv!, keyBase64);
        setCredential(cred);
        setState('success');
      } catch {
        setState('error');
      }
    })();
  }, [shareId]);

  return (
    <main className="min-h-screen bg-surface flex items-center justify-center p-4">
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-blue-600 flex items-center justify-center mx-auto mb-4">
            <Share2 size={32} className="text-white" />
          </div>
          <h1 className="text-2xl font-headline font-black tracking-tight text-black dark:text-white mb-2">
            Shared Credential
          </h1>
          <p className="text-sm text-on-surface-variant">Encrypted by the sender - decrypted in your browser.</p>
        </div>

        <div className="bg-surface-container rounded-2xl p-8 shadow-lg">
          {(state === 'loading' || state === 'decrypting') && (
            <div className="flex flex-col items-center py-10 gap-4">
              <Loader2 size={32} className="animate-spin text-on-surface-variant" />
              <p className="text-sm text-on-surface-variant font-semibold">
                {state === 'loading' ? 'Loading…' : 'Decrypting…'}
              </p>
            </div>
          )}

          {state === 'success' && credential && (
            <div className="space-y-5">
              {isSingleView && (
                <div className="flex items-center gap-2 p-3 rounded-xl bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-900/50">
                  <Eye size={14} className="text-amber-600 shrink-0" />
                  <p className="text-xs text-amber-800 dark:text-amber-200 font-semibold">Single-view link - this page is now invalidated.</p>
                </div>
              )}
              {expiresAt && (
                <div className="flex items-center gap-2 p-3 rounded-xl bg-surface-container-high">
                  <Clock size={14} className="text-on-surface-variant shrink-0" />
                  <p className="text-xs text-on-surface-variant">Expires {new Date(expiresAt).toLocaleString()}</p>
                </div>
              )}
              <div className="space-y-4">
                <PlainField label="Service" value={credential.service} />
                {credential.url && <PlainField label="URL" value={credential.url} />}
                {credential.username && credential.username !== 'No username' && (
                  <PlainField label="Username" value={credential.username} />
                )}
                {credential.password && <MaskedField label="Password" value={credential.password} />}
                {credential.description && <PlainField label="Notes" value={credential.description} />}
              </div>
              <p className="text-xs text-on-surface-variant text-center pt-2">
                Shared via <span className="font-bold">PWDnow</span> - zero-knowledge encrypted sharing
              </p>
            </div>
          )}

          {state === 'expired' && (
            <div className="flex flex-col items-center text-center gap-4 py-6">
              <div className="w-14 h-14 rounded-full bg-amber-100 dark:bg-amber-950/40 flex items-center justify-center">
                <Clock size={28} className="text-amber-600" />
              </div>
              <div>
                <h2 className="font-bold text-lg text-black dark:text-white mb-1">Link Expired</h2>
                <p className="text-sm text-on-surface-variant">This share link has expired and is no longer accessible.</p>
              </div>
            </div>
          )}

          {state === 'already_viewed' && (
            <div className="flex flex-col items-center text-center gap-4 py-6">
              <div className="w-14 h-14 rounded-full bg-blue-100 dark:bg-blue-950/40 flex items-center justify-center">
                <Eye size={28} className="text-blue-600" />
              </div>
              <div>
                <h2 className="font-bold text-lg text-black dark:text-white mb-1">Already Viewed</h2>
                <p className="text-sm text-on-surface-variant">This single-view link has already been accessed and is no longer valid.</p>
              </div>
            </div>
          )}

          {state === 'error' && (
            <div className="flex flex-col items-center text-center gap-4 py-6">
              <div className="w-14 h-14 rounded-full bg-red-100 dark:bg-red-950/40 flex items-center justify-center">
                <AlertTriangle size={28} className="text-red-600" />
              </div>
              <div>
                <h2 className="font-bold text-lg text-black dark:text-white mb-1">Link Invalid</h2>
                <p className="text-sm text-on-surface-variant">This share link is invalid, has been revoked, or the decryption key is missing from the URL.</p>
              </div>
            </div>
          )}
        </div>
      </motion.div>
    </main>
  );
}
