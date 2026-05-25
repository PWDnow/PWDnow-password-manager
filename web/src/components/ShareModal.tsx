import { getCsrfToken, apiFetch } from '../utils/api';
import React, { useState } from 'react';
import { X, Share2, Clock, Check, Copy, Eye, EyeOff, Loader2, Link, AlertTriangle } from 'lucide-react';
import { motion } from 'motion/react';
import { useTranslation } from 'react-i18next';
import type { Credential } from '../types';

interface Props {
  credential: Credential;
  onClose: () => void;
}

type TTL = '1h' | '24h' | '7d';

// Encrypt the credential object with a freshly generated AES-256-GCM key.
// Returns { encryptedBlob, iv, keyBase64 } - key never leaves the browser.
async function encryptCredential(cred: Credential): Promise<{ encryptedBlob: string; iv: string; keyBase64: string }> {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(cred));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  const rawKey = await crypto.subtle.exportKey('raw', key);
  return {
    encryptedBlob: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    iv: btoa(String.fromCharCode(...iv)),
    keyBase64: btoa(String.fromCharCode(...new Uint8Array(rawKey))),
  };
}

export default function ShareModal({ credential, onClose }: Props) {
  const { t } = useTranslation();
  const [ttl, setTtl] = useState<TTL>('24h');
  const [singleView, setSingleView] = useState(false);
  const [shareUrl, setShareUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');

  const TTL_LABELS: Record<TTL, string> = {
    '1h': t('share.ttl1h', '1 hour'),
    '24h': t('share.ttl24h', '24 hours'),
    '7d': t('share.ttl7d', '7 days'),
  };

  async function createShare() {
    setBusy(true);
    setError('');
    try {
      const { encryptedBlob, iv, keyBase64 } = await encryptCredential(credential);
      const data = await apiFetch<{ ok: boolean; shareId: string; error?: string }>('/api/vault/shares', {
        method: 'POST',
        body: JSON.stringify({ encryptedBlob, iv, ttl, singleView, label: credential.service }),
      });
      if (!data.ok) throw new Error(data.error ?? 'Failed to create share');
      const url = `${window.location.origin}/share/${data.shareId}#${encodeURIComponent(keyBase64)}`;
      setShareUrl(url);
    } catch (e: any) {
      setError(e.message ?? 'Something went wrong.');
    } finally {
      setBusy(false);
    }
  }

  function copyLink() {
    navigator.clipboard.writeText(shareUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 12 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95 }}
        onClick={e => e.stopPropagation()}
        className="bg-surface-container rounded-2xl w-full max-w-md shadow-2xl overflow-hidden"
      >
        <div className="flex items-center justify-between p-6 border-b border-outline-variant/20">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center">
              <Share2 size={18} className="text-white" />
            </div>
            <div>
              <h2 className="font-bold text-lg text-black dark:text-white">{t('share.shareCredential', 'Share Credential')}</h2>
              <p className="text-xs text-on-surface-variant truncate max-w-[200px]">{credential.service}</p>
            </div>
          </div>
          <button onClick={onClose} className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-surface-container-high transition-colors text-on-surface-variant">
            <X size={18} />
          </button>
        </div>

        <div className="p-6 space-y-5">
          {!shareUrl ? (
            <>
              {/* Security notice */}
              <div className="flex items-start gap-3 p-4 rounded-xl bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-900/50">
                <AlertTriangle size={16} className="text-blue-600 shrink-0 mt-0.5" />
                <p className="text-xs text-blue-800 dark:text-blue-200 leading-relaxed">
                  {t('share.securityNotice', 'Credentials are encrypted in your browser before upload. The decryption key lives only in the URL fragment — the server never sees it.')}
                </p>
              </div>

              {/* TTL picker */}
              <div>
                <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant block mb-2">
                  <Clock size={10} className="inline mr-1" /> {t('share.linkExpiresIn', 'Link Expires In')}
                </label>
                <div className="grid grid-cols-3 gap-2">
                  {(Object.entries(TTL_LABELS) as [TTL, string][]).map(([key, label]) => (
                    <button
                      key={key}
                      onClick={() => setTtl(key)}
                      className={`py-2.5 rounded-xl border-2 text-xs font-bold transition-all ${
                        ttl === key
                          ? 'border-black dark:border-white bg-black dark:bg-white text-white dark:text-black'
                          : 'border-outline-variant/30 text-on-surface-variant hover:border-outline-variant/60'
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Single view toggle */}
              <div className="flex items-center justify-between p-4 rounded-xl bg-surface-container-high">
                <div className="flex items-center gap-3">
                  {singleView ? <EyeOff size={16} className="text-on-surface-variant" /> : <Eye size={16} className="text-on-surface-variant" />}
                  <div>
                    <p className="font-bold text-sm text-black dark:text-white">{t('share.singleView', 'Single View')}</p>
                    <p className="text-xs text-on-surface-variant">{t('share.singleViewDesc', 'Link self-destructs after first view')}</p>
                  </div>
                </div>
                <button
                  onClick={() => setSingleView(!singleView)}
                  className={`w-11 h-6 rounded-full transition-colors relative ${singleView ? 'bg-black dark:bg-white' : 'bg-outline-variant/40'}`}
                >
                  <span className={`absolute top-1 w-4 h-4 rounded-full transition-all ${singleView ? 'left-6 bg-white dark:bg-black' : 'left-1 bg-white'}`} />
                </button>
              </div>

              {error && <p className="text-xs text-error font-semibold">{error}</p>}

              <button
                onClick={createShare}
                disabled={busy}
                className="w-full py-3 bg-black dark:bg-white text-white dark:text-black rounded-xl font-bold text-sm hover:opacity-90 transition-opacity disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {busy ? <Loader2 size={16} className="animate-spin" /> : <Link size={16} />}
                {t('share.generateShareLink', 'Generate Share Link')}
              </button>
            </>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center gap-3 p-4 rounded-xl bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-900/50">
                <Check size={18} className="text-green-600 shrink-0" />
                <p className="text-sm font-semibold text-green-800 dark:text-green-200">{t('share.linkCreated', 'Share link created!')}</p>
              </div>

              <div>
                <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant block mb-2">{t('share.shareLink', 'Share Link')}</label>
                <div className="flex items-center gap-2">
                  <div className="flex-1 bg-surface-container-high rounded-xl px-4 py-3 text-xs font-mono text-on-surface-variant truncate border border-outline-variant/20">
                    {shareUrl}
                  </div>
                  <button
                    onClick={copyLink}
                    className="shrink-0 w-10 h-10 flex items-center justify-center rounded-xl bg-black dark:bg-white text-white dark:text-black hover:opacity-80 transition-opacity"
                  >
                    {copied ? <Check size={16} /> : <Copy size={16} />}
                  </button>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-surface-container-high text-xs text-on-surface-variant space-y-1">
                <p>• {t('share.expiresNote', 'Expires: {{ttl}}', { ttl: TTL_LABELS[ttl] })}</p>
                {singleView && <p>• {t('share.selfDestructNote', 'Self-destructs after first view')}</p>}
                <p>• {t('share.keyNote', 'The decryption key is in the URL fragment — never transmitted to the server')}</p>
              </div>

              <button
                onClick={() => { setShareUrl(''); setSingleView(false); }}
                className="w-full py-2.5 border border-outline-variant/30 rounded-xl text-xs font-bold text-on-surface-variant hover:bg-surface-container-high transition-colors"
              >
                {t('share.createAnother', 'Create Another Share')}
              </button>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
