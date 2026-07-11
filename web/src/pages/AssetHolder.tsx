import React, { useState, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Mail, Phone, KeyRound, Plus, X, Save, CheckCircle2, Info, AlertCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useVault } from '../context/VaultContext';
import { generateUUID } from '../utils/crypto';
import SEO from '../components/SEO';
import PhoneCountrySelect from '../components/PhoneCountrySelect';

import COUNTRIES from '../data/countries.json';

/* ─── Types ────────────────────────────────────────────────────────────── */

interface EmailEntry { id: string; value: string; error?: string | null }
interface PhoneEntry { id: string; iso: string; value: string }
interface U2fEntry   { id: string; value: string }

/* ─── Helpers ──────────────────────────────────────────────────────────── */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function fieldId(section: string, index: number, suffix = '') {
  return `asset-${section}-${index}${suffix ? `-${suffix}` : ''}`;
}

/* ─── Component ────────────────────────────────────────────────────────── */

export default function AssetHolder() {
  const { t } = useTranslation();
  const { assetHolder, updateAssetHolder } = useVault();

  /* ── State ────────────────────────────────────────────────────────────── */
  const [emails, setEmails] = useState<EmailEntry[]>(
    assetHolder.emails.length > 0
      ? assetHolder.emails.map(e => ({ id: generateUUID(), value: e }))
      : [{ id: generateUUID(), value: '' }],
  );
  const [phoneNumbers, setPhoneNumbers] = useState<PhoneEntry[]>(
    assetHolder.phoneNumbers.length > 0
      ? assetHolder.phoneNumbers.map(p => {
          const match = COUNTRIES.find(c => p.startsWith(c.code));
          return match
            ? { id: generateUUID(), iso: match.iso, value: p.replace(match.code, '').trim() }
            : { id: generateUUID(), iso: 'US', value: p };
        })
      : [{ id: generateUUID(), iso: 'US', value: '' }],
  );
  const [u2fKeys, setU2fKeys] = useState<U2fEntry[]>(
    assetHolder.u2fKeys.length > 0
      ? assetHolder.u2fKeys.map(u => ({ id: generateUUID(), value: u }))
      : [{ id: generateUUID(), value: '' }],
  );

  const [saved, setSaved] = useState(false);
  const saveTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  /* ── Email handlers ──────────────────────────────────────────────────── */
  const addEmail = useCallback(() => {
    setEmails(prev => [...prev, { id: generateUUID(), value: '' }]);
  }, []);

  const updateEmail = useCallback((id: string, value: string) => {
    setEmails(prev => prev.map(item => {
      if (item.id !== id) return item;
      const error = value && !EMAIL_RE.test(value) ? t('assetHolder.invalidEmail', 'Invalid email format') : null;
      return { ...item, value, error };
    }));
  }, [t]);

  const cleanEmail = useCallback((id: string) => {
    setEmails(prev => prev.map(item => {
      if (item.id !== id || !item.value.includes('@')) return item;
      return { ...item, value: item.value.replace(/[^\w@.-]/g, '') };
    }));
  }, []);

  const removeEmail = useCallback((id: string) => {
    setEmails(prev => prev.length > 1 ? prev.filter(item => item.id !== id) : prev);
  }, []);

  /* ── Phone handlers ──────────────────────────────────────────────────── */
  const formatPhoneNumber = useCallback((value: string, iso: string) => {
    const digits = value.replace(/\D/g, '');
    const country = COUNTRIES.find(c => c.iso === iso);
    if (!country || !country.format) return digits;
    let result = '';
    let digitIndex = 0;
    for (let i = 0; i < country.format.length && digitIndex < digits.length; i++) {
      if (country.format[i].toLowerCase() === 'x') {
        result += digits[digitIndex++];
      } else {
        result += country.format[i];
      }
    }
    return result;
  }, []);

  const addPhoneNumber = useCallback(() => {
    setPhoneNumbers(prev => [...prev, { id: generateUUID(), iso: 'US', value: '' }]);
  }, []);

  const updatePhoneNumber = useCallback((id: string, field: 'iso' | 'value', val: string) => {
    setPhoneNumbers(prev => prev.map(item => {
      if (item.id !== id) return item;
      if (field === 'value') return { ...item, value: formatPhoneNumber(val, item.iso) };
      return { ...item, iso: val, value: formatPhoneNumber(item.value, val) };
    }));
  }, [formatPhoneNumber]);

  const removePhoneNumber = useCallback((id: string) => {
    setPhoneNumbers(prev => prev.length > 1 ? prev.filter(item => item.id !== id) : prev);
  }, []);

  /* ── U2F handlers ────────────────────────────────────────────────────── */
  const addU2fKey = useCallback(() => {
    setU2fKeys(prev => prev.length < 2 ? [...prev, { id: generateUUID(), value: '' }] : prev);
  }, []);

  const updateU2fKey = useCallback((id: string, value: string) => {
    setU2fKeys(prev => prev.map(item => item.id === id ? { ...item, value } : item));
  }, []);

  const removeU2fKey = useCallback((id: string) => {
    setU2fKeys(prev => prev.length > 1 ? prev.filter(item => item.id !== id) : prev);
  }, []);

  /* ── Save ─────────────────────────────────────────────────────────────── */
  const handleSave = useCallback(() => {
    updateAssetHolder({
      emails: emails.map(e => e.value).filter(Boolean),
      phoneNumbers: phoneNumbers.map(p => {
        const country = COUNTRIES.find(c => c.iso === p.iso);
        return `${country?.code || '+1'} ${p.value}`;
      }).filter(v => v.trim().length > 3),
      u2fKeys: u2fKeys.map(u => u.value).filter(Boolean),
    });
    setSaved(true);
    if (saveTimeoutRef.current) clearTimeout(saveTimeoutRef.current);
    saveTimeoutRef.current = setTimeout(() => setSaved(false), 3000);
  }, [emails, phoneNumbers, u2fKeys, updateAssetHolder]);

  const hasErrors = emails.some(e => !!e.error);

  /* ── Render ──────────────────────────────────────────────────────────── */
  return (
    <div className="max-w-4xl mx-auto pb-24">
      <SEO
        title={t('sidebar.assetHolder', 'Asset Holder')}
        description="Manage your identity templates — emails, phone numbers, and security keys for credential auto-fill."
      />

      {/* ── Page header ─────────────────────────────────────────────────── */}
      <header className="mb-10">
        <h1 className="text-3xl md:text-4xl font-headline font-black tracking-tighter mb-3 text-black dark:text-white">
          {t('sidebar.assetHolder', 'Asset Holder')}
        </h1>
        <p className="text-base text-on-surface-variant font-medium max-w-2xl">
          {t('assetHolder.subtitle', 'Store your shared identifiers once. They auto-suggest in the credential form so you never retype them.')}
        </p>
      </header>

      {/* ── How it works banner ─────────────────────────────────────────── */}
      <div
        role="note"
        className="flex items-start gap-3 p-4 mb-8 rounded-xl border border-blue-200 dark:border-blue-900/40 bg-blue-50/60 dark:bg-blue-950/20"
      >
        <Info size={18} className="text-blue-600 dark:text-blue-400 shrink-0 mt-0.5" aria-hidden="true" />
        <p className="text-sm text-blue-900 dark:text-blue-200">
          {t('assetHolder.howItWorks', 'When you add or edit a credential, the fields below auto-suggest your saved emails, phone numbers, and security key names — saving you time and avoiding typos.')}
        </p>
      </div>

      <div className="space-y-8">
        {/* ═══════════════════════════════════════════════════════════════════
            EMAIL SECTION
            ═══════════════════════════════════════════════════════════════════ */}
        <section
          aria-labelledby="section-email-title"
          className="bg-white dark:bg-surface-container-low rounded-2xl border border-outline-variant/30 dark:border-outline-variant/20 shadow-sm"
        >
          {/* Section header */}
          <div className="flex items-center justify-between px-6 py-5 border-b border-outline-variant/15 dark:border-outline-variant/10">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-blue-100 dark:bg-blue-950/40 flex items-center justify-center" aria-hidden="true">
                <Mail size={18} className="text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <h2 id="section-email-title" className="text-base font-bold text-black dark:text-white">
                  {t('assetHolder.emailTitle', 'Email Addresses')}
                </h2>
                <p className="text-xs text-on-surface-variant mt-0.5">
                  {t('assetHolder.emailDesc', 'Used as the username / email when adding login credentials.')}
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={addEmail}
              aria-label={t('assetHolder.add', 'Add') + ' email'}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-blue-900 dark:text-blue-300 bg-blue-50 dark:bg-blue-950/30 hover:bg-blue-100 dark:hover:bg-blue-900/40 border border-blue-200 dark:border-blue-800/40 rounded-lg transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-[#1a1a1a]"
            >
              <Plus size={14} aria-hidden="true" />
              {t('assetHolder.add', 'Add')}
            </button>
          </div>

          {/* Email fields */}
          <div className="p-6 space-y-4">
            <AnimatePresence initial={false}>
              {emails.map((item, index) => (
                <motion.div
                  key={item.id}
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.2 }}
                  className="space-y-1.5"
                >
                  <div className="flex items-center gap-3">
                    <div className="flex-1">
                      <label htmlFor={fieldId('email', index)} className="sr-only">
                        {t('assetHolder.emailAddresses', 'Email Addresses')} {index + 1}
                      </label>
                      <input
                        id={fieldId('email', index)}
                        type="email"
                        value={item.value}
                        onChange={(e) => updateEmail(item.id, e.target.value)}
                        onBlur={() => cleanEmail(item.id)}
                        placeholder={t('assetHolder.emailPlaceholder', 'name@example.com')}
                        aria-invalid={!!item.error}
                        aria-describedby={item.error ? fieldId('email', index, 'error') : undefined}
                        autoComplete="email"
                        className={`w-full px-4 py-3 bg-white dark:bg-surface-container rounded-lg border text-sm text-black dark:text-white placeholder:text-on-surface-variant/60 font-medium transition-all outline-none focus-visible:ring-2 focus-visible:ring-offset-1 dark:focus-visible:ring-offset-[#1a1a1a] ${
                          item.error
                            ? 'border-red-400 dark:border-red-500 focus-visible:ring-red-500/40'
                            : 'border-outline-variant/40 dark:border-outline-variant/30 hover:border-outline-variant/70 dark:hover:border-outline-variant/50 focus-visible:ring-blue-500/40 focus-visible:border-blue-400'
                        }`}
                      />
                    </div>
                    {emails.length > 1 && (
                      <button
                        type="button"
                        onClick={() => removeEmail(item.id)}
                        aria-label={`${t('common.remove', 'Remove')} email ${index + 1}`}
                        className="p-2.5 text-on-surface-variant hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/20 rounded-lg transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:ring-offset-1 dark:focus-visible:ring-offset-[#1a1a1a]"
                      >
                        <X size={16} aria-hidden="true" />
                      </button>
                    )}
                  </div>
                  {item.error && (
                    <motion.p
                      id={fieldId('email', index, 'error')}
                      role="alert"
                      initial={{ opacity: 0, y: -4 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="flex items-center gap-1.5 text-xs font-semibold text-red-600 dark:text-red-400 pl-1"
                    >
                      <AlertCircle size={12} aria-hidden="true" />
                      {item.error}
                    </motion.p>
                  )}
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </section>

        {/* ═══════════════════════════════════════════════════════════════════
            PHONE SECTION
            ═══════════════════════════════════════════════════════════════════ */}
        <section
          aria-labelledby="section-phone-title"
          className="bg-white dark:bg-surface-container-low rounded-2xl border border-outline-variant/30 dark:border-outline-variant/20 shadow-sm"
        >
          <div className="flex items-center justify-between px-6 py-5 border-b border-outline-variant/15 dark:border-outline-variant/10">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-emerald-100 dark:bg-emerald-950/40 flex items-center justify-center" aria-hidden="true">
                <Phone size={18} className="text-emerald-600 dark:text-emerald-400" />
              </div>
              <div>
                <h2 id="section-phone-title" className="text-base font-bold text-black dark:text-white">
                  {t('assetHolder.phoneTitle', 'Phone Numbers')}
                </h2>
                <p className="text-xs text-on-surface-variant mt-0.5">
                  {t('assetHolder.phoneDesc', 'Used for 2FA (SMS / authenticator). Suggests when the 2FA tag is enabled.')}
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={addPhoneNumber}
              aria-label={t('assetHolder.add', 'Add') + ' phone number'}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-emerald-900 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/30 hover:bg-emerald-100 dark:hover:bg-emerald-900/40 border border-emerald-200 dark:border-emerald-800/40 rounded-lg transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-[#1a1a1a]"
            >
              <Plus size={14} aria-hidden="true" />
              {t('assetHolder.add', 'Add')}
            </button>
          </div>

          <div className="p-6 space-y-4">
            <AnimatePresence initial={false}>
              {phoneNumbers.map((item, index) => (
                <motion.div
                  key={item.id}
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  <div className="flex items-center gap-3">
                    <label htmlFor={fieldId('phone', index)} className="sr-only">
                      {t('assetHolder.phoneNumbers', 'Phone Numbers')} {index + 1}
                    </label>
                    <PhoneCountrySelect
                      value={item.iso}
                      onChange={(iso) => updatePhoneNumber(item.id, 'iso', iso)}
                      countries={COUNTRIES}
                    />
                    <input
                      id={fieldId('phone', index)}
                      type="tel"
                      value={item.value}
                      onChange={(e) => updatePhoneNumber(item.id, 'value', e.target.value)}
                      placeholder={COUNTRIES.find(c => c.iso === item.iso)?.format?.toLowerCase() || '0000000000'}
                      autoComplete="tel"
                      className="flex-1 px-4 py-3 bg-white dark:bg-surface-container rounded-lg border border-outline-variant/40 dark:border-outline-variant/30 hover:border-outline-variant/70 dark:hover:border-outline-variant/50 text-sm text-black dark:text-white placeholder:text-on-surface-variant/60 font-medium transition-all outline-none focus-visible:ring-2 focus-visible:ring-emerald-500/40 focus-visible:border-emerald-400 focus-visible:ring-offset-1 dark:focus-visible:ring-offset-[#1a1a1a]"
                    />
                    {phoneNumbers.length > 1 && (
                      <button
                        type="button"
                        onClick={() => removePhoneNumber(item.id)}
                        aria-label={`${t('common.remove', 'Remove')} phone ${index + 1}`}
                        className="p-2.5 text-on-surface-variant hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/20 rounded-lg transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:ring-offset-1 dark:focus-visible:ring-offset-[#1a1a1a]"
                      >
                        <X size={16} aria-hidden="true" />
                      </button>
                    )}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </section>

        {/* ═══════════════════════════════════════════════════════════════════
            U2F KEYS SECTION
            ═══════════════════════════════════════════════════════════════════ */}
        <section
          aria-labelledby="section-u2f-title"
          className="bg-white dark:bg-surface-container-low rounded-2xl border border-outline-variant/30 dark:border-outline-variant/20 shadow-sm"
        >
          <div className="flex items-center justify-between px-6 py-5 border-b border-outline-variant/15 dark:border-outline-variant/10">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-amber-100 dark:bg-amber-950/40 flex items-center justify-center" aria-hidden="true">
                <KeyRound size={18} className="text-amber-600 dark:text-amber-400" />
              </div>
              <div>
                <h2 id="section-u2f-title" className="text-base font-bold text-black dark:text-white">
                  {t('assetHolder.u2fTitle', 'Security Keys (U2F)')}
                </h2>
                <p className="text-xs text-on-surface-variant mt-0.5">
                  {t('assetHolder.u2fDesc', 'Hardware key names (YubiKey, etc.). Suggests when the U2F tag is enabled on a credential.')}
                </p>
              </div>
            </div>
            {u2fKeys.length < 2 && (
              <button
                type="button"
                onClick={addU2fKey}
                aria-label={t('assetHolder.add', 'Add') + ' security key'}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-amber-900 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/30 hover:bg-amber-100 dark:hover:bg-amber-900/40 border border-amber-200 dark:border-amber-800/40 rounded-lg transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-500 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-[#1a1a1a]"
              >
                <Plus size={14} aria-hidden="true" />
                {t('assetHolder.add', 'Add')}
              </button>
            )}
          </div>

          <div className="p-6 space-y-4">
            <AnimatePresence initial={false}>
              {u2fKeys.map((item, index) => (
                <motion.div
                  key={item.id}
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  <div className="flex items-center gap-3">
                    <div className="flex-1">
                      <label htmlFor={fieldId('u2f', index)} className="sr-only">
                        {t('assetHolder.securityKeys', 'Security Keys (U2F)')} {index + 1}
                      </label>
                      <input
                        id={fieldId('u2f', index)}
                        type="text"
                        value={item.value}
                        onChange={(e) => updateU2fKey(item.id, e.target.value)}
                        placeholder={t('assetHolder.u2fPlaceholder', 'e.g. YubiKey 5C NFC')}
                        className="w-full px-4 py-3 bg-white dark:bg-surface-container rounded-lg border border-outline-variant/40 dark:border-outline-variant/30 hover:border-outline-variant/70 dark:hover:border-outline-variant/50 text-sm text-black dark:text-white placeholder:text-on-surface-variant/60 font-medium transition-all outline-none focus-visible:ring-2 focus-visible:ring-amber-500/40 focus-visible:border-amber-400 focus-visible:ring-offset-1 dark:focus-visible:ring-offset-[#1a1a1a]"
                      />
                    </div>
                    {u2fKeys.length > 1 && (
                      <button
                        type="button"
                        onClick={() => removeU2fKey(item.id)}
                        aria-label={`${t('common.remove', 'Remove')} security key ${index + 1}`}
                        className="p-2.5 text-on-surface-variant hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/20 rounded-lg transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:ring-offset-1 dark:focus-visible:ring-offset-[#1a1a1a]"
                      >
                        <X size={16} aria-hidden="true" />
                      </button>
                    )}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
            {u2fKeys.length >= 2 && (
              <p className="text-xs text-on-surface-variant pl-1">
                {t('assetHolder.u2fMax', 'Maximum 2 keys')}
              </p>
            )}
          </div>
        </section>

        {/* ═══════════════════════════════════════════════════════════════════
            SAVE BAR
            ═══════════════════════════════════════════════════════════════════ */}
        <div className="flex items-center justify-between pt-4">
          <AnimatePresence>
            {saved && (
              <motion.div
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -8 }}
                role="status"
                aria-live="polite"
                className="flex items-center gap-2 text-sm font-semibold text-green-700 dark:text-green-400"
              >
                <CheckCircle2 size={16} aria-hidden="true" />
                {t('common.saved', 'Saved successfully')}
              </motion.div>
            )}
          </AnimatePresence>

          <button
            type="button"
            onClick={handleSave}
            disabled={hasErrors}
            aria-disabled={hasErrors}
            className="ml-auto inline-flex items-center gap-2 px-6 py-3 bg-black dark:bg-white text-white dark:text-black rounded-xl font-bold text-sm tracking-wide hover:bg-neutral-800 dark:hover:bg-neutral-200 transition-all disabled:opacity-40 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-black dark:focus-visible:ring-white focus-visible:ring-offset-2 dark:focus-visible:ring-offset-[#0f0f0f]"
          >
            <Save size={16} aria-hidden="true" />
            {t('assetHolder.save', 'Save Templates')}
          </button>
        </div>
      </div>
    </div>
  );
}
