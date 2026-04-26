import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Key, Plus, X, Save } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useVault } from '../context/VaultContext';
import { generateUUID } from '../utils/crypto';
import SEO from '../components/SEO';
import PhoneCountrySelect from '../components/PhoneCountrySelect';

import COUNTRIES from '../data/countries.json';

export default function AssetHolder() {
  const { t } = useTranslation();
  const { assetHolder, updateAssetHolder } = useVault();
  const [emails, setEmails] = useState<{id: string, value: string, error?: string | null}[]>(
    assetHolder.emails.length > 0 
      ? assetHolder.emails.map(e => ({ id: generateUUID(), value: e })) 
      : [{ id: generateUUID(), value: '' }]
  );
  const [phoneNumbers, setPhoneNumbers] = useState<{id: string, iso: string, value: string}[]>(
    assetHolder.phoneNumbers.length > 0 
      ? assetHolder.phoneNumbers.map(p => {
          const match = COUNTRIES.find(c => p.startsWith(c.code));
          if (match) {
            return { id: generateUUID(), iso: match.iso, value: p.replace(match.code, '').trim() };
          }
          return { id: generateUUID(), iso: 'US', value: p };
        }) 
      : [{ id: generateUUID(), iso: 'US', value: '' }]
  );
  const [u2fKeys, setU2fKeys] = useState<{id: string, value: string}[]>(
    assetHolder.u2fKeys.length > 0 
      ? assetHolder.u2fKeys.map(u => ({ id: generateUUID(), value: u })) 
      : [{ id: generateUUID(), value: '' }]
  );

  const addEmail = () => {
    setEmails([...emails, { id: generateUUID(), value: '' }]);
  };

  const updateEmail = (id: string, value: string) => {
    setEmails(emails.map(item => {
      if (item.id === id) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const error = value && !emailRegex.test(value) ? 'Invalid email format' : null;
        return { ...item, value, error };
      }
      return item;
    }));
  };

  const cleanEmail = (id: string) => {
    setEmails(emails.map(item => {
      if (item.id === id && item.value.includes('@')) {
        const cleaned = item.value.replace(/[^\w@.-]/g, '');
        return { ...item, value: cleaned };
      }
      return item;
    }));
  };

  const removeEmail = (id: string) => {
    if (emails.length > 1) {
      setEmails(emails.filter(item => item.id !== id));
    }
  };

  const addPhoneNumber = () => {
    setPhoneNumbers([...phoneNumbers, { id: generateUUID(), iso: 'US', value: '' }]);
  };

  const formatPhoneNumber = (value: string, iso: string) => {
    const digits = value.replace(/\D/g, '');
    const country = COUNTRIES.find(c => c.iso === iso);
    if (!country || !country.format) return digits;
    
    let result = '';
    let digitIndex = 0;
    for (let i = 0; i < country.format.length && digitIndex < digits.length; i++) {
      if (country.format[i] === 'x') {
        result += digits[digitIndex++];
      } else {
        result += country.format[i];
      }
    }
    if (digitIndex < digits.length) {
      result += digits.slice(digitIndex);
    }
    return result;
  };

  const updatePhoneNumber = (id: string, field: 'iso' | 'value', val: string) => {
    setPhoneNumbers(phoneNumbers.map(item => {
      if (item.id === id) {
        if (field === 'value') {
          return { ...item, value: formatPhoneNumber(val, item.iso) };
        }
        return { ...item, iso: val, value: formatPhoneNumber(item.value, val) };
      }
      return item;
    }));
  };

  const removePhoneNumber = (id: string) => {
    if (phoneNumbers.length > 1) {
      setPhoneNumbers(phoneNumbers.filter(item => item.id !== id));
    }
  };

  const addU2fKey = () => {
    if (u2fKeys.length < 2) {
      setU2fKeys([...u2fKeys, { id: generateUUID(), value: '' }]);
    }
  };

  const updateU2fKey = (id: string, value: string) => {
    setU2fKeys(u2fKeys.map(item => item.id === id ? { ...item, value } : item));
  };

  const removeU2fKey = (id: string) => {
    if (u2fKeys.length > 1) {
      setU2fKeys(u2fKeys.filter(item => item.id !== id));
    }
  };

  const handleSave = () => {
    updateAssetHolder({
      emails: emails.map(e => e.value).filter(Boolean),
      phoneNumbers: phoneNumbers.map(p => {
        const country = COUNTRIES.find(c => c.iso === p.iso);
        return `${country?.code || '+1'} ${p.value}`;
      }).filter(v => v.trim().length > 3),
      u2fKeys: u2fKeys.map(u => u.value).filter(Boolean)
    });
  };

  return (
    <div className="max-w-4xl mx-auto pb-24">
      <div className="mb-12">
        <h1 className="text-3xl md:text-4xl font-headline font-black tracking-tighter mb-4">{t('sidebar.assetHolder', 'Asset holder')}</h1>
        <p className="text-base md:text-lg text-on-surface-variant font-medium">Configure template values for credentials.</p>
      </div>

      <div className="space-y-8">
        {/* Emails Section */}
        <div className="bg-white dark:bg-surface-container-low rounded-3xl p-8 border border-outline-variant/10 shadow-sm">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-headline font-black tracking-tight">Email Addresses</h2>
            <button
              onClick={addEmail}
              className="p-2 bg-surface-container-low hover:bg-surface-container-high rounded-lg transition-colors text-black dark:text-white"
            >
              <Plus size={20} />
            </button>
          </div>
          <div className="space-y-4">
            {emails.map((item, index) => (
              <div key={item.id} className="space-y-2">
                <div className="flex items-center gap-4 relative group">
                  <input
                    type="email"
                    value={item.value}
                    onChange={(e) => updateEmail(item.id, e.target.value)}
                    onBlur={() => cleanEmail(item.id)}
                    placeholder="name@example.com"
                    className={`flex-1 px-6 py-4 bg-surface-container-low rounded-xl border-none text-black dark:text-white placeholder:text-outline-variant font-bold focus:ring-2 ${item.error ? 'focus:ring-red-500/20 ring-1 ring-red-500' : 'focus:ring-on-primary-container/20'} transition-all outline-none`}
                  />
                  {emails.length > 1 && (
                    <button
                      onClick={() => removeEmail(item.id)}
                      className="p-4 text-on-surface-variant hover:text-error hover:bg-error/10 rounded-xl transition-all"
                    >
                      <X size={20} />
                    </button>
                  )}
                </div>
                {item.error && (
                  <motion.p 
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="text-[10px] font-bold text-red-600 uppercase tracking-wider ml-2"
                  >
                    {item.error}
                  </motion.p>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Phone Numbers Section */}
        <div className="bg-white dark:bg-surface-container-low rounded-3xl p-8 border border-outline-variant/10 shadow-sm">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-headline font-black tracking-tight">Phone Numbers</h2>
            <button
              onClick={addPhoneNumber}
              className="p-2 bg-surface-container-low hover:bg-surface-container-high rounded-lg transition-colors text-black dark:text-white"
            >
              <Plus size={20} />
            </button>
          </div>
          <div className="space-y-4">
            {phoneNumbers.map((item, index) => (
              <div key={item.id} className="flex items-center gap-4 relative group">
                <div className="flex flex-1 gap-3">
                  <PhoneCountrySelect
                    value={item.iso}
                    onChange={(iso) => updatePhoneNumber(item.id, 'iso', iso)}
                    countries={COUNTRIES}
                  />
                  <input
                    type="tel"
                    value={item.value}
                    onChange={(e) => updatePhoneNumber(item.id, 'value', e.target.value)}
                    placeholder={COUNTRIES.find(c => c.iso === item.iso)?.format || "0000000000"}
                    className="flex-1 px-6 py-4 bg-surface-container-low rounded-xl border-none text-black dark:text-white placeholder:text-outline-variant font-bold focus:ring-2 focus:ring-on-primary-container/20 transition-all outline-none"
                  />
                </div>
                {phoneNumbers.length > 1 && (
                  <button
                    onClick={() => removePhoneNumber(item.id)}
                    className="p-4 text-on-surface-variant hover:text-error hover:bg-error/10 rounded-xl transition-all"
                  >
                    <X size={20} />
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* U2F Keys Section */}
        <div className="bg-white dark:bg-surface-container-low rounded-3xl p-8 border border-outline-variant/10 shadow-sm">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-headline font-black tracking-tight">Security Keys (U2F)</h2>
            {u2fKeys.length < 2 && (
              <button
                onClick={addU2fKey}
                className="p-2 bg-surface-container-low hover:bg-surface-container-high rounded-lg transition-colors text-black dark:text-white"
              >
                <Plus size={20} />
              </button>
            )}
          </div>
          <div className="space-y-4">
            {u2fKeys.map((item, index) => (
              <div key={item.id} className="flex items-center gap-4 relative group">
                <input
                  type="text"
                  value={item.value}
                  onChange={(e) => updateU2fKey(item.id, e.target.value)}
                  placeholder="Security Key Name"
                  className="flex-1 px-6 py-4 bg-surface-container-low rounded-xl border-none text-black placeholder:text-outline-variant font-bold focus:ring-2 focus:ring-on-primary-container/20 transition-all outline-none"
                />
                {u2fKeys.length > 1 && (
                  <button
                    onClick={() => removeU2fKey(item.id)}
                    className="p-4 text-on-surface-variant hover:text-error hover:bg-error/10 rounded-xl transition-all"
                  >
                    <X size={20} />
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="flex justify-end pt-8">
          <button
            onClick={handleSave}
            className="px-8 py-4 bg-black text-white rounded-xl font-black uppercase tracking-widest text-xs hover:bg-black/80 transition-all flex items-center gap-2"
          >
            <Save size={16} />
            Save Templates
          </button>
        </div>
      </div>
    </div>
  );
}
