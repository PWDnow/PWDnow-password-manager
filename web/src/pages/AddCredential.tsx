import React, { useState, useEffect, useCallback, useRef, useReducer, useMemo } from 'react';
import { ChevronRight, ChevronLeft, Calendar, RefreshCw, Copy, Info, Lock, Briefcase, User, Wallet, MoreHorizontal, Check, X, Wand2, Hash, Type, Globe, Plus, Gamepad2, Bitcoin, Dices, Folder as FolderIcon, CreditCard, Key, Clock, Eye, EyeOff, Smartphone, HelpCircle, Shield, Bold, Italic, Underline, List, Eraser, ToggleLeft, ToggleRight, FileText, ShieldCheck, Atom, ShieldAlert, Loader2, AlertTriangle } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { TOTP } from 'totp-generator';
import { useNavigate } from 'react-router-dom';
import { Folder, Credential, type CredentialType } from '../types';
import { useVault } from '../context/VaultContext';
import { generateUUID } from '../utils/crypto';
import { sanitizeSvg } from '../utils/sanitize';
import { useNotification } from '../context/NotificationContext';
import { daemon } from '../utils/daemonClient';
import { secureClipboard } from '../utils/clipboardGuard';
import { readDecryptedLocal } from '../utils/localCrypto';
import { checkHibpPassword } from '../utils/hibp';
import {
  charsetSize,
  randomPasswordBits,
  passphraseBits,
  classifyQuantum,
  crackTime,
  quantumCrackTime,
  ATTACKER_PROFILES,
  QUANTUM_PROOF_BITS,
  type AttackerProfileId,
  type CrackTime,
} from '../utils/passwordEntropy';
import PhoneCountrySelect from '../components/PhoneCountrySelect';

/** Words in the EFF long wordlist — used to score passphrase entropy. */
const EFF_WORDLIST_SIZE = 7776;

type BreachStatus = 'idle' | 'checking' | 'pwned' | 'clean' | 'unavailable' | 'error';

// Fallback for the initial render before the EFF list loads.
const WORD_LIST_FALLBACK = [
  'Bridge', 'Castle', 'Dragon', 'Eagle', 'Falcon', 'Giant', 'Horse', 'Island', 'Knight', 'Lion',
  'Mountain', 'River', 'Ocean', 'Forest', 'Desert', 'Stone', 'Fire', 'Water', 'Earth', 'Gold',
];

interface AddCredentialProps {
  folders: Folder[];
  activeTab?: string;
  initialData?: Credential;
  onCreateFolder?: () => void;
  onAddCredential?: (cred: Credential) => void;
  onUpdateCredential?: (cred: Credential) => void;
  onCancel?: () => void;
}

const ICON_MAP: Record<string, React.FC<any>> = {
  Wallet,
  Globe,
  Briefcase,
  Gamepad2,
  Bitcoin,
  Dices,
  Folder: FolderIcon,
  Shield,
  CreditCard,
  Key
};

import COUNTRIES from '../data/countries.json';
import {
  detectCardNetwork, formatPan, maskPan, maxPanLength, luhnCheck, isPanComplete,
  daysUntilExpiry, CARD_EXPIRY_MIN_DAYS, PAN_UNHIDE, BROWSER_AUTOFILL, type CardNetwork,
} from '../utils/cardUtils';

// ── Card Expiry Month/Year Picker ──────────────────────────────────────────
interface CardExpiryPickerProps {
  value: string;
  onChange: (v: string) => void;
  minDays: number;
}

function CardExpiryPicker({ value, onChange, minDays }: CardExpiryPickerProps) {
  const { t, i18n } = useTranslation();

  const monthLabels = useMemo(() => {
    const fmt = new Intl.DateTimeFormat(i18n.language, { month: 'short' });
    return Array.from({ length: 12 }, (_, idx) =>
      fmt.format(new Date(2000, idx, 1)).replace(/\.$/, '').toUpperCase()
    );
  }, [i18n.language]);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const today = new Date();
  const todayYear  = today.getFullYear();
  const todayMonth = today.getMonth() + 1; // 1-based

  const parsed        = value.match(/^(\d{1,2})\/(\d{4})$/);
  const selectedMonth = parsed ? parseInt(parsed[1], 10) : null;
  const selectedYear  = parsed ? parseInt(parsed[2], 10) : null;

  const [pickerYear, setPickerYear] = useState(selectedYear ?? todayYear);

  // Sync picker year when value is cleared externally
  useEffect(() => {
    if (!value) setPickerYear(todayYear);
  }, [value, todayYear]);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const selectMonth = (month: number) => {
    onChange(`${String(month).padStart(2, '0')}/${pickerYear}`);
    setOpen(false);
  };

  const isDisabled = (month: number) => {
    if (pickerYear < todayYear) return true;
    if (pickerYear === todayYear && month <= todayMonth) return true;
    return false;
  };

  const daysLeft   = daysUntilExpiry(value);
  const isExpired  = daysLeft !== null && daysLeft < 0;
  const isCurrent  = selectedYear === todayYear && selectedMonth === todayMonth;
  const isSoon     = daysLeft !== null && daysLeft >= 0 && daysLeft <= minDays;

  let borderCls = 'border-black/15 dark:border-white/15';
  let statusEl: React.ReactNode = null;
  if (value) {
    if (isExpired || isCurrent) {
      borderCls = 'border-red-500';
      statusEl = (
        <p className="text-[10px] font-bold text-red-600 uppercase tracking-wider flex items-center gap-1 mt-1.5">
          <AlertTriangle size={10} />{t('addCredential.cardExpired', 'This card has already expired')}
        </p>
      );
    } else if (isSoon) {
      borderCls = 'border-amber-400';
      statusEl = (
        <p className="text-[10px] font-bold text-amber-600 uppercase tracking-wider flex items-center gap-1 mt-1.5">
          <AlertTriangle size={10} />{t('addCredential.cardExpiringSoon', 'Expires in {{days}} days. Verify before saving.', { days: daysLeft })}
        </p>
      );
    }
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen(v => !v)}
        className={`w-full px-6 py-4 bg-surface-container-low rounded-xl border ${borderCls} text-black dark:text-white font-bold outline-none focus:ring-2 focus:ring-on-primary-container/20 transition-all text-left flex items-center justify-between`}
      >
        <span className={value ? 'font-mono' : 'text-outline-variant'}>
          {value || t('addCredential.cardExpiryPick', 'MM / YYYY')}
        </span>
        <Calendar size={16} className="text-on-surface-variant shrink-0" />
      </button>
      {statusEl}

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -8, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.97 }}
            transition={{ duration: 0.14 }}
            className="absolute z-50 top-full mt-2 left-0 bg-white dark:bg-surface-container-low border border-outline-variant/20 rounded-2xl shadow-2xl p-4 w-64"
          >
            {/* Year navigation */}
            <div className="flex items-center justify-between mb-3">
              <button
                type="button"
                onClick={() => setPickerYear(y => Math.max(todayYear, y - 1))}
                disabled={pickerYear <= todayYear}
                className="p-1.5 rounded-lg hover:bg-surface-container-high disabled:opacity-25 disabled:cursor-not-allowed transition-colors text-black dark:text-white"
              >
                <ChevronLeft size={16} />
              </button>
              <span className="text-sm font-black text-black dark:text-white">{pickerYear}</span>
              <button
                type="button"
                onClick={() => setPickerYear(y => Math.min(todayYear + 20, y + 1))}
                disabled={pickerYear >= todayYear + 20}
                className="p-1.5 rounded-lg hover:bg-surface-container-high disabled:opacity-25 disabled:cursor-not-allowed transition-colors text-black dark:text-white"
              >
                <ChevronRight size={16} />
              </button>
            </div>

            {/* Month grid — 4 columns × 3 rows */}
            <div className="grid grid-cols-4 gap-1">
              {monthLabels.map((name, idx) => {
                const month    = idx + 1;
                const disabled = isDisabled(month);
                const active   = selectedMonth === month && selectedYear === pickerYear;
                const dToEnd   = daysUntilExpiry(`${String(month).padStart(2, '0')}/${pickerYear}`);
                const soonWarn = !disabled && dToEnd !== null && dToEnd >= 0 && dToEnd <= minDays;

                return (
                  <button
                    key={month}
                    type="button"
                    disabled={disabled}
                    onClick={() => selectMonth(month)}
                    className={`relative py-2 rounded-xl text-[11px] font-bold transition-all text-center ${
                      active
                        ? 'bg-black dark:bg-white text-white dark:text-black'
                        : disabled
                        ? 'text-outline-variant/30 cursor-not-allowed'
                        : soonWarn
                        ? 'text-amber-700 dark:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-900/20'
                        : 'text-black dark:text-white hover:bg-surface-container-high'
                    }`}
                  >
                    {name}
                    {soonWarn && !active && (
                      <span className="absolute top-0.5 right-0.5 w-1.5 h-1.5 rounded-full bg-amber-400" />
                    )}
                  </button>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// Renders **bold**, *italic*, __underline__, and - bullet lists as React elements.
function parseMarkdown(text: string): React.ReactNode[] {
  let k = 0;

  const parseInline = (str: string): React.ReactNode[] => {
    const re = /(\*\*[\s\S]+?\*\*|__[\s\S]+?__|(?<!\*)\*(?!\*)[\s\S]+?(?<!\*)\*(?!\*))/g;
    const out: React.ReactNode[] = [];
    let last = 0;
    for (const m of str.matchAll(re)) {
      if (m.index! > last) out.push(str.slice(last, m.index));
      const tok = m[0];
      if (tok.startsWith('**'))      out.push(<strong key={k++}>{tok.slice(2, -2)}</strong>);
      else if (tok.startsWith('__')) out.push(<u key={k++}>{tok.slice(2, -2)}</u>);
      else                           out.push(<em key={k++}>{tok.slice(1, -1)}</em>);
      last = m.index! + tok.length;
    }
    if (last < str.length) out.push(str.slice(last));
    return out;
  };

  const result: React.ReactNode[] = [];
  const lines = text.split('\n');
  let i = 0;
  while (i < lines.length) {
    if (lines[i].startsWith('- ')) {
      const items: React.ReactNode[] = [];
      while (i < lines.length && lines[i].startsWith('- ')) {
        items.push(<li key={k++}>{parseInline(lines[i].slice(2))}</li>);
        i++;
      }
      result.push(<ul key={k++} className="list-disc list-inside space-y-0.5 my-1">{items}</ul>);
    } else {
      const content = parseInline(lines[i]);
      result.push(<p key={k++} className="min-h-[1.25em]">{content}</p>);
      i++;
    }
  }
  return result;
}

// ── Form state managed by useReducer ──────────────────────────────────────
interface CredentialFormState {
  credentialType: CredentialType;
  // Passkey fields
  rpId: string; rpName: string; credentialId: string; userHandle: string;
  authenticatorName: string; backedUp: boolean;
  // Secure note
  noteContent: string;
  // Payment card
  cardholderName: string; cardNumber: string; cardExpiry: string;
  cardCvv: string; cardBillingAddress: string;
  // Login basics
  title: string; username: string; url: string; password: string;
  otpSecret: string; otpAlgorithm: 'SHA1' | 'SHA256' | 'SHA512'; otpDigits: number;
  description: string; accountType: string;
  // Login identifier type + phone-as-identifier state
  usernameType: 'username' | 'email' | 'phone';
  loginPhoneIso: string;
  loginPhoneValue: string;
  // Expiry
  expiryEnabled: boolean; expiryValue: number;
  expiryUnit: 'days' | 'months' | 'years'; expiryNotifyEmail: boolean;
  // Folder + tags + arrays
  folderId: string; tags: string[];
  phoneNumbers: { id: string; iso: string; value: string }[];
  kba: { id: string; question: string; answer: string }[];
  u2fKeys: { id: string; value: string }[];
}

type FormAction =
  | { type: 'setField'; field: keyof CredentialFormState; value: CredentialFormState[keyof CredentialFormState] }
  | { type: 'reset'; from: Partial<CredentialFormState> };

function formReducer(state: CredentialFormState, action: FormAction): CredentialFormState {
  switch (action.type) {
    case 'setField': return { ...state, [action.field]: action.value };
    case 'reset': return { ...state, ...action.from };
    default: return state;
  }
}

export default function AddCredential({ folders, activeTab, initialData, onCreateFolder, onAddCredential, onUpdateCredential, onCancel }: AddCredentialProps) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const { assetHolder } = useVault();
  const effWordListRef = useRef<string[]>(WORD_LIST_FALLBACK);

  // Lazy-load the EFF long wordlist (7 776 words, ~77 bits for 6 words) so it
  // doesn't inflate the initial JS bundle.
  useEffect(() => {
    import('../data/eff-wordlist.json').then((m) => {
      effWordListRef.current = m.default as string[];
    }).catch(() => { /* stay on fallback */ });
  }, []);

  useEffect(() => {
    readDecryptedLocal('email_server_config').then(raw => {
      if (!raw) return;
      try {
        const cfg = JSON.parse(raw);
        setHasSmtp(!!(cfg?.host && cfg?.username && cfg?.password));
      } catch { /* noop */ }
    });
  }, []);
  const [showCardNumber, setShowCardNumber]     = useState(false);
  const [showCvv, setShowCvv]                   = useState(false);
  // null = unchecked, false = Luhn ok, true = Luhn failed
  const [cardLuhnError, setCardLuhnError]       = useState<boolean | null>(null);

  const [length, setLength] = useState(24);
  const [wordCount, setWordCount] = useState(6);
  const [includeUppercase, setIncludeUppercase] = useState(true);
  const [includeLowercase, setIncludeLowercase] = useState(true);
  const [includeNumbers, setIncludeNumbers] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);
  const [isPassphrase, setIsPassphrase] = useState(false);
  const [isGeneratorVisible, setIsGeneratorVisible] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState(false);
  const [urlError, setUrlError] = useState<string | null>(null);
  const [otpSecretError, setOtpSecretError] = useState<string | null>(null);
  const [usernameError, setUsernameError] = useState<string | null>(null);
  const { addNotification } = useNotification();
  const descTextareaRef = useRef<HTMLTextAreaElement>(null);
  const [hasSmtp, setHasSmtp] = useState(false);
  // HIBP breach status for the current password. Advisory only - does not
  // block submit. Kept in state rather than derived so the UI can show
  // "checking…" feedback during the async daemon round-trip.
  const [breachStatus, setBreachStatus] = useState<BreachStatus>('idle');
  // Number of times the current password appears in HIBP (0 when clean/unknown).
  const [breachCount, setBreachCount] = useState(0);
  // Which adversary the crack-time estimate is modelled against. Defaults to the
  // worst realistic case ("high-value target") so the figures stay conservative.
  const [attackerProfile, setAttackerProfile] = useState<AttackerProfileId>('nationState');

  const [showEmailSuggestions, setShowEmailSuggestions] = useState(false);
  const [showPhoneSuggestions, setShowPhoneSuggestions] = useState<string | null>(null);
  const [showU2fSuggestions, setShowU2fSuggestions] = useState<string | null>(null);

  // Default to activeTab if it's a valid folder, otherwise default to the first folder
  const initialFolder = initialData?.folderId || ((activeTab && activeTab !== 'vault' && folders.some(f => f.id === activeTab))
    ? activeTab
    : (folders[0]?.id || 'work'));

  const [formState, dispatch] = useReducer(formReducer, undefined, (): CredentialFormState => ({
    credentialType: initialData?.credentialType || 'login',
    rpId: initialData?.rpId || '',
    rpName: initialData?.rpName || '',
    credentialId: initialData?.credentialId || '',
    userHandle: initialData?.userHandle || '',
    authenticatorName: initialData?.authenticatorName || '',
    backedUp: initialData?.backedUp ?? false,
    noteContent: initialData?.noteContent || '',
    cardholderName: initialData?.cardholderName || '',
    cardNumber: initialData?.cardNumber || '',
    cardExpiry: initialData?.cardExpiry || '',
    cardCvv: initialData?.cardCvv || '',
    cardBillingAddress: initialData?.cardBillingAddress || '',
    title: initialData?.service || '',
    username: (() => {
      const u = initialData?.username;
      if (!u || u === 'No username') return '';
      // Strip the stored phone number so it doesn't bleed into the text field
      if (/^\+\d/.test(u.trim())) return '';
      return u;
    })(),
    usernameType: (() => {
      const u = initialData?.username;
      if (!u || u === 'No username') return 'username';
      if (/^\+\d/.test(u.trim())) return 'phone';
      if (u.includes('@')) return 'email';
      return 'username';
    })() as 'username' | 'email' | 'phone',
    loginPhoneIso: (() => {
      const u = initialData?.username;
      if (!u || u === 'No username') return 'US';
      const match = COUNTRIES.find(c => u.startsWith(c.code));
      return match?.iso || 'US';
    })(),
    loginPhoneValue: (() => {
      const u = initialData?.username;
      if (!u || u === 'No username') return '';
      const match = COUNTRIES.find(c => u.startsWith(c.code));
      if (match) return u.replace(match.code, '').trim();
      if (/^\+?\d/.test(u.trim())) return u.trim();
      return '';
    })(),
    url: initialData?.url || '',
    password: initialData?.password || '',
    otpSecret: initialData?.otpSecret || '',
    otpAlgorithm: (initialData as any)?.otpAlgorithm || 'SHA1',
    otpDigits: (initialData as any)?.otpDigits || 6,
    description: initialData?.description ?? '',
    accountType: initialData?.accountType ?? '',
    expiryEnabled: initialData?.expiryEnabled ?? false,
    expiryValue: initialData?.expiryValue ?? 90,
    expiryUnit: initialData?.expiryUnit ?? 'days',
    expiryNotifyEmail: initialData?.expiryNotifyEmail ?? false,
    folderId: initialFolder,
    tags: (() => {
      const initialTags = initialData?.tags || [];
      const finalTags = [...initialTags];
      if (initialData?.otpSecret && !finalTags.includes('OTP')) finalTags.push('OTP');
      if (initialData?.phoneNumber && Array.isArray(initialData.phoneNumber) && initialData.phoneNumber.length > 0 && !finalTags.includes('2FA')) finalTags.push('2FA');
      else if (initialData?.phoneNumber && typeof initialData.phoneNumber === 'string' && !finalTags.includes('2FA')) finalTags.push('2FA');
      return finalTags;
    })(),
    phoneNumbers: (() => {
      if (Array.isArray(initialData?.phoneNumber)) {
        return initialData!.phoneNumber.map(p => {
          const match = COUNTRIES.find(c => p.startsWith(c.code));
          if (match) return { id: generateUUID(), iso: match.iso, value: p.replace(match.code, '').trim() };
          return { id: generateUUID(), iso: 'US', value: p };
        });
      } else if (initialData?.phoneNumber) {
        const p = initialData.phoneNumber as string;
        const match = COUNTRIES.find(c => p.startsWith(c.code));
        if (match) return [{ id: generateUUID(), iso: match.iso, value: p.replace(match.code, '').trim() }];
        return [{ id: generateUUID(), iso: 'US', value: p }];
      }
      return [{ id: generateUUID(), iso: 'US', value: '' }];
    })(),
    kba: (() => {
      if (initialData?.kba && initialData.kba.length > 0) {
        return initialData.kba.map(k => ({ ...k, id: generateUUID() }));
      }
      if ((initialData as any)?.kbaQuestion || (initialData as any)?.kbaAnswer) {
        return [{ id: generateUUID(), question: (initialData as any).kbaQuestion || '', answer: (initialData as any).kbaAnswer || '' }];
      }
      return [{ id: generateUUID(), question: '', answer: '' }];
    })(),
    u2fKeys: (() => {
      if (Array.isArray(initialData?.u2fKeyName)) {
        return initialData!.u2fKeyName.map(u => ({ id: generateUUID(), value: u }));
      } else if (initialData?.u2fKeyName) {
        return [{ id: generateUUID(), value: initialData.u2fKeyName as string }];
      }
      return [{ id: generateUUID(), value: '' }];
    })(),
  }));

  // Destructure for convenience — all handlers continue to use the same names
  const {
    credentialType, rpId, rpName, credentialId, userHandle, authenticatorName, backedUp,
    noteContent, cardholderName, cardNumber, cardExpiry, cardCvv, cardBillingAddress,
    title, username, url, password, otpSecret, description, accountType,
    usernameType, loginPhoneIso, loginPhoneValue,
    expiryEnabled, expiryValue, expiryUnit, expiryNotifyEmail,
    folderId: selectedFolder, tags, phoneNumbers, kba, u2fKeys,
  } = formState;

  const [showFolderOptions, setShowFolderOptions] = useState(false);
  const folderOptionsRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!showFolderOptions) return;
    const handler = (e: MouseEvent) => {
      if (folderOptionsRef.current && !folderOptionsRef.current.contains(e.target as Node)) {
        setShowFolderOptions(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [showFolderOptions]);

  // Toggles markdown formatting markers around the selection.
  // Applying bold to already-bold text removes the markers instead of double-wrapping.
  const toggleWrap = (marker: string) => {
    const el = descTextareaRef.current;
    if (!el) return;
    const { selectionStart: s, selectionEnd: e, value } = el;
    const m = marker.length;

    // No selection → insert empty marker pair, place cursor between them.
    if (s === e) {
      dispatch({ type: 'setField', field: 'description', value: value.slice(0, s) + marker + marker + value.slice(s) });
      requestAnimationFrame(() => { el.focus(); el.setSelectionRange(s + m, s + m); });
      return;
    }

    const selected = value.slice(s, e);

    // Case 1: the selection itself IS the wrapped text (e.g. user selected "**bold**").
    if (
      selected.length > m * 2 &&
      selected.slice(0, m) === marker &&
      selected.slice(-m) === marker &&
      // For '*', ensure it isn't actually '**bold**' being processed by the italic handler.
      !(marker === '*' && (selected[1] === '*' || selected[selected.length - 2] === '*'))
    ) {
      const inner = selected.slice(m, -m);
      dispatch({ type: 'setField', field: 'description', value: value.slice(0, s) + inner + value.slice(e) });
      requestAnimationFrame(() => { el.focus(); el.setSelectionRange(s, s + inner.length); });
      return;
    }

    // Case 2: markers sit OUTSIDE the selection boundary in the full text
    //         (e.g. textarea has "**bold**" but only "bold" is selected).
    if (s >= m && e + m <= value.length) {
      const before = value.slice(s - m, s);
      const after  = value.slice(e, e + m);
      if (before === marker && after === marker) {
        // For '*', guard against accidentally stripping a '**' wrap.
        const bogus = marker === '*' && (
          (s - m - 1 >= 0 && value[s - m - 1] === '*') ||
          (e + m < value.length && value[e + m] === '*')
        );
        if (!bogus) {
          dispatch({ type: 'setField', field: 'description', value: value.slice(0, s - m) + selected + value.slice(e + m) });
          requestAnimationFrame(() => { el.focus(); el.setSelectionRange(s - m, s - m + selected.length); });
          return;
        }
      }
    }

    // Case 3: not wrapped → wrap.
    dispatch({ type: 'setField', field: 'description', value: value.slice(0, s) + marker + selected + marker + value.slice(e) });
    requestAnimationFrame(() => { el.focus(); el.setSelectionRange(s + m, e + m); });
  };

  // Toggles a "- " bullet prefix on the current line.
  const toggleBulletList = () => {
    const el = descTextareaRef.current;
    if (!el) return;
    const { selectionStart: s, value } = el;
    const lineStart = value.lastIndexOf('\n', s - 1) + 1;
    const lineEnd   = value.indexOf('\n', s);
    const line      = value.slice(lineStart, lineEnd === -1 ? value.length : lineEnd);
    if (line.startsWith('- ')) {
      const next = value.slice(0, lineStart) + line.slice(2) + (lineEnd === -1 ? '' : value.slice(lineEnd));
      dispatch({ type: 'setField', field: 'description', value: next });
      requestAnimationFrame(() => { el.focus(); el.setSelectionRange(Math.max(lineStart, s - 2), Math.max(lineStart, s - 2)); });
    } else {
      const next = value.slice(0, lineStart) + '- ' + line + (lineEnd === -1 ? '' : value.slice(lineEnd));
      dispatch({ type: 'setField', field: 'description', value: next });
      requestAnimationFrame(() => { el.focus(); el.setSelectionRange(s + 2, s + 2); });
    }
  };

  const clearMarkdown = () => {
    const el = descTextareaRef.current;
    if (!el) return;
    const { selectionStart: s, selectionEnd: e, value } = el;
    const cleaned = value.slice(s, e).replace(/\*\*|__|(?<!\*)\*(?!\*)/g, '');
    const newVal = value.slice(0, s) + cleaned + value.slice(e);
    dispatch({ type: 'setField', field: 'description', value: newVal });
    requestAnimationFrame(() => { el.focus(); el.setSelectionRange(s, s + cleaned.length); });
  };

  const addPhoneNumber = () => {
    if (phoneNumbers.length < 2) {
      dispatch({ type: 'setField', field: 'phoneNumbers', value: [...phoneNumbers, { id: generateUUID(), iso: 'US', value: '' }] });
    }
  };

  const formatPhoneNumber = (value: string, iso: string) => {
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
  };

  const updatePhoneNumber = (id: string, field: 'iso' | 'value', val: string) => {
    dispatch({ type: 'setField', field: 'phoneNumbers', value: phoneNumbers.map(item => {
      if (item.id === id) {
        if (field === 'value') {
          return { ...item, value: formatPhoneNumber(val, item.iso) };
        }
        return { ...item, iso: val, value: formatPhoneNumber(item.value, val) };
      }
      return item;
    }) });
  };

  const removePhoneNumber = (id: string) => {
    if (phoneNumbers.length > 1) {
      dispatch({ type: 'setField', field: 'phoneNumbers', value: phoneNumbers.filter(item => item.id !== id) });
    }
  };

  const addU2fKey = () => {
    if (u2fKeys.length < 2) {
      dispatch({ type: 'setField', field: 'u2fKeys', value: [...u2fKeys, { id: generateUUID(), value: '' }] });
    }
  };

  const updateU2fKey = (id: string, value: string) => {
    dispatch({ type: 'setField', field: 'u2fKeys', value: u2fKeys.map(item => item.id === id ? { ...item, value } : item) });
  };

  const removeU2fKey = (id: string) => {
    if (u2fKeys.length > 1) {
      dispatch({ type: 'setField', field: 'u2fKeys', value: u2fKeys.filter(item => item.id !== id) });
    }
  };

  const addKbaQuestion = () => {
    dispatch({ type: 'setField', field: 'kba', value: [...kba, { id: generateUUID(), question: '', answer: '' }] });
  };

  const updateKba = (id: string, field: 'question' | 'answer', value: string) => {
    dispatch({ type: 'setField', field: 'kba', value: kba.map(item => item.id === id ? { ...item, [field]: value } : item) });
  };

  const removeKbaQuestion = (id: string) => {
    if (kba.length > 1) {
      dispatch({ type: 'setField', field: 'kba', value: kba.filter(item => item.id !== id) });
    }
  };

  const toggleTag = (tag: string) => {
    dispatch({ type: 'setField', field: 'tags', value: tags.includes(tag) ? tags.filter(t => t !== tag) : [...tags, tag] });
  };

  const renderFolderIcon = (folder: Folder, isSelected: boolean) => {
    if (folder.customSvg) {
      return (
        <div 
          className={`w-4 h-4 shrink-0 flex items-center justify-center [&>svg]:w-full [&>svg]:h-full ${isSelected ? 'text-white' : 'text-black dark:text-white'}`}
          dangerouslySetInnerHTML={{ __html: sanitizeSvg(folder.customSvg) }}
        />
      );
    }
    
    const IconComponent = (folder.iconName && ICON_MAP[folder.iconName]) ? ICON_MAP[folder.iconName] : FolderIcon;
    return <IconComponent size={16} fill={isSelected ? "currentColor" : "none"} aria-hidden="true" />;
  };

  // CRIT-01 fix: use crypto.getRandomValues() instead of Math.random().
  // Returns a cryptographically secure integer in [0, max).
  const secureRandInt = (max: number): number => {
    const buf = new Uint32Array(1);
    // Rejection-sampling to eliminate modulo bias
    const limit = 0x100000000 - (0x100000000 % max);
    let val: number;
    do {
      crypto.getRandomValues(buf);
      val = buf[0];
    } while (val >= limit);
    return val % max;
  };

  const generatePassword = useCallback(() => {
    if (isPassphrase) {
      const wordList = effWordListRef.current;
      const words = [];
      const numberIndex = secureRandInt(wordCount);

      for (let i = 0; i < wordCount; i++) {
        let word = wordList[secureRandInt(wordList.length)];
        let modifiedWord = word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();

        if (i === numberIndex) {
          modifiedWord += secureRandInt(10);
        }

        if (includeSymbols && secureRandInt(10) > 3) {
          modifiedWord = modifiedWord
            .replace(/i/g, '!')
            .replace(/o/g, '0')
            .replace(/l/g, '1');
        }

        words.push(modifiedWord);
      }
      let result = words.join('-');

      if (includeSymbols) {
        const symbols = '!@#$%&*?';
        const symbol = symbols[secureRandInt(symbols.length)];
        if (secureRandInt(2) === 0) {
          result = symbol + result;
        } else {
          result = result + symbol;
        }
      }
      dispatch({ type: 'setField', field: 'password', value: result });
    } else {
      let charset = '';
      const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      const lowercase = 'abcdefghijklmnopqrstuvwxyz';
      const numbers = '0123456789';
      const symbols = '!@#$%^&*()_+~`|}{[]:;?><,./-=';

      if (includeUppercase) charset += uppercase;
      if (includeLowercase) charset += lowercase;
      if (includeNumbers) charset += numbers;
      if (includeSymbols) charset += symbols;

      if (charset === '') return;

      let generatedPassword = '';
      for (let i = 0; i < length; i++) {
        generatedPassword += charset[secureRandInt(charset.length)];
      }
      dispatch({ type: 'setField', field: 'password', value: generatedPassword });
    }
  }, [length, wordCount, includeUppercase, includeLowercase, includeNumbers, includeSymbols, isPassphrase]);

  useEffect(() => {
    generatePassword();
  }, [generatePassword]);

  // HIBP breach lookup, debounced. Primary: HIBP k-anonymity range API
  // (only a 5-char SHA-1 prefix leaves the browser). Fallback: daemon's
  // local cuckoo filter if the API is unreachable. Advisory only — does
  // not block save.
  useEffect(() => {
    if (!password) { setBreachStatus('idle'); setBreachCount(0); return; }
    setBreachStatus('checking');
    const snapshot = password;
    const controller = new AbortController();
    const timer = setTimeout(() => {
      checkHibpPassword(snapshot, controller.signal)
        .then(({ pwned, count }) => {
          if (snapshot !== password || controller.signal.aborted) return;
          setBreachCount(pwned ? count : 0);
          setBreachStatus(pwned ? 'pwned' : 'clean');
        })
        .catch(() => {
          if (snapshot !== password || controller.signal.aborted) return;
          // HIBP API failed — try daemon's local filter as fallback (no count).
          if (!daemon.isConnected) { setBreachStatus('unavailable'); return; }
          daemon.checkPasswordBreached(snapshot)
            .then(({ pwned, filter_available }) => {
              if (snapshot !== password) return;
              setBreachCount(0);
              if (!filter_available) setBreachStatus('unavailable');
              else setBreachStatus(pwned ? 'pwned' : 'clean');
            })
            .catch(() => { if (snapshot === password) setBreachStatus('error'); });
        });
    }, 400);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [password]);

  const getStrength = (pwd: string) => {
    const len = pwd.length;
    const hasUpper = /[A-Z]/.test(pwd);
    const hasLower = /[a-z]/.test(pwd);
    const hasNumber = /[0-9]/.test(pwd);
    const hasSpecial = /[^A-Za-z0-9]/.test(pwd);

    // Password Strength Rules - barText uses bright variants for dark generator bg
    if (len >= 16 && hasUpper && hasLower && hasNumber && hasSpecial) {
      return { label: t('vault.strength.excellent', 'Excellent'), color: 'text-green-700', bg: 'bg-green-50', border: 'border-green-100', dot: 'bg-green-600', bar: 'bg-green-500', barText: 'text-green-400', barWidth: 'w-full' };
    }
    if (len >= 12 && hasUpper && hasLower && hasNumber && hasSpecial) {
      return { label: t('vault.strength.veryStrong', 'Very Strong'), color: 'text-green-600', bg: 'bg-green-50', border: 'border-green-100', dot: 'bg-green-500', bar: 'bg-green-400', barText: 'text-green-300', barWidth: 'w-[85%]' };
    }
    if (len >= 8 && hasUpper && hasLower && hasNumber) {
      return { label: t('vault.strength.strong', 'Strong'), color: 'text-blue-700', bg: 'bg-blue-50', border: 'border-blue-100', dot: 'bg-blue-600', bar: 'bg-blue-500', barText: 'text-blue-400', barWidth: 'w-[70%]' };
    }
    if (len >= 6 && hasLower && hasNumber && !hasSpecial) {
      return { label: t('vault.strength.medium', 'Medium'), color: 'text-orange-700', bg: 'bg-orange-50', border: 'border-orange-100', dot: 'bg-orange-600', bar: 'bg-orange-500', barText: 'text-orange-400', barWidth: 'w-1/2' };
    }
    if (len >= 4 && hasLower && !hasUpper && !hasSpecial) {
      return { label: t('vault.strength.weak', 'Weak'), color: 'text-red-700', bg: 'bg-red-50', border: 'border-red-100', dot: 'bg-red-600', bar: 'bg-red-500', barText: 'text-red-400', barWidth: 'w-[30%]' };
    }
    if (len >= 1 && len <= 3 && !hasUpper && !hasNumber && !hasSpecial) {
      return { label: t('vault.strength.veryWeak', 'Very Weak'), color: 'text-red-800', bg: 'bg-red-50', border: 'border-red-100', dot: 'bg-red-800', bar: 'bg-red-700', barText: 'text-red-400', barWidth: 'w-[15%]' };
    }

    // Dynamic fallback
    if (len >= 20) return { label: t('vault.strength.excellent', 'Excellent'), color: 'text-green-700', bg: 'bg-green-50', border: 'border-green-100', dot: 'bg-green-600', bar: 'bg-green-500', barText: 'text-green-400', barWidth: 'w-full' };
    if (len >= 12) return { label: t('vault.strength.strong', 'Strong'), color: 'text-blue-700', bg: 'bg-blue-50', border: 'border-blue-100', dot: 'bg-blue-600', bar: 'bg-blue-500', barText: 'text-blue-400', barWidth: 'w-[70%]' };
    if (len >= 8) return { label: t('vault.strength.medium', 'Medium'), color: 'text-orange-700', bg: 'bg-orange-50', border: 'border-orange-100', dot: 'bg-orange-600', bar: 'bg-orange-500', barText: 'text-orange-400', barWidth: 'w-1/2' };
    return { label: t('vault.strength.weak', 'Weak'), color: 'text-red-700', bg: 'bg-red-50', border: 'border-red-100', dot: 'bg-red-600', bar: 'bg-red-500', barText: 'text-red-400', barWidth: 'w-[30%]' };
  };

  const strength = getStrength(password);

  // ── Live entropy / quantum / crack-time analysis (drives the advisory) ──────
  // Bits reflect the *current* generator configuration so the figures update as
  // the user drags the length/word-count sliders or toggles character classes.
  const entropyBits = isPassphrase
    ? passphraseBits(wordCount, EFF_WORDLIST_SIZE)
    : randomPasswordBits(
        password.length,
        charsetSize({ uppercase: includeUppercase, lowercase: includeLowercase, numbers: includeNumbers, symbols: includeSymbols }),
      );
  const bitsRounded = Math.round(entropyBits);
  const quantum = classifyQuantum(entropyBits);
  const bitsToQuantumProof = Math.max(0, Math.ceil(QUANTUM_PROOF_BITS - entropyBits));
  const guessesPerSecond = ATTACKER_PROFILES[attackerProfile];
  const classicalCrack = crackTime(entropyBits, guessesPerSecond);
  const quantumCrack = quantumCrackTime(entropyBits, guessesPerSecond);

  // Locale-aware compact formatter ("9.5K", "14B", "1.2T") for large year counts.
  const numberFmt = useMemo(
    () => new Intl.NumberFormat(i18n.language, { notation: 'compact', maximumFractionDigits: 1 }),
    [i18n.language],
  );
  const formatCrack = (ct: CrackTime): string => {
    switch (ct.unit) {
      case 'instant': return t('addCredential.crack.instant', 'instantly');
      case 'seconds': return t('addCredential.crack.seconds', '{{value}} seconds', { value: ct.value });
      case 'minutes': return t('addCredential.crack.minutes', '{{value}} minutes', { value: ct.value });
      case 'hours': return t('addCredential.crack.hours', '{{value}} hours', { value: ct.value });
      case 'days': return t('addCredential.crack.days', '{{value}} days', { value: ct.value });
      case 'years': return t('addCredential.crack.years', '{{value}} years', { value: numberFmt.format(ct.value) });
      case 'powerYears': return t('addCredential.crack.powerYears', '10^{{exp}} years', { exp: ct.value });
      default: return '';
    }
  };

  const handleCopy = () => {
    secureClipboard(password, () => {}, () => {}, 10);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className={`${isGeneratorVisible ? 'max-w-7xl' : 'max-w-5xl'} mx-auto transition-all duration-500`}
    >
      <div className="bg-white dark:bg-surface-container-low rounded-2xl shadow-xl border border-outline-variant/10 flex flex-col lg:flex-row transition-all duration-500">
        {/* Form Section */}
        <div className="flex-1 p-10 lg:p-16 lg:border-r border-outline-variant/10 rounded-l-2xl">
          <div className="mb-10">
            <nav className="flex items-center gap-2 text-[10px] font-black tracking-[0.3em] text-on-surface-variant uppercase mb-4">
              <span className="hover:text-black dark:hover:text-white cursor-pointer transition-colors" onClick={onCancel}>{t('sidebar.vault', 'Vault')}</span>
              <ChevronRight size={10} className="opacity-40" />
              <span className="text-black dark:text-white">{initialData ? t('addCredential.editTitle', 'Edit Credential') : t('addCredential.addTitle', 'Add New Credential')}</span>
            </nav>
            <h1 className="text-4xl md:text-5xl font-headline font-black tracking-tighter text-black dark:text-white leading-none">{initialData ? t('addCredential.editTitle', 'Edit Credential') : t('addCredential.addTitle', 'New Credential')}</h1>
            <p className="text-on-surface-variant text-base font-medium mt-3 max-w-2xl leading-relaxed">{t('addCredential.description', 'Securely store your login information with enterprise-grade encryption and advanced security protocols.')}</p>
          </div>
          <form className="space-y-10" onSubmit={async (e) => {
            e.preventDefault();
            if (!title.trim()) return;

            // Non-login types bypass the URL/password validation flow
            if (credentialType !== 'login') {
              const nonLoginCred: Credential = {
                id: initialData?.id || generateUUID(),
                service: title.trim(),
                url: rpId || '',
                username: '',
                password: '',
                status: 'good',
                statusColor: '',
                logo: initialData?.logo || '',
                folderId: selectedFolder,
                tags: [],
                credentialType,
                ...(credentialType === 'passkey' ? { rpId, rpName, credentialId, userHandle, authenticatorName, backedUp } : {}),
                ...(credentialType === 'secure_note' ? { noteContent } : {}),
                ...(credentialType === 'payment_card' ? { cardholderName, cardNumber, cardExpiry, cardCvv, cardBillingAddress, cardType: detectCardNetwork(cardNumber)?.id ?? '' } : {}),
                description: description.trim() || undefined,
              };
              try {
                if (initialData && onUpdateCredential) await onUpdateCredential(nonLoginCred);
                else if (onAddCredential) await onAddCredential(nonLoginCred);
                if (onCancel) onCancel();
              } catch (err: any) {
                addNotification({
                  type: 'credential_deleted',
                  title: 'Error Saving Credential',
                  message: err.message || 'An error occurred while saving.',
                });
              }
              return;
            }

            let formattedUrl = url.trim();
            if (formattedUrl && !/^https?:\/\//i.test(formattedUrl)) {
              formattedUrl = `https://${formattedUrl}`;
            }

            // URL Validation with TLD requirement
            const urlPattern = /^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)/i;
            if (formattedUrl && !urlPattern.test(formattedUrl)) {
              setUrlError('Please enter a correct URL (e.g. https://example.com)');
              return;
            } else {
              setUrlError(null);
            }

            if (tags.includes('OTP') && otpSecret) {
              try {
                await TOTP.generate(otpSecret);
                setOtpSecretError(null);
              } catch (err) {
                setOtpSecretError(t('vault.invalidOtpSecret', 'Invalid OTP secret key'));
                // scroll to OTP section
                const otpEl = document.getElementById('otp-secret');
                otpEl?.scrollIntoView({ behavior: 'smooth', block: 'center' });
                return;
              }
            }

            const credData = {
                id: initialData?.id || generateUUID(),
                service: title,
                url: formattedUrl,
                username: usernameType === 'phone'
                  ? (() => {
                      const country = COUNTRIES.find(c => c.iso === loginPhoneIso);
                      const full = `${country?.code || '+1'} ${loginPhoneValue}`.trim();
                      return full || 'No username';
                    })()
                  : (username.trim() || 'No username'),
                password: password,
                status: strength.label,
                statusColor: `${strength.color} ${strength.bg} ${strength.border} ${strength.dot} ${strength.bar}`,
                logo: initialData?.logo || '',
                folderId: selectedFolder,
                tags: tags,
                phoneNumber: tags.includes('2FA') ? phoneNumbers.filter(p => p.value.trim().length > 0).map(p => {
                  const country = COUNTRIES.find(c => c.iso === p.iso);
                  return `${country?.code || '+1'} ${p.value}`;
                }) : undefined,
                kba: tags.includes('KBA') ? kba.map(({ id, ...rest }) => rest) : undefined,
                u2fKeyName: tags.includes('U2F') ? u2fKeys.map(u => u.value).filter(Boolean) : undefined,
                otpSecret: tags.includes('OTP') ? otpSecret : undefined,
                otpAlgorithm: tags.includes('OTP') ? (initialData?.otpAlgorithm || 'SHA256') : undefined,
                otpDigits: tags.includes('OTP') ? (initialData?.otpDigits || 8) : undefined,
                accountType: accountType.trim() || undefined,
                expiryEnabled,
                expiryValue: expiryEnabled ? expiryValue : undefined,
                expiryUnit: expiryEnabled ? expiryUnit : undefined,
                expiryNotifyEmail: expiryEnabled ? expiryNotifyEmail : undefined,
                expirySetAt: expiryEnabled
                  ? (initialData?.expiryEnabled ? initialData.expirySetAt : Date.now())
                  : undefined,
                description: description.trim() || undefined,
                credentialType: 'login' as const,
              };

            try {
              if (initialData && onUpdateCredential) {
                await onUpdateCredential(credData);
                // Positive reinforcement: password changed AND expiry is configured
                const passwordChanged = !!password && !!initialData.password && password !== initialData.password;
                if (passwordChanged && expiryEnabled) {
                  addNotification({
                    type: 'credential_added',
                    title: t('notifications.goodShapeTitle', 'Account in good shape!'),
                    message: t('notifications.goodShapeMessage',
                      '{{service}} password updated with expiry tracking. Great security hygiene!',
                      { service: title }),
                  });
                }
              } else if (onAddCredential) {
                await onAddCredential(credData);
              }
              if (onCancel) onCancel();
            } catch (err: any) {
              addNotification({
                type: 'credential_deleted',
                title: 'Error Saving Credential',
                message: err.message || 'An error occurred while saving.',
              });
            }
          }}>
            {/* Credential type selector */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-2">
              {([
                { type: 'login',        icon: <Key size={18} />,      label: t('addCredential.typeLogin', 'Login') },
                { type: 'passkey',      icon: <Shield size={18} />,   label: t('addCredential.typePasskey', 'Passkey') },
                { type: 'secure_note',  icon: <FileText size={18} />, label: t('addCredential.typeNote', 'Note') },
                { type: 'payment_card', icon: <CreditCard size={18} />,label: t('addCredential.typeCard', 'Card') },
              ] as const).map(({ type, icon, label }) => (
                <button
                  key={type} type="button"
                  onClick={() => dispatch({ type: 'setField', field: 'credentialType', value: type })}
                  className={`flex items-center justify-center gap-2 px-4 py-3 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${credentialType === type ? 'bg-black text-white dark:bg-white dark:text-black' : 'bg-surface-container-high text-on-surface-variant hover:bg-surface-container-highest'}`}
                >
                  {icon}{label}
                </button>
              ))}
            </div>

            <div className="space-y-3">
              <label htmlFor="service-title" className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">
                {credentialType === 'secure_note' ? t('addCredential.noteTitle', 'Note Title') :
                 credentialType === 'payment_card' ? t('addCredential.cardLabel', 'Card Label') :
                 credentialType === 'passkey' ? t('addCredential.passkeyTitle', 'Passkey Name') :
                 t('addCredential.serviceLabel', 'Title / Service Name')} <span className="text-red-500">*</span>
              </label>
              <input 
                id="service-title"
                type="text" 
                required
                value={title}
                onChange={(e) => dispatch({ type: 'setField', field: 'title', value: e.target.value })}
                placeholder={t('addCredential.servicePlaceholder', 'e.g. GitHub Enterprise')} 
                aria-label="Service Name"
                className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant font-bold focus:ring-2 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30 transition-all outline-none"
              />
            </div>

            {/* Non-login credential type forms */}
            {credentialType !== 'login' && (
              <div className="space-y-8">
                {/* Folder selector (all non-login types) */}
                <div className="space-y-4 pt-2">
                  <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.folderAssignment', 'Folder Assignment')}</label>
                  <div className="flex flex-wrap gap-3">
                    {folders.map(folder => (
                      <button key={folder.id} type="button" onClick={() => dispatch({ type: 'setField', field: 'folderId', value: folder.id })}
                        className={`px-5 py-2.5 rounded-xl flex items-center gap-2 transition-all text-xs font-bold ${selectedFolder === folder.id ? 'bg-black text-white dark:bg-white dark:text-black' : 'bg-surface-container-high text-black dark:text-white hover:bg-surface-container-highest'}`}
                      >
                        {renderFolderIcon(folder, selectedFolder === folder.id)}
                        {folder.label}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Passkey-specific fields */}
                {credentialType === 'passkey' && (
                  <div className="space-y-6">
                    <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-xl text-xs text-blue-700 dark:text-blue-400">
                      {t('addCredential.passkeyNote', 'Private key stays on your authenticator - only metadata is stored here, never the key material.')}
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="space-y-3">
                        <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.rpId', 'Relying Party ID')}</label>
                        <input type="text" value={rpId} onChange={e => dispatch({ type: 'setField', field: 'rpId', value: e.target.value })} placeholder="github.com"
                          className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant font-bold outline-none focus:ring-2 focus:ring-on-primary-container/20 transition-all" />
                      </div>
                      <div className="space-y-3">
                        <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.rpName', 'Site Name')}</label>
                        <input type="text" value={rpName} onChange={e => dispatch({ type: 'setField', field: 'rpName', value: e.target.value })} placeholder="GitHub"
                          className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant font-bold outline-none focus:ring-2 focus:ring-on-primary-container/20 transition-all" />
                      </div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="space-y-3">
                        <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.credentialId', 'Credential ID (optional)')}</label>
                        <input type="text" value={credentialId} onChange={e => dispatch({ type: 'setField', field: 'credentialId', value: e.target.value })} placeholder="base64url…"
                          className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant font-mono text-sm outline-none focus:ring-2 focus:ring-on-primary-container/20 transition-all" />
                      </div>
                      <div className="space-y-3">
                        <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.authenticatorName', 'Authenticator')}</label>
                        <input type="text" value={authenticatorName} onChange={e => dispatch({ type: 'setField', field: 'authenticatorName', value: e.target.value })} placeholder="YubiKey 5C NFC"
                          className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant font-bold outline-none focus:ring-2 focus:ring-on-primary-container/20 transition-all" />
                      </div>
                    </div>
                    <div className="flex items-center gap-3 cursor-pointer" onClick={() => dispatch({ type: 'setField', field: 'backedUp', value: !backedUp })}>
                      {backedUp ? <ToggleRight size={28} className="text-black dark:text-white shrink-0" /> : <ToggleLeft size={28} className="text-on-surface-variant shrink-0" />}
                      <span className="text-sm font-bold">{t('addCredential.backedUp', 'Backed up (synced passkey)')}</span>
                    </div>
                  </div>
                )}

                {/* Secure note fields */}
                {credentialType === 'secure_note' && (
                  <div className="space-y-3">
                    <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.noteContent', 'Note')} <span className="text-red-500">*</span></label>
                    <textarea value={noteContent} onChange={e => dispatch({ type: 'setField', field: 'noteContent', value: e.target.value })} rows={12}
                      placeholder={t('addCredential.noteContentPlaceholder', 'Write your secure note here…')}
                      className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant resize-y outline-none focus:ring-2 focus:ring-on-primary-container/20 transition-all" />
                    {noteContent.length > 45000 && <p className="text-xs text-error">{t('addCredential.noteTooLong', 'Note is very long - consider splitting into multiple notes.')}</p>}
                  </div>
                )}

                {/* Payment card fields */}
                {credentialType === 'payment_card' && (() => {
                  const cardNetwork = detectCardNetwork(cardNumber);
                  const cvvMax      = cardNetwork?.cvvLength ?? 4;
                  return (
                    <div className="space-y-6">
                      <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-xl text-xs text-yellow-700 dark:text-yellow-400">
                        {t('addCredential.cardDisclaimer', 'Personal reference storage only — not PCI-DSS certified.')}
                      </div>

                      {/* Row 1: Cardholder + Card Number */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* Cardholder name */}
                        <div className="space-y-3">
                          <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">
                            {t('addCredential.cardholderName', 'Cardholder Name')}
                          </label>
                          <input
                            type="text"
                            value={cardholderName}
                            onChange={e => dispatch({ type: 'setField', field: 'cardholderName', value: e.target.value })}
                            placeholder="John Doe"
                            className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant font-bold outline-none focus:ring-2 focus:ring-on-primary-container/20 transition-all"
                          />
                        </div>

                        {/* Card Number with live BIN detection + Luhn */}
                        <div className="space-y-3">
                          <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">
                            {t('addCredential.cardNumber', 'Card Number')}
                          </label>
                          <div
                            className="relative"
                            onBlur={e => {
                              if (!e.currentTarget.contains(e.relatedTarget as Node)) {
                                setShowCardNumber(false);
                              }
                            }}
                          >
                            <input
                              type="text"
                              inputMode="numeric"
                              value={cardNumber === '' ? '' : showCardNumber ? formatPan(cardNumber, null) : maskPan(cardNumber, PAN_UNHIDE)}
                              placeholder="XXXX XXXX XXXX XXXX"
                              onFocus={() => { if (!showCardNumber) setShowCardNumber(true); }}
                              onChange={e => {
                                const raw = e.target.value.replace(/\D/g, '');
                                const net = detectCardNetwork(raw);
                                const trimmed = raw.slice(0, maxPanLength(net));
                                dispatch({ type: 'setField', field: 'cardNumber', value: trimmed });
                                if (isPanComplete(trimmed, net)) {
                                  setCardLuhnError(!luhnCheck(trimmed));
                                } else {
                                  setCardLuhnError(null);
                                }
                              }}
                              className={`w-full px-6 py-4 pr-28 bg-surface-container-low rounded-xl border font-mono outline-none focus:ring-2 transition-all ${
                                cardLuhnError
                                  ? 'border-red-500 focus:ring-red-500/20 text-red-600 dark:text-red-400'
                                  : 'border-black/15 dark:border-white/15 text-black dark:text-white focus:ring-on-primary-container/20'
                              }`}
                            />
                            {/* Network badge + eye toggle */}
                            <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-2">
                              {cardNetwork && (
                                <span
                                  className="text-[9px] font-black px-2 py-0.5 rounded-md whitespace-nowrap leading-none"
                                  style={{ backgroundColor: cardNetwork.bgColor, color: cardNetwork.textColor }}
                                >
                                  {cardNetwork.label}
                                </span>
                              )}
                              <button
                                type="button"
                                onClick={() => setShowCardNumber(v => !v)}
                                className="text-on-surface-variant hover:text-black dark:hover:text-white transition-colors"
                              >
                                {showCardNumber ? <EyeOff size={16} /> : <Eye size={16} />}
                              </button>
                            </div>
                          </div>

                          {/* Luhn error */}
                          <AnimatePresence>
                            {cardLuhnError && (
                              <motion.p
                                initial={{ opacity: 0, y: -6 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -6 }}
                                className="text-[10px] font-bold text-red-600 uppercase tracking-wider flex items-center gap-1"
                              >
                                <AlertTriangle size={10} />
                                {t('addCredential.cardLuhnError', 'Invalid card number. Check your digits.')}
                              </motion.p>
                            )}
                          </AnimatePresence>

                          {/* Luhn valid badge */}
                          {cardLuhnError === false && cardNumber && (
                            <p className="text-[10px] font-bold text-green-600 flex items-center gap-1">
                              <Check size={10} strokeWidth={3} />
                              {t('addCredential.cardLuhnValid', 'Valid card number')}
                            </p>
                          )}

                          {/* Network hint while typing */}
                          {cardLuhnError == null && cardNetwork && cardNumber && !isPanComplete(cardNumber, cardNetwork) && (
                            <p className="text-[10px] text-on-surface-variant/60 font-medium">
                              {t('addCredential.cardNetworkHint', '{{network}}, {{length}} digits expected', {
                                network: cardNetwork.label,
                                length: maxPanLength(cardNetwork),
                              })}
                            </p>
                          )}
                        </div>
                      </div>

                      {/* Row 2: Expiry picker + CVV */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div className="space-y-3">
                          <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">
                            {t('addCredential.cardExpiry', 'Expiry Date')}
                          </label>
                          <CardExpiryPicker
                            value={cardExpiry}
                            onChange={v => dispatch({ type: 'setField', field: 'cardExpiry', value: v })}
                            minDays={CARD_EXPIRY_MIN_DAYS}
                          />
                        </div>

                        <div className="space-y-3">
                          <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">
                            {t('addCredential.cardCvv', 'CVV')}
                          </label>
                          <div className="relative">
                            <input
                              type={showCvv ? 'text' : 'password'}
                              value={cardCvv}
                              onChange={e => dispatch({ type: 'setField', field: 'cardCvv', value: e.target.value.replace(/\D/g, '').slice(0, cvvMax) })}
                              placeholder={cvvMax === 4 ? '••••' : '•••'}
                              inputMode="numeric"
                              autoComplete={BROWSER_AUTOFILL ? 'cc-csc' : 'new-password'}
                              className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant font-mono outline-none focus:ring-2 focus:ring-on-primary-container/20 transition-all pr-12"
                            />
                            <button
                              type="button"
                              onClick={() => setShowCvv(v => !v)}
                              className="absolute right-4 top-1/2 -translate-y-1/2 text-on-surface-variant"
                            >
                              {showCvv ? <EyeOff size={16} /> : <Eye size={16} />}
                            </button>
                          </div>
                          {cvvMax === 4 && (
                            <p className="text-[10px] text-on-surface-variant/60">
                              {t('addCredential.cardCvv4Hint', 'Amex uses a 4-digit security code')}
                            </p>
                          )}
                        </div>
                      </div>

                      {/* Billing address */}
                      <div className="space-y-3">
                        <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">
                          {t('addCredential.cardBillingAddress', 'Billing Address (optional)')}
                        </label>
                        <input
                          type="text"
                          value={cardBillingAddress}
                          onChange={e => dispatch({ type: 'setField', field: 'cardBillingAddress', value: e.target.value })}
                          placeholder={t('addCredential.cardBillingPlaceholder', '123 Main St, City')}
                          className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant font-bold outline-none focus:ring-2 focus:ring-on-primary-container/20 transition-all"
                        />
                      </div>
                    </div>
                  );
                })()}
              </div>
            )}

            {credentialType === 'login' && <>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div className="space-y-3 relative">
                {/* Identifier type selector */}
                <div className="flex gap-2 items-center">
                  {(['username', 'email', 'phone'] as const).map(type => (
                    <button
                      key={type}
                      type="button"
                      onClick={() => {
                        dispatch({ type: 'setField', field: 'usernameType', value: type });
                        setUsernameError(null);
                      }}
                      className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${usernameType === type ? 'bg-black text-white dark:bg-white dark:text-black' : 'bg-surface-container-high text-on-surface-variant hover:bg-surface-container-highest'}`}
                    >
                      {type === 'username' ? t('addCredential.typeUsername', 'Username')
                       : type === 'email' ? t('addCredential.typeEmail', 'Email')
                       : t('addCredential.typePhone', 'Phone')}
                    </button>
                  ))}
                </div>

                <label htmlFor="username" className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">
                  {usernameType === 'username' ? t('addCredential.usernameOnlyLabel', 'Username')
                   : usernameType === 'email' ? t('addCredential.emailLabel', 'Email')
                   : t('addCredential.phoneLabel', 'Phone Number')}
                </label>

                {usernameType === 'phone' ? (
                  <div className="flex gap-3 relative">
                    <PhoneCountrySelect
                      value={loginPhoneIso}
                      onChange={(iso) => {
                        dispatch({ type: 'setField', field: 'loginPhoneIso', value: iso });
                        dispatch({ type: 'setField', field: 'loginPhoneValue', value: formatPhoneNumber(loginPhoneValue, iso) });
                      }}
                      countries={COUNTRIES}
                    />
                    <div className="relative flex-1">
                      <input
                        id="username"
                        type="tel"
                        value={loginPhoneValue}
                        onChange={(e) => dispatch({ type: 'setField', field: 'loginPhoneValue', value: formatPhoneNumber(e.target.value, loginPhoneIso) })}
                        onFocus={() => setShowPhoneSuggestions('login-id')}
                        onBlur={() => setTimeout(() => setShowPhoneSuggestions(null), 200)}
                        placeholder={COUNTRIES.find(c => c.iso === loginPhoneIso)?.format?.toLowerCase() || '0000000000'}
                        aria-label="Phone number for login"
                        className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant font-bold focus:ring-2 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30 transition-all outline-none"
                      />
                      <AnimatePresence>
                        {showPhoneSuggestions === 'login-id' && assetHolder.phoneNumbers.length > 0 && (
                          <motion.div
                            initial={{ opacity: 0, y: -10 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -10 }}
                            className="absolute top-full left-0 w-full mt-2 bg-white dark:bg-surface-container-low border border-outline-variant/10 rounded-xl shadow-lg overflow-hidden z-50"
                          >
                            {assetHolder.phoneNumbers.map((phone, i) => (
                              <button
                                key={i}
                                type="button"
                                onClick={() => {
                                  const match = COUNTRIES.find(c => phone.startsWith(c.code));
                                  if (match) {
                                    dispatch({ type: 'setField', field: 'loginPhoneIso', value: match.iso });
                                    dispatch({ type: 'setField', field: 'loginPhoneValue', value: phone.replace(match.code, '').trim() });
                                  } else {
                                    dispatch({ type: 'setField', field: 'loginPhoneValue', value: phone });
                                  }
                                  setShowPhoneSuggestions(null);
                                }}
                                className="w-full text-left px-6 py-3 hover:bg-surface-container-low transition-colors text-sm font-bold text-black dark:text-white"
                              >
                                {phone}
                              </button>
                            ))}
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  </div>
                ) : (
                  <input
                    id="username"
                    type="text"
                    value={username}
                    onChange={(e) => {
                      const val = e.target.value;
                      dispatch({ type: 'setField', field: 'username', value: val });
                      if (usernameType === 'email') {
                        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                        setUsernameError(val && !emailRegex.test(val) ? t('addCredential.invalidEmail', 'Invalid email format') : null);
                      } else {
                        setUsernameError(null);
                      }
                    }}
                    onFocus={() => { if (usernameType === 'email') setShowEmailSuggestions(true); }}
                    onBlur={() => {
                      setTimeout(() => setShowEmailSuggestions(false), 200);
                      if (usernameType === 'email' && username.includes('@')) {
                        const cleaned = username.replace(/[^\w@.-]/g, '');
                        if (cleaned !== username) dispatch({ type: 'setField', field: 'username', value: cleaned });
                      }
                    }}
                    placeholder={
                      usernameType === 'email'
                        ? t('assetHolder.emailPlaceholder', 'name@example.com')
                        : t('addCredential.usernamePlaceholder', 'e.g. john_doe')
                    }
                    aria-label="Username or Email"
                    autoComplete={BROWSER_AUTOFILL ? 'username' : 'off'}
                    className={`w-full px-6 py-4 bg-surface-container-low rounded-xl text-black dark:text-white placeholder:text-outline-variant focus:ring-2 transition-all outline-none ${usernameError ? 'border border-red-500 focus:ring-red-500/20' : 'border border-black/15 dark:border-white/15 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30'}`}
                  />
                )}

                {usernameError && (
                  <motion.p
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="text-[10px] font-bold text-red-600 uppercase tracking-wider"
                  >
                    {usernameError}
                  </motion.p>
                )}

                <AnimatePresence>
                  {usernameType === 'email' && showEmailSuggestions && assetHolder.emails.length > 0 && (
                    <motion.div
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      className="absolute top-full left-0 w-full mt-2 bg-white dark:bg-surface-container-low border border-outline-variant/10 rounded-xl shadow-lg overflow-hidden z-50"
                    >
                      {assetHolder.emails.map((email, i) => (
                        <button
                          key={i}
                          type="button"
                          onClick={() => {
                            dispatch({ type: 'setField', field: 'username', value: email });
                            setShowEmailSuggestions(false);
                          }}
                          className="w-full text-left px-6 py-3 hover:bg-surface-container-low transition-colors text-sm font-bold text-black dark:text-white"
                        >
                          {email}
                        </button>
                      ))}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
              <div className="space-y-3 self-end">
                <label htmlFor="website-url" className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.urlLabel', 'Website URL')}</label>
                <input 
                  id="website-url"
                  type="text" 
                  value={url}
                  onChange={(e) => {
                    dispatch({ type: 'setField', field: 'url', value: e.target.value });
                    if (urlError) setUrlError(null);
                  }}
                  placeholder="https://github.com" 
                  aria-label="Website URL"
                  className={`w-full px-6 py-4 bg-surface-container-low rounded-xl text-black dark:text-white placeholder:text-outline-variant focus:ring-2 transition-all outline-none ${urlError ? 'border border-red-500 focus:ring-red-500/20' : 'border border-black/15 dark:border-white/15 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30'}`}
                />
                {urlError && (
                  <motion.p 
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="text-[10px] font-bold text-red-600 uppercase tracking-wider"
                  >
                    {t('addCredential.urlError', 'Please enter a correct URL (e.g. https://example.com)')}
                  </motion.p>
                )}
              </div>
            </div>

            <div className="space-y-3">
              <label htmlFor="password-input" className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.passwordLabel', 'Password')}</label>
              <div className="relative">
                {/* HIGH-05 fix: type="password" by default; toggle reveals plaintext */}
                <input
                  id="password-input"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => dispatch({ type: 'setField', field: 'password', value: e.target.value })}
                  aria-label="Password"
                  autoComplete="new-password"
                  className="w-full px-6 py-4 pr-52 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white font-mono tracking-widest focus:ring-2 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30 transition-all outline-none"
                />
                <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => setShowPassword(v => !v)}
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    className="p-2 rounded-lg hover:bg-black/10 dark:hover:bg-white/10 text-black/50 dark:text-white/50 transition-all"
                  >
                    {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                  <button
                    type="button"
                    onClick={() => setIsGeneratorVisible(!isGeneratorVisible)}
                    aria-expanded={isGeneratorVisible}
                    aria-controls="desktop-generator mobile-generator"
                    className={`px-4 py-2 ${isGeneratorVisible ? 'bg-black/10 text-black dark:bg-white/10 dark:text-white' : 'bg-black text-white dark:bg-white dark:text-black'} text-[10px] font-black uppercase tracking-widest rounded-lg hover:opacity-80 transition-all flex items-center gap-2`}
                  >
                    <Wand2 size={14} aria-hidden="true" />
                    {isGeneratorVisible ? t('addCredential.hideTool', 'Hide Tool') : t('addCredential.generate', 'Generate')}
                  </button>
                </div>
              </div>
              {breachStatus === 'pwned' && (
                <motion.div
                  initial={{ opacity: 0, y: -6 }}
                  animate={{ opacity: 1, y: 0 }}
                  role="alert"
                  className="flex items-start gap-2 px-4 py-3 rounded-lg border border-red-200 bg-red-50 dark:bg-red-950/30 dark:border-red-900/50 text-red-800 dark:text-red-200"
                >
                  <ShieldCheck size={14} aria-hidden="true" className="mt-[2px] shrink-0" />
                  <span className="text-[11px] font-semibold leading-snug">
                    {t(
                      'addCredential.breachWarning',
                      'This password appears in public breaches - consider regenerating.'
                    )}
                  </span>
                </motion.div>
              )}
            </div>

            {/* Account Type */}
            <div className="space-y-2">
              <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">
                {t('addCredential.accountTypeLabel', 'Account Type')}
              </label>
              <input
                type="text"
                value={accountType}
                onChange={e => dispatch({ type: 'setField', field: 'accountType', value: e.target.value.slice(0, 50) })}
                placeholder={t('addCredential.accountTypePlaceholder', 'e.g. Free, Starter, Pro')}
                className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white focus:ring-2 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30 transition-all outline-none text-sm"
              />
            </div>

            {/* Password Expiry */}
            <div className="border border-outline-variant/20 rounded-2xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-black text-black dark:text-white">
                    {t('addCredential.expiryLabel', 'Password Expiry')}
                  </p>
                  <p className="text-[11px] text-on-surface-variant mt-0.5">
                    {t('addCredential.expiryDesc', 'Get reminded when this password should be changed')}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => dispatch({ type: 'setField', field: 'expiryEnabled', value: !expiryEnabled })}
                  className={`w-11 h-6 rounded-full transition-colors relative shrink-0 ${expiryEnabled ? 'bg-black dark:bg-white' : 'bg-gray-200 dark:bg-gray-700'}`}
                  aria-pressed={expiryEnabled}
                  aria-label={t('addCredential.expiryLabel', 'Password Expiry')}
                >
                  <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white dark:bg-black shadow transition-transform ${expiryEnabled ? 'translate-x-5' : ''}`} />
                </button>
              </div>

              <AnimatePresence>
                {expiryEnabled && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="space-y-4 overflow-hidden"
                  >
                    <div className="flex items-end gap-3">
                      <div className="flex-1">
                        <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant mb-2 block">
                          {t('addCredential.expiryEvery', 'Every')}
                        </label>
                        <input
                          type="number"
                          min={1}
                          max={1000}
                          value={expiryValue}
                          onChange={e => {
                            const n = parseInt(e.target.value, 10);
                            if (!isNaN(n)) dispatch({ type: 'setField', field: 'expiryValue', value: Math.min(1000, Math.max(1, n)) });
                          }}
                          className="w-full px-4 py-3 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white focus:ring-2 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30 transition-all outline-none text-sm font-mono"
                        />
                      </div>
                      <div className="flex-1">
                        <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant mb-2 block">
                          {t('addCredential.expiryPeriod', 'Period')}
                        </label>
                        <select
                          value={expiryUnit}
                          onChange={e => dispatch({ type: 'setField', field: 'expiryUnit', value: e.target.value as 'days' | 'months' | 'years' })}
                          className="w-full px-4 py-3 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white focus:ring-2 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30 transition-all outline-none text-sm"
                        >
                          <option value="days">{t('addCredential.expiryDays', 'Days')}</option>
                          <option value="months">{t('addCredential.expiryMonths', 'Months')}</option>
                          <option value="years">{t('addCredential.expiryYears', 'Years')}</option>
                        </select>
                      </div>
                    </div>

                    {hasSmtp && (
                      <div className="flex items-center justify-between py-3 border-t border-outline-variant/10">
                        <p className="text-sm font-medium text-black dark:text-white">
                          {t('addCredential.expiryNotifyEmail', 'Notify me by email on expiry')}
                        </p>
                        <button
                          type="button"
                          onClick={() => dispatch({ type: 'setField', field: 'expiryNotifyEmail', value: !expiryNotifyEmail })}
                          className={`w-11 h-6 rounded-full transition-colors relative shrink-0 ${expiryNotifyEmail ? 'bg-black dark:bg-white' : 'bg-gray-200 dark:bg-gray-700'}`}
                          aria-pressed={expiryNotifyEmail}
                          aria-label={t('addCredential.expiryNotifyEmail', 'Notify me by email on expiry')}
                        >
                          <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white dark:bg-black shadow transition-transform ${expiryNotifyEmail ? 'translate-x-5' : ''}`} />
                        </button>
                      </div>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.tagsLabel', 'Tags')}</label>
                <p className="text-[10px] text-on-surface-variant/60 mt-1">Select all security features stored with this credential.</p>
              </div>
              <div className="grid grid-cols-2 gap-2.5">
                {([
                  { tag: '2FA',  Icon: Smartphone,  title: t('addCredential.tags.2fa', 'Two-Factor Auth'),     desc: t('addCredential.tags.2faDesc', 'Phone number for SMS / app verification') },
                  { tag: 'OTP',  Icon: Clock,        title: t('addCredential.tags.otp', 'One-Time Password'),   desc: t('addCredential.tags.otpDesc', 'TOTP secret for authenticator apps') },
                  { tag: 'KBA',  Icon: HelpCircle,   title: t('addCredential.tags.kba', 'Security Questions'),  desc: t('addCredential.tags.kbaDesc', 'Knowledge-based security answers') },
                  { tag: 'U2F',  Icon: Key,           title: t('addCredential.tags.u2f', 'Hardware Key'),        desc: t('addCredential.tags.u2fDesc', 'Physical security key (YubiKey etc.)') },
                ] as const).map(({ tag, Icon, title, desc }) => {
                  const active = tags.includes(tag);
                  return (
                    <button
                      key={tag}
                      type="button"
                      onClick={() => toggleTag(tag)}
                      aria-pressed={active}
                      className={`flex items-center gap-3 p-3.5 rounded-xl border-2 text-left transition-all ${
                        active
                          ? 'bg-black dark:bg-white border-black dark:border-white'
                          : 'bg-surface-container-low border-outline-variant/20 hover:border-outline-variant/60 hover:bg-surface-container-high'
                      }`}
                    >
                      <div className={`p-1.5 rounded-lg shrink-0 ${active ? 'bg-white/20 dark:bg-black/20' : 'bg-surface-container-high'}`}>
                        <Icon size={13} className={active ? 'text-white dark:text-black' : 'text-on-surface-variant'} />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className={`text-[10px] font-black uppercase tracking-widest leading-tight ${active ? 'text-white dark:text-black' : 'text-black dark:text-white'}`}>{tag}</div>
                        <div className={`text-[10px] leading-snug mt-0.5 ${active ? 'text-white/70 dark:text-black/60' : 'text-on-surface-variant'}`}>{desc}</div>
                      </div>
                      <div className={`shrink-0 w-4 h-4 rounded border-2 flex items-center justify-center ${
                        active ? 'border-white dark:border-black bg-white dark:bg-black' : 'border-outline-variant/40'
                      }`}>
                        {active && <Check size={9} className="text-black dark:text-white" strokeWidth={3} />}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            <AnimatePresence>
              {tags.includes('OTP') && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="space-y-3 overflow-hidden"
                >
                  <div className="flex items-center gap-2.5 p-3 rounded-xl bg-surface-container-low border border-outline-variant/20 mb-2">
                    <div className="p-1.5 rounded-lg bg-black dark:bg-white shrink-0">
                      <Clock size={13} className="text-white dark:text-black" />
                    </div>
                    <div>
                      <h4 className="text-xs font-black uppercase tracking-widest text-black dark:text-white">{t('addCredential.otpTitle', 'One-Time Password (OTP)')}</h4>
                      <p className="text-[10px] text-on-surface-variant mt-0.5">{t('addCredential.otpDesc', 'TOTP secret for authenticator apps')}</p>
                    </div>
                  </div>
                  <label htmlFor="otp-secret" className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">
                    {t('vault.otpSecretLabel', 'Secret Key')}
                  </label>
                  <input
                    id="otp-secret"
                    type="text" 
                    value={otpSecret}
                    onChange={(e) => {
                      dispatch({ type: 'setField', field: 'otpSecret', value: e.target.value.replace(/\s+/g, '').toUpperCase() });
                      if (otpSecretError) setOtpSecretError(null);
                    }}
                    placeholder="JBSWY3DPEHPK3PXP"
                    className={`w-full px-6 py-4 bg-surface-container-low rounded-xl border text-black dark:text-white placeholder:text-outline-variant font-mono focus:ring-2 transition-all outline-none ${otpSecretError ? 'border-red-500 focus:ring-red-500/20' : 'border-black/15 dark:border-white/15 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30'}`}
                  />
                  {otpSecretError && (
                    <motion.p 
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="text-xs text-red-500 font-bold flex items-center gap-1.5 mt-2 ml-1"
                    >
                      <AlertTriangle size={12} />
                      {otpSecretError}
                    </motion.p>
                  )}                </motion.div>
              )}
            </AnimatePresence>

            <AnimatePresence>
              {tags.includes('2FA') && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="space-y-4 overflow-hidden"
                >
                  <div className="flex items-center gap-2.5 p-3 rounded-xl bg-surface-container-low border border-outline-variant/20 mb-2">
                    <div className="p-1.5 rounded-lg bg-black dark:bg-white shrink-0">
                      <Smartphone size={13} className="text-white dark:text-black" />
                    </div>
                    <div>
                      <h4 className="text-xs font-black uppercase tracking-widest text-black dark:text-white">{t('addCredential.mfaTitle', 'Two-Factor Auth')}</h4>
                      <p className="text-[10px] text-on-surface-variant mt-0.5">{t('addCredential.mfaDesc', 'Phone number for SMS / app verification')}</p>
                    </div>
                  </div>
                  {phoneNumbers.map((item, index) => (
                    <div key={item.id} className="p-6 bg-surface-container-low/30 rounded-2xl border border-outline-variant/20 space-y-3 relative group">
                      {phoneNumbers.length > 1 && (
                        <button
                          type="button"
                          onClick={() => removePhoneNumber(item.id)}
                          className="absolute top-4 right-4 p-2 text-on-surface-variant hover:text-error hover:bg-error/10 rounded-lg transition-all opacity-0 group-hover:opacity-100"
                          title={t('addCredential.removePhoneNumber', 'Remove Phone Number')}
                        >
                          <X size={16} />
                        </button>
                      )}
                      <h5 className="text-[10px] font-black uppercase tracking-widest text-black dark:text-white mb-4">{t('addCredential.phoneNumberN', { n: index + 1, defaultValue: `Phone Number ${index + 1}` })}</h5>
                      <label htmlFor={`phone-number-${item.id}`} className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.phoneNumber', 'Phone Number')}</label>
                      <div className="flex gap-3">
                        <PhoneCountrySelect
                          value={item.iso}
                          onChange={(iso) => updatePhoneNumber(item.id, 'iso', iso)}
                          countries={COUNTRIES}
                        />
                        <div className="relative flex-1">
                          <input 
                            id={`phone-number-${item.id}`}
                            type="tel" 
                            value={item.value}
                            onChange={(e) => updatePhoneNumber(item.id, 'value', e.target.value)}
                            onFocus={() => setShowPhoneSuggestions(item.id)}
                            onBlur={() => setTimeout(() => setShowPhoneSuggestions(null), 200)}
                            placeholder={COUNTRIES.find(c => c.iso === item.iso)?.format?.toLowerCase() || "0000000000"} 
                            className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant font-bold focus:ring-2 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30 transition-all outline-none"
                          />
                          <AnimatePresence>
                            {showPhoneSuggestions === item.id && assetHolder.phoneNumbers.length > 0 && (
                              <motion.div
                                initial={{ opacity: 0, y: -10 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -10 }}
                                className="absolute top-full left-0 w-full mt-2 bg-white border border-outline-variant/10 rounded-xl shadow-lg overflow-hidden z-50"
                              >
                                {assetHolder.phoneNumbers.map((phone, i) => (
                                  <button
                                    key={i}
                                    type="button"
                                    onClick={() => {
                                      updatePhoneNumber(item.id, 'value', phone);
                                      setShowPhoneSuggestions(null);
                                    }}
                                    className="w-full text-left px-6 py-3 hover:bg-surface-container-low transition-colors text-sm font-bold text-black dark:text-white"
                                  >
                                    {phone}
                                  </button>
                                ))}
                              </motion.div>
                            )}
                          </AnimatePresence>
                        </div>
                      </div>
                    </div>
                  ))}
                  {phoneNumbers.length < 2 && (
                    <button
                      type="button"
                      onClick={addPhoneNumber}
                      className="w-full py-4 border-2 border-dashed border-outline-variant/30 text-on-surface-variant hover:text-black dark:hover:text-white hover:border-black dark:hover:border-white hover:bg-surface-container-low rounded-xl font-black uppercase tracking-widest text-xs transition-all flex items-center justify-center gap-2"
                    >
                      <Plus size={16} />
                      {t('addCredential.addPhoneNumber', 'Add Another Phone Number')}
                    </button>
                  )}
                </motion.div>
              )}

              {tags.includes('KBA') && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="space-y-4 overflow-hidden"
                >
                  <div className="flex items-center gap-2.5 p-3 rounded-xl bg-surface-container-low border border-outline-variant/20 mb-2">
                    <div className="p-1.5 rounded-lg bg-black dark:bg-white shrink-0">
                      <HelpCircle size={13} className="text-white dark:text-black" />
                    </div>
                    <div>
                      <h4 className="text-xs font-black uppercase tracking-widest text-black dark:text-white">{t('addCredential.kbaTitle', 'Security Questions (KBA)')}</h4>
                      <p className="text-[10px] text-on-surface-variant mt-0.5">{t('addCredential.kbaDesc', 'Knowledge-based security answers')}</p>
                    </div>
                  </div>
                  {kba.map((item, index) => (
                    <div key={item.id} className="space-y-4 p-6 bg-surface-container-low/30 rounded-2xl border border-outline-variant/20 relative group">
                      {kba.length > 1 && (
                        <button
                          type="button"
                          onClick={() => removeKbaQuestion(item.id)}
                          className="absolute top-4 right-4 p-2 text-on-surface-variant hover:text-error hover:bg-error/10 rounded-lg transition-all opacity-0 group-hover:opacity-100"
                          title="Remove Question"
                        >
                          <X size={16} />
                        </button>
                      )}
                      
                      <h5 className="text-[10px] font-black uppercase tracking-widest text-black dark:text-white mb-4">{t('addCredential.questionN', { n: index + 1, defaultValue: `Question ${index + 1}` })}</h5>

                      <div className="space-y-3">
                        <label htmlFor={`kba-question-${item.id}`} className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">
                          {t('addCredential.kbaQuestion', 'Security Question')}
                        </label>
                        <input 
                          id={`kba-question-${item.id}`}
                          type="text" 
                          value={item.question}
                          onChange={(e) => updateKba(item.id, 'question', e.target.value)}
                          placeholder={t('addCredential.kbaQuestionPlaceholder', 'What was the name of your first pet?')} 
                          className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant font-bold focus:ring-2 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30 transition-all outline-none"
                        />
                      </div>
                      <div className="space-y-3">
                        <label htmlFor={`kba-answer-${item.id}`} className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.kbaAnswer', 'Answer')}</label>
                        <input 
                          id={`kba-answer-${item.id}`}
                          type="text" 
                          value={item.answer}
                          onChange={(e) => updateKba(item.id, 'answer', e.target.value)}
                          placeholder={t('addCredential.kbaAnswerPlaceholder', 'Your answer')} 
                          className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant font-bold focus:ring-2 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30 transition-all outline-none"
                        />
                      </div>
                    </div>
                  ))}
                  
                  <button
                    type="button"
                    onClick={addKbaQuestion}
                    className="w-full py-4 border-2 border-dashed border-outline-variant/30 text-on-surface-variant hover:text-black dark:hover:text-white hover:border-black dark:hover:border-white hover:bg-surface-container-low rounded-xl font-black uppercase tracking-widest text-xs transition-all flex items-center justify-center gap-2"
                  >
                    <Plus size={16} />
                    {t('addCredential.addQuestion', 'Add Another Question')}
                  </button>
                </motion.div>
              )}

              {tags.includes('U2F') && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="space-y-4 overflow-hidden"
                >
                  <div className="flex items-center gap-2.5 p-3 rounded-xl bg-surface-container-low border border-outline-variant/20 mb-2">
                    <div className="p-1.5 rounded-lg bg-black dark:bg-white shrink-0">
                      <Key size={13} className="text-white dark:text-black" />
                    </div>
                    <div>
                      <h4 className="text-xs font-black uppercase tracking-widest text-black dark:text-white">{t('addCredential.u2fTitle', 'Hardware Key (U2F)')}</h4>
                      <p className="text-[10px] text-on-surface-variant mt-0.5">{t('addCredential.u2fDesc', 'Physical security key (YubiKey etc.)')}</p>
                    </div>
                  </div>
                  {u2fKeys.map((item, index) => (
                    <div key={item.id} className="p-6 bg-surface-container-low/30 rounded-2xl border border-outline-variant/20 space-y-3 relative group">
                      {u2fKeys.length > 1 && (
                        <button
                          type="button"
                          onClick={() => removeU2fKey(item.id)}
                          className="absolute top-4 right-4 p-2 text-on-surface-variant hover:text-error hover:bg-error/10 rounded-lg transition-all opacity-0 group-hover:opacity-100"
                          title={t('addCredential.removeU2fKey', 'Remove Security Key')}
                        >
                          <X size={16} />
                        </button>
                      )}
                      <h5 className="text-[10px] font-black uppercase tracking-widest text-black dark:text-white mb-4">{t('addCredential.u2fKeyN', { n: index + 1, defaultValue: `Security Key ${index + 1}` })}</h5>
                      <label htmlFor={`u2f-key-name-${item.id}`} className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.u2fKeyName', 'Key Name')}</label>
                      <div className="relative">
                        <input 
                          id={`u2f-key-name-${item.id}`}
                          type="text" 
                          value={item.value}
                          onChange={(e) => updateU2fKey(item.id, e.target.value)}
                          onFocus={() => setShowU2fSuggestions(item.id)}
                          onBlur={() => setTimeout(() => setShowU2fSuggestions(null), 200)}
                          placeholder={t('addCredential.u2fPlaceholder', 'e.g. YubiKey 5')} 
                          className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant font-bold focus:ring-2 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30 transition-all outline-none"
                        />
                        <AnimatePresence>
                          {showU2fSuggestions === item.id && assetHolder.u2fKeys.length > 0 && (
                            <motion.div
                              initial={{ opacity: 0, y: -10 }}
                              animate={{ opacity: 1, y: 0 }}
                              exit={{ opacity: 0, y: -10 }}
                              className="absolute top-full left-0 w-full mt-2 bg-white border border-outline-variant/10 rounded-xl shadow-lg overflow-hidden z-50"
                            >
                              {assetHolder.u2fKeys.map((key, i) => (
                                <button
                                  key={i}
                                  type="button"
                                  onClick={() => {
                                    updateU2fKey(item.id, key);
                                    setShowU2fSuggestions(null);
                                  }}
                                  className="w-full text-left px-6 py-3 hover:bg-surface-container-low transition-colors text-sm font-bold text-black dark:text-white"
                                >
                                  {key}
                                </button>
                              ))}
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </div>
                    </div>
                  ))}
                  {u2fKeys.length < 2 && (
                    <button
                      type="button"
                      onClick={addU2fKey}
                      className="w-full py-4 border-2 border-dashed border-outline-variant/30 text-on-surface-variant hover:text-black dark:hover:text-white hover:border-black dark:hover:border-white hover:bg-surface-container-low rounded-xl font-black uppercase tracking-widest text-xs transition-all flex items-center justify-center gap-2"
                    >
                      <Plus size={16} />
                      {t('addCredential.addU2fKey', 'Add Another Security Key')}
                    </button>
                  )}
                </motion.div>
              )}
            </AnimatePresence>

            <div className="space-y-4 pt-4">
              <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.folderAssignment', 'Folder Assignment')}</label>
              <div className="flex flex-wrap gap-3" role="radiogroup" aria-label={t('addCredential.folderAssignment', 'Folder Assignment')}>
                {folders.map((folder) => (
                  <button 
                    key={folder.id}
                    type="button" 
                    onClick={() => dispatch({ type: 'setField', field: 'folderId', value: folder.id })}
                    role="radio"
                    aria-checked={selectedFolder === folder.id}
                    aria-label={`Assign to ${folder.label} folder`}
                    className={`px-6 py-3 rounded-xl flex items-center gap-3 transition-all duration-300 ${
                      selectedFolder === folder.id 
                        ? 'bg-black text-white shadow-lg scale-105' 
                        : 'bg-surface-container-high text-black dark:text-white hover:bg-surface-container-highest'
                    }`}
                  >
                    {renderFolderIcon(folder, selectedFolder === folder.id)}
                    <span className="text-xs font-bold">{folder.label}</span>
                  </button>
                ))}
                <div className="relative z-10" ref={folderOptionsRef}>
                  <button
                    type="button"
                    onClick={() => setShowFolderOptions(!showFolderOptions)}
                    aria-label="More folder options"
                    aria-expanded={showFolderOptions}
                    className={`p-3 border border-outline-variant/30 text-on-surface-variant rounded-xl hover:bg-surface-container-low transition-colors ${showFolderOptions ? 'bg-surface-container-low border-black' : ''}`}
                  >
                    <MoreHorizontal size={20} aria-hidden="true" />
                  </button>
                  <AnimatePresence>
                    {showFolderOptions && (
                      <motion.div
                        initial={{ opacity: 0, y: 10, scale: 0.95 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        exit={{ opacity: 0, y: 10, scale: 0.95 }}
                        className="absolute bottom-full left-0 mb-4 w-48 bg-white rounded-2xl shadow-2xl border border-outline-variant/10 p-2 z-[100]"
                      >
                        <button 
                          type="button"
                          onClick={() => {
                            setShowFolderOptions(false);
                            if (onCreateFolder) onCreateFolder();
                          }}
                          className="w-full flex items-center gap-3 px-4 py-3 text-xs font-bold text-black dark:text-white hover:bg-surface-container-low rounded-xl transition-colors"
                          aria-label="Create new folder"
                        >
                          <Plus size={16} aria-hidden="true" />
                          {t('addCredential.createFolder', 'Create Folder')}
                        </button>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              </div>
            </div>

            {/* Notes - stored as plain markdown text, encrypted in the credential blob */}
            <div className="space-y-1.5">
              <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">
                {t('addCredential.descriptionLabel', 'Notes')}
              </label>

              {/* Word-processor-style editor card */}
              <div className="rounded-xl overflow-hidden border border-black/10 dark:border-white/10 shadow-sm focus-within:ring-2 focus-within:ring-on-primary-container/20 focus-within:border-black/25 dark:focus-within:border-white/25 transition-all">

                {/* Toolbar */}
                <div className="flex items-center gap-0.5 px-2.5 py-1.5 bg-surface-container-low border-b border-black/8 dark:border-white/8">
                  <button type="button" onMouseDown={(e) => { e.preventDefault(); toggleWrap('**'); }}
                    className="w-7 h-6 rounded flex items-center justify-center text-on-surface-variant hover:bg-surface-container-high hover:text-black dark:hover:text-white transition-all"
                    title={t('addCredential.toolbar.bold', 'Bold - toggle **text**')}>
                    <Bold size={13} strokeWidth={2.5} />
                  </button>
                  <button type="button" onMouseDown={(e) => { e.preventDefault(); toggleWrap('*'); }}
                    className="w-7 h-6 rounded flex items-center justify-center text-on-surface-variant hover:bg-surface-container-high hover:text-black dark:hover:text-white transition-all"
                    title={t('addCredential.toolbar.italic', 'Italic - toggle *text*')}>
                    <Italic size={13} strokeWidth={2} />
                  </button>
                  <button type="button" onMouseDown={(e) => { e.preventDefault(); toggleWrap('__'); }}
                    className="w-7 h-6 rounded flex items-center justify-center text-on-surface-variant hover:bg-surface-container-high hover:text-black dark:hover:text-white transition-all"
                    title={t('addCredential.toolbar.underline', 'Underline - toggle __text__')}>
                    <Underline size={13} strokeWidth={2} />
                  </button>

                  <div className="h-4 w-px bg-outline-variant/25 mx-1.5" />

                  <button type="button" onMouseDown={(e) => { e.preventDefault(); toggleBulletList(); }}
                    className="w-7 h-6 rounded flex items-center justify-center text-on-surface-variant hover:bg-surface-container-high hover:text-black dark:hover:text-white transition-all"
                    title={t('addCredential.toolbar.bulletList', 'Bullet list')}>
                    <List size={13} strokeWidth={2} />
                  </button>

                  <div className="grow" />

                  <button type="button" onMouseDown={(e) => { e.preventDefault(); clearMarkdown(); }}
                    className="w-7 h-6 rounded flex items-center justify-center text-on-surface-variant/60 hover:bg-surface-container-high hover:text-black dark:hover:text-white transition-all"
                    title={t('addCredential.toolbar.clear', 'Remove formatting from selection')}>
                    <Eraser size={12} strokeWidth={2} />
                  </button>
                </div>

                {/* Writing area - no monospace, document-like feel */}
                <textarea
                  ref={descTextareaRef}
                  value={description}
                  onChange={e => dispatch({ type: 'setField', field: 'description', value: e.target.value })}
                  onKeyDown={e => {
                    if ((e.ctrlKey || e.metaKey) && !e.shiftKey) {
                      if (e.key === 'b') { e.preventDefault(); toggleWrap('**'); }
                      if (e.key === 'i') { e.preventDefault(); toggleWrap('*'); }
                      if (e.key === 'u') { e.preventDefault(); toggleWrap('__'); }
                    }
                  }}
                  rows={6}
                  placeholder={t('addCredential.descriptionPlaceholder', 'Write your notes here… Ctrl+B bold, Ctrl+I italic')}
                  className="w-full px-5 py-4 bg-white dark:bg-[#111111] text-black dark:text-white text-[13.5px] leading-7 resize-y outline-none placeholder:text-gray-300 dark:placeholder:text-gray-600 block"
                />

                {/* Rendered preview - shows below the textarea when there is content */}
                {description.trim() && (
                  <div className="border-t border-black/8 dark:border-white/8 px-5 py-3.5 bg-surface-container-lowest dark:bg-[#0d0d0d]">
                    <p className="text-[8.5px] font-black uppercase tracking-widest text-outline-variant/50 mb-2.5 select-none">
                      {t('addCredential.descriptionPreview', 'Preview')}
                    </p>
                    <div className="text-[13px] leading-7 text-black dark:text-white [&_strong]:font-bold [&_em]:italic [&_u]:underline [&_ul]:list-disc [&_ul]:list-inside [&_ul]:space-y-0.5 [&_p]:min-h-[1.25em]">
                      {parseMarkdown(description)}
                    </div>
                  </div>
                )}
              </div>
            </div>

            </>}

            <div className="pt-12 flex items-center gap-6 border-t border-outline-variant/10">
              <button 
                type="button" 
                onClick={onCancel}
                aria-label={t('common.cancel', 'Cancel')}
                className="px-10 py-6 bg-surface-container-low text-on-surface-variant rounded-2xl font-black text-xs uppercase tracking-widest hover:bg-black hover:text-white transition-all flex items-center justify-center gap-3"
              >
                <X size={18} aria-hidden="true" />
                {t('common.cancel', 'Cancel')}
              </button>
              <button 
                type="submit" 
                aria-label={t('addCredential.save', 'Save Credential')}
                className="flex-1 px-12 py-6 bg-black text-white font-black uppercase tracking-widest text-xs rounded-2xl shadow-[0_20px_50px_rgba(0,0,0,0.2)] hover:bg-neutral-800 active:scale-95 transition-all flex items-center justify-center gap-3"
              >
                <Check size={18} aria-hidden="true" />
                {initialData ? t('addCredential.update', 'Update Credential') : t('addCredential.save', 'Save Credential')}
              </button>
            </div>
          </form>
        </div>

        {/* Generator Section */}
        <AnimatePresence>
          {isGeneratorVisible && (
            <motion.div 
              key="desktop-generator"
              initial={{ width: 0, opacity: 0 }}
              animate={{ width: 600, opacity: 1 }}
              exit={{ width: 0, opacity: 0 }}
              transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
              className="bg-black overflow-x-hidden overflow-y-auto relative border-l border-white/10 hidden lg:block rounded-r-2xl [scrollbar-width:thin] [scrollbar-color:rgba(255,255,255,0.2)_transparent] [&::-webkit-scrollbar]:w-1 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-white/20"
            >
              {/* Close Button */}
              <button 
                onClick={() => setIsGeneratorVisible(false)}
                aria-label="Close generator"
                className="absolute top-8 right-8 p-3 bg-white/10 hover:bg-white/20 rounded-full transition-all text-white/60 hover:text-white z-10"
              >
                <X size={24} aria-hidden="true" />
              </button>

              <div className="w-full p-5 flex flex-col">
                <div className="mb-2">
                  <h2 className="font-headline font-black text-2xl md:text-3xl tracking-tight text-white mb-1">{t('addCredential.proGenerator', 'Pro Generator')}</h2>
                  <p className="text-white/40 text-xs font-medium">{t('addCredential.generatorDesc', 'Create enterprise-grade credentials with high entropy.')}</p>
                </div>

                <div className="flex p-1 bg-white/5 rounded-2xl mb-2 w-fit" role="tablist" aria-label={t('addCredential.generator', 'Generator Mode')}>
                  <button
                    onClick={() => setIsPassphrase(false)}
                    role="tab"
                    aria-selected={!isPassphrase}
                    aria-label={t('addCredential.random', 'Random password mode')}
                    className={`px-6 py-2 ${!isPassphrase ? 'bg-white text-black shadow-xl' : 'text-white/40'} text-xs font-black uppercase tracking-widest rounded-xl transition-all flex items-center gap-2`}
                  >
                    <Type size={14} aria-hidden="true" />
                    {t('addCredential.random', 'Random')}
                  </button>
                  <button
                    onClick={() => setIsPassphrase(true)}
                    role="tab"
                    aria-selected={isPassphrase}
                    aria-label={t('addCredential.passphrase', 'Passphrase mode')}
                    className={`px-6 py-2 ${isPassphrase ? 'bg-white text-black shadow-xl' : 'text-white/40'} text-xs font-black uppercase tracking-widest rounded-xl transition-all flex items-center gap-2`}
                  >
                    <Hash size={16} aria-hidden="true" />
                    {t('addCredential.passphrase', 'Passphrase')}
                  </button>
                </div>

                {/* Password Display */}
                <div className="bg-white/5 rounded-2xl p-5 mb-5 border border-white/10 relative group">
                  <div className="flex justify-between items-start mb-3">
                    <div
                      className="text-base sm:text-lg lg:text-xl font-mono font-bold tracking-tight text-white break-all leading-snug pr-14"
                      aria-live="polite"
                      aria-atomic="true"
                    >
                      {password}
                    </div>
                    <div className="flex flex-col gap-1.5 absolute top-5 right-5">
                      <button
                        onClick={generatePassword}
                        aria-label="Regenerate password"
                        className="p-2 bg-white/10 text-white hover:bg-white/20 rounded-xl transition-all"
                      >
                        <RefreshCw size={16} aria-hidden="true" />
                      </button>
                      <button
                        onClick={handleCopy}
                        aria-label="Copy password to clipboard"
                        className="p-2 bg-white/10 text-white hover:bg-white/20 rounded-xl transition-all relative"
                      >
                        {copied ? <Check size={16} className="text-green-400" aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}
                      </button>
                    </div>
                  </div>
                  <div className="space-y-4 mt-3">
                    <div className="flex items-center justify-between pr-14">
                      <span className="text-[10px] font-black uppercase text-white/40 tracking-[0.3em]">{t('addCredential.entropyAnalysis', 'Entropy Analysis')}</span>
                      <span className={`text-xs font-black uppercase ${strength.barText} tracking-widest`}>{strength.label}</span>
                    </div>
                    <div className="h-3 bg-white/5 rounded-full overflow-hidden" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-label={t('vault.securityHealth', 'Password strength')}>
                      <div className={`h-full ${strength.bar} ${strength.barWidth} rounded-full transition-all duration-700 ease-out shadow-[0_0_20px_rgba(255,255,255,0.2)]`}></div>
                    </div>
                  </div>
                </div>

                {/* Controls */}
                <div className="space-y-5">
                  {!isPassphrase ? (
                    <div className="space-y-4">
                      <div className="flex justify-between items-center">
                        <label htmlFor="char-length" className="text-[10px] font-black uppercase tracking-[0.3em] text-white/40">{t('addCredential.charLength', 'Character Length')}</label>
                        <span className="text-sm font-black text-white bg-white/10 px-3 py-1.5 rounded-xl border border-white/10">{length}</span>
                      </div>
                      <input 
                        id="char-length"
                        type="range" 
                        min="4" 
                        max="128"
                        value={length}
                        onChange={(e) => setLength(parseInt(e.target.value))}
                        aria-label={t('addCredential.charLength', 'Adjust character length')}
                        className="w-full h-2 bg-white/10 rounded-lg appearance-none cursor-pointer accent-white"
                      />
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className="flex justify-between items-center">
                        <label htmlFor="word-count" className="text-[10px] font-black uppercase tracking-[0.3em] text-white/40">{t('addCredential.wordCount', 'Word Count')}</label>
                        <span className="text-sm font-black text-white bg-white/10 px-3 py-1.5 rounded-xl border border-white/10">{wordCount}</span>
                      </div>
                      <input 
                        id="word-count"
                        type="range" 
                        min="3" 
                        max="10" 
                        value={wordCount}
                        onChange={(e) => setWordCount(parseInt(e.target.value))}
                        aria-label={t('addCredential.wordCount', 'Adjust word count')}
                        className="w-full h-2 bg-white/10 rounded-lg appearance-none cursor-pointer accent-white"
                      />
                    </div>
                  )}

                  <div className="space-y-5">
                    <span className="text-[10px] font-black uppercase tracking-[0.3em] text-white/40">{t('addCredential.securityParameters', 'Security Parameters')}</span>
                    <div className="grid grid-cols-2 gap-3">
                      {!isPassphrase && (
                        <>
                          <button
                            onClick={() => setIncludeUppercase(!includeUppercase)}
                            aria-pressed={includeUppercase}
                            aria-label={t('addCredential.uppercase', 'Include uppercase characters')}
                            className={`flex items-center justify-between p-3 rounded-xl border-2 transition-all ${includeUppercase ? 'bg-white border-white text-black' : 'bg-white/5 border-white/10 text-white/60 hover:border-white/20'}`}
                          >
                            <span className="text-xs font-bold">{t('addCredential.uppercase', 'Uppercase')}</span>
                            {includeUppercase ? <Check size={14} aria-hidden="true" /> : <div className="w-3.5 h-3.5 rounded border border-white/20" aria-hidden="true" />}
                          </button>
                          <button
                            onClick={() => setIncludeLowercase(!includeLowercase)}
                            aria-pressed={includeLowercase}
                            aria-label={t('addCredential.lowercase', 'Include lowercase characters')}
                            className={`flex items-center justify-between p-3 rounded-xl border-2 transition-all ${includeLowercase ? 'bg-white border-white text-black' : 'bg-white/5 border-white/10 text-white/60 hover:border-white/20'}`}
                          >
                            <span className="text-xs font-bold">{t('addCredential.lowercase', 'Lowercase')}</span>
                            {includeLowercase ? <Check size={14} aria-hidden="true" /> : <div className="w-3.5 h-3.5 rounded border border-white/20" aria-hidden="true" />}
                          </button>
                          <button
                            onClick={() => setIncludeNumbers(!includeNumbers)}
                            aria-pressed={includeNumbers}
                            aria-label={t('addCredential.numbers', 'Include numbers')}
                            className={`flex items-center justify-between p-3 rounded-xl border-2 transition-all ${includeNumbers ? 'bg-white border-white text-black' : 'bg-white/5 border-white/10 text-white/60 hover:border-white/20'}`}
                          >
                            <span className="text-xs font-bold">{t('addCredential.numbers', 'Numbers')}</span>
                            {includeNumbers ? <Check size={14} aria-hidden="true" /> : <div className="w-3.5 h-3.5 rounded border border-white/20" aria-hidden="true" />}
                          </button>
                        </>
                      )}
                      <button
                        onClick={() => setIncludeSymbols(!includeSymbols)}
                        aria-pressed={includeSymbols}
                        aria-label={t('addCredential.symbols', 'Include symbols')}
                        className={`flex items-center justify-between p-3 rounded-xl border-2 transition-all ${includeSymbols ? 'bg-white border-white text-black' : 'bg-white/5 border-white/10 text-white/60 hover:border-white/20'} ${isPassphrase ? 'col-span-2' : ''}`}
                      >
                        <span className="text-xs font-bold">{t('addCredential.symbols', 'Symbols')}</span>
                        {includeSymbols ? <Check size={14} aria-hidden="true" /> : <div className="w-3.5 h-3.5 rounded border border-white/20" aria-hidden="true" />}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="mt-3 p-4 bg-white/5 rounded-2xl border border-white/10 space-y-4">
                  {/* Header — entropy headline */}
                  <div className="flex gap-3 items-center">
                    <div className="w-10 h-10 bg-white/10 rounded-xl flex items-center justify-center shrink-0">
                      <ShieldCheck size={20} className="text-white" />
                    </div>
                    <div>
                      <h4 className="text-white font-bold text-sm">{t('addCredential.securityAdvisory', 'Security Advisory')}</h4>
                      <p className="text-[11px] text-white/40 font-medium">
                        {t('addCredential.entropyHeadline', '{{bits}} bits of entropy · {{label}}', { bits: bitsRounded, label: strength.label })}
                      </p>
                    </div>
                  </div>

                  {/* Quantum-resistance badge (reactive to entropy) */}
                  <div
                    className={`rounded-xl border p-3 ${
                      quantum.level === 'proof' ? 'border-green-500/40 bg-green-500/10'
                      : quantum.level === 'resistant' ? 'border-amber-500/40 bg-amber-500/10'
                      : 'border-red-500/40 bg-red-500/10'
                    }`}
                    role="status"
                    aria-live="polite"
                  >
                    <div className="flex items-center gap-2 mb-1">
                      {quantum.level === 'proof' ? <ShieldCheck size={15} className="text-green-300 shrink-0" aria-hidden="true" />
                        : quantum.level === 'resistant' ? <Atom size={15} className="text-amber-300 shrink-0" aria-hidden="true" />
                        : <ShieldAlert size={15} className="text-red-300 shrink-0" aria-hidden="true" />}
                      <span className={`text-xs font-black uppercase tracking-widest ${
                        quantum.level === 'proof' ? 'text-green-300'
                        : quantum.level === 'resistant' ? 'text-amber-300'
                        : 'text-red-300'
                      }`}>
                        {quantum.level === 'proof' ? t('addCredential.quantum.proof', 'Quantum-Proof')
                          : quantum.level === 'resistant' ? t('addCredential.quantum.resistant', 'Quantum-Resistant')
                          : t('addCredential.quantum.vulnerable', 'Quantum-Vulnerable')}
                      </span>
                    </div>
                    <p className="text-[11px] text-white/50 leading-relaxed">
                      {quantum.level === 'proof'
                        ? t('addCredential.quantum.proofDesc', "Retains 128-bit security even against Grover's algorithm — on par with the AES-256 backbone of this vault.")
                        : quantum.level === 'resistant'
                        ? t('addCredential.quantum.resistantDesc', "Grover's algorithm halves this to {{pq}} effective bits. Add ~{{add}} more bits of entropy to reach quantum-proof.", { pq: Math.round(quantum.postQuantumBits), add: bitsToQuantumProof })
                        : t('addCredential.quantum.vulnerableDesc', "Grover's algorithm halves this to just {{pq}} effective bits against a quantum attacker.", { pq: Math.round(quantum.postQuantumBits) })}
                    </p>
                  </div>

                  {/* Threat-model selector — recomputes crack time live */}
                  <div>
                    <span className="text-[9px] font-black uppercase tracking-[0.3em] text-white/40">{t('addCredential.attacker.label', 'Threat Model')}</span>
                    <div className="flex p-1 bg-white/5 rounded-xl gap-1 mt-2" role="tablist" aria-label={t('addCredential.attacker.label', 'Threat Model')}>
                      {(['online', 'gpu', 'nationState'] as AttackerProfileId[]).map((id) => (
                        <button
                          key={id}
                          type="button"
                          role="tab"
                          aria-selected={attackerProfile === id}
                          onClick={() => setAttackerProfile(id)}
                          className={`flex-1 px-2 py-2 text-[9px] font-black uppercase tracking-wider rounded-lg transition-all ${attackerProfile === id ? 'bg-white text-black shadow' : 'text-white/40 hover:text-white/70'}`}
                        >
                          {id === 'online' ? t('addCredential.attacker.online', 'Online')
                            : id === 'gpu' ? t('addCredential.attacker.gpu', 'GPU Rig')
                            : t('addCredential.attacker.nationState', 'Nation-State')}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Crack-time estimate — classical vs quantum */}
                  <div className="grid grid-cols-2 gap-2">
                    <div className="rounded-xl bg-white/5 border border-white/10 p-3">
                      <div className="flex items-center gap-1.5 mb-1">
                        <Clock size={12} className="text-white/40" aria-hidden="true" />
                        <span className="text-[9px] font-black uppercase tracking-widest text-white/40">{t('addCredential.crack.classical', 'Classical')}</span>
                      </div>
                      <p className="text-sm font-bold text-white break-words leading-tight">{formatCrack(classicalCrack)}</p>
                    </div>
                    <div className="rounded-xl bg-white/5 border border-white/10 p-3">
                      <div className="flex items-center gap-1.5 mb-1">
                        <Atom size={12} className="text-white/40" aria-hidden="true" />
                        <span className="text-[9px] font-black uppercase tracking-widest text-white/40">{t('addCredential.crack.quantum', 'Quantum')}</span>
                      </div>
                      <p className="text-sm font-bold text-white break-words leading-tight">{formatCrack(quantumCrack)}</p>
                    </div>
                  </div>
                  <p className="text-[10px] text-white/30 leading-snug -mt-1">
                    {t('addCredential.crack.note', "Average time to exhaust the keyspace at {{rate}} guesses/sec. Quantum figures assume Grover's algorithm.", { rate: numberFmt.format(guessesPerSecond) })}
                  </p>

                  {/* Breach intelligence (Have I Been Pwned) */}
                  <div
                    className={`rounded-xl border p-3 flex items-start gap-2 ${
                      breachStatus === 'pwned' ? 'border-red-500/40 bg-red-500/10'
                      : breachStatus === 'clean' ? 'border-green-500/40 bg-green-500/10'
                      : 'border-white/10 bg-white/5'
                    }`}
                    role="status"
                    aria-live="polite"
                  >
                    {breachStatus === 'checking' ? <Loader2 size={15} className="text-white/50 animate-spin mt-[1px] shrink-0" aria-hidden="true" />
                      : breachStatus === 'pwned' ? <ShieldAlert size={15} className="text-red-300 mt-[1px] shrink-0" aria-hidden="true" />
                      : breachStatus === 'clean' ? <ShieldCheck size={15} className="text-green-300 mt-[1px] shrink-0" aria-hidden="true" />
                      : <Info size={15} className="text-white/40 mt-[1px] shrink-0" aria-hidden="true" />}
                    <div>
                      <p className={`text-xs font-bold ${
                        breachStatus === 'pwned' ? 'text-red-300'
                        : breachStatus === 'clean' ? 'text-green-300'
                        : 'text-white/60'
                      }`}>
                        {breachStatus === 'checking' ? t('addCredential.breach.checking', 'Checking breach databases…')
                          : breachStatus === 'pwned' ? t('addCredential.breach.pwned', 'Found in public breaches')
                          : breachStatus === 'clean' ? t('addCredential.breach.clean', 'Not found in any known breach')
                          : breachStatus === 'idle' ? t('addCredential.breach.idle', 'Enter a password to check')
                          : t('addCredential.breach.unavailable', 'Breach check unavailable')}
                      </p>
                      {breachStatus === 'pwned' && (
                        <p className="text-[11px] text-red-200/70 leading-snug">
                          {breachCount > 0
                            ? t('addCredential.breach.pwnedCount', 'Exposed {{count}} times in known breaches — never use this password.', { count: breachCount })
                            : t('addCredential.breach.pwnedGeneric', 'This password has leaked publicly — choose another.')}
                        </p>
                      )}
                      {breachStatus === 'clean' && (
                        <p className="text-[11px] text-green-200/60 leading-snug">{t('addCredential.breach.cleanDesc', 'Checked against Have I Been Pwned via k-anonymity — your password never left the device.')}</p>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {/* Mobile Generator (Overlay or Full width) */}
          {isGeneratorVisible && (
            <motion.div 
              key="mobile-generator"
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="w-full bg-surface-container-low border-t border-outline-variant/10 lg:hidden overflow-hidden rounded-b-2xl"
            >
              <div className="p-8">
                {/* Same content as above but optimized for mobile if needed, 
                    for now just reusing the same structure by letting it flow */}
                <div className="flex items-center justify-between mb-8">
                  <h2 className="font-headline font-black text-xl tracking-tight">{t('addCredential.generator', 'Generator')}</h2>
                  <div className="flex p-1 bg-surface-container-high rounded-lg">
                    <button onClick={() => setIsPassphrase(false)} className={`px-4 py-1.5 ${!isPassphrase ? 'bg-white shadow-sm' : 'text-on-surface-variant'} text-[10px] font-black uppercase rounded-md transition-all`}>{t('addCredential.random', 'Random')}</button>
                    <button onClick={() => setIsPassphrase(true)} className={`px-4 py-1.5 ${isPassphrase ? 'bg-white shadow-sm' : 'text-on-surface-variant'} text-[10px] font-black uppercase rounded-md transition-all`}>{t('addCredential.passphrase', 'Passphrase')}</button>
                  </div>
                </div>
                {/* ... (rest of mobile content could be simplified or identical) ... */}
                <div className="bg-white rounded-2xl p-6 mb-8 shadow-lg overflow-hidden">
                  <div className="text-xl font-mono font-bold break-all mb-4 pr-10 relative">
                    {password}
                    <div className="absolute top-0 right-0 flex flex-col gap-2">
                      <button onClick={generatePassword} className="p-1.5 text-on-surface-variant"><RefreshCw size={16} /></button>
                      <button onClick={handleCopy} className="p-1.5 text-on-surface-variant">{copied ? <Check size={16} className="text-green-600" /> : <Copy size={16} />}</button>
                    </div>
                  </div>
                  <div className="h-1.5 bg-surface-container-low rounded-full overflow-hidden">
                    <div className={`h-full ${strength.bg} ${strength.barWidth} rounded-full`}></div>
                  </div>
                </div>
                {/* Mobile controls simplified */}
                <div className="space-y-6">
                  <input type="range" min={isPassphrase ? 3 : 4} max={isPassphrase ? 10 : 64} value={isPassphrase ? wordCount : length} onChange={(e) => isPassphrase ? setWordCount(parseInt(e.target.value)) : setLength(parseInt(e.target.value))} className="w-full accent-black" />
                  <div className="grid grid-cols-2 gap-3">
                    {/* Simplified mobile checkboxes */}
                    <button onClick={() => setIncludeSymbols(!includeSymbols)} className={`p-3 rounded-xl border-2 text-[10px] font-black uppercase transition-all ${includeSymbols ? 'bg-black text-white border-black' : 'bg-white text-black border-transparent shadow-sm'}`}>{t('addCredential.symbols', 'Symbols')}</button>
                    {!isPassphrase && <button onClick={() => setIncludeNumbers(!includeNumbers)} className={`p-3 rounded-xl border-2 text-[10px] font-black uppercase transition-all ${includeNumbers ? 'bg-black text-white border-black' : 'bg-white text-black border-transparent shadow-sm'}`}>{t('addCredential.numbers', 'Numbers')}</button>}
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Footer Security Notice */}
      <div className="mt-12 flex items-center justify-center gap-8 opacity-30">
        <div className="flex items-center gap-3">
          <ShieldCheck size={16} />
          <span className="text-[10px] font-black uppercase tracking-[0.2em]">{t('addCredential.aesEncryption', 'AES-256 Bit Encryption')}</span>
        </div>
        <div className="w-1.5 h-1.5 bg-outline-variant rounded-full"></div>
        <div className="flex items-center gap-3">
          <Lock size={16} />
          <span className="text-[10px] font-black uppercase tracking-[0.2em]">{t('addCredential.zeroKnowledge', 'Zero-Knowledge Architecture')}</span>
        </div>
      </div>
    </motion.div>
  );
}
