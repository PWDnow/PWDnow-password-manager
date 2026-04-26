import React, { useState, useEffect, useCallback, useRef } from 'react';
import { ChevronRight, ShieldCheck, RefreshCw, Copy, Info, Lock, Briefcase, User, Wallet, MoreHorizontal, Check, X, Wand2, Hash, Type, Globe, Plus, Gamepad2, Bitcoin, Dices, Folder as FolderIcon, CreditCard, Key, Clock, Eye, EyeOff, Smartphone, HelpCircle, Shield } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation, Trans } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { Folder, Credential } from '../types';
import { useVault } from '../context/VaultContext';
import { generateUUID } from '../utils/crypto';
import { sanitizeSvg } from '../utils/sanitize';
import { daemon } from '../utils/daemonClient';
import PhoneCountrySelect from '../components/PhoneCountrySelect';

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
  ShieldCheck,
  CreditCard,
  Key
};

import COUNTRIES from '../data/countries.json';

export default function AddCredential({ folders, activeTab, initialData, onCreateFolder, onAddCredential, onUpdateCredential, onCancel }: AddCredentialProps) {
  const { t } = useTranslation();
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
  const [title, setTitle] = useState(initialData?.service || '');
  const [username, setUsername] = useState(initialData?.username === 'No username' ? '' : (initialData?.username || ''));
  const [url, setUrl] = useState(initialData?.url || '');
  const [length, setLength] = useState(24);
  const [wordCount, setWordCount] = useState(6);
  const [includeUppercase, setIncludeUppercase] = useState(true);
  const [includeLowercase, setIncludeLowercase] = useState(true);
  const [includeNumbers, setIncludeNumbers] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);
  const [isPassphrase, setIsPassphrase] = useState(false);
  const [password, setPassword] = useState(initialData?.password || '');
  const [isGeneratorVisible, setIsGeneratorVisible] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState(false);
  const [urlError, setUrlError] = useState<string | null>(null);
  const [usernameError, setUsernameError] = useState<string | null>(null);
  const [otpSecret, setOtpSecret] = useState(initialData?.otpSecret || '');
  // HIBP breach status for the current password. Advisory only — does not
  // block submit. Kept in state rather than derived so the UI can show
  // "checking…" feedback during the async daemon round-trip.
  const [breachStatus, setBreachStatus] = useState<BreachStatus>('idle');
  
  const [showEmailSuggestions, setShowEmailSuggestions] = useState(false);
  const [showPhoneSuggestions, setShowPhoneSuggestions] = useState<string | null>(null);
  const [showU2fSuggestions, setShowU2fSuggestions] = useState<string | null>(null);

  // Default to activeTab if it's a valid folder, otherwise default to the first folder
  const initialFolder = initialData?.folderId || ((activeTab && activeTab !== 'vault' && folders.some(f => f.id === activeTab)) 
    ? activeTab 
    : (folders[0]?.id || 'work'));
    
  const [selectedFolder, setSelectedFolder] = useState(initialFolder);
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
  const [tags, setTags] = useState<string[]>(() => {
    const initialTags = initialData?.tags || [];
    const finalTags = [...initialTags];
    if (initialData?.otpSecret && !finalTags.includes('OTP')) {
      finalTags.push('OTP');
    }
    if (initialData?.phoneNumber && Array.isArray(initialData.phoneNumber) && initialData.phoneNumber.length > 0 && !finalTags.includes('2FA')) {
      finalTags.push('2FA');
    } else if (initialData?.phoneNumber && typeof initialData.phoneNumber === 'string' && !finalTags.includes('2FA')) {
      finalTags.push('2FA');
    }
    return finalTags;
  });
  const [phoneNumbers, setPhoneNumbers] = useState<{id: string, iso: string, value: string}[]>(() => {
    if (Array.isArray(initialData?.phoneNumber)) {
      return initialData.phoneNumber.map(p => {
        const match = COUNTRIES.find(c => p.startsWith(c.code));
        if (match) {
          return { id: generateUUID(), iso: match.iso, value: p.replace(match.code, '').trim() };
        }
        return { id: generateUUID(), iso: 'US', value: p };
      });
    } else if (initialData?.phoneNumber) {
      const p = initialData.phoneNumber as string;
      const match = COUNTRIES.find(c => p.startsWith(c.code));
      if (match) {
        return [{ id: generateUUID(), iso: match.iso, value: p.replace(match.code, '').trim() }];
      }
      return [{ id: generateUUID(), iso: 'US', value: p }];
    }
    return [{ id: generateUUID(), iso: 'US', value: '' }];
  });
  const [kba, setKba] = useState<{id: string, question: string, answer: string}[]>(() => {
    if (initialData?.kba && initialData.kba.length > 0) {
      return initialData.kba.map(k => ({ ...k, id: generateUUID() }));
    }
    // Handle legacy data format
    if ((initialData as any)?.kbaQuestion || (initialData as any)?.kbaAnswer) {
      return [{ 
        id: generateUUID(),
        question: (initialData as any).kbaQuestion || '', 
        answer: (initialData as any).kbaAnswer || '' 
      }];
    }
    return [{ id: generateUUID(), question: '', answer: '' }];
  });
  const [u2fKeys, setU2fKeys] = useState<{id: string, value: string}[]>(() => {
    if (Array.isArray(initialData?.u2fKeyName)) {
      return initialData.u2fKeyName.map(u => ({ id: generateUUID(), value: u }));
    } else if (initialData?.u2fKeyName) {
      return [{ id: generateUUID(), value: initialData.u2fKeyName as string }];
    }
    return [{ id: generateUUID(), value: '' }];
  });

  const addPhoneNumber = () => {
    if (phoneNumbers.length < 2) {
      setPhoneNumbers([...phoneNumbers, { id: generateUUID(), iso: 'US', value: '' }]);
    }
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

  const addKbaQuestion = () => {
    setKba([...kba, { id: generateUUID(), question: '', answer: '' }]);
  };

  const updateKba = (id: string, field: 'question' | 'answer', value: string) => {
    setKba(kba.map(item => item.id === id ? { ...item, [field]: value } : item));
  };

  const removeKbaQuestion = (id: string) => {
    if (kba.length > 1) {
      setKba(kba.filter(item => item.id !== id));
    }
  };

  const toggleTag = (tag: string) => {
    setTags(prev => prev.includes(tag) ? prev.filter(t => t !== tag) : [...prev, tag]);
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
    
    const IconComponent = folder.iconName ? ICON_MAP[folder.iconName] : FolderIcon;
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
      setPassword(result);
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
      setPassword(generatedPassword);
    }
  }, [length, wordCount, includeUppercase, includeLowercase, includeNumbers, includeSymbols, isPassphrase]);

  useEffect(() => {
    generatePassword();
  }, [generatePassword]);

  // HIBP breach lookup, debounced. Only runs against the local daemon filter
  // (architecture §4 — passwords never leave the machine). Debounced so
  // typing doesn't hammer the socket; reset to idle for empty inputs.
  useEffect(() => {
    if (!password) { setBreachStatus('idle'); return; }
    if (!daemon.isConnected) { setBreachStatus('unavailable'); return; }
    setBreachStatus('checking');
    const snapshot = password;
    const timer = setTimeout(() => {
      daemon.checkPasswordBreached(snapshot)
        .then(({ pwned, filter_available }) => {
          // Late responses for a stale password would flicker the banner;
          // drop them if the user has typed since we issued the request.
          if (snapshot !== password) return;
          if (!filter_available) setBreachStatus('unavailable');
          else setBreachStatus(pwned ? 'pwned' : 'clean');
        })
        .catch(() => { if (snapshot === password) setBreachStatus('error'); });
    }, 400);
    return () => clearTimeout(timer);
  }, [password]);

  const getStrength = (pwd: string) => {
    const len = pwd.length;
    const hasUpper = /[A-Z]/.test(pwd);
    const hasLower = /[a-z]/.test(pwd);
    const hasNumber = /[0-9]/.test(pwd);
    const hasSpecial = /[^A-Za-z0-9]/.test(pwd);

    // Password Strength Rules — barText uses bright variants for dark generator bg
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

  const handleCopy = () => {
    navigator.clipboard.writeText(password);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    // HIGH-06: clear clipboard after 30 s so the password doesn't linger
    setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 30_000);
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
          <form className="space-y-10" onSubmit={(e) => {
            e.preventDefault();
            if (!title.trim()) return;

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

              const credData = {
                id: initialData?.id || generateUUID(),
                service: title,
                url: formattedUrl,
                username: username.trim() || 'No username',
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
                otpSecret: tags.includes('OTP') ? otpSecret : undefined
              };

            if (initialData && onUpdateCredential) {
              onUpdateCredential(credData);
            } else if (onAddCredential) {
              onAddCredential(credData);
            }
            if (onCancel) onCancel();
          }}>
            <div className="space-y-3">
              <label htmlFor="service-title" className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.serviceLabel', 'Title / Service Name')} <span className="text-red-500">*</span></label>
              <input 
                id="service-title"
                type="text" 
                required
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder={t('addCredential.servicePlaceholder', 'e.g. GitHub Enterprise')} 
                aria-label="Service Name"
                className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant font-bold focus:ring-2 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30 transition-all outline-none"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div className="space-y-3 relative">
                <label htmlFor="username" className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.usernameLabel', 'Username / Email')}</label>
                <input 
                  id="username"
                  type="text" 
                  value={username}
                  onChange={(e) => {
                    const val = e.target.value;
                    setUsername(val);
                    // Regex validation: must have @ and a dot in domain, and no spaces
                    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                    if (val && !emailRegex.test(val)) {
                      setUsernameError('Invalid email format');
                    } else {
                      setUsernameError(null);
                    }
                  }}
                  onFocus={() => setShowEmailSuggestions(true)}
                  onBlur={() => {
                    setTimeout(() => setShowEmailSuggestions(false), 200);
                    // Clean up email: remove non-essential characters if it looks like an email
                    if (username.includes('@')) {
                      const cleaned = username.replace(/[^\w@.-]/g, '');
                      if (cleaned !== username) setUsername(cleaned);
                    }
                  }}
                  placeholder="name@example.com" 
                  aria-label="Username or Email"
                  className={`w-full px-6 py-4 bg-surface-container-low rounded-xl text-black dark:text-white placeholder:text-outline-variant focus:ring-2 transition-all outline-none ${usernameError ? 'border border-red-500 focus:ring-red-500/20' : 'border border-black/15 dark:border-white/15 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30'}`}
                />
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
                  {showEmailSuggestions && assetHolder.emails.length > 0 && (
                    <motion.div
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      className="absolute top-full left-0 w-full mt-2 bg-white border border-outline-variant/10 rounded-xl shadow-lg overflow-hidden z-50"
                    >
                      {assetHolder.emails.map((email, i) => (
                        <button
                          key={i}
                          type="button"
                          onClick={() => {
                            setUsername(email);
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
              <div className="space-y-3">
                <label htmlFor="website-url" className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.urlLabel', 'Website URL')}</label>
                <input 
                  id="website-url"
                  type="text" 
                  value={url}
                  onChange={(e) => {
                    setUrl(e.target.value);
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
                  onChange={(e) => setPassword(e.target.value)}
                  aria-label="Password"
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
                      'This password appears in public breaches — consider regenerating.'
                    )}
                  </span>
                </motion.div>
              )}
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.tags', 'Tags')}</label>
                <p className="text-[10px] text-on-surface-variant/60 mt-1">Select all security features stored with this credential.</p>
              </div>
              <div className="grid grid-cols-2 gap-2.5">
                {([
                  { tag: '2FA',  Icon: Smartphone,  title: 'Two-Factor Auth',     desc: 'Phone number for SMS / app verification' },
                  { tag: 'OTP',  Icon: Clock,        title: 'One-Time Password',   desc: 'TOTP secret for authenticator apps' },
                  { tag: 'KBA',  Icon: HelpCircle,   title: 'Security Questions',  desc: 'Knowledge-based security answers' },
                  { tag: 'U2F',  Icon: Key,           title: 'Hardware Key',        desc: 'Physical security key (YubiKey etc.)' },
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
                      <h4 className="text-xs font-black uppercase tracking-widest text-black dark:text-white">One-Time Password (OTP)</h4>
                      <p className="text-[10px] text-on-surface-variant mt-0.5">TOTP secret for authenticator apps</p>
                    </div>
                  </div>
                  <label htmlFor="otp-secret" className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">
                    {t('vault.otpSecretLabel', 'Secret Key')}
                  </label>
                  <input 
                    id="otp-secret"
                    type="text" 
                    value={otpSecret}
                    onChange={(e) => setOtpSecret(e.target.value.replace(/\s+/g, '').toUpperCase())}
                    placeholder="JBSWY3DPEHPK3PXP" 
                    className="w-full px-6 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white placeholder:text-outline-variant font-mono focus:ring-2 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30 transition-all outline-none"
                  />
                </motion.div>
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
                      <h4 className="text-xs font-black uppercase tracking-widest text-black dark:text-white">Two-Factor Auth</h4>
                      <p className="text-[10px] text-on-surface-variant mt-0.5">Phone number for SMS / app verification</p>
                    </div>
                  </div>
                  {phoneNumbers.map((item, index) => (
                    <div key={item.id} className="p-6 bg-surface-container-low/30 rounded-2xl border border-outline-variant/20 space-y-3 relative group">
                      {phoneNumbers.length > 1 && (
                        <button
                          type="button"
                          onClick={() => removePhoneNumber(item.id)}
                          className="absolute top-4 right-4 p-2 text-on-surface-variant hover:text-error hover:bg-error/10 rounded-lg transition-all opacity-0 group-hover:opacity-100"
                          title="Remove Phone Number"
                        >
                          <X size={16} />
                        </button>
                      )}
                      <h5 className="text-[10px] font-black uppercase tracking-widest text-black dark:text-white mb-4">Phone Number {index + 1}</h5>
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
                            placeholder={COUNTRIES.find(c => c.iso === item.iso)?.format || "0000000000"} 
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
                      Add Another Phone Number
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
                      <h4 className="text-xs font-black uppercase tracking-widest text-black dark:text-white">Security Questions (KBA)</h4>
                      <p className="text-[10px] text-on-surface-variant mt-0.5">Knowledge-based security answers</p>
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
                      
                      <h5 className="text-[10px] font-black uppercase tracking-widest text-black dark:text-white mb-4">Question {index + 1}</h5>

                      <div className="space-y-3">
                        <label htmlFor={`kba-question-${item.id}`} className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">
                          {t('addCredential.kbaQuestion', 'Security Question')}
                        </label>
                        <input 
                          id={`kba-question-${item.id}`}
                          type="text" 
                          value={item.question}
                          onChange={(e) => updateKba(item.id, 'question', e.target.value)}
                          placeholder="What was the name of your first pet?" 
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
                          placeholder="Your answer" 
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
                    Add Another Question
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
                      <h4 className="text-xs font-black uppercase tracking-widest text-black dark:text-white">Hardware Key (U2F)</h4>
                      <p className="text-[10px] text-on-surface-variant mt-0.5">Physical security key (YubiKey etc.)</p>
                    </div>
                  </div>
                  {u2fKeys.map((item, index) => (
                    <div key={item.id} className="p-6 bg-surface-container-low/30 rounded-2xl border border-outline-variant/20 space-y-3 relative group">
                      {u2fKeys.length > 1 && (
                        <button
                          type="button"
                          onClick={() => removeU2fKey(item.id)}
                          className="absolute top-4 right-4 p-2 text-on-surface-variant hover:text-error hover:bg-error/10 rounded-lg transition-all opacity-0 group-hover:opacity-100"
                          title="Remove Security Key"
                        >
                          <X size={16} />
                        </button>
                      )}
                      <h5 className="text-[10px] font-black uppercase tracking-widest text-black dark:text-white mb-4">Security Key {index + 1}</h5>
                      <label htmlFor={`u2f-key-name-${item.id}`} className="text-[10px] font-black uppercase tracking-[0.2em] text-on-surface-variant">{t('addCredential.u2fKeyName', 'Key Name')}</label>
                      <div className="relative">
                        <input 
                          id={`u2f-key-name-${item.id}`}
                          type="text" 
                          value={item.value}
                          onChange={(e) => updateU2fKey(item.id, e.target.value)}
                          onFocus={() => setShowU2fSuggestions(item.id)}
                          onBlur={() => setTimeout(() => setShowU2fSuggestions(null), 200)}
                          placeholder="e.g. YubiKey 5" 
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
                      Add Another Security Key
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
                    onClick={() => setSelectedFolder(folder.id)}
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

                <div className="mt-3 p-3 bg-white/5 rounded-2xl border border-white/10">
                  <div className="flex gap-4">
                    <div className="w-10 h-10 bg-white/10 rounded-xl flex items-center justify-center shrink-0">
                      <ShieldCheck size={20} className="text-white" />
                    </div>
                    <div>
                      <h4 className="text-white font-bold text-sm mb-1">{t('addCredential.securityAdvisory', 'Security Advisory')}</h4>
                      <p className="text-xs text-white/40 leading-relaxed font-medium">
                        {isPassphrase ? (
                          <Trans i18nKey="addCredential.passphraseAdvisory" values={{ bits: wordCount * 12 }}>
                            Passphrases provide high entropy with low cognitive load. This configuration yields approximately <span className="text-white font-bold">{wordCount * 12} bits</span> of security.
                          </Trans>
                        ) : (
                          <Trans i18nKey="addCredential.passwordAdvisory" values={{ bits: Math.floor(password.length * Math.log2(charsetLength(includeUppercase, includeLowercase, includeNumbers, includeSymbols))) }}>
                            This password uses <span className="text-white font-bold">{Math.floor(password.length * Math.log2(charsetLength(includeUppercase, includeLowercase, includeNumbers, includeSymbols)))} bit entropy</span>. Recommended for high-value targets.
                          </Trans>
                        )}
                      </p>
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

function charsetLength(u: boolean, l: boolean, n: boolean, s: boolean) {
  let count = 0;
  if (u) count += 26;
  if (l) count += 26;
  if (n) count += 10;
  if (s) count += 30;
  return count || 1;
}
