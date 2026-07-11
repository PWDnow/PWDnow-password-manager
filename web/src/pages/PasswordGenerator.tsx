import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Copy, RefreshCw, Check, Shield, Wand2, Hash, Type } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import SEO from '../components/SEO';
import { secureClipboard, ClipboardGuardHandle } from '../utils/clipboardGuard';

const WORD_LIST_FALLBACK = [
  'Bridge', 'Castle', 'Dragon', 'Eagle', 'Falcon', 'Giant', 'Horse', 'Island', 'Knight', 'Lion',
  'Mountain', 'River', 'Ocean', 'Forest', 'Desert', 'Stone', 'Fire', 'Water', 'Earth', 'Gold',
];

function StrengthBar({ password }: { password: string }) {
  const { t } = useTranslation();

  const getStrength = (pwd: string) => {
    const len = pwd.length;
    const hasUpper   = /[A-Z]/.test(pwd);
    const hasLower   = /[a-z]/.test(pwd);
    const hasNumber  = /[0-9]/.test(pwd);
    const hasSpecial = /[^A-Za-z0-9]/.test(pwd);
    // Text colors are tuned for the always-black StrengthBar panel background
    // (see the `bg-black text-white` card below) - light shades needed for AAA
    // contrast (7:1) regardless of the site's light/dark theme.
    if (len >= 16 && hasUpper && hasLower && hasNumber && hasSpecial)
      return { label: t('vault.strength.excellent', 'Excellent'),  fill: 'w-full',   color: 'bg-green-500', text: 'text-green-400' };
    if (len >= 12 && hasUpper && hasLower && hasNumber && hasSpecial)
      return { label: t('vault.strength.veryStrong', 'Very Strong'), fill: 'w-[85%]', color: 'bg-green-400', text: 'text-green-300' };
    if (len >= 8  && hasUpper && hasLower && hasNumber)
      return { label: t('vault.strength.strong', 'Strong'),         fill: 'w-[70%]', color: 'bg-blue-500',  text: 'text-blue-300' };
    if (len >= 6  && hasLower && hasNumber)
      return { label: t('vault.strength.medium', 'Medium'),         fill: 'w-1/2',   color: 'bg-amber-500', text: 'text-amber-300' };
    if (len >= 4  && hasLower)
      return { label: t('vault.strength.weak', 'Weak'),             fill: 'w-[30%]', color: 'bg-red-500',   text: 'text-red-300' };
    return       { label: t('vault.strength.veryWeak', 'Very Weak'), fill: 'w-[10%]', color: 'bg-red-700',  text: 'text-red-300' };
  };

  if (!password) return null;
  const { label, fill, color, text } = getStrength(password);

  return (
    <div className="space-y-1.5">
      <div className="h-1.5 w-full bg-surface-container-high rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all duration-500 ${fill} ${color}`} />
      </div>
      <p className={`text-xs font-bold uppercase tracking-widest ${text}`}>{label}</p>
    </div>
  );
}

export default function PasswordGenerator() {
  const { t } = useTranslation();
  const wordListRef = useRef<string[]>(WORD_LIST_FALLBACK);
  const clipGuardRef = useRef<ClipboardGuardHandle | null>(null);

  const [password,          setPassword]          = useState('');
  const [length,            setLength]            = useState(24);
  const [wordCount,         setWordCount]         = useState(6);
  const [includeUppercase,  setIncludeUppercase]  = useState(true);
  const [includeLowercase,  setIncludeLowercase]  = useState(true);
  const [includeNumbers,    setIncludeNumbers]    = useState(true);
  const [includeSymbols,    setIncludeSymbols]    = useState(true);
  const [isPassphrase,      setIsPassphrase]      = useState(false);
  const [copied,            setCopied]            = useState(false);
  const [countdown,         setCountdown]         = useState<number | null>(null);
  const [history,           setHistory]           = useState<string[]>([]);

  // Lazy-load the EFF long wordlist
  useEffect(() => {
    import('../data/eff-wordlist.json')
      .then(m => { wordListRef.current = m.default as string[]; })
      .catch(() => {});
  }, []);

  // Cryptographically secure random int in [0, max)
  const secureRandInt = (max: number): number => {
    const buf = new Uint32Array(1);
    const limit = 0x100000000 - (0x100000000 % max);
    let val: number;
    do { crypto.getRandomValues(buf); val = buf[0]; } while (val >= limit);
    return val % max;
  };

  const generate = useCallback(() => {
    let result = '';
    if (isPassphrase) {
      const words: string[] = [];
      const numIdx = secureRandInt(wordCount);
      for (let i = 0; i < wordCount; i++) {
        let w = wordListRef.current[secureRandInt(wordListRef.current.length)];
        w = w.charAt(0).toUpperCase() + w.slice(1).toLowerCase();
        if (i === numIdx) w += secureRandInt(10);
        words.push(w);
      }
      result = words.join('-');
      if (includeSymbols) {
        const syms = '!@#$%&*?';
        result = secureRandInt(2) === 0
          ? syms[secureRandInt(syms.length)] + result
          : result + syms[secureRandInt(syms.length)];
      }
    } else {
      let charset = '';
      if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
      if (includeNumbers)   charset += '0123456789';
      if (includeSymbols)   charset += '!@#$%^&*()_+~`|}{[]:;?><,./-=';
      if (!charset) return;
      for (let i = 0; i < length; i++) result += charset[secureRandInt(charset.length)];
    }
    setPassword(result);
    // Keep last 5 generated passwords for quick recall
    setHistory(prev => [result, ...prev.filter(p => p !== result)].slice(0, 5));
  }, [length, wordCount, includeUppercase, includeLowercase, includeNumbers, includeSymbols, isPassphrase]);

  // Auto-generate on mount and setting changes
  useEffect(() => { generate(); }, [generate]);

  const handleCopy = async () => {
    if (!password) return;
    clipGuardRef.current?.cancel();
    clipGuardRef.current = await secureClipboard(
      password,
      (s) => setCountdown(s),
      () => setCountdown(null),
    );
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const Toggle = ({ value, onChange, id }: { value: boolean; onChange: (v: boolean) => void; id: string }) => (
    <button
      id={id}
      role="switch"
      aria-checked={value}
      onClick={() => onChange(!value)}
      className={`relative w-10 h-6 rounded-full transition-colors duration-300 focus:outline-none focus:ring-2 focus:ring-black/20 ${value ? 'bg-black dark:bg-white' : 'bg-outline-variant/30'}`}
    >
      <span className={`absolute top-1 left-1 w-4 h-4 rounded-full transition-transform duration-300 ${value ? 'translate-x-4 bg-white dark:bg-black' : 'bg-white/70'}`} />
    </button>
  );

  return (
    <div className="max-w-3xl mx-auto">
      <SEO
        title={t('generator.title', 'Password Generator')}
        description={t('generator.desc', 'Generate cryptographically secure passwords and passphrases.')}
      />

      <div className="mb-10">
        <h1 className="text-4xl font-headline font-black tracking-tighter text-black dark:text-white mb-2">
          {t('generator.title', 'Password Generator')}
        </h1>
        <p className="text-on-surface-variant">
          {t('generator.subtitle', 'Cryptographically secure passwords using Web Crypto API — generated entirely on-device.')}
        </p>
      </div>

      {/* Generated password display */}
      <div className="bg-black text-white rounded-3xl p-8 mb-6 relative overflow-hidden">
        <div className="relative z-10">
          <p className="text-[10px] font-black uppercase tracking-[0.25em] text-white/70 mb-4">
            {t('generator.generated', 'Generated Password')}
          </p>
          <div
            className="font-mono text-lg md:text-2xl font-bold break-all leading-relaxed mb-8 select-all min-h-[3rem] cursor-text"
            aria-label="Generated password"
          >
            {password}
          </div>
          <StrengthBar password={password} />
          <div className="flex gap-3 mt-6">
            <button
              onClick={handleCopy}
              className="flex items-center gap-2 px-5 py-3 bg-white text-black rounded-xl font-bold text-sm hover:bg-white/90 transition-all active:scale-95"
              aria-label="Copy password to clipboard"
            >
              {copied ? <Check size={16} className="text-green-600" /> : <Copy size={16} />}
              {copied ? t('common.copied', 'Copied!') : t('common.copy', 'Copy')}
            </button>
            <button
              onClick={generate}
              className="flex items-center gap-2 px-5 py-3 bg-white/10 text-white rounded-xl font-bold text-sm hover:bg-white/20 transition-all active:scale-95"
              aria-label="Regenerate password"
            >
              <RefreshCw size={16} />
              {t('generator.regenerate', 'Regenerate')}
            </button>
          </div>
        </div>
        <Wand2 size={200} className="absolute -right-10 -bottom-10 text-white/[0.04]" aria-hidden="true" />
      </div>

      {/* Clipboard countdown toast */}
      <AnimatePresence>
        {countdown !== null && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 10 }}
            className="fixed bottom-6 right-6 z-[200] bg-white dark:bg-surface-container-low shadow-xl border border-orange-200/60 dark:border-orange-800/40 rounded-2xl px-5 py-3 flex items-center gap-3"
          >
            <span className="text-sm font-semibold">
              {t('vault.clipboardClears', 'Clears in {{s}}s', { s: countdown })}
            </span>
            <button
              onClick={() => clipGuardRef.current?.cancel()}
              className="text-xs font-bold text-orange-500 hover:text-orange-700"
            >
              {t('vault.clearNow', 'Clear now')}
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Settings */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        {/* Mode */}
        <div className="bg-white dark:bg-surface-container-low rounded-2xl p-6 border border-outline-variant/5 shadow-sm">
          <h2 className="text-xs font-black uppercase tracking-widest text-on-surface-variant mb-5">
            {t('generator.mode', 'Generation Mode')}
          </h2>
          <div className="flex gap-3">
            <button
              onClick={() => setIsPassphrase(false)}
              className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl font-bold text-sm transition-all ${!isPassphrase ? 'bg-black dark:bg-white text-white dark:text-black shadow-md' : 'bg-surface-container-low hover:bg-surface-container-high'}`}
            >
              <Hash size={16} /> {t('generator.password', 'Password')}
            </button>
            <button
              onClick={() => setIsPassphrase(true)}
              className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl font-bold text-sm transition-all ${isPassphrase ? 'bg-black dark:bg-white text-white dark:text-black shadow-md' : 'bg-surface-container-low hover:bg-surface-container-high'}`}
            >
              <Type size={16} /> {t('generator.passphrase', 'Passphrase')}
            </button>
          </div>

          {/* Length / word count slider */}
          <div className="mt-6">
            <div className="flex justify-between mb-2">
              <label htmlFor="gen-length" className="text-xs font-bold text-on-surface-variant uppercase tracking-widest">
                {isPassphrase ? t('generator.words', 'Words') : t('generator.characters', 'Characters')}
              </label>
              <span className="text-sm font-black">{isPassphrase ? wordCount : length}</span>
            </div>
            <input
              id="gen-length"
              type="range"
              min={isPassphrase ? 3 : 8}
              max={isPassphrase ? 10 : 64}
              value={isPassphrase ? wordCount : length}
              onChange={e => isPassphrase ? setWordCount(+e.target.value) : setLength(+e.target.value)}
              className="w-full accent-black dark:accent-white"
            />
            <div className="flex justify-between text-[9px] font-bold text-on-surface-variant mt-1">
              <span>{isPassphrase ? '3' : '8'}</span>
              <span>{isPassphrase ? '10' : '64'}</span>
            </div>
          </div>
        </div>

        {/* Character set toggles */}
        <div className="bg-white dark:bg-surface-container-low rounded-2xl p-6 border border-outline-variant/5 shadow-sm">
          <h2 className="text-xs font-black uppercase tracking-widest text-on-surface-variant mb-5">
            {t('generator.include', 'Include')}
          </h2>
          <div className="space-y-4">
            {[
              { id: 'gen-upper',   label: t('generator.uppercase', 'Uppercase (A-Z)'),  value: includeUppercase, set: setIncludeUppercase },
              { id: 'gen-lower',   label: t('generator.lowercase', 'Lowercase (a-z)'),  value: includeLowercase, set: setIncludeLowercase },
              { id: 'gen-numbers', label: t('generator.numbers',   'Numbers (0-9)'),     value: includeNumbers,   set: setIncludeNumbers },
              { id: 'gen-symbols', label: t('generator.symbols',   'Symbols (!@#…)'),    value: includeSymbols,   set: setIncludeSymbols },
            ].map(opt => (
              <div key={opt.id} className="flex items-center justify-between">
                <label htmlFor={opt.id} className="text-sm font-bold cursor-pointer select-none">
                  {opt.label}
                </label>
                <Toggle id={opt.id} value={opt.value} onChange={opt.set} />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent history */}
      {history.length > 1 && (
        <div className="bg-white dark:bg-surface-container-low rounded-2xl p-6 border border-outline-variant/5 shadow-sm">
          <h2 className="text-xs font-black uppercase tracking-widest text-on-surface-variant mb-4">
            {t('generator.history', 'Recently Generated')}
          </h2>
          <div className="space-y-2">
            {history.slice(1).map((pw, i) => (
              <div key={i} className="flex items-center justify-between gap-4 p-3 rounded-xl hover:bg-surface-container-low transition-colors group">
                <code className="font-mono text-xs text-on-surface-variant truncate flex-1">{pw}</code>
                <button
                  onClick={async () => {
                    setPassword(pw);
                    clipGuardRef.current?.cancel();
                    clipGuardRef.current = await secureClipboard(pw, s => setCountdown(s), () => setCountdown(null));
                  }}
                  className="p-1.5 rounded-lg opacity-0 group-hover:opacity-100 hover:bg-surface-container-high transition-all"
                  aria-label="Use this password"
                >
                  <Copy size={13} />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Security note */}
      <div className="mt-6 p-5 rounded-2xl bg-surface-container-low/50 border border-outline-variant/10 flex items-start gap-4">
        <Shield size={18} className="text-on-surface-variant shrink-0 mt-0.5" aria-hidden="true" />
        <p className="text-xs text-on-surface-variant leading-relaxed">
          {t('generator.securityNote', 'All passwords are generated locally using the Web Crypto API (CSPRNG). Nothing is transmitted. The clipboard is automatically cleared after 10 seconds.')}
        </p>
      </div>
    </div>
  );
}
