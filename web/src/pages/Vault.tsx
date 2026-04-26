import React, { useState, useRef, useEffect } from 'react';
import { Wallet, Verified, Key, ChevronRight, Copy, MoreVertical, PlusCircle, TrendingUp, ShieldCheck, ArrowLeft, Check, Trash2, Pencil, AlertTriangle, X, Search, Globe, ImageOff, Shield, Clock, Timer } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useParams, useNavigate } from 'react-router-dom';
import { useTranslation, Trans } from 'react-i18next';
import { TOTP } from 'totp-generator';
import AddCredential from './AddCredential';
import SEO from '../components/SEO';
import { Folder, Credential } from '../types';
import { useVault } from '../context/VaultContext';

const SecurityBadge = ({ status, statusColor }: { status: string, statusColor: string }) => {
  const [showText, setShowText] = useState(false);
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);

  const handleMouseEnter = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    setShowText(true);
  };

  const handleMouseLeave = () => {
    timeoutRef.current = setTimeout(() => {
      setShowText(false);
    }, 1500);
  };

  useEffect(() => {
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, []);

  const isGood = ['Strong', 'Very Strong', 'Excellent'].includes(status);
  const colorParts = statusColor.split(' ');
  const dotColor = colorParts.length >= 4 ? colorParts[3] : (isGood ? 'bg-green-500' : 'bg-orange-500');

  return (
    <div 
      className={`flex items-center rounded-full cursor-default transition-all duration-700 border ${
        showText 
          ? `${colorParts.slice(0, 3).join(' ')} shadow-[0_10px_20px_-5px_rgba(0,0,0,0.1)] scale-105` 
          : 'border-outline-variant/5 bg-surface-container-low/30 p-1.5'
      }`}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      <div className={`relative flex items-center justify-center ${showText ? 'ml-1' : ''}`}>
        <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${dotColor} shadow-[0_0_10px_rgba(0,0,0,0.1)] transition-transform duration-500 ${showText ? 'scale-110' : ''}`} aria-hidden="true"></span>
        {isGood && <span className={`absolute inset-0 rounded-full ${dotColor} animate-ping opacity-30`} />}
      </div>
      <AnimatePresence>
        {showText && (
          <motion.span 
            initial={{ width: 0, opacity: 0, marginLeft: 0 }}
            animate={{ width: 'auto', opacity: 1, marginLeft: 10, marginRight: 10 }}
            exit={{ width: 0, opacity: 0, marginLeft: 0, marginRight: 0 }}
            className="text-[11px] font-black uppercase tracking-[0.2em] whitespace-nowrap overflow-hidden text-black/90"
          >
            {status}
          </motion.span>
        )}
      </AnimatePresence>
    </div>
  );
};

const SERVICE_COLORS: Record<string, { bg: string, text: string, border: string, glow: string }> = {
  'Google': { bg: 'bg-red-50/50', text: 'text-red-600', border: 'border-red-100/50', glow: 'shadow-red-500/20' },
  'GitHub': { bg: 'bg-neutral-100/50', text: 'text-neutral-800', border: 'border-neutral-200/50', glow: 'shadow-neutral-500/20' },
  'Facebook': { bg: 'bg-blue-50/50', text: 'text-blue-600', border: 'border-blue-100/50', glow: 'shadow-blue-500/20' },
  'Twitter': { bg: 'bg-sky-50/50', text: 'text-sky-500', border: 'border-sky-100/50', glow: 'shadow-sky-500/20' },
  'LinkedIn': { bg: 'bg-indigo-50/50', text: 'text-indigo-600', border: 'border-indigo-100/50', glow: 'shadow-indigo-500/20' },
  'Spotify': { bg: 'bg-green-50/50', text: 'text-green-600', border: 'border-green-100/50', glow: 'shadow-green-500/20' },
  'Netflix': { bg: 'bg-red-50/50', text: 'text-red-600', border: 'border-red-100/50', glow: 'shadow-red-500/20' },
  'Amazon': { bg: 'bg-orange-50/50', text: 'text-orange-600', border: 'border-orange-100/50', glow: 'shadow-orange-500/20' },
  'Apple': { bg: 'bg-neutral-50/50', text: 'text-neutral-800', border: 'border-neutral-200/50', glow: 'shadow-neutral-500/20' },
  'Microsoft': { bg: 'bg-blue-50/50', text: 'text-blue-600', border: 'border-blue-100/50', glow: 'shadow-blue-500/20' },
};

const getServiceStyle = (service: string) => {
  const normalized = service.trim();
  for (const [key, value] of Object.entries(SERVICE_COLORS)) {
    if (normalized.toLowerCase().includes(key.toLowerCase())) return value;
  }
  const palettes = [
    { bg: 'bg-blue-50/50', text: 'text-blue-600', border: 'border-blue-100/50', glow: 'shadow-blue-500/20' },
    { bg: 'bg-purple-50/50', text: 'text-purple-600', border: 'border-purple-100/50', glow: 'shadow-purple-500/20' },
    { bg: 'bg-emerald-50/50', text: 'text-emerald-600', border: 'border-emerald-100/50', glow: 'shadow-emerald-500/20' },
    { bg: 'bg-rose-50/50', text: 'text-rose-600', border: 'border-rose-100/50', glow: 'shadow-rose-500/20' },
    { bg: 'bg-amber-50/50', text: 'text-amber-600', border: 'border-amber-100/50', glow: 'shadow-amber-500/20' },
  ];
  const hash = normalized.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
  return palettes[hash % palettes.length];
};

// HIGH-07 fix: removed Google favicon service (leaked full service list to Google).
// Now renders a letter avatar using the service name — zero external requests.
const FaviconImage = ({ service, className }: { url: string; service: string; className?: string }) => {
  const style = getServiceStyle(service);
  const letter = (service || '?').trim().charAt(0).toUpperCase();

  return (
    <div className={`${className} ${style.bg} backdrop-blur-md flex items-center justify-center ${style.text} border ${style.border} shadow-lg ${style.glow} transition-all duration-500 group-hover:shadow-xl group-hover:scale-105`}>
      <span className="text-xl font-bold select-none" aria-hidden="true">{letter}</span>
    </div>
  );
};

export default function Vault() {
  const { folderId } = useParams();
  const navigate = useNavigate();
  const { t } = useTranslation();
  const activeTab = folderId || 'vault';
  const { folders, credentials, addCredential, updateCredential, deleteCredential } = useVault();
  
  const [isAdding, setIsAdding] = useState(false);
  const [itemToEdit, setItemToEdit] = useState<Credential | null>(null);
  const [copiedId, setCopiedId] = useState<number | string | null>(null);
  const [copiedPwdId, setCopiedPwdId] = useState<number | string | null>(null);
  const [activeDropdown, setActiveDropdown] = useState<number | string | null>(null);
  const [itemToDelete, setItemToDelete] = useState<Credential | null>(null);
  const [deleteInput, setDeleteInput] = useState('');
  const [isDeleteConfirming, setIsDeleteConfirming] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  
  const [otpSetupItem, setOtpSetupItem] = useState<Credential | null>(null);
  const [otpRemoveItem, setOtpRemoveItem] = useState<Credential | null>(null);
  const [otpShowItem, setOtpShowItem] = useState<Credential | null>(null);
  const [otpSecretInput, setOtpSecretInput] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [otpProgress, setOtpProgress] = useState(100);

  const clipboardTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const dropdownRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setActiveDropdown(null);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    let interval: NodeJS.Timeout;
    
    const updateTotp = async () => {
      if (otpShowItem && otpShowItem.otpSecret) {
        try {
          const { otp, expires } = await TOTP.generate(otpShowItem.otpSecret);
          setOtpCode(otp);
          
          const now = Date.now();
          const remaining = expires - now;
          const total = 30000; // 30 seconds
          const progress = Math.max(0, Math.min(100, (remaining / total) * 100));
          setOtpProgress(progress);
        } catch (error) {
          console.error("Failed to generate TOTP", error);
          setOtpCode("Error");
        }
      }
    };

    if (otpShowItem) {
      updateTotp();
      interval = setInterval(updateTotp, 1000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [otpShowItem]);

  const clearClipboardLater = () => {
    if (clipboardTimeoutRef.current) {
      clearTimeout(clipboardTimeoutRef.current);
    }
    clipboardTimeoutRef.current = setTimeout(() => {
      copyToClipboard('');
    }, 30000);
  };

  const copyToClipboard = async (text: string) => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        throw new Error('Clipboard API not available');
      }
    } catch (err) {
      // Fallback for iframes or when document is not focused
      const textArea = document.createElement("textarea");
      textArea.value = text;
      
      // Avoid scrolling to bottom
      textArea.style.top = "0";
      textArea.style.left = "0";
      textArea.style.position = "fixed";
      textArea.style.opacity = "0";
      
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      
      try {
        document.execCommand('copy');
      } catch (e) {
        console.error('Fallback: Oops, unable to copy', e);
      }
      
      document.body.removeChild(textArea);
    }
  };

  const handleCopyUsername = async (username: string, id: number | string) => {
    if (!username || username === 'No username') return;
    await copyToClipboard(username);
    setCopiedId(id);
    setToastMessage(t('generator.copied', 'Username copied !'));
    setTimeout(() => setCopiedId(null), 2000);
    setTimeout(() => setToastMessage(null), 3000);
    clearClipboardLater();
  };

  const handleCopyPassword = async (password: string | undefined, id: number | string) => {
    if (!password) return;
    await copyToClipboard(password);
    setCopiedPwdId(id);
    setTimeout(() => setCopiedPwdId(null), 2000);
    clearClipboardLater();
  };

  const formatUsername = (username: string) => {
    if (!username || username === 'No username') return null;
    const visiblePart = username.substring(0, 2);
    return `${visiblePart}••••••••`;
  };

  const activeFolder = folders.find(f => f.id === activeTab);
  
  const getFolderTitle = () => {
    if (activeFolder) return activeFolder.label;
    return t('sidebar.vault', 'All Vault Items');
  };

  const getFolderDescription = () => {
    if (activeFolder && activeFolder.description) return activeFolder.description;
    return t('vault.subtitle', `Manage sensitive ${getFolderTitle().toLowerCase()} credentials with high-precision security protocols.`);
  };

  const folderCredentials = activeTab === 'vault' 
    ? credentials 
    : credentials.filter(c => c.folderId === activeTab);

  const displayedCredentials = folderCredentials
    .filter(c => {
      const search = searchTerm.toLowerCase();
      const cleanUrl = c.url.replace(/^https?:\/\//i, '').toLowerCase();
      return (
        c.service.toLowerCase().includes(search) ||
        cleanUrl.includes(search) ||
        c.username.toLowerCase().includes(search) ||
        c.tags?.some(t => t.toLowerCase().includes(search))
      );
    })
    .sort((a, b) => {
      const search = searchTerm.toLowerCase();
      if (!search) return 0;

      // Priority 1: Service Name
      const aServiceMatch = a.service.toLowerCase().includes(search);
      const bServiceMatch = b.service.toLowerCase().includes(search);
      if (aServiceMatch && !bServiceMatch) return -1;
      if (!aServiceMatch && bServiceMatch) return 1;

      // Priority 2: Website Name (Ignoring protocol)
      const aCleanUrl = a.url.replace(/^https?:\/\//i, '').toLowerCase();
      const bCleanUrl = b.url.replace(/^https?:\/\//i, '').toLowerCase();
      const aUrlMatch = aCleanUrl.includes(search);
      const bUrlMatch = bCleanUrl.includes(search);
      if (aUrlMatch && !bUrlMatch) return -1;
      if (!aUrlMatch && bUrlMatch) return 1;

      // Priority 3: Username
      const aUserMatch = a.username.toLowerCase().includes(search);
      const bUserMatch = b.username.toLowerCase().includes(search);
      if (aUserMatch && !bUserMatch) return -1;
      if (!aUserMatch && bUserMatch) return 1;

      return 0;
    });

  const isFolderEmpty = folderCredentials.length === 0;
  const isSearchEmpty = searchTerm && displayedCredentials.length === 0;
  const isEmptyFolder = isFolderEmpty || isSearchEmpty;

  const totalItems = displayedCredentials.length;
  
  const getScore = (status: string) => {
    switch(status) {
      case 'Excellent': return 100;
      case 'Very Strong': return 90;
      case 'Strong': return 80;
      case 'Medium': return 60;
      case 'Weak': return 40;
      case 'Very Weak': return 20;
      default: return 0;
    }
  };

  const securityHealthScore = displayedCredentials.length > 0 
    ? Math.round(displayedCredentials.reduce((acc, curr) => acc + getScore(curr.status), 0) / displayedCredentials.length)
    : 0;
  
  const securityHealth = isEmptyFolder ? '- %' : `${securityHealthScore}%`;

  const weakCount = displayedCredentials.filter(c => ['Weak', 'Very Weak', 'Medium'].includes(c.status)).length;
  const pendingActions = isEmptyFolder ? `0 ${t('vault.actions', 'Actions')}` : `${weakCount} ${t('vault.actions', 'Actions')}`;
  const pendingActionsSubtext = weakCount > 0 ? t('vault.weakPasswords', { count: weakCount, defaultValue: `${weakCount} weak passwords` }) : t('vault.allClear', 'All clear');

  return (
    <div className="max-w-7xl mx-auto">
      <SEO 
        title={t('vault.title', 'My Vault')}
        description={t('vault.description', 'Securely manage your passwords, secure notes, and digital assets.')}
      />
      <AnimatePresence>
        {toastMessage && (
          <motion.div
            initial={{ opacity: 0, x: 100 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 100 }}
            className="fixed top-6 right-6 z-[200] bg-white/80 backdrop-blur-xl border border-outline-variant/20 shadow-lg rounded-2xl px-6 py-4 flex items-center gap-3"
          >
            <div className="w-8 h-8 rounded-full bg-green-100 flex items-center justify-center">
              <Check size={16} className="text-green-600" />
            </div>
            <span className="font-medium text-black dark:text-white">{toastMessage}</span>
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence mode="wait">
        {(isAdding || itemToEdit) ? (
          <motion.div 
            key="add-credential"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.3 }}
            className="max-w-7xl mx-auto"
          >
            <button 
              onClick={() => {
                setIsAdding(false);
                setItemToEdit(null);
              }}
              aria-label={`${t('vault.backTo', 'Back to')} ${getFolderTitle()}`}
              className="flex items-center gap-2 text-on-surface-variant hover:text-black dark:hover:text-white transition-colors mb-8 font-bold text-sm uppercase tracking-widest"
            >
              <ArrowLeft size={16} aria-hidden="true" />
              {t('vault.backTo', 'Back to')} {getFolderTitle()}
            </button>
            <AddCredential 
              folders={folders} 
              activeTab={activeTab}
              initialData={itemToEdit || undefined}
              onAddCredential={addCredential}
              onUpdateCredential={updateCredential}
              onCancel={() => {
                setIsAdding(false);
                setItemToEdit(null);
              }}
            />
          </motion.div>
        ) : (
          <motion.div 
            key="vault-list"
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
            transition={{ duration: 0.3 }}
          >
            {/* Breadcrumbs & Header */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-8 mb-16">
              <div className="space-y-2">
                <nav className="flex items-center gap-2 text-[10px] font-black tracking-[0.3em] text-on-surface-variant uppercase">
                  <span className="hover:text-black dark:hover:text-white cursor-pointer transition-colors">{t('sidebar.vault', 'Vault')}</span>
                  <ChevronRight size={10} className="opacity-40" />
                  <span className="text-black dark:text-white">{getFolderTitle()}</span>
                </nav>
                <h1 className="text-4xl md:text-6xl font-headline font-black tracking-tighter text-black dark:text-white leading-none">{getFolderTitle()}</h1>
                <p className="text-on-surface-variant text-lg font-medium max-w-xl leading-relaxed">{getFolderDescription()}</p>
              </div>
              <button 
                onClick={() => setIsAdding(true)}
                aria-label={t('vault.addCredential', 'Add Credential')}
                className="group relative inline-flex items-center gap-3 bg-black dark:bg-white text-white dark:text-black px-10 py-5 rounded-2xl font-black text-xs uppercase tracking-widest transition-all hover:bg-neutral-800 dark:hover:bg-neutral-200 active:scale-95 shadow-[0_20px_50px_rgba(0,0,0,0.2)] hover:shadow-[0_20px_50px_rgba(0,0,0,0.3)]"
              >
                <PlusCircle size={20} className="group-hover:rotate-90 transition-transform duration-500" />
                {t('vault.addCredential', 'New Credential')}
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-12 gap-6 mb-16">
              <div className="md:col-span-4 bg-white dark:bg-surface-container-low p-6 sm:p-8 md:p-10 rounded-[2.5rem] relative overflow-hidden group flex flex-col border border-outline-variant/10 shadow-[0_4px_20px_-4px_rgba(0,0,0,0.05)] hover:shadow-[0_40px_80px_-20px_rgba(0,0,0,0.1)] hover:-translate-y-2 transition-all duration-700">
                <div className="flex items-center gap-6 mb-8">
                  <div className="w-16 h-16 bg-primary-container/20 text-on-primary-container rounded-[1.25rem] flex items-center justify-center shadow-inner">
                    <Wallet size={32} fill="currentColor" className="opacity-80 group-hover:scale-110 transition-transform duration-500" />
                  </div>
                  <div>
                    <div className="text-[11px] font-black tracking-[0.3em] text-on-surface-variant uppercase opacity-60 mb-1">{t('vault.assets', 'Vault Assets')}</div>
                    <div className="text-3xl md:text-4xl font-black tracking-tighter text-black dark:text-white">{totalItems} <span className="text-sm font-medium text-on-surface-variant tracking-normal">{t('vault.items', 'Items')}</span></div>
                  </div>
                </div>
                <div className="mt-auto pt-6 border-t border-outline-variant/5 flex items-center justify-between">
                  <div className="text-[10px] font-black text-on-surface-variant/40 uppercase tracking-[0.2em]">{t('vault.lastUpdated', 'Last Updated')}</div>
                  <div className="text-[10px] font-black text-black dark:text-white uppercase tracking-[0.2em]">{t('vault.justNow', 'Just Now')}</div>
                </div>
                <div className="absolute -right-8 -bottom-8 w-32 h-32 bg-primary-container/5 rounded-full blur-3xl group-hover:scale-150 transition-transform duration-1000" />
              </div>

              <div className="md:col-span-4 bg-white dark:bg-surface-container-low p-6 sm:p-8 md:p-10 rounded-[2.5rem] relative overflow-hidden group flex flex-col border border-outline-variant/10 shadow-[0_4px_20px_-4px_rgba(0,0,0,0.05)] hover:shadow-[0_40px_80px_-20px_rgba(0,0,0,0.1)] hover:-translate-y-2 transition-all duration-700">
                <div className="flex items-center gap-6 mb-8">
                  <div className="w-16 h-16 bg-green-50 text-green-700 rounded-[1.25rem] flex items-center justify-center shadow-inner">
                    <ShieldCheck size={32} fill="currentColor" className="opacity-80 group-hover:scale-110 transition-transform duration-500" />
                  </div>
                  <div>
                    <div className="text-[11px] font-black tracking-[0.3em] text-on-surface-variant uppercase opacity-60 mb-1">{t('vault.securityHealth', 'Security Health')}</div>
                    <div className="text-3xl md:text-4xl font-black tracking-tighter text-black dark:text-white">{securityHealth}</div>
                  </div>
                </div>
                <div className="mt-auto pt-6 border-t border-outline-variant/5 flex items-center justify-between">
                  <div className="flex items-center gap-2 text-[10px] font-black text-green-600 uppercase tracking-[0.2em]">
                    <TrendingUp size={16} />
                    {securityHealthScore === 100 ? t('vault.perfectScore', 'Perfect Score') : t('vault.improving', 'Improving')}
                  </div>
                  <div className="text-[10px] font-black text-black dark:text-white uppercase tracking-[0.2em]">{securityHealthScore}%</div>
                </div>
                <div className="absolute -right-8 -bottom-8 w-32 h-32 bg-green-500/5 rounded-full blur-3xl group-hover:scale-150 transition-transform duration-1000" />
              </div>

              <div className="md:col-span-4 bg-white dark:bg-surface-container-low p-6 sm:p-8 md:p-10 rounded-[2.5rem] relative overflow-hidden group flex flex-col border border-outline-variant/10 shadow-[0_4px_20px_-4px_rgba(0,0,0,0.05)] hover:shadow-[0_40px_80px_-20px_rgba(0,0,0,0.1)] hover:-translate-y-2 transition-all duration-700">
                <div className="flex items-center gap-6 mb-8">
                  <div className="w-16 h-16 bg-orange-50 text-orange-700 rounded-[1.25rem] flex items-center justify-center shadow-inner">
                    <Key size={32} fill="currentColor" className="opacity-80 group-hover:scale-110 transition-transform duration-500" />
                  </div>
                  <div>
                    <div className="text-[11px] font-black tracking-[0.3em] text-on-surface-variant uppercase opacity-60 mb-1">{t('vault.pendingActions', 'Pending Actions')}</div>
                    <div className="text-3xl md:text-4xl font-black tracking-tighter text-black dark:text-white">{pendingActions.split(' ')[0]} <span className="text-sm font-medium text-on-surface-variant tracking-normal">{t('vault.actions', 'Actions')}</span></div>
                  </div>
                </div>
                <div className="mt-auto pt-6 border-t border-outline-variant/5 flex items-center justify-between">
                  <div className="text-[10px] font-black text-orange-600 uppercase tracking-[0.2em]">{!isEmptyFolder && pendingActionsSubtext}</div>
                  <div className="w-2.5 h-2.5 rounded-full bg-orange-500 animate-pulse shadow-[0_0_10px_rgba(249,115,22,0.4)]" />
                </div>
                <div className="absolute -right-8 -bottom-8 w-32 h-32 bg-orange-500/5 rounded-full blur-3xl group-hover:scale-150 transition-transform duration-1000" />
              </div>
            </div>

              {/* Search Bar */}
              <div className="relative group max-w-xl mx-auto w-full mb-12">
                <input 
                  type="text" 
                  placeholder={t('vault.searchPlaceholder', { folder: getFolderTitle(), defaultValue: `Search in ${getFolderTitle()}...` })}
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full bg-surface-container-low/60 backdrop-blur-md border border-outline-variant/10 rounded-2xl py-4 pl-14 pr-12 text-sm font-bold text-black dark:text-white placeholder:text-on-surface-variant/40 focus:ring-4 focus:ring-black/5 dark:focus:ring-white/5 focus:border-black/20 dark:focus:border-white/20 focus:bg-surface-container-low transition-all outline-none shadow-sm"
                />
                <div className="absolute inset-y-0 left-5 flex items-center pointer-events-none text-on-surface-variant group-focus-within:text-black dark:group-focus-within:text-white transition-all duration-300 z-10">
                  <Search size={18} strokeWidth={2.5} />
                </div>
                {searchTerm && (
                  <button 
                    onClick={() => setSearchTerm('')}
                    className="absolute inset-y-0 right-5 flex items-center text-on-surface-variant hover:text-black dark:hover:text-white transition-all z-10"
                  >
                    <X size={18} strokeWidth={2.5} />
                  </button>
                )}
              </div>

            {/* Credentials List */}
            <div className="space-y-4">
              {isEmptyFolder ? (
                <motion.div 
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="bg-white/40 backdrop-blur-xl rounded-[3rem] p-20 flex flex-col items-center justify-center text-center border border-outline-variant/10 shadow-[0_20px_50px_-20px_rgba(0,0,0,0.05)] relative overflow-hidden"
                >
                  <div className="relative mb-10">
                    <div className="w-24 h-24 bg-surface-container-high/50 rounded-[2rem] flex items-center justify-center relative z-10 shadow-inner">
                      {isSearchEmpty ? <Search size={40} strokeWidth={1.5} className="text-on-surface-variant" /> : <Key size={40} strokeWidth={1.5} className="text-on-surface-variant" />}
                    </div>
                    <div className="absolute -inset-4 bg-primary-container/10 rounded-full blur-2xl animate-pulse" />
                  </div>
                  <h3 className="text-2xl md:text-3xl font-black text-black dark:text-white mb-4 tracking-tighter">
                    {isSearchEmpty ? t('vault.noResults', 'No results found') : t('vault.noItems', 'No items found')}
                  </h3>
                  <p className="text-on-surface-variant text-lg font-medium max-w-md mb-10 leading-relaxed">
                    {isSearchEmpty 
                      ? t('vault.noResultsDesc', { term: searchTerm, folder: getFolderTitle(), defaultValue: `Nothing found for "${searchTerm}" in ${getFolderTitle()} folder.` })
                      : t('vault.noItemsDesc', `There are currently no credentials stored in this folder. Add a new credential to get started.`)
                    }
                  </p>
                  {!isSearchEmpty && (
                    <button 
                      onClick={() => setIsAdding(true)}
                      className="inline-flex items-center gap-3 bg-black text-white px-10 py-5 rounded-2xl font-black text-xs uppercase tracking-widest transition-all hover:bg-neutral-800 active:scale-95 shadow-[0_20px_50px_rgba(0,0,0,0.2)]"
                    >
                      <PlusCircle size={20} />
                      {t('vault.addNew', 'Add a new credential')}
                    </button>
                  )}
                  {isSearchEmpty && (
                    <button 
                      onClick={() => setSearchTerm('')}
                      className="inline-flex items-center gap-3 bg-surface-container-high text-black dark:text-white px-10 py-5 rounded-2xl font-black text-xs uppercase tracking-widest transition-all hover:bg-surface-container-highest active:scale-95 shadow-sm"
                    >
                      {t('vault.clearSearch', 'Clear search query')}
                    </button>
                  )}
                  <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(circle_at_50%_50%,rgba(0,0,0,0.02)_0%,transparent_50%)] pointer-events-none" />
                </motion.div>
              ) : (
                <>
                  <div className="hidden md:grid grid-cols-12 gap-4 px-8 text-[10px] font-black tracking-widest text-on-surface-variant uppercase">
                    <div className="col-span-4">{t('vault.service', 'Service')}</div>
                    <div className="col-span-3">{t('vault.username', 'Username')}</div>
                    <div className="col-span-3 text-center">{t('vault.password', 'Password')}</div>
                    <div className="col-span-2 text-right">{t('vault.actions', 'Actions')}</div>
                  </div>

                  {displayedCredentials.map((item, index) => (
                      <motion.div 
                        key={item.id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: index * 0.05, ease: [0.16, 1, 0.3, 1], duration: 0.6 }}
                        className={`group bg-white dark:bg-surface-container-low hover:bg-white dark:hover:bg-surface-container-high transition-all duration-500 rounded-2xl p-4 md:p-0 md:px-6 md:h-20 flex flex-col md:grid md:grid-cols-12 items-center gap-4 cursor-default border border-outline-variant/10 hover:border-black/10 dark:hover:border-white/10 shadow-sm hover:shadow-lg hover:-translate-y-1 relative ${activeDropdown === item.id ? 'z-[100]' : 'z-0'}`}
                      >
                        <div className="absolute inset-0 bg-gradient-to-br from-transparent via-transparent to-surface-container-low/20 opacity-0 group-hover:opacity-100 transition-opacity duration-700" />
                        
                        <div className="col-span-4 flex items-center gap-4 w-full relative z-10">
                          <div className="w-12 h-12 flex-shrink-0 rounded-lg flex items-center justify-center shadow-md border border-white/50 overflow-hidden group-hover:scale-105 transition-all duration-500">
                            <FaviconImage url={item.url} service={item.service} className="w-full h-full" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="font-black text-base text-black dark:text-white leading-tight tracking-tight truncate">{item.service}</div>
                            <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                              <div className="text-[10px] text-on-surface-variant font-black opacity-40 group-hover:opacity-100 group-hover:text-black transition-all uppercase tracking-widest truncate max-w-[120px] sm:max-w-none">{item.url.replace(/^https?:\/\//, '')}</div>
                              {item.tags && item.tags.length > 0 && (
                                <div className="flex gap-1 flex-wrap">
                                  {Array.from(new Set(item.tags)).map(tag => (
                                    <span key={tag} className="text-[8px] font-black px-1.5 py-0.5 bg-black/5 text-on-surface-variant rounded uppercase tracking-tighter border border-black/5 group-hover:bg-black group-hover:text-white transition-all">
                                      {tag}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                        
                        <div className="col-span-3 w-full relative z-10 flex md:block justify-between items-center">
                          <span className="md:hidden text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('vault.username', 'Username')}</span>
                          <div className="flex items-center gap-2 group/field">
                            {formatUsername(item.username) ? (
                              <span 
                                onClick={() => handleCopyUsername(item.username, item.id)}
                                className="text-[11px] font-mono font-black text-on-surface-variant tracking-wider bg-surface-container-low/50 px-3 md:px-4 py-1.5 md:py-2 rounded-xl cursor-pointer hover:bg-black hover:text-white transition-all flex items-center gap-2 group-hover:shadow-md active:scale-95 truncate max-w-[150px] sm:max-w-[200px] md:max-w-none"
                                title={t('vault.copyUsername', 'Click to copy username')}
                              >
                                <span className="truncate">{formatUsername(item.username)}</span>
                                {copiedId === item.id && <Check size={12} className="text-green-400 shrink-0" />}
                              </span>
                            ) : (
                              <span className="text-[10px] italic font-black text-on-surface-variant/30 px-3 md:px-4 py-1.5 md:py-2 uppercase tracking-widest">{t('vault.noUsername', 'No username')}</span>
                            )}
                          </div>
                        </div>

                        <div className="col-span-3 w-full relative z-10 flex md:block justify-between items-center">
                          <span className="md:hidden text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('vault.password', 'Password')}</span>
                          <div className="flex items-center gap-2">
                            <span 
                              onClick={() => handleCopyPassword(item.password, item.id)}
                              className="text-[11px] font-mono font-black text-on-surface-variant tracking-[0.3em] bg-surface-container-low/50 px-3 md:px-4 py-1.5 md:py-2 rounded-xl cursor-pointer hover:bg-black hover:text-white transition-all group-hover:shadow-md active:scale-95"
                              title={t('vault.copyPassword', 'Click to copy password')}
                            >
                              ••••••••
                            </span>
                            <div className="hidden sm:block">
                              <SecurityBadge status={item.status} statusColor={item.statusColor} />
                            </div>
                          </div>
                        </div>

                        <div className="col-span-2 flex items-center justify-between md:justify-end gap-3 w-full relative z-10 mt-2 md:mt-0 pt-4 md:pt-0 border-t border-outline-variant/10 md:border-none">
                          <div className="sm:hidden">
                            <SecurityBadge status={item.status} statusColor={item.statusColor} />
                          </div>
                          <div className="flex items-center gap-2 ml-auto">
                            <button 
                              onClick={() => handleCopyPassword(item.password, item.id)}
                              aria-label={`Copy password for ${item.service}`}
                              className="p-2 md:p-3 bg-surface-container-low/50 hover:bg-black hover:text-white text-on-surface-variant rounded-xl transition-all shadow-sm hover:shadow-lg active:scale-90"
                            >
                              {copiedPwdId === item.id ? <Check size={16} className="text-green-400" aria-hidden="true" /> : <Key size={16} aria-hidden="true" />}
                            </button>
                            
                            <div className="relative" ref={activeDropdown === item.id ? dropdownRef : null}>
                              <button 
                                onClick={() => setActiveDropdown(activeDropdown === item.id ? null : item.id)}
                                aria-label={`More options for ${item.service}`}
                                className="p-2 md:p-3 bg-surface-container-low/50 hover:bg-black hover:text-white text-on-surface-variant rounded-xl transition-all shadow-sm hover:shadow-lg active:scale-90"
                              >
                                <MoreVertical size={16} aria-hidden="true" />
                              </button>
                            
                            <AnimatePresence>
                              {activeDropdown === item.id && (
                                <motion.div
                                  initial={{ opacity: 0, scale: 0.9, y: 10 }}
                                  animate={{ opacity: 1, scale: 1, y: 0 }}
                                  exit={{ opacity: 0, scale: 0.9, y: 10 }}
                                  transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                                  className="absolute right-0 top-full mt-4 w-56 bg-white dark:bg-surface-container-high rounded-2xl shadow-2xl border border-outline-variant/10 z-[110] overflow-hidden p-2 ring-1 ring-black/5"
                                >
                                  <button 
                                    className="w-full text-left px-4 py-3 text-[10px] font-black uppercase tracking-widest text-on-surface-variant hover:text-black dark:hover:text-white hover:bg-surface-container-low rounded-xl transition-all flex items-center gap-4"
                                    onClick={() => {
                                      setActiveDropdown(null);
                                      setItemToEdit(item);
                                    }}
                                  >
                                    <div className="w-8 h-8 rounded-lg bg-surface-container-low flex items-center justify-center shadow-inner">
                                      <Pencil size={14} />
                                    </div>
                                    {t('vault.editItem', 'Edit Item')}
                                  </button>
                                  
                                  {!item.otpSecret ? (
                                    <button 
                                      className="w-full text-left px-4 py-3 text-[10px] font-black uppercase tracking-widest text-on-surface-variant hover:text-black dark:hover:text-white hover:bg-surface-container-low rounded-xl transition-all flex items-center gap-4"
                                      onClick={() => {
                                        setActiveDropdown(null);
                                        setOtpSetupItem(item);
                                        setOtpSecretInput('');
                                      }}
                                    >
                                      <div className="w-8 h-8 rounded-lg bg-surface-container-low flex items-center justify-center shadow-inner">
                                        <Clock size={14} />
                                      </div>
                                      {t('vault.setupOtp', 'Setup OTP')}
                                    </button>
                                  ) : (
                                    <>
                                      <button 
                                        className="w-full text-left px-4 py-3 text-[10px] font-black uppercase tracking-widest text-on-surface-variant hover:text-black dark:hover:text-white hover:bg-surface-container-low rounded-xl transition-all flex items-center gap-4"
                                        onClick={() => {
                                          setActiveDropdown(null);
                                          setOtpShowItem(item);
                                        }}
                                      >
                                        <div className="w-8 h-8 rounded-lg bg-surface-container-low flex items-center justify-center shadow-inner">
                                          <Timer size={14} />
                                        </div>
                                        {t('vault.showOtp', 'Show OTP code')}
                                      </button>
                                      <button 
                                        className="w-full text-left px-4 py-3 text-[10px] font-black uppercase tracking-widest text-on-surface-variant hover:text-black dark:hover:text-white hover:bg-surface-container-low rounded-xl transition-all flex items-center gap-4"
                                        onClick={() => {
                                          setActiveDropdown(null);
                                          setOtpSetupItem(item);
                                          setOtpSecretInput(item.otpSecret || '');
                                        }}
                                      >
                                        <div className="w-8 h-8 rounded-lg bg-surface-container-low flex items-center justify-center shadow-inner">
                                          <Pencil size={14} />
                                        </div>
                                        {t('vault.editOtp', 'Edit OTP')}
                                      </button>
                                      <button 
                                        className="w-full text-left px-4 py-3 text-[10px] font-black uppercase tracking-widest text-red-600 hover:bg-red-50 rounded-xl transition-all flex items-center gap-4"
                                        onClick={() => {
                                          setActiveDropdown(null);
                                          setOtpRemoveItem(item);
                                        }}
                                      >
                                        <div className="w-8 h-8 rounded-lg bg-red-100 flex items-center justify-center shadow-inner">
                                          <Trash2 size={14} />
                                        </div>
                                        {t('vault.removeOtp', 'Remove OTP')}
                                      </button>
                                    </>
                                  )}

                                  <button 
                                    className="w-full text-left px-4 py-3 text-[10px] font-black uppercase tracking-widest text-red-600 hover:bg-red-50 rounded-xl transition-all flex items-center gap-4"
                                    onClick={() => {
                                      setActiveDropdown(null);
                                      setItemToDelete(item);
                                    }}
                                  >
                                    <div className="w-8 h-8 rounded-lg bg-red-100 flex items-center justify-center shadow-inner">
                                      <Trash2 size={14} />
                                    </div>
                                    {item.otpSecret ? t('vault.removeCredential', 'Remove Credential') : t('vault.remove', 'Remove')}
                                  </button>
                                </motion.div>
                              )}
                            </AnimatePresence>
                          </div>
                        </div>
                        </div>
                      </motion.div>
                  ))}
                </>
              )}
            </div>

            {/* Footer Context */}
            <footer className="mt-24 pt-12 border-t border-outline-variant/10 flex flex-col md:flex-row justify-between items-start md:items-center gap-8 pb-12">
              <div className="flex items-center gap-16">
                <div>
                  <div className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant mb-3">{t('vault.encryptionStatus', 'Encryption Status')}</div>
                  <div className="text-sm font-bold text-black dark:text-white flex items-center gap-3">
                    <div className="w-2.5 h-2.5 rounded-full bg-green-500 animate-pulse shadow-[0_0_10px_rgba(34,197,94,0.5)]"></div>
                    {t('vault.aesActive', 'AES-256 Bit Active')}
                  </div>
                </div>
              </div>
            </footer>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Delete Confirmation Modal */}
      <AnimatePresence>
        {itemToDelete && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40 backdrop-blur-sm"
              onClick={() => setItemToDelete(null)}
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-md bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl overflow-hidden border border-outline-variant/10"
            >
              <div className="p-8">
                <div className="w-12 h-12 rounded-2xl bg-red-50 flex items-center justify-center mb-6">
                  <AlertTriangle className="text-red-600" size={24} />
                </div>
                <h3 className="text-xl font-bold text-black dark:text-white mb-2">{t('vault.deleteTitle', 'Delete Credential')}</h3>
                <p className="text-on-surface-variant text-sm mb-6">
                  {t('vault.deleteConfirmDesc', 'Are you sure you would like to delete the data? What would be removed:')}
                </p>
                
                <div className="bg-surface-container-low rounded-xl p-4 mb-8">
                  <div className="flex items-center gap-3 mb-3">
                    <img src={itemToDelete.logo} alt="" className="w-5 h-5 object-contain" />
                    <span className="font-bold text-sm text-black dark:text-white">{itemToDelete.service}</span>
                  </div>
                  <ul className="space-y-2 text-sm text-on-surface-variant">
                    <li className="flex items-center gap-2">
                      <div className="w-1 h-1 rounded-full bg-black/30" />
                      {t('vault.username', 'Username')}: <span className="font-mono text-black dark:text-white">{itemToDelete.username || 'N/A'}</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <div className="w-1 h-1 rounded-full bg-black/30" />
                      {t('vault.password', 'Password')}: <span className="font-mono text-black dark:text-white">••••••••</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <div className="w-1 h-1 rounded-full bg-black/30" />
                      URL: <span className="text-black dark:text-white">{itemToDelete.url}</span>
                    </li>
                  </ul>
                </div>

                <div className="space-y-3 mb-8">
                  <label htmlFor="delete-confirm" className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">
                    <Trans i18nKey="vault.typeDelete">
                      Type <span className="text-red-600">delete</span> to confirm
                    </Trans>
                  </label>
                  <input 
                    id="delete-confirm"
                    type="text" 
                    value={deleteInput}
                    onChange={(e) => setDeleteInput(e.target.value)}
                    placeholder={t('vault.deletePlaceholder', 'delete')}
                    className="w-full px-4 py-3 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-red-600/20 outline-none transition-all"
                  />
                </div>

                <div className="flex gap-3">
                  <button 
                    onClick={() => {
                      setItemToDelete(null);
                      setDeleteInput('');
                    }}
                    className="flex-1 px-4 py-3 rounded-xl font-bold text-sm text-black dark:text-white bg-surface-container-low hover:bg-surface-container-high transition-colors"
                  >
                    {t('common.cancel', 'Cancel')}
                  </button>
                  <button 
                    disabled={deleteInput.toLowerCase() !== 'delete'}
                    onClick={() => {
                      deleteCredential(itemToDelete.id);
                      setItemToDelete(null);
                      setDeleteInput('');
                    }}
                    className="flex-1 px-4 py-3 rounded-xl font-bold text-sm text-white bg-red-600 hover:bg-red-700 transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed disabled:grayscale"
                  >
                    {t('vault.yesDelete', 'Yes, Delete')}
                  </button>
                </div>
              </div>
              <button 
                onClick={() => setItemToDelete(null)}
                className="absolute top-6 right-6 text-on-surface-variant hover:text-black dark:hover:text-white transition-colors"
              >
                <X size={20} />
              </button>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* OTP Setup/Edit Modal */}
      <AnimatePresence>
        {otpSetupItem && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40 backdrop-blur-sm"
              onClick={() => {
                setOtpSetupItem(null);
                setOtpSecretInput('');
              }}
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-md bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl overflow-hidden border border-outline-variant/10"
            >
              <div className="p-8">
                <div className="w-12 h-12 rounded-2xl bg-surface-container-low flex items-center justify-center mb-6">
                  <Clock className="text-black dark:text-white" size={24} />
                </div>
                <h3 className="text-xl font-bold text-black dark:text-white mb-2">{otpSetupItem.otpSecret ? t('vault.editOtp', 'Edit OTP') : t('vault.setupOtp', 'Setup OTP')}</h3>
                <p className="text-on-surface-variant text-sm mb-6">
                  {t('vault.otpSetupDesc', 'Enter the secret key provided by the service to generate one-time passwords.')}
                </p>
                
                <div className="space-y-3 mb-8">
                  <label htmlFor="otp-secret" className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">
                    {t('vault.otpSecretLabel', 'Secret Key')}
                  </label>
                  <input 
                    id="otp-secret"
                    type="text" 
                    value={otpSecretInput}
                    onChange={(e) => setOtpSecretInput(e.target.value.replace(/\s+/g, '').toUpperCase())}
                    placeholder="JBSWY3DPEHPK3PXP"
                    className="w-full px-4 py-3 bg-surface-container-low rounded-xl border border-outline-variant/10 text-black dark:text-white font-mono focus:ring-2 focus:ring-black/20 dark:focus:ring-white/20 outline-none transition-all"
                  />
                </div>

                <div className="flex gap-3">
                  <button 
                    onClick={() => {
                      setOtpSetupItem(null);
                      setOtpSecretInput('');
                    }}
                    className="flex-1 px-4 py-3 rounded-xl font-bold text-sm text-black dark:text-white bg-surface-container-low hover:bg-surface-container-high transition-colors"
                  >
                    {t('common.cancel', 'Cancel')}
                  </button>
                  <button 
                    disabled={!otpSecretInput}
                    onClick={() => {
                      updateCredential({ ...otpSetupItem, otpSecret: otpSecretInput });
                      setOtpSetupItem(null);
                      setOtpSecretInput('');
                    }}
                    className="flex-1 px-4 py-3 rounded-xl font-bold text-sm text-white bg-black hover:bg-black/80 transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {t('common.save', 'Save')}
                  </button>
                </div>
              </div>
              <button 
                onClick={() => {
                  setOtpSetupItem(null);
                  setOtpSecretInput('');
                }}
                className="absolute top-6 right-6 text-on-surface-variant hover:text-black dark:hover:text-white transition-colors"
              >
                <X size={20} />
              </button>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* OTP Remove Confirmation Modal */}
      <AnimatePresence>
        {otpRemoveItem && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40 backdrop-blur-sm"
              onClick={() => setOtpRemoveItem(null)}
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-md bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl overflow-hidden border border-outline-variant/10"
            >
              <div className="p-8">
                <div className="w-12 h-12 rounded-2xl bg-red-50 flex items-center justify-center mb-6">
                  <AlertTriangle className="text-red-600" size={24} />
                </div>
                <h3 className="text-xl font-bold text-black dark:text-white mb-2">{t('vault.removeOtpTitle', 'Remove OTP')}</h3>
                <p className="text-on-surface-variant text-sm mb-8">
                  {t('vault.removeOtpConfirmDesc', 'Are you sure you would like to remove your OTP code?')}
                </p>

                <div className="flex gap-3">
                  <button 
                    onClick={() => setOtpRemoveItem(null)}
                    className="flex-1 px-4 py-3 rounded-xl font-bold text-sm text-black dark:text-white bg-surface-container-low hover:bg-surface-container-high transition-colors"
                  >
                    {t('common.cancel', 'Cancel')}
                  </button>
                  <button 
                    onClick={() => {
                      const { otpSecret, ...rest } = otpRemoveItem;
                      updateCredential(rest as Credential);
                      setOtpRemoveItem(null);
                    }}
                    className="flex-1 px-4 py-3 rounded-xl font-bold text-sm text-white bg-red-600 hover:bg-red-700 transition-colors shadow-sm"
                  >
                    {t('vault.yesRemove', 'Yes, Remove')}
                  </button>
                </div>
              </div>
              <button 
                onClick={() => setOtpRemoveItem(null)}
                className="absolute top-6 right-6 text-on-surface-variant hover:text-black dark:hover:text-white transition-colors"
              >
                <X size={20} />
              </button>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Show OTP Modal */}
      <AnimatePresence>
        {otpShowItem && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40 backdrop-blur-sm"
              onClick={() => setOtpShowItem(null)}
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-sm bg-white rounded-3xl shadow-2xl overflow-hidden border border-outline-variant/10"
            >
              <div className="p-8 text-center">
                <div className="w-16 h-16 rounded-2xl bg-surface-container-low flex items-center justify-center mx-auto mb-6">
                  <Timer className="text-black dark:text-white" size={32} />
                </div>
                <h3 className="text-xl font-bold text-black dark:text-white mb-2">{otpShowItem.service}</h3>
                <p className="text-on-surface-variant text-sm mb-8">
                  {t('vault.otpCodeDesc', 'Your one-time password is:')}
                </p>
                
                <div className="mb-8">
                  <div className="text-3xl md:text-4xl font-mono font-black tracking-[0.2em] text-black dark:text-white mb-4">
                    {otpCode ? `${otpCode.slice(0, 3)} ${otpCode.slice(3)}` : '------'}
                  </div>
                  
                  {/* Progress Bar */}
                  <div className="w-full h-2 bg-surface-container-low rounded-full overflow-hidden">
                    <motion.div 
                      className={`h-full ${otpProgress < 20 ? 'bg-red-500' : 'bg-black'}`}
                      initial={{ width: `${otpProgress}%` }}
                      animate={{ width: `${otpProgress}%` }}
                      transition={{ ease: "linear", duration: 1 }}
                    />
                  </div>
                </div>

                <div className="flex gap-3">
                  <button 
                    onClick={() => {
                      copyToClipboard(otpCode);
                      setToastMessage(t('vault.otpCopied', 'OTP code copied!'));
                      setTimeout(() => setToastMessage(null), 3000);
                    }}
                    className="flex-1 px-4 py-3 rounded-xl font-bold text-sm text-black dark:text-white bg-surface-container-low hover:bg-surface-container-high transition-colors flex items-center justify-center gap-2"
                  >
                    <Copy size={16} />
                    {t('common.copy', 'Copy')}
                  </button>
                  <button 
                    onClick={() => setOtpShowItem(null)}
                    className="flex-1 px-4 py-3 rounded-xl font-bold text-sm text-white bg-black hover:bg-black/80 transition-colors shadow-sm"
                  >
                    {t('common.close', 'Close')}
                  </button>
                </div>
              </div>
              <button 
                onClick={() => setOtpShowItem(null)}
                className="absolute top-6 right-6 text-on-surface-variant hover:text-black dark:hover:text-white transition-colors"
              >
                <X size={20} />
              </button>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
