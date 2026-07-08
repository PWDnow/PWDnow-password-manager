import React, { useState, useRef } from 'react';
import { X, Upload } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { useNotification } from '../context/NotificationContext';
import { Folder } from '../types';
import { sanitizeSvg } from '../utils/sanitize';
import { BROWSER_AUTOFILL } from '../utils/cardUtils';
import { useAutofillGuard } from '../utils/autofill';
import { generateUUID } from '../utils/crypto';
import { ICON_MAP } from '../utils/folderIcons';

interface CreateFolderModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAddFolder: (folder: Folder) => void;
}

const PREDEFINED_ICONS = Object.entries(ICON_MAP).map(([name, icon]) => ({ name, icon }));

// id -> English fallback. The button click sets the folder title to the
// *translated* label (t() below) so the created folder name matches the
// user's UI language, not always English.
const TEMPLATES: { id: string; fallback: string }[] = [
  { id: 'personalFinance',   fallback: 'Personal Finance' },
  { id: 'banking',           fallback: 'Banking' },
  { id: 'investment',        fallback: 'Investment' },
  { id: 'cryptocurrency',    fallback: 'Cryptocurrency' },
  { id: 'gaming',            fallback: 'Gaming' },
  { id: 'streamingServices', fallback: 'Streaming Services' },
  { id: 'emails',            fallback: 'Emails' },
  { id: 'socialMedia',       fallback: 'Social Media' },
  { id: 'shopping',          fallback: 'Shopping' },
  { id: 'healthMedical',     fallback: 'Health & Medical' },
  { id: 'travel',            fallback: 'Travel' },
  { id: 'workOffice',        fallback: 'Work & Office' },
  { id: 'developerTools',    fallback: 'Developer Tools' },
  { id: 'cloudServices',     fallback: 'Cloud Services' },
  { id: 'education',         fallback: 'Education' },
  { id: 'communication',     fallback: 'Communication' },
  { id: 'entertainment',     fallback: 'Entertainment' },
  { id: 'securityVpn',       fallback: 'Security & VPN' },
  { id: 'utilities',         fallback: 'Utilities' },
  { id: 'government',        fallback: 'Government' },
  { id: 'family',            fallback: 'Family' },
  { id: 'insurance',         fallback: 'Insurance' },
];

export default function CreateFolderModal({ isOpen, onClose, onAddFolder }: CreateFolderModalProps) {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [selectedIconName, setSelectedIconName] = useState<string>('Folder');
  const [customSvg, setCustomSvg] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Browser-autofill suppression (see useAutofillGuard). Gated by the
  // VITE_BROWSER_AUTOFILL flag.
  const guardTitle = useAutofillGuard();
  const guardDesc = useAutofillGuard();

  const { addNotification } = useNotification();
  const { t } = useTranslation();

  if (!isOpen) return null;

  const handleTemplateClick = (label: string) => {
    setTitle(label);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target?.result as string;
        // Basic validation to ensure it's an SVG
        if (content.includes('<svg')) {
          setCustomSvg(content);
          setSelectedIconName('custom');
        } else {
          addNotification({ title: t('folders.error', 'Error'), message: t('folders.invalidSvg', 'Please upload a valid SVG file.'), type: 'error' });
        }
      };
      reader.readAsText(file);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;

    // Use a fresh UUID, not a slug. Two folders with the same name (or even
    // an existing folder whose slug matches) would otherwise collide on `id`,
    // causing React key duplication and an invisible folder in the sidebar.
    const newFolder: Folder = {
      id: generateUUID(),
      label: title,
      description: description || `Manage sensitive ${title.toLowerCase()} credentials with high-precision security protocols.`,
      iconName: selectedIconName !== 'custom' ? selectedIconName : undefined,
      customSvg: selectedIconName === 'custom' && customSvg ? customSvg : undefined,
    };

    onAddFolder(newFolder);
    
    // Reset state
    setTitle('');
    setDescription('');
    setSelectedIconName('Folder');
    setCustomSvg(null);
    onClose();
  };

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-[100] flex items-center justify-center p-4" role="presentation">
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          className="absolute inset-0 bg-[#000000]/40"
        />
        <motion.div 
          role="dialog"
          aria-modal="true"
          aria-labelledby="create-folder-title"
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          className="relative bg-surface w-full max-w-2xl rounded-3xl shadow-2xl overflow-hidden border border-outline-variant/10 flex flex-col max-h-[90vh]"
        >
          <div className="flex items-center justify-between p-6 border-b border-outline-variant/10">
            <h2 id="create-folder-title" className="text-2xl font-headline font-black tracking-tight">{t('sidebar.createFolder', 'Create Folder')}</h2>
            <button
              onClick={onClose}
              className="p-2 hover:bg-surface-container-high rounded-full transition-colors"
              aria-label={t('common.close', 'Close')}
            >
              <X size={24} />
            </button>
          </div>

          <div className="p-6 overflow-y-auto no-scrollbar">
            <form id="create-folder-form" onSubmit={handleSubmit} className="space-y-8" autoComplete={BROWSER_AUTOFILL ? 'on' : 'off'}>
              {/* Folder Name */}
              <div>
                <label htmlFor="folder-title" className="block text-xs font-black uppercase tracking-widest text-on-surface-variant mb-2">
                  {t('folders.createModal.folderName', 'Folder Name')}
                </label>
                <input
                  id="folder-title"
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  {...guardTitle}
                  placeholder={t('manageFolders.folderNamePlaceholder', 'e.g. Personal, Gaming, Crypto')}
                  className="w-full bg-white dark:bg-surface-container-high border border-on-surface-variant/50 dark:border-outline-variant/30 rounded-xl px-4 py-3 text-black dark:text-white font-medium focus:outline-none focus:border-black dark:focus:border-white focus:ring-1 focus:ring-black dark:focus:ring-white transition-all"
                  required
                />

                {/* Templates */}
                <div className="mt-3">
                  <p className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-2">{t('vault.templates', 'Templates')}</p>
                  <div className="flex flex-wrap gap-2">
                    {TEMPLATES.map((template) => {
                      const label = t(`folders.templates.${template.id}`, template.fallback);
                      return (
                        <button
                          key={template.id}
                          type="button"
                          onClick={() => handleTemplateClick(label)}
                          className="text-xs font-medium px-3 py-1.5 bg-surface-container-high hover:bg-black hover:text-white rounded-full transition-colors"
                        >
                          {label}
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Folder Description */}
              <div>
                <label htmlFor="folder-desc" className="block text-xs font-black uppercase tracking-widest text-on-surface-variant mb-2">
                  {t('folders.createModal.description', 'Description')}
                </label>
                <textarea
                  id="folder-desc"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  {...guardDesc}
                  placeholder={t('manageFolders.descriptionPlaceholder', "What's inside this folder?")}
                  className="w-full bg-white dark:bg-surface-container-high border border-on-surface-variant/50 dark:border-outline-variant/30 rounded-xl px-4 py-3 text-black dark:text-white font-medium focus:outline-none focus:border-black dark:focus:border-white focus:ring-1 focus:ring-black dark:focus:ring-white transition-all resize-none h-24"
                />
              </div>

              {/* Icon Selection */}
              <div>
                <label id="folder-icon-label" className="block text-xs font-black uppercase tracking-widest text-on-surface-variant mb-3">
                  {t('folders.createModal.folderIcon', 'Folder Icon')}
                </label>
                <div className="grid grid-cols-5 sm:grid-cols-8 gap-3 mb-4" role="radiogroup" aria-labelledby="folder-icon-label">
                  {PREDEFINED_ICONS.map((item) => (
                    <button
                      key={item.name}
                      type="button"
                      role="radio"
                      onClick={() => setSelectedIconName(item.name)}
                      className={`aspect-square flex items-center justify-center rounded-xl border transition-all ${
                        selectedIconName === item.name 
                          ? 'border-black bg-black text-white' 
                          : 'border-outline-variant/20 bg-surface-container-low text-on-surface-variant hover:bg-surface-container-high'
                      }`}
                      aria-label={`Select ${item.name} icon`}
                      aria-checked={selectedIconName === item.name}
                    >
                      <item.icon size={24} />
                    </button>
                  ))}
                  
                  {/* Custom SVG Preview Button */}
                  {customSvg && (
                    <button
                      type="button"
                      role="radio"
                      onClick={() => setSelectedIconName('custom')}
                      className={`aspect-square flex items-center justify-center rounded-xl border transition-all overflow-hidden p-2 ${
                        selectedIconName === 'custom' 
                          ? 'border-black bg-black text-white' 
                          : 'border-outline-variant/20 bg-surface-container-low text-on-surface-variant hover:bg-surface-container-high'
                      }`}
                      aria-label="Select custom uploaded icon"
                      aria-checked={selectedIconName === 'custom'}
                    >
                      <div 
                        className="w-full h-full flex items-center justify-center [&>svg]:w-6 [&>svg]:h-6"
                        dangerouslySetInnerHTML={{ __html: sanitizeSvg(customSvg) }} 
                      />
                    </button>
                  )}
                </div>

                {/* Upload Custom Icon */}
                <div className="flex items-center gap-4">
                  <input 
                    type="file" 
                    accept=".svg" 
                    className="hidden" 
                    ref={fileInputRef}
                    onChange={handleFileUpload}
                  />
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="flex items-center gap-2 px-4 py-2 bg-surface-container-high hover:bg-surface-container-highest rounded-lg text-sm font-bold transition-colors"
                  >
                    <Upload size={16} />
                    {t('folders.createModal.uploadCustomSvg', 'Upload Custom SVG')}
                  </button>
                  <p className="text-xs text-on-surface-variant">{t('folders.createModal.svgFilesOnly', 'SVG files only')}</p>
                </div>
              </div>
            </form>
          </div>

          <div className="p-6 border-t border-outline-variant/10 bg-surface-container-low flex justify-end gap-4">
            <button
              type="button"
              onClick={onClose}
              className="px-6 py-3 rounded-lg font-bold text-sm hover:bg-surface-container-high transition-colors"
            >
              {t('common.cancel', 'Cancel')}
            </button>
            <button
              type="submit"
              form="create-folder-form"
              className="px-8 py-3 bg-black text-white rounded-lg font-bold text-sm hover:bg-black/80 transition-colors"
            >
              {t('sidebar.createFolder', 'Create Folder')}
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
