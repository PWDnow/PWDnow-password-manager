import React, { useState, useRef } from 'react';
import { X, Upload, Wallet, Globe, Briefcase, Gamepad2, Bitcoin, Dices, Folder as FolderIcon, Shield, CreditCard, Key } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { Folder } from '../types';
import { sanitizeSvg } from '../utils/sanitize';
import { generateUUID } from '../utils/crypto';

interface CreateFolderModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAddFolder: (folder: Folder) => void;
}

const PREDEFINED_ICONS = [
  { name: 'Wallet', icon: Wallet },
  { name: 'Globe', icon: Globe },
  { name: 'Briefcase', icon: Briefcase },
  { name: 'Gamepad2', icon: Gamepad2 },
  { name: 'Bitcoin', icon: Bitcoin },
  { name: 'Dices', icon: Dices },
  { name: 'Folder', icon: FolderIcon },
  { name: 'Shield', icon: Shield },
  { name: 'CreditCard', icon: CreditCard },
  { name: 'Key', icon: Key },
];

const TEMPLATES = [
  'Personal Finance',
  'Gaming',
  'Cryptocurrency',
  'Streaming Services',
  'Emails',
  'Shopping',
  'Health',
  'Travel',
];

export default function CreateFolderModal({ isOpen, onClose, onAddFolder }: CreateFolderModalProps) {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [selectedIconName, setSelectedIconName] = useState<string>('Folder');
  const [customSvg, setCustomSvg] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleTemplateClick = (template: string) => {
    setTitle(template);
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
          alert('Please upload a valid SVG file.');
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
      <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          className="absolute inset-0 bg-[#000000]/40"
        />
        <motion.div 
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          className="relative bg-surface w-full max-w-2xl rounded-3xl shadow-2xl overflow-hidden border border-outline-variant/10 flex flex-col max-h-[90vh]"
        >
          <div className="flex items-center justify-between p-6 border-b border-outline-variant/10">
            <h2 className="text-2xl font-headline font-black tracking-tight">Create Folder</h2>
            <button 
              onClick={onClose}
              className="p-2 hover:bg-surface-container-high rounded-full transition-colors"
              aria-label="Close modal"
            >
              <X size={24} />
            </button>
          </div>

          <div className="p-6 overflow-y-auto no-scrollbar">
            <form id="create-folder-form" onSubmit={handleSubmit} className="space-y-8">
              {/* Folder Name */}
              <div>
                <label htmlFor="folder-title" className="block text-xs font-black uppercase tracking-widest text-on-surface-variant mb-2">
                  Folder Name
                </label>
                <input
                  id="folder-title"
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g. Gaming"
                  className="w-full bg-white dark:bg-surface-container-high border border-on-surface-variant/50 dark:border-outline-variant/30 rounded-xl px-4 py-3 text-black dark:text-white font-medium focus:outline-none focus:border-black dark:focus:border-white focus:ring-1 focus:ring-black dark:focus:ring-white transition-all"
                  required
                />
                
                {/* Templates */}
                <div className="mt-3">
                  <p className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-2">Templates</p>
                  <div className="flex flex-wrap gap-2">
                    {TEMPLATES.map((template) => (
                      <button
                        key={template}
                        type="button"
                        onClick={() => handleTemplateClick(template)}
                        className="text-xs font-medium px-3 py-1.5 bg-surface-container-high hover:bg-black hover:text-white rounded-full transition-colors"
                      >
                        {template}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Folder Description */}
              <div>
                <label htmlFor="folder-desc" className="block text-xs font-black uppercase tracking-widest text-on-surface-variant mb-2">
                  Description
                </label>
                <textarea
                  id="folder-desc"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Manage sensitive credentials with high-precision security protocols."
                  className="w-full bg-white dark:bg-surface-container-high border border-on-surface-variant/50 dark:border-outline-variant/30 rounded-xl px-4 py-3 text-black dark:text-white font-medium focus:outline-none focus:border-black dark:focus:border-white focus:ring-1 focus:ring-black dark:focus:ring-white transition-all resize-none h-24"
                />
              </div>

              {/* Icon Selection */}
              <div>
                <label id="folder-icon-label" className="block text-xs font-black uppercase tracking-widest text-on-surface-variant mb-3">
                  Folder Icon
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
                    Upload Custom SVG
                  </button>
                  <p className="text-xs text-on-surface-variant">SVG files only</p>
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
              Cancel
            </button>
            <button
              type="submit"
              form="create-folder-form"
              className="px-8 py-3 bg-black text-white rounded-lg font-bold text-sm hover:bg-black/80 transition-colors"
            >
              Create Folder
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
