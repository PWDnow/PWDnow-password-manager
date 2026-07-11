import React, { useState } from 'react';
import { 
  Folder as FolderIcon, 
  Plus, 
  Trash2, 
  GripVertical, 
  ArrowLeft, 
  Pencil,
  Wallet,
  Globe,
  Briefcase,
  Gamepad2,
  Bitcoin,
  Dices,
  Shield,
  CreditCard,
  Key,
  Check,
  X
} from 'lucide-react';
import { motion, AnimatePresence, Reorder } from 'motion/react';
import { useNavigate } from 'react-router-dom';
import { useTranslation, Trans } from 'react-i18next';
import { Folder, Credential } from '../types';
import { useVault } from '../context/VaultContext';
import { generateUUID } from '../utils/crypto';
import { sanitizeSvg } from '../utils/sanitize';
import { useAutofillGuard } from '../utils/autofill';
import { BROWSER_AUTOFILL } from '../utils/cardUtils';
import SEO from '../components/SEO';

const ICON_ARIA_LABELS: Record<string, string> = {
  Gamepad2: 'Gamepad',
  CreditCard: 'Credit Card',
};

const ICON_OPTIONS = [
  { name: 'Wallet', icon: Wallet },
  { name: 'Globe', icon: Globe },
  { name: 'Briefcase', icon: Briefcase },
  { name: 'Gamepad2', icon: Gamepad2 },
  { name: 'Bitcoin', icon: Bitcoin },
  { name: 'Dices', icon: Dices },
  { name: 'Shield', icon: Shield },
  { name: 'CreditCard', icon: CreditCard },
  { name: 'Key', icon: Key },
  { name: 'Folder', icon: FolderIcon },
];

export default function ManageFolders() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { 
    folders, 
    credentials, 
    updateFolder: onUpdateFolder, 
    deleteFolder: onDeleteFolder, 
    reorderFolders: onReorderFolders, 
    moveCredentials: onMoveCredentials, 
    addFolder: onAddFolder 
  } = useVault();
  
  const onBack = () => navigate('/vault');

  const [editingId, setEditingId] = useState<string | null>(null);
  const [editLabel, setEditLabel] = useState('');
  const [editIcon, setEditIcon] = useState('');
  const [isAdding, setIsAdding] = useState(false);
  const [newLabel, setNewLabel] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newCustomSvg, setNewCustomSvg] = useState('');
  const [newIcon, setNewIcon] = useState('Folder');
  const [folderToDelete, setFolderToDelete] = useState<Folder | null>(null);
  const [targetFolderId, setTargetFolderId] = useState<string>('');
  const [selectedCredentialIds, setSelectedCredentialIds] = useState<(string | number)[]>([]);
  const [isDraggingItem, setIsDraggingItem] = useState<string | number | null>(null);
  const [hoveredTargetId, setHoveredTargetId] = useState<string | null>(null);
  const [localFolderCredentials, setLocalFolderCredentials] = useState<Credential[]>([]);
  const modalRef = React.useRef<HTMLDivElement>(null);

  // Browser-autofill suppression for the "create folder" form (see
  // useAutofillGuard). Gated by the VITE_BROWSER_AUTOFILL flag.
  const guardNewLabel = useAutofillGuard();
  const guardNewDesc = useAutofillGuard();

  const folderCredentials = folderToDelete 
    ? credentials.filter(c => c.folderId === folderToDelete.id)
    : [];

  const otherFolders = folders.filter(f => f.id !== folderToDelete?.id);

  React.useEffect(() => {
    if (folderToDelete) {
      setLocalFolderCredentials(credentials.filter(c => c.folderId === folderToDelete.id));
    } else {
      setLocalFolderCredentials([]);
    }
  }, [folderToDelete?.id, credentials]);

  const handleStartEdit = (folder: Folder) => {
    setEditingId(folder.id);
    setEditLabel(folder.label);
    setEditIcon(folder.iconName || 'Folder');
  };

  const handleSaveEdit = (folder: Folder) => {
    onUpdateFolder({
      ...folder,
      label: editLabel,
      iconName: editIcon
    });
    setEditingId(null);
  };

  const handleAddNew = async () => {
    if (!newLabel.trim()) return;
    const id = generateUUID();
    let resolvedId = id;
    try {
      // VaultContext.addFolder may substitute its own UUID (collision) or the
      // daemon-assigned id. Capture the resolved id so the move-target stays
      // correct.
      resolvedId = await onAddFolder({
        id,
        label: newLabel,
        iconName: newCustomSvg ? undefined : newIcon,
        customSvg: newCustomSvg || undefined,
        description: newDescription || `Manage sensitive ${newLabel.toLowerCase()} credentials with high-precision security protocols.`
      }) ?? id;
    } catch {
      // Notification was already pushed by VaultContext; keep the inline
      // dialog open so the user can retry without losing their inputs.
      return;
    }

    // If we are in the middle of deleting a folder, select the new one as target
    if (folderToDelete) {
      setTargetFolderId(resolvedId);
    }

    setNewLabel('');
    setNewDescription('');
    setNewCustomSvg('');
    setIsAdding(false);
  };

  const handleConfirmDelete = (move: boolean) => {
    if (!folderToDelete) return;
    
    if (move && targetFolderId && selectedCredentialIds.length > 0) {
      onMoveCredentials(folderToDelete.id, targetFolderId, selectedCredentialIds);
    }
    
    onDeleteFolder(folderToDelete.id);
    setFolderToDelete(null);
    setTargetFolderId('');
    setSelectedCredentialIds([]);
  };

  const toggleCredentialSelection = (id: string | number) => {
    setSelectedCredentialIds(prev => 
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  const handleDragEnd = (credentialId: string | number, point: { x: number; y: number }) => {
    setIsDraggingItem(null);
    setHoveredTargetId(null);
    const elements = document.elementsFromPoint(point.x, point.y);
    const targetFolderElement = elements.find(el => el.getAttribute('data-folder-id'));
    
    if (targetFolderElement && folderToDelete) {
      const targetId = targetFolderElement.getAttribute('data-folder-id');
      if (targetId) {
        const idsToMove = selectedCredentialIds.includes(credentialId)
          ? selectedCredentialIds
          : [credentialId];
        onMoveCredentials(folderToDelete.id, targetId, idsToMove);
        setSelectedCredentialIds(prev => prev.filter(id => !idsToMove.includes(id)));
      }
    }
  };

  const handleDrag = (_: any, info: any) => {
    const elements = document.elementsFromPoint(info.point.x, info.point.y);
    const targetFolderElement = elements.find(el => el.getAttribute('data-folder-id'));
    const targetId = targetFolderElement?.getAttribute('data-folder-id') || null;
    setHoveredTargetId(targetId);
  };

  const handleKeyboardReorder = (folderId: string, direction: 'up' | 'down') => {
    const index = folders.findIndex(f => f.id === folderId);
    if (index === -1) return;
    const newIndex = direction === 'up' ? index - 1 : index + 1;
    if (newIndex < 0 || newIndex >= folders.length) return;
    const newFolders = [...folders];
    const [moved] = newFolders.splice(index, 1);
    newFolders.splice(newIndex, 0, moved);
    onReorderFolders(newFolders);
  };

  return (
    <div className="max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-12">
        <div className="space-y-2">
          <button 
            onClick={onBack}
            className="flex items-center gap-2 text-on-surface-variant hover:text-black dark:hover:text-white transition-colors mb-4 font-bold text-[10px] uppercase tracking-widest"
          >
            <ArrowLeft size={14} aria-hidden="true" />
            {t('manageFolders.backToVault', 'Back to Vault')}
          </button>
          <h1 className="text-4xl md:text-5xl font-headline font-black tracking-tighter text-black dark:text-white leading-none">{t('manageFolders.title', 'Manage Folders')}</h1>
          <p className="text-on-surface-variant text-lg font-medium leading-relaxed">{t('manageFolders.subtitle', 'Organize your vault structure and prioritize your assets.')}</p>
        </div>
        <button 
          onClick={() => setIsAdding(true)}
          className="group relative inline-flex items-center gap-3 bg-black text-white px-8 py-4 rounded-2xl font-black text-xs uppercase tracking-widest transition-all hover:bg-neutral-800 active:scale-95 shadow-lg"
        >
          <Plus size={18} />
          {t('manageFolders.createFolder', 'Create Folder')}
        </button>
      </div>

      <div className="bg-white dark:bg-surface-container-low rounded-3xl border border-outline-variant/10 shadow-sm overflow-hidden">
        <div className="p-4 border-b border-outline-variant/5 bg-surface-container-low/30 text-[10px] font-black uppercase tracking-widest text-on-surface-variant flex items-center justify-between px-8">
          <span>{t('manageFolders.folderStructure', 'Folder Structure')}</span>
          <span>{t('manageFolders.reorderEdit', 'Reorder & Edit')}</span>
        </div>

        <Reorder.Group axis="y" values={folders} onReorder={onReorderFolders} className="divide-y divide-outline-variant/5">
          <AnimatePresence initial={false}>
            {folders.map((folder) => (
              <Reorder.Item 
                key={folder.id} 
                value={folder}
                className="bg-white dark:bg-surface-container-low hover:bg-surface-container-low dark:hover:bg-surface-container-high transition-colors group"
              >
                <div className="p-6 px-8 flex items-center gap-6">
                  <button
                    type="button"
                    aria-label={`Reorder ${folder.label} folder. Use arrow keys to move up or down.`}
                    onKeyDown={(e) => {
                      if (e.key === 'ArrowUp') {
                        e.preventDefault();
                        handleKeyboardReorder(folder.id, 'up');
                      } else if (e.key === 'ArrowDown') {
                        e.preventDefault();
                        handleKeyboardReorder(folder.id, 'down');
                      }
                    }}
                    className="cursor-grab active:cursor-grabbing text-on-surface-variant/30 hover:text-black dark:hover:text-white transition-colors"
                  >
                    <GripVertical size={20} />
                  </button>

                  {editingId === folder.id ? (
                    <div className="flex-1 flex items-center gap-4">
                      <div className="flex-1 space-y-4">
                        <input 
                          type="text" 
                          value={editLabel}
                          onChange={(e) => setEditLabel(e.target.value)}
                          className="w-full bg-white dark:bg-surface-container-high border border-on-surface-variant/50 dark:border-outline-variant/30 rounded-xl px-4 py-3 text-sm font-bold text-black dark:text-white outline-none focus:border-black dark:focus:border-white transition-all"
                          autoFocus
                        />
                        <div className="flex flex-wrap gap-2">
                          {ICON_OPTIONS.map((opt) => (
                            <button
                              key={opt.name}
                              onClick={() => setEditIcon(opt.name)}
                              className={`p-2 rounded-lg border transition-all ${
                                editIcon === opt.name 
                                  ? 'bg-black text-white border-black' 
                                  : 'bg-white dark:bg-surface-container-high text-on-surface-variant border-outline-variant/10 hover:border-black/20'
                              }`}
                            >
                              <opt.icon size={16} />
                            </button>
                          ))}
                        </div>
                      </div>
                      <div className="flex flex-col gap-2">
                        <button 
                          onClick={() => handleSaveEdit(folder)}
                          className="p-3 bg-black text-white rounded-xl hover:bg-neutral-800 transition-all shadow-md"
                        >
                          <Check size={18} />
                        </button>
                        <button 
                          onClick={() => setEditingId(null)}
                          className="p-3 bg-surface-container-high text-on-surface-variant rounded-xl hover:bg-surface-container-highest transition-all"
                        >
                          <ArrowLeft size={18} />
                        </button>
                      </div>
                    </div>
                  ) : (
                    <>
                      <div className="w-12 h-12 bg-surface-container-low rounded-xl flex items-center justify-center border border-outline-variant/10">
                        {folder.customSvg ? (
                          <div className="w-6 h-6 text-black dark:text-white" dangerouslySetInnerHTML={{ __html: sanitizeSvg(folder.customSvg!) }} />
                        ) : folder.iconName && ICON_OPTIONS.find(o => o.name === folder.iconName) ? (
                          React.createElement(ICON_OPTIONS.find(o => o.name === folder.iconName)!.icon, { size: 20 })
                        ) : (
                          <FolderIcon size={20} />
                        )}
                      </div>
                      <div className="flex-1">
                        <div className="font-black text-lg text-black dark:text-white leading-tight tracking-tight">{folder.label}</div>
                        <div className="text-xs text-on-surface-variant font-medium mt-1 opacity-60 line-clamp-1">{folder.description}</div>
                      </div>
                      <div className="flex items-center gap-2 transition-opacity">
                        <button
                          onClick={() => handleStartEdit(folder)}
                          aria-label={`Edit ${folder.label} folder`}
                          className="p-3 bg-surface-container-low hover:bg-black hover:text-white text-on-surface-variant rounded-xl transition-all"
                        >
                          <Pencil size={18} />
                        </button>
                        <button
                          onClick={() => setFolderToDelete(folder)}
                          aria-label={`Delete ${folder.label} folder`}
                          className="p-3 bg-red-50 hover:bg-red-600 hover:text-white text-red-600 rounded-xl transition-all"
                        >
                          <Trash2 size={18} />
                        </button>
                      </div>
                    </>
                  )}
                </div>
              </Reorder.Item>
            ))}
          </AnimatePresence>
        </Reorder.Group>
      </div>

      <AnimatePresence>
        {isAdding && (
          <div className="fixed inset-0 z-[110] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40"
              onClick={() => setIsAdding(false)}
            />
            <motion.div
              role="dialog"
              aria-modal="true"
              aria-labelledby="create-folder-title"
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-2xl bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl overflow-hidden border border-outline-variant/10"
            >
              <div className="p-8">
                <h2 id="create-folder-title" className="text-2xl font-black tracking-tighter text-black dark:text-white mb-2">{t('manageFolders.createNewFolder', 'Create New Folder')}</h2>
                <p className="text-on-surface-variant text-sm mb-8 font-medium">{t('manageFolders.createNewFolderDesc', 'Create a new category to organize your vault.')}</p>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                  <div className="space-y-6">
                    <div className="space-y-2">
                      <label htmlFor="input-ynr6df09k" className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('manageFolders.folderName', 'Folder Name')}</label>
<input id="input-ynr6df09k" 
                        type="text" 
                        value={newLabel}
                        onChange={(e) => setNewLabel(e.target.value)}
                        {...guardNewLabel}
                        placeholder={t('manageFolders.folderNamePlaceholder', 'e.g. Personal, Gaming, Crypto')}
                        className="w-full bg-white dark:bg-surface-container-high border border-on-surface-variant/50 dark:border-outline-variant/30 rounded-xl px-4 py-4 text-sm font-bold text-black dark:text-white outline-none focus:border-black dark:focus:border-white transition-all"
                        autoFocus={BROWSER_AUTOFILL}
                      />
                    </div>
 
                    <div className="space-y-2">
                      <label htmlFor="input-description" className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('manageFolders.description', 'Description')}</label>
                      <textarea
                        id="input-description"
                        value={newDescription}
                        onChange={(e) => setNewDescription(e.target.value)}
                        {...guardNewDesc}
                        placeholder={t('manageFolders.descriptionPlaceholder', "What's inside this folder?")}
                        className="w-full bg-white dark:bg-surface-container-high border border-on-surface-variant/50 dark:border-outline-variant/30 rounded-xl px-4 py-4 text-sm font-bold text-black dark:text-white outline-none focus:border-black dark:focus:border-white transition-all h-32 resize-none"
                      />
                    </div>
                  </div>
 
                  <div className="space-y-6">
                    <div className="space-y-2">
                      <label htmlFor="input-rt7xis3ng" className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('manageFolders.customSvg', 'Custom SVG Icon (Optional)')}</label>
<textarea id="input-rt7xis3ng" 
                        value={newCustomSvg}
                        onChange={(e) => setNewCustomSvg(e.target.value)}
                        placeholder={t('manageFolders.customSvgPlaceholder', 'Paste SVG code here...')}
                        className="w-full bg-white dark:bg-surface-container-high border border-on-surface-variant/50 dark:border-outline-variant/30 rounded-xl px-4 py-4 text-xs font-mono text-black dark:text-white outline-none focus:border-black dark:focus:border-white transition-all h-24 resize-none"
                      />
                    </div>
 
                    {!newCustomSvg && (
                      <fieldset className="space-y-2">
                        <legend className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('manageFolders.selectPresetIcon', 'Or Select Preset Icon')}</legend>
                        <div className="grid grid-cols-5 gap-2">
                          {ICON_OPTIONS.map((opt) => (
                            <button
                              key={opt.name}
                              type="button"
                              onClick={() => setNewIcon(opt.name)}
                              aria-label={`Select ${ICON_ARIA_LABELS[opt.name] || opt.name} icon`}
                              aria-pressed={newIcon === opt.name}
                              className={`p-3 rounded-xl border transition-all flex items-center justify-center ${
                                newIcon === opt.name
                                  ? 'bg-black text-white border-black shadow-lg'
                                  : 'bg-surface-container-low text-on-surface-variant border-outline-variant/10 hover:border-black/20'
                              }`}
                            >
                              <opt.icon size={20} />
                            </button>
                          ))}
                        </div>
                      </fieldset>
                    )}
 
                    {newCustomSvg && (
                      <div className="p-4 bg-surface-container-low rounded-2xl border border-outline-variant/10 flex flex-col items-center justify-center gap-3">
                        <div className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant">{t('manageFolders.preview', 'Preview')}</div>
                        <div className="w-12 h-12 flex items-center justify-center bg-white rounded-xl shadow-sm" dangerouslySetInnerHTML={{ __html: sanitizeSvg(newCustomSvg) }} />
                      </div>
                    )}
                  </div>
                </div>
 
                <div className="flex gap-3 mt-10">
                  <button 
                    onClick={() => setIsAdding(false)}
                    className="flex-1 py-4 bg-surface-container-high text-black dark:text-white rounded-2xl font-black text-xs uppercase tracking-widest hover:bg-surface-container-highest transition-all"
                  >
                    {t('manageFolders.cancel', 'Cancel')}
                  </button>
                  <button
                    onClick={handleAddNew}
                    className="flex-1 py-4 bg-black text-white rounded-2xl font-black text-xs uppercase tracking-widest hover:bg-neutral-800 transition-all shadow-lg"
                  >
                    {t('manageFolders.createFolder', 'Create Folder')}
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {folderToDelete && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-[#000000]/40"
              onClick={() => setFolderToDelete(null)}
            />
            <motion.div 
              ref={modalRef}
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-4xl bg-white dark:bg-surface-container-low rounded-3xl shadow-2xl border border-outline-variant/10"
            >
              <div className="p-8 overflow-visible">
                <div className="flex items-center justify-between mb-8">
                  <div className="flex items-center gap-4">
                    <div className="w-12 h-12 rounded-2xl bg-red-50 flex items-center justify-center">
                      <Trash2 className="text-red-600" size={24} />
                    </div>
                    <div>
                      <h3 className="text-2xl font-black tracking-tighter text-black dark:text-white leading-none">{t('manageFolders.deleteFolderTitle', 'Delete Folder?')}</h3>
                      <p className="text-on-surface-variant text-sm font-medium mt-1">
                        <Trans i18nKey="manageFolders.deleteFolderDesc" values={{ name: folderToDelete.label }}>
                          You are about to delete <span className="text-black dark:text-white font-bold">"{folderToDelete.label}"</span>.
                        </Trans>
                      </p>
                    </div>
                  </div>
                  <button 
                    onClick={() => setFolderToDelete(null)}
                    className="p-2 hover:bg-surface-container-low rounded-full transition-colors"
                  >
                    <ArrowLeft size={20} />
                  </button>
                </div>

                <div className="flex flex-col lg:flex-row items-stretch gap-6 relative">
                  {/* Left Box: Source Folder & Items */}
                  <div className="flex-1 bg-surface-container-low/50 rounded-3xl p-6 border border-outline-variant/5">
                    <div className="flex items-center justify-between mb-4">
                      <div className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant flex items-center gap-2">
                        <div className="w-1 h-1 rounded-full bg-red-500" />
                        {t('manageFolders.source', { name: folderToDelete.label, defaultValue: `Source: ${folderToDelete.label}` })}
                      </div>
                    </div>
                    
                    <div className="space-y-4">
                      <div className="flex items-center gap-4 p-4 bg-white dark:bg-surface-container-high rounded-2xl border border-outline-variant/10 shadow-sm">
                        <div className="w-10 h-10 bg-surface-container-low rounded-xl flex items-center justify-center">
                          {folderToDelete.iconName && ICON_OPTIONS.find(o => o.name === folderToDelete.iconName) ? (
                            React.createElement(ICON_OPTIONS.find(o => o.name === folderToDelete.iconName)!.icon, { size: 18 })
                          ) : (
                            <FolderIcon size={18} />
                          )}
                        </div>
                        <div className="font-bold text-black dark:text-white">{folderToDelete.label}</div>
                      </div>

                      <div className="bg-white dark:bg-surface-container-high rounded-2xl p-4 border border-outline-variant/10">
                        <div className="flex items-center justify-between mb-3">
                          <div className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant/40">
                            {t('manageFolders.affectedItems', { count: folderCredentials.length, defaultValue: `${folderCredentials.length} Items to be affected:` })}
                          </div>
                          {folderCredentials.length > 0 && (
                            <button 
                              onClick={() => {
                                if (selectedCredentialIds.length === folderCredentials.length) {
                                  setSelectedCredentialIds([]);
                                } else {
                                  setSelectedCredentialIds(folderCredentials.map(c => c.id));
                                }
                              }}
                              className="text-[9px] font-black uppercase tracking-widest text-black dark:text-white hover:underline"
                            >
                              {selectedCredentialIds.length === folderCredentials.length ? t('manageFolders.deselectAll', 'Deselect All') : t('manageFolders.selectAll', 'Select All')}
                            </button>
                          )}
                        </div>
                        <div className={`no-scrollbar transition-all ${isDraggingItem ? 'overflow-visible' : 'max-h-80 overflow-y-auto'}`}>
                          {localFolderCredentials.length > 0 ? (
                            <Reorder.Group 
                              axis="y" 
                              values={localFolderCredentials} 
                              onReorder={setLocalFolderCredentials}
                              className="space-y-3"
                            >
                              {localFolderCredentials.map(c => {
                                const isSelected = selectedCredentialIds.includes(c.id);
                                const selectionCount = selectedCredentialIds.length;
                                
                                return (
                                  <Reorder.Item 
                                    key={c.id}
                                    value={c}
                                    dragConstraints={modalRef}
                                    dragElastic={0.1}
                                    dragSnapToOrigin
                                    onDragStart={() => setIsDraggingItem(c.id)}
                                    onDrag={handleDrag}
                                    onDragEnd={(_, info) => handleDragEnd(c.id, info.point)}
                                    whileDrag={{ 
                                      scale: 1.02, 
                                      zIndex: 5000, 
                                      cursor: 'grabbing',
                                      boxShadow: '0 20px 25px -5px rgb(0 0 0 / 0.1), 0 10px 10px -5px rgb(0 0 0 / 0.04)',
                                      backgroundColor: 'white',
                                      pointerEvents: 'none',
                                      // Glitch effect when dragging multiple
                                      skewX: isSelected && selectionCount > 1 ? [0, -1, 1, 0] : 0,
                                      transition: { skewX: { repeat: Infinity, duration: 0.2 } }
                                    }}
                                    className="flex items-center gap-4 text-sm font-bold text-black dark:text-white p-4 bg-white dark:bg-surface-container-low rounded-2xl border border-outline-variant/10 shadow-sm cursor-grab active:cursor-grabbing group/item relative select-none"
                                  >
                                    {/* Stack Glitch Effect for Multiple Selection */}
                                    {isDraggingItem === c.id && isSelected && selectionCount > 1 && (
                                      <>
                                        <div className="absolute inset-0 bg-white rounded-2xl border border-outline-variant/10 -z-10 translate-x-1 translate-y-1 opacity-50" />
                                        <div className="absolute inset-0 bg-white rounded-2xl border border-outline-variant/10 -z-20 translate-x-2 translate-y-2 opacity-25" />
                                        <div className="absolute -top-2 -right-2 bg-black text-white text-[10px] px-2 py-0.5 rounded-full z-50 font-black shadow-lg">
                                          {selectionCount}
                                        </div>
                                      </>
                                    )}

                                    <div className="flex items-center gap-3 flex-1">
                                      <button 
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          toggleCredentialSelection(c.id);
                                        }}
                                        className={`w-6 h-6 rounded-lg border flex items-center justify-center transition-all ${
                                          selectedCredentialIds.includes(c.id)
                                            ? 'bg-black border-black text-white'
                                            : 'bg-white dark:bg-surface-container-high border-outline-variant/30 text-transparent hover:border-black/30'
                                        }`}
                                      >
                                        <Check size={14} />
                                      </button>
                                      <div className="w-2 h-2 rounded-full bg-black/5" />
                                      <span className="truncate">{c.service}</span>
                                    </div>
                                    <div className="flex items-center gap-2 text-on-surface-variant/20 group-hover/item:text-on-surface-variant/40 transition-colors">
                                      <GripVertical size={16} />
                                    </div>
                                  </Reorder.Item>
                                );
                              })}
                            </Reorder.Group>
                          ) : (
                            <div className="text-xs text-on-surface-variant/40 font-bold italic py-8 text-center">{t('manageFolders.folderEmpty', 'Folder is empty')}</div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
 
                  {/* Flow Indicator */}
                  <div className="hidden lg:flex flex-col items-center justify-center gap-2 px-2">
                    <div className="w-px h-12 bg-gradient-to-b from-transparent via-outline-variant/20 to-transparent" />
                    <div className="w-10 h-10 rounded-full bg-surface-container-low border border-outline-variant/10 flex items-center justify-center text-on-surface-variant/40">
                      <ArrowLeft className="rotate-180" size={20} />
                    </div>
                    <div className="w-px h-12 bg-gradient-to-b from-transparent via-outline-variant/20 to-transparent" />
                  </div>
 
                  {/* Right Box: Target Folder Selection */}
                  <div className="flex-1 flex flex-col">
                    <div className="flex items-center justify-between mb-4">
                      <div className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant flex items-center gap-2">
                        <div className="w-1 h-1 rounded-full bg-green-500" />
                        {t('manageFolders.targetMoveTo', 'Target: Move to')}
                      </div>
                      <button 
                        onClick={() => setIsAdding(true)}
                        className="flex items-center gap-2 px-3 py-1.5 bg-black text-white rounded-lg font-black text-[9px] uppercase tracking-widest hover:bg-neutral-800 transition-all shadow-sm"
                      >
                        <Plus size={12} />
                        {t('manageFolders.newFolder', 'New Folder')}
                      </button>
                    </div>
 
                    <div className="flex-1 bg-surface-container-low/50 rounded-3xl p-6 border border-outline-variant/5">
                      {otherFolders.length > 0 ? (
                        <div className="space-y-2 max-h-[360px] overflow-y-auto no-scrollbar pr-1">
                          {otherFolders.map(f => (
                            <div
                              key={f.id}
                              data-folder-id={f.id}
                              className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl border transition-all text-left relative group/folder ${
                                hoveredTargetId === f.id 
                                  ? 'bg-black text-white border-black shadow-2xl scale-[1.05] z-10' 
                                  : isDraggingItem 
                                    ? 'bg-surface-container-low text-on-surface-variant border-dashed border-black/10'
                                    : 'bg-white dark:bg-surface-container-high text-on-surface-variant border-outline-variant/10'
                              }`}
                            >
                              <div className={`w-8 h-8 rounded-lg flex items-center justify-center transition-colors ${
                                hoveredTargetId === f.id ? 'bg-white/20' : 'bg-surface-container-low group-hover:bg-surface-container-high'
                              }`}>
                                {f.customSvg ? (
                                  <div className="w-4 h-4 text-current" dangerouslySetInnerHTML={{ __html: sanitizeSvg(f.customSvg!) }} />
                                ) : f.iconName && ICON_OPTIONS.find(o => o.name === f.iconName) ? (
                                  React.createElement(ICON_OPTIONS.find(o => o.name === f.iconName)!.icon, { size: 16 })
                                ) : (
                                  <FolderIcon size={16} />
                                )}
                              </div>
                              <span className="font-bold text-sm truncate">{f.label}</span>
                              
                              {/* Drop Zone Highlight */}
                              {isDraggingItem && (
                                <motion.div 
                                  className={`absolute inset-0 flex items-center justify-center border-2 rounded-xl pointer-events-none transition-all duration-200 ${
                                    hoveredTargetId === f.id 
                                      ? 'bg-white/10 border-white/40 opacity-100 scale-100' 
                                      : 'bg-black/5 border-black/20 border-dashed opacity-0 group-hover/folder:opacity-100 group-hover/folder:scale-100 scale-95'
                                  }`}
                                >
                                  <div className={`px-2 py-1 rounded text-[8px] font-black uppercase tracking-widest shadow-sm ${
                                    hoveredTargetId === f.id ? 'bg-white text-black' : 'bg-black text-white'
                                  }`}>
                                    {t('manageFolders.dropToMove', 'Drop to Move')}
                                  </div>
                                </motion.div>
                              )}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="h-full flex flex-col items-center justify-center text-center p-8">
                          <div className="w-12 h-12 bg-white dark:bg-surface-container-high rounded-full flex items-center justify-center mb-4 border border-outline-variant/10">
                            <FolderIcon size={20} className="text-on-surface-variant/20" />
                          </div>
                          <p className="text-xs text-on-surface-variant font-bold leading-relaxed">
                            {t('manageFolders.noOtherFolders', 'No other folders available.')}<br/>{t('manageFolders.noOtherFoldersDesc', 'Create one to move your items.')}
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
 
                <div className="flex flex-col md:flex-row gap-3 mt-10">
                  <button 
                    onClick={() => setFolderToDelete(null)}
                    className="flex-1 py-4 bg-surface-container-high text-black dark:text-white rounded-2xl font-black text-xs uppercase tracking-widest hover:bg-surface-container-highest transition-all"
                  >
                    {t('manageFolders.cancel', 'Cancel')}
                  </button>

                  <button
                    onClick={() => handleConfirmDelete(false)}
                    className="flex-[2] py-4 bg-black text-white rounded-2xl font-black text-xs uppercase tracking-widest hover:bg-neutral-800 transition-all shadow-lg"
                  >
                    {localFolderCredentials.length > 0 ? t('manageFolders.deleteEverything', 'Delete Everything') : t('manageFolders.confirmDelete', 'Confirm Delete')}
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
