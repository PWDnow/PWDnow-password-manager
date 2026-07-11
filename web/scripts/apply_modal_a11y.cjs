const fs = require('fs');
const path = require('path');

const targetFiles = [
    'src/components/ConfirmModal.tsx',
    'src/components/CreateFolderModal.tsx',
    'src/components/EmergencyAccessModal.tsx',
    'src/components/LanguageModal.tsx',
    'src/components/PasswordPromptModal.tsx',
    'src/components/ShareModal.tsx',
    'src/pages/Settings/AuditLogModal.tsx',
    'src/pages/Settings/RecoveryKeyModal.tsx',
    'src/pages/Settings/SharesModal.tsx'
];

targetFiles.forEach(relPath => {
    const filePath = path.join(__dirname, '..', relPath);
    if (!fs.existsSync(filePath)) return;
    
    let content = fs.readFileSync(filePath, 'utf8');
    
    // Add FocusLock import if not present
    if (!content.includes('react-focus-lock')) {
        const importRegex = /import\s+.*?;/g;
        let lastImportIndex = 0;
        let match;
        while ((match = importRegex.exec(content)) !== null) {
            lastImportIndex = match.index + match[0].length;
        }
        content = content.slice(0, lastImportIndex) + "\nimport FocusLock from 'react-focus-lock';" + content.slice(lastImportIndex);
    }
    
    // If we haven't already wrapped the modal in FocusLock
    if (!content.includes('<FocusLock')) {
        // Find the <motion.div that acts as the dialog
        content = content.replace(/(<motion\.div[^>]*className="[^"]*bg-(?:white|surface|surface-container)[^>]*>)/, '<FocusLock returnFocus>\n        $1');
        
        // This regex tries to find the matching closing tag. It's tricky to do correctly with regex.
        // Instead, let's use a simpler heuristic: find the last </motion.div> that corresponds to this.
        // Actually, replacing <motion.div ...> with <FocusLock><motion.div ...> and then finding the end is hard in regex.
        
        // Better: let's inject <FocusLock returnFocus> after the presentation div or AnimatePresence wrapper.
        // Or we can just let it fail and I'll do it manually. I will do it with basic regex.
        content = content.replace(/(<\/motion\.div>\s*)(<\/div>\s*<\/AnimatePresence>|<\/div>\s*\)?[;:]?|)$/m, '$1      </FocusLock>\n$2');
    }
    
    // Add role dialog if not present on motion.div
    if (!content.includes('role="dialog"')) {
        content = content.replace(/(<motion\.div[^>]*className="[^"]*bg-(?:white|surface|surface-container)[^>]*>)/, '$1\n        role="dialog"\n        aria-modal="true"');
    }

    fs.writeFileSync(filePath, content);
    console.log(`Processed ${relPath}`);
});
