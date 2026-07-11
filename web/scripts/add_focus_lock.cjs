const fs = require('fs');
const path = require('path');

function processFile(filePath) {
    if (!fs.existsSync(filePath)) return;
    let content = fs.readFileSync(filePath, 'utf8');
    
    // Only process if it has a modal or "fixed inset-0" and hasn't been processed
    if (content.includes('react-focus-lock')) return;
    if (!content.includes('fixed inset-0')) return;

    // Add import
    const importRegex = /import\s+.*?;/g;
    let lastImportIndex = 0;
    let match;
    while ((match = importRegex.exec(content)) !== null) {
        lastImportIndex = match.index + match[0].length;
    }
    
    content = content.slice(0, lastImportIndex) + "\nimport FocusLock from 'react-focus-lock';" + content.slice(lastImportIndex);

    // Wrap the inner part inside fixed inset-0
    // Most start with <div className="fixed inset-0...
    // Let's replace the first child of this div with <FocusLock returnFocus> ... </FocusLock>
    
    // This is safer to do manually or with a more robust parser. For now let's just log files that need it.
    console.log(`Needs FocusLock: ${path.basename(filePath)}`);
}

const dir = path.join(__dirname, '../src/components');
fs.readdirSync(dir).forEach(file => {
    if (file.endsWith('.tsx')) {
        processFile(path.join(dir, file));
    }
});
const pagesDir = path.join(__dirname, '../src/pages/Settings');
fs.readdirSync(pagesDir).forEach(file => {
    if (file.endsWith('.tsx')) {
        processFile(path.join(pagesDir, file));
    }
});
