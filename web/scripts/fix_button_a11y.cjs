const fs = require('fs');
const path = require('path');

// A list of common icon-only buttons we found in grep
const regexes = [
    // Close buttons usually have onClick={onClose} or <X .../>
    {
        pattern: /<button([^>]*)>\s*<X([^>]*)\/>\s*<\/button>/gs,
        replacement: (match, btnAttrs, xAttrs) => {
            if (btnAttrs.includes('aria-label')) return match;
            return `<button aria-label="Close"${btnAttrs}>\n  <X aria-hidden="true"${xAttrs}/>\n</button>`;
        }
    },
    // Generic button matching <button ...><Icon /></button>
    // This is hard to do safely, let's target specific ones we saw.
    {
        pattern: /<button([^>]*)>\s*<Search([^>]*)\/>\s*<\/button>/gs,
        replacement: (match, btnAttrs, iconAttrs) => {
            if (btnAttrs.includes('aria-label')) return match;
            return `<button aria-label="Search"${btnAttrs}>\n  <Search aria-hidden="true"${iconAttrs}/>\n</button>`;
        }
    },
    {
        pattern: /<button([^>]*)>\s*<Plus([^>]*)\/>\s*<\/button>/gs,
        replacement: (match, btnAttrs, iconAttrs) => {
            if (btnAttrs.includes('aria-label')) return match;
            return `<button aria-label="Add"${btnAttrs}>\n  <Plus aria-hidden="true"${iconAttrs}/>\n</button>`;
        }
    },
    {
        pattern: /<button([^>]*)>\s*<RefreshCw([^>]*)\/>\s*<\/button>/gs,
        replacement: (match, btnAttrs, iconAttrs) => {
            if (btnAttrs.includes('aria-label')) return match;
            return `<button aria-label="Refresh"${btnAttrs}>\n  <RefreshCw aria-hidden="true"${iconAttrs}/>\n</button>`;
        }
    },
    {
        pattern: /<button([^>]*)>\s*<Copy([^>]*)\/>\s*<\/button>/gs,
        replacement: (match, btnAttrs, iconAttrs) => {
            if (btnAttrs.includes('aria-label')) return match;
            return `<button aria-label="Copy"${btnAttrs}>\n  <Copy aria-hidden="true"${iconAttrs}/>\n</button>`;
        }
    },
    {
        pattern: /<button([^>]*)>\s*<Settings2([^>]*)\/>\s*<\/button>/gs,
        replacement: (match, btnAttrs, iconAttrs) => {
            if (btnAttrs.includes('aria-label')) return match;
            return `<button aria-label="Settings"${btnAttrs}>\n  <Settings2 aria-hidden="true"${iconAttrs}/>\n</button>`;
        }
    }
];

function processFile(filePath) {
    if (!fs.existsSync(filePath)) return;
    let content = fs.readFileSync(filePath, 'utf8');
    let original = content;

    regexes.forEach(rule => {
        content = content.replace(rule.pattern, rule.replacement);
    });

    if (content !== original) {
        fs.writeFileSync(filePath, content);
        console.log(`Added aria-labels in ${path.basename(filePath)}`);
    }
}

function processDir(dir) {
    if (!fs.existsSync(dir)) return;
    fs.readdirSync(dir).forEach(file => {
        const fullPath = path.join(dir, file);
        if (fs.statSync(fullPath).isDirectory()) {
            processDir(fullPath);
        } else if (file.endsWith('.tsx')) {
            processFile(fullPath);
        }
    });
}

processDir(path.join(__dirname, '../src/pages'));
processDir(path.join(__dirname, '../src/components'));
