const fs = require('fs');
const path = require('path');

const targetFile = path.join(__dirname, '../src/pages/AddCredential.tsx');
let content = fs.readFileSync(targetFile, 'utf8');

// A simple regex to find label and adjacent input.
// We'll look for `<label className="...">{t(..., '...')}</label>\n<input`
// and inject an ID.

let counter = 0;
content = content.replace(/<label([^>]*)>(.*?)<\/label>\s*<input(.*?)>/gs, (match, labelAttrs, labelContent, inputAttrs) => {
    counter++;
    const id = `input-${counter}`;
    
    // Check if input already has an id
    if (inputAttrs.includes('id=')) {
        return match;
    }
    
    // Check if label already has htmlFor
    if (labelAttrs.includes('htmlFor=')) {
        return match;
    }
    
    return `<label htmlFor="${id}"${labelAttrs}>${labelContent}</label>\n<input id="${id}"${inputAttrs}>`;
});

// also for textareas
content = content.replace(/<label([^>]*)>(.*?)<\/label>\s*<textarea(.*?)>/gs, (match, labelAttrs, labelContent, inputAttrs) => {
    counter++;
    const id = `input-${counter}`;
    if (inputAttrs.includes('id=')) return match;
    if (labelAttrs.includes('htmlFor=')) return match;
    return `<label htmlFor="${id}"${labelAttrs}>${labelContent}</label>\n<textarea id="${id}"${inputAttrs}>`;
});

// also for selects
content = content.replace(/<label([^>]*)>(.*?)<\/label>\s*<select(.*?)>/gs, (match, labelAttrs, labelContent, inputAttrs) => {
    counter++;
    const id = `input-${counter}`;
    if (inputAttrs.includes('id=')) return match;
    if (labelAttrs.includes('htmlFor=')) return match;
    return `<label htmlFor="${id}"${labelAttrs}>${labelContent}</label>\n<select id="${id}"${inputAttrs}>`;
});

fs.writeFileSync(targetFile, content);
console.log(`Replaced ${counter} inputs/textareas in AddCredential.tsx`);
