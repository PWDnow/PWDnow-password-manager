const fs = require('fs');
const path = require('path');

function processFile(filePath) {
    if (!fs.existsSync(filePath)) return;
    let content = fs.readFileSync(filePath, 'utf8');
    let counter = 0;
    
    content = content.replace(/<label([^>]*)>(.*?)<\/label>\s*<input(.*?)>/gs, (match, labelAttrs, labelContent, inputAttrs) => {
        if (inputAttrs.includes('id=')) return match;
        if (labelAttrs.includes('htmlFor=')) return match;
        counter++;
        const id = `input-${Math.random().toString(36).substr(2, 9)}`;
        return `<label htmlFor="${id}"${labelAttrs}>${labelContent}</label>\n<input id="${id}"${inputAttrs}>`;
    });

    content = content.replace(/<label([^>]*)>(.*?)<\/label>\s*<textarea(.*?)>/gs, (match, labelAttrs, labelContent, inputAttrs) => {
        if (inputAttrs.includes('id=')) return match;
        if (labelAttrs.includes('htmlFor=')) return match;
        counter++;
        const id = `input-${Math.random().toString(36).substr(2, 9)}`;
        return `<label htmlFor="${id}"${labelAttrs}>${labelContent}</label>\n<textarea id="${id}"${inputAttrs}>`;
    });

    content = content.replace(/<label([^>]*)>(.*?)<\/label>\s*<select(.*?)>/gs, (match, labelAttrs, labelContent, inputAttrs) => {
        if (inputAttrs.includes('id=')) return match;
        if (labelAttrs.includes('htmlFor=')) return match;
        counter++;
        const id = `input-${Math.random().toString(36).substr(2, 9)}`;
        return `<label htmlFor="${id}"${labelAttrs}>${labelContent}</label>\n<select id="${id}"${inputAttrs}>`;
    });

    if (counter > 0) {
        fs.writeFileSync(filePath, content);
        console.log(`Replaced ${counter} inputs in ${path.basename(filePath)}`);
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
