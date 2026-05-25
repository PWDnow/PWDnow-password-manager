const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const MEMORIES_DIR = path.join(__dirname, '..', 'Memories');

async function sync() {
  console.log('🔄 Syncing RuFlo Memory to Obsidian...');
  
  try {
    // Search for all entries in RuVector (example query to get recent patterns)
    const output = execSync('npx ruflo memory search --query "*" --limit 10').toString();
    
    // Simple parsing (Ruflo output varies, but this is a placeholder for actual logic)
    const entries = output.split('\n').filter(line => line.includes('Key:'));
    
    if (entries.length === 0) {
      console.log('ℹ️ No new memories to sync.');
      return;
    }

    let markdown = '# 🤖 Recent RuFlo Insights\n\n';
    entries.forEach(entry => {
      markdown += `> [!info] ${entry}\n\n`;
    });

    fs.writeFileSync(path.join(MEMORIES_DIR, 'RuFlo-Insights.md'), markdown);
    console.log('✅ Sync complete: Memories/RuFlo-Insights.md updated.');
  } catch (err) {
    console.error('❌ Sync failed:', err.message);
  }
}

sync();
