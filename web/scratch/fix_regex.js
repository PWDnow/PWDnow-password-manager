import fs from 'fs';
import path from 'path';

const routesDir = '/home/pwd-vm/PWDnow/web/routes';
const files = fs.readdirSync(routesDir).filter(f => f.endsWith('.js'));

for (const file of files) {
  const filePath = path.join(routesDir, file);
  let content = fs.readFileSync(filePath, 'utf8');

  // Fix the regex disaster
  content = content.replace(/checkEmergencyRate\(([^)]+)\)\) \{\n\s*return res\.status\(429, res\)/g, 'checkEmergencyRate($1, res)) {\n      return res.status(429)');
  // Same for other check rates if they got mangled
  content = content.replace(/checkLoginRate\(([^)]+)\)\) \{\n\s*return res\.status\(429, res\)/g, 'checkLoginRate($1, res)) {\n      return res.status(429)');
  content = content.replace(/checkHintsRate\(([^)]+)\)\) \{\n\s*return res\.status\(429, res\)/g, 'checkHintsRate($1, res)) {\n      return res.status(429)');
  content = content.replace(/checkRegisterRate\(([^)]+)\)\) \{\n\s*return res\.status\(429, res\)/g, 'checkRegisterRate($1, res)) {\n      return res.status(429)');
  content = content.replace(/checkRegisterEmailRate\(([^)]+)\)\) \{\n\s*return res\.status\(429, res\)/g, 'checkRegisterEmailRate($1, res)) {\n      return res.status(429)');
  content = content.replace(/checkDnsRate\(([^)]+)\)\) \{\n\s*return res\.status\(429, res\)/g, 'checkDnsRate($1, res)) {\n      return res.status(429)');

  fs.writeFileSync(filePath, content, 'utf8');
}
