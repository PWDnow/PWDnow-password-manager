const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, 'src', 'locales');
const countriesJsonPath = path.join(__dirname, 'src', 'data', 'countries.json');
const countryListJsonPath = path.join(__dirname, 'src', 'data', 'country-list.json');

const countriesData = JSON.parse(fs.readFileSync(countriesJsonPath, 'utf8'));
const countryListData = JSON.parse(fs.readFileSync(countryListJsonPath, 'utf8'));

// Build a map from name to iso
const nameToIso = {};
for (const c of countriesData) {
  nameToIso[c.name] = c.iso;
}
// Add some manual mappings for anything missing
nameToIso["Aland Islands"] = "AX";
nameToIso["American Samoa"] = "AS";
nameToIso["Antigua and Barbuda"] = "AG";
// The country-list.json contains 195 entries. Let's map them to ISO codes.
// Since country-list.json names might differ slightly, we'll try to find the closest match.
// Let's just create translations for all entities in countryListData.entities
// We'll guess the ISO code from countries.json

const nameToIsoFallback = {};
for (const c of countriesData) {
    nameToIsoFallback[c.name.toLowerCase()] = c.iso;
}

const getIso = (name) => {
    if (nameToIso[name]) return nameToIso[name];
    if (nameToIsoFallback[name.toLowerCase()]) return nameToIsoFallback[name.toLowerCase()];
    // special cases
    if (name === "Antigua and Barbuda") return "AG";
    if (name === "Bolivia") return "BO";
    if (name === "Bosnia and Herzegovina") return "BA";
    if (name === "Brunei") return "BN";
    if (name === "Cape Verde") return "CV";
    if (name === "Central African Republic") return "CF";
    if (name === "Cote d'Ivoire") return "CI";
    if (name === "Democratic Republic of the Congo") return "CD";
    if (name === "Dominican Republic") return "DO";
    if (name === "Equatorial Guinea") return "GQ";
    if (name === "Falkland Islands") return "FK";
    if (name === "Iran") return "IR";
    if (name === "Laos") return "LA";
    if (name === "Macao") return "MO";
    if (name === "Macedonia") return "MK";
    if (name === "Micronesia") return "FM";
    if (name === "Moldova") return "MD";
    if (name === "North Korea") return "KP";
    if (name === "Palestine") return "PS";
    if (name === "Russia") return "RU";
    if (name === "Saint Kitts and Nevis") return "KN";
    if (name === "Saint Lucia") return "LC";
    if (name === "Saint Vincent and the Grenadines") return "VC";
    if (name === "Sao Tome and Principe") return "ST";
    if (name === "South Korea") return "KR";
    if (name === "Syria") return "SY";
    if (name === "Taiwan") return "TW";
    if (name === "Tanzania") return "TZ";
    if (name === "Trinidad and Tobago") return "TT";
    if (name === "United Kingdom") return "GB";
    if (name === "United States") return "US";
    if (name === "Vatican City") return "VA";
    if (name === "Venezuela") return "VE";
    if (name === "Vietnam") return "VN";
    if (name === "Virgin Islands, British") return "VG";
    if (name === "Virgin Islands, U.S.") return "VI";
    return null;
};

// Map of locales to Intl.DisplayNames language
const localeMap = {
  ar: 'ar',
  de: 'de',
  en: 'en',
  es: 'es',
  fr: 'fr',
  hi: 'hi',
  id: 'id',
  it: 'it',
  ja: 'ja',
  ko: 'ko',
  pt: 'pt',
  ru: 'ru',
  zh: 'zh'
};

const files = fs.readdirSync(localesDir).filter(f => f.endsWith('.json'));

for (const file of files) {
  const locale = file.replace('.json', '');
  const lang = localeMap[locale] || locale;
  const filePath = path.join(localesDir, file);
  
  let data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  
  if (!data.countries) {
    data.countries = {};
  }
  
  const displayNames = new Intl.DisplayNames([lang], { type: 'region' });
  
  for (const name of countryListData.entities) {
    const iso = getIso(name);
    try {
      if (iso) {
          data.countries[name] = displayNames.of(iso) || name;
      } else {
          data.countries[name] = name;
      }
    } catch (e) {
      data.countries[name] = name;
    }
  }
  
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
  console.log(`Updated ${file}`);
}
