import React, { useState, useRef, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { ChevronDown, Search } from 'lucide-react';

interface Country {
  name: string;
  code: string;
  iso: string;
}

interface PhoneCountrySelectProps {
  value: string;
  onChange: (iso: string) => void;
  countries: Country[];
}

function isoToFlag(iso: string): string {
  return iso.toUpperCase().split('').map(c => String.fromCodePoint(c.charCodeAt(0) + 127397)).join('');
}

export default function PhoneCountrySelect({ value, onChange, countries }: PhoneCountrySelectProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [dropdownPos, setDropdownPos] = useState({ top: 0, left: 0, width: 260 });
  const containerRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  const selected = countries.find(c => c.iso === value) ?? countries[0];

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
        setSearch('');
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  useEffect(() => {
    if (open) setTimeout(() => searchRef.current?.focus(), 50);
  }, [open]);

  function handleToggle() {
    if (!open && containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect();
      const spaceBelow = window.innerHeight - rect.bottom;
      const dropdownH = 280;
      const top = spaceBelow >= dropdownH ? rect.bottom + 4 : rect.top - dropdownH - 4;
      setDropdownPos({ top: top + window.scrollY, left: rect.left + window.scrollX, width: 280 });
    }
    setOpen(o => !o);
  }

  const filtered = search.trim()
    ? countries.filter(c =>
        c.name.toLowerCase().includes(search.toLowerCase()) ||
        c.code.includes(search) ||
        c.iso.toLowerCase().includes(search.toLowerCase())
      )
    : countries;

  const dropdown = open ? (
    <div
      role="listbox"
      onKeyDown={(e) => { if (e.key === 'Escape') { setOpen(false); setSearch(''); } }}
      style={{ position: 'absolute', top: dropdownPos.top, left: dropdownPos.left, width: dropdownPos.width, zIndex: 9999 }}
      className="bg-white dark:bg-[#1a1a1a] rounded-xl shadow-2xl border border-outline-variant/20 overflow-hidden"
    >
      <div className="p-2 border-b border-outline-variant/10">
        <div className="flex items-center gap-2 px-3 py-2 bg-surface-container-low rounded-lg">
          <Search size={13} className="text-on-surface-variant shrink-0" />
          <input
            ref={searchRef}
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search…"
            className="flex-1 bg-transparent text-xs text-black dark:text-white placeholder:text-on-surface-variant outline-none"
          />
        </div>
      </div>
      <ul className="max-h-52 overflow-y-auto [scrollbar-width:thin]">
        {filtered.length === 0 ? (
          <li className="px-4 py-3 text-xs text-on-surface-variant text-center">No results</li>
        ) : filtered.map(c => (
          <li key={c.iso}>
            <button
              type="button"
              role="option"
              aria-selected={c.iso === value}
              onClick={() => { onChange(c.iso); setOpen(false); setSearch(''); }}
              className={`w-full flex items-center gap-3 px-4 py-2.5 text-xs hover:bg-surface-container-low transition-colors ${c.iso === value ? 'bg-surface-container-low font-bold text-black dark:text-white' : 'text-on-surface-variant'}`}
            >
              <span className="text-base leading-none shrink-0">{isoToFlag(c.iso)}</span>
              <span className="truncate flex-1 text-left">{c.name}</span>
              <span className="shrink-0 font-mono opacity-60">{c.code}</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  ) : null;

  return (
    <div className="relative w-32 shrink-0" ref={containerRef}>
      <button
        type="button"
        onClick={handleToggle}
        aria-haspopup="listbox"
        aria-expanded={open}
        className="w-full flex items-center gap-2 pl-3 pr-2 py-4 bg-surface-container-low rounded-xl border border-black/15 dark:border-white/15 text-black dark:text-white font-bold focus:ring-2 focus:ring-on-primary-container/20 focus:border-black/30 dark:focus:border-white/30 transition-all outline-none cursor-pointer text-sm"
      >
        <span className="text-lg leading-none shrink-0">{isoToFlag(selected?.iso ?? 'US')}</span>
        <span className="flex-1 text-left truncate text-xs">{selected?.code}</span>
        <ChevronDown size={12} className={`shrink-0 opacity-50 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
      </button>
      {typeof document !== 'undefined' && createPortal(dropdown, document.body)}
    </div>
  );
}
