import React, { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import {
  Accessibility, X, Type, Contrast, Orbit, BookOpen, Link2,
  MousePointer2, Settings2, RefreshCcw, Palette, SpellCheck, Space,
  Mouse, ChevronsUpDown, Crosshair, ImageOff, SunMoon, Droplets, AlignLeft, Pointer,
  Eye, Hand, LetterText
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';

// Accessibility options interface
interface A11ySettings {
  textSize: 'normal' | 'medium' | 'large';
  highContrast: boolean;
  reduceMotion: boolean;
  readableFont: boolean;
  dyslexiaFont: boolean;
  monochrome: boolean;
  letterSpacing: boolean;
  highlightLinks: boolean;
  largerButtons: boolean;
  readingRuler: boolean;
  bigCursor: boolean;
  lineHeight: boolean;
  enhancedFocus: boolean;
  hideImages: boolean;
  invertColors: boolean;
  lowSaturation: boolean;
  leftAlign: boolean;
  highlightHover: boolean;
}

const defaultSettings: A11ySettings = {
  textSize: 'normal',
  highContrast: false,
  reduceMotion: false,
  readableFont: false,
  dyslexiaFont: false,
  monochrome: false,
  letterSpacing: false,
  highlightLinks: false,
  largerButtons: false,
  readingRuler: false,
  bigCursor: false,
  lineHeight: false,
  enhancedFocus: false,
  hideImages: false,
  invertColors: false,
  lowSaturation: false,
  leftAlign: false,
  highlightHover: false,
};

export default function AccessibilityWidget() {
  const { t } = useTranslation();
  const [isOpen, setIsOpen] = useState(false);
  const [settings, setSettings] = useState<A11ySettings>(defaultSettings);
  const [rulerPos, setRulerPos] = useState({ x: 0, y: 0 });
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Try reading from cookie first
    const cookieMatch = document.cookie.match(/(?:^|; )Accessibility=([^;]*)/);
    let saved = null;
    if (cookieMatch && cookieMatch[1]) {
      try {
        saved = decodeURIComponent(cookieMatch[1]);
      } catch (e) {
        /* ignore */
      }
    }
    // Fallback to localStorage if cookie isn't present
    if (!saved) {
      saved = localStorage.getItem('a11y-settings');
    }
    
    if (saved) {
      try {
        setSettings({ ...defaultSettings, ...JSON.parse(saved) });
      } catch (e) {
        /* ignore */
      }
    }
  }, []);

  useEffect(() => {
    const settingsStr = JSON.stringify(settings);
    localStorage.setItem('a11y-settings', settingsStr);
    
    // Save to Accessibility cookie (1 year expiry)
    document.cookie = `Accessibility=${encodeURIComponent(settingsStr)}; max-age=31536000; path=/; SameSite=Lax`;

    const root = document.documentElement;
    // Text Size
    root.classList.remove('a11y-text-medium', 'a11y-text-large');
    if (settings.textSize === 'medium') root.classList.add('a11y-text-medium');
    if (settings.textSize === 'large') root.classList.add('a11y-text-large');

    // Class-based toggles
    root.classList.toggle('a11y-high-contrast', settings.highContrast);
    root.classList.toggle('a11y-reduce-motion', settings.reduceMotion);
    root.classList.toggle('a11y-readable-font', settings.readableFont);
    root.classList.toggle('a11y-highlight-links', settings.highlightLinks);
    root.classList.toggle('a11y-larger-buttons', settings.largerButtons);
    root.classList.toggle('a11y-reading-ruler', settings.readingRuler);
    root.classList.toggle('a11y-dyslexia-font', settings.dyslexiaFont);
    root.classList.toggle('a11y-letter-spacing', settings.letterSpacing);
    root.classList.toggle('a11y-big-cursor', settings.bigCursor);
    root.classList.toggle('a11y-line-height', settings.lineHeight);
    root.classList.toggle('a11y-enhanced-focus', settings.enhancedFocus);
    root.classList.toggle('a11y-hide-images', settings.hideImages);
    root.classList.toggle('a11y-left-align', settings.leftAlign);
    root.classList.toggle('a11y-highlight-hover', settings.highlightHover);
    root.classList.toggle('a11y-monochrome', settings.monochrome);
    root.classList.toggle('a11y-invert-colors', settings.invertColors);
    root.classList.toggle('a11y-low-saturation', settings.lowSaturation);

    // Combined CSS filters on #root so the a11y portal (on body) stays unfiltered
    const rootEl = document.getElementById('root');
    if (rootEl) {
      const filters: string[] = [];
      if (settings.monochrome) filters.push('grayscale(100%)');
      if (settings.invertColors) filters.push('invert(1) hue-rotate(180deg)');
      if (settings.lowSaturation) filters.push('saturate(0.3)');
      rootEl.style.filter = filters.length > 0 ? filters.join(' ') : '';
    }
  }, [settings]);

  useEffect(() => {
    if (!settings.readingRuler) return;
    const updateRuler = (e: MouseEvent) => setRulerPos({ x: e.clientX, y: e.clientY });
    window.addEventListener('mousemove', updateRuler);
    return () => window.removeEventListener('mousemove', updateRuler);
  }, [settings.readingRuler]);

  const toggleSetting = (key: keyof A11ySettings) => {
    setSettings(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const updateTextSize = (size: 'normal' | 'medium' | 'large') => {
    setSettings(prev => ({ ...prev, textSize: size }));
  };

  const resetAll = () => {
    setSettings(defaultSettings);
    const rootEl = document.getElementById('root');
    if (rootEl) rootEl.style.filter = '';
  };

  // Count active features for the badge
  const activeCount = Object.entries(settings).filter(([key, val]) => {
    if (key === 'textSize') return val !== 'normal';
    return val === true;
  }).length;

  return (
    <>
      {/* Everything below is portaled to document.body, not rendered inline under
          #root. A CSS `filter` (monochrome/invert/low-saturation) is applied to
          #root's inline style, and `filter` on an ancestor creates a new
          containing block for `position: fixed` descendants (same as `transform`).
          Left inline, these fixed-positioned elements would stop being fixed to
          the viewport and instead anchor to the bottom of #root's full
          scroll-height box - on a tall page that places them far off-screen,
          which is exactly the "button disappears" bug this fixes. */}
      {createPortal(
        <>
          {settings.readingRuler && (
            <div
              className="fixed left-0 right-0 h-[10px] pointer-events-none z-[9999]"
              style={{
                top: rulerPos.y - 5,
                background: 'linear-gradient(to bottom, transparent, rgba(255,200,0,0.5), transparent)',
                boxShadow: '0 0 12px 2px rgba(255,200,0,0.3)',
              }}
              aria-hidden="true"
            />
          )}

          <button
            onClick={() => setIsOpen(true)}
            className="fixed bottom-24 right-6 p-4 rounded-full bg-theme-primary text-theme-on-primary shadow-xl hover:scale-105 transition-transform z-[60] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2"
            aria-label="Accessibility Settings"
            aria-expanded={isOpen}
          >
            <Accessibility size={24} aria-hidden="true" />
            {activeCount > 0 && (
              <span className="absolute -top-1 -right-1 min-w-[22px] h-[22px] flex items-center justify-center rounded-full bg-red-500 text-white text-[11px] font-black px-1 shadow-lg ring-2 ring-white dark:ring-neutral-800">
                {activeCount}
              </span>
            )}
          </button>
        </>,
        document.body
      )}

      {/* Panel portal - also outside the filtered #root */}
      {createPortal(
        <AnimatePresence>
          {isOpen && (
            <>
              {/* Backdrop */}
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 bg-black/30 backdrop-blur-sm z-[9990]"
                onClick={() => setIsOpen(false)}
                aria-hidden="true"
              />
              <motion.div
                ref={panelRef}
                initial={{ opacity: 0, scale: 0.9, y: 20 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.9, y: 20 }}
                role="dialog"
                aria-modal="true"
                aria-labelledby="a11y-title"
                className="fixed bottom-24 right-6 w-full max-w-[380px] max-h-[80vh] overflow-y-auto rounded-3xl shadow-2xl border z-[9991] p-6 flex flex-col"
                style={{
                  backgroundColor: 'var(--a11y-panel-bg, #ffffff)',
                  borderColor: 'var(--a11y-panel-border, #e5e7eb)',
                  color: 'var(--a11y-panel-text, #111827)',
                }}
            >
              <div className="flex justify-between items-center mb-2">
                <h2 id="a11y-title" className="text-xl font-headline font-black flex items-center gap-2" style={{ color: 'var(--a11y-panel-text, #111827)' }}>
                  <Accessibility size={20} aria-hidden="true" />
                  Accessibility
                </h2>
                <button
                  onClick={() => setIsOpen(false)}
                  className="p-2 rounded-full transition-colors"
                  style={{ color: 'var(--a11y-panel-text, #111827)' }}
                  aria-label="Close accessibility panel"
                >
                  <X size={20} aria-hidden="true" />
                </button>
              </div>

              <p className="text-sm mb-5 font-medium" style={{ color: 'var(--a11y-panel-muted, #6b7280)' }}>
                Adjust the page to suit you. Choices are saved on this device.
              </p>

              <div className="space-y-5">
                {/* ── Text & Content ── */}
                <SectionHeader icon={LetterText} label="Text & Content" />
                <div className="space-y-3">
                  <div className="flex items-center gap-2 font-bold text-sm" style={{ color: 'var(--a11y-panel-text, #111827)' }}>
                    <Type size={18} aria-hidden="true" />
                    Text size
                  </div>
                  <div className="flex gap-2 p-1 rounded-xl" style={{ backgroundColor: 'var(--a11y-panel-subtle, #f3f4f6)' }}>
                    {(['normal', 'medium', 'large'] as const).map((size, i) => (
                      <button
                        key={size}
                        onClick={() => updateTextSize(size)}
                        aria-pressed={settings.textSize === size}
                        className="flex-1 py-2 rounded-lg font-bold transition-colors"
                        style={{
                          fontSize: i === 0 ? '1rem' : i === 1 ? '1.125rem' : '1.25rem',
                          backgroundColor: settings.textSize === size ? '#ffffff' : 'transparent',
                          color: settings.textSize === size ? '#2563eb' : 'var(--a11y-panel-muted, #6b7280)',
                          boxShadow: settings.textSize === size ? '0 1px 3px rgba(0,0,0,0.12)' : 'none',
                        }}
                      >
                        A
                      </button>
                    ))}
                  </div>
                </div>
                <div className="space-y-2">
                  <ToggleOption
                    icon={BookOpen}
                    title="Readable font"
                    description="Switch to a high-legibility typeface"
                    checked={settings.readableFont}
                    onChange={() => toggleSetting('readableFont')}
                  />
                  <ToggleOption
                    icon={SpellCheck}
                    title="Dyslexia friendly"
                    description="A heavier bottom-weighted font"
                    checked={settings.dyslexiaFont}
                    onChange={() => toggleSetting('dyslexiaFont')}
                  />
                  <ToggleOption
                    icon={Space}
                    title="Letter spacing"
                    description="Increase tracking for legibility"
                    checked={settings.letterSpacing}
                    onChange={() => toggleSetting('letterSpacing')}
                  />
                  <ToggleOption
                    icon={ChevronsUpDown}
                    title="Line height"
                    description="Double line spacing for readability"
                    checked={settings.lineHeight}
                    onChange={() => toggleSetting('lineHeight')}
                  />
                  <ToggleOption
                    icon={AlignLeft}
                    title="Left align text"
                    description="Force all text to left alignment"
                    checked={settings.leftAlign}
                    onChange={() => toggleSetting('leftAlign')}
                  />
                </div>

                {/* ── Vision ── */}
                <SectionHeader icon={Eye} label="Vision" />
                <div className="space-y-2">
                  <ToggleOption
                    icon={Contrast}
                    title="High contrast"
                    description="Maximise text & border contrast"
                    checked={settings.highContrast}
                    onChange={() => toggleSetting('highContrast')}
                  />
                  <ToggleOption
                    icon={Palette}
                    title="Monochrome"
                    description="Change colors to grayscale"
                    checked={settings.monochrome}
                    onChange={() => toggleSetting('monochrome')}
                  />
                  <ToggleOption
                    icon={SunMoon}
                    title="Invert colors"
                    description="Reverse light and dark areas"
                    checked={settings.invertColors}
                    onChange={() => toggleSetting('invertColors')}
                  />
                  <ToggleOption
                    icon={Droplets}
                    title="Low saturation"
                    description="Soften colors for visual comfort"
                    checked={settings.lowSaturation}
                    onChange={() => toggleSetting('lowSaturation')}
                  />
                  <ToggleOption
                    icon={ImageOff}
                    title="Hide images"
                    description="Remove images to reduce visual noise"
                    checked={settings.hideImages}
                    onChange={() => toggleSetting('hideImages')}
                  />
                </div>

                {/* ── Navigation & Motor ── */}
                <SectionHeader icon={Hand} label="Navigation" />
                <div className="space-y-2">
                  <ToggleOption
                    icon={Link2}
                    title="Highlight links"
                    description="Underline & shade every link"
                    checked={settings.highlightLinks}
                    onChange={() => toggleSetting('highlightLinks')}
                  />
                  <ToggleOption
                    icon={Settings2}
                    title="Larger buttons"
                    description="Enlarge clickable controls"
                    checked={settings.largerButtons}
                    onChange={() => toggleSetting('largerButtons')}
                  />
                  <ToggleOption
                    icon={Mouse}
                    title="Big cursor"
                    description="Enlarge the mouse pointer"
                    checked={settings.bigCursor}
                    onChange={() => toggleSetting('bigCursor')}
                  />
                  <ToggleOption
                    icon={Crosshair}
                    title="Enhanced focus"
                    description="Thicker, high-visibility focus rings"
                    checked={settings.enhancedFocus}
                    onChange={() => toggleSetting('enhancedFocus')}
                  />
                  <ToggleOption
                    icon={Pointer}
                    title="Highlight hover"
                    description="Outline the element under cursor"
                    checked={settings.highlightHover}
                    onChange={() => toggleSetting('highlightHover')}
                  />
                  <ToggleOption
                    icon={MousePointer2}
                    title="Reading ruler"
                    description="A guide bar follows your pointer"
                    checked={settings.readingRuler}
                    onChange={() => toggleSetting('readingRuler')}
                  />
                </div>

                {/* ── Motion ── */}
                <SectionHeader icon={Orbit} label="Motion" />
                <div className="space-y-2">
                  <ToggleOption
                    icon={Orbit}
                    title="Reduce motion"
                    description="Stop animations and transitions"
                    checked={settings.reduceMotion}
                    onChange={() => toggleSetting('reduceMotion')}
                  />
                </div>

                <div className="pt-4" style={{ borderTop: '1px solid var(--a11y-panel-border, #e5e7eb)' }}>
                  <button
                    onClick={resetAll}
                    className="w-full py-3 flex items-center justify-center gap-2 font-bold rounded-xl transition-colors"
                    style={{ color: '#dc2626' }}
                  >
                    <RefreshCcw size={16} aria-hidden="true" />
                    Reset all
                  </button>
                </div>

                <p className="text-[10px] opacity-80 leading-relaxed pb-2" style={{ color: 'var(--a11y-panel-muted, #6b7280)' }}>
                  Your browser zoom, system font size and OS settings (dark mode, reduced motion) are also respected.
                </p>
              </div>
              </motion.div>
            </>
          )}
        </AnimatePresence>,
        document.body
      )}
    </>
  );
}

function SectionHeader({ icon: Icon, label }: { icon: React.ElementType; label: string }) {
  return (
    <div className="flex items-center gap-2 pt-2 pb-1" style={{ borderBottom: '1px solid var(--a11y-panel-border, #e5e7eb)' }}>
      <Icon size={14} style={{ color: 'var(--a11y-panel-muted, #6b7280)' }} aria-hidden="true" />
      <span className="text-[11px] font-black uppercase tracking-widest" style={{ color: 'var(--a11y-panel-muted, #6b7280)' }}>
        {label}
      </span>
    </div>
  );
}

function ToggleOption({ icon: Icon, title, description, checked, onChange }: {
  icon: React.ElementType;
  title: string;
  description: string;
  checked: boolean;
  onChange: () => void;
}) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      onClick={onChange}
      className="w-full flex items-center gap-4 p-3 rounded-xl text-left transition-all duration-150"
      style={{
        backgroundColor: checked ? 'rgba(37, 99, 235, 0.1)' : 'transparent',
        border: checked ? '1.5px solid rgba(37, 99, 235, 0.4)' : '1.5px solid var(--a11y-panel-border, #e5e7eb)',
      }}
    >
      {/* Icon container */}
      <div
        className="p-2 rounded-lg flex-shrink-0"
        aria-hidden="true"
        style={{
          backgroundColor: checked ? '#2563eb' : 'var(--a11y-panel-subtle, #f3f4f6)',
          color: checked ? '#ffffff' : 'var(--a11y-panel-muted, #6b7280)',
        }}
      >
        <Icon size={18} />
      </div>

      {/* Label */}
      <div className="flex-1 min-w-0">
        <div className="font-bold text-sm" style={{ color: 'var(--a11y-panel-text, #111827)' }}>{title}</div>
        <div className="text-[11px] mt-0.5" style={{ color: 'var(--a11y-panel-muted, #6b7280)' }}>{description}</div>
      </div>

      {/* Toggle switch — high contrast colors */}
      <div
        className="flex-shrink-0 w-11 h-[26px] rounded-full p-[3px] transition-colors duration-200"
        aria-hidden="true"
        style={{
          backgroundColor: checked ? '#2563eb' : '#d1d5db',
        }}
      >
        <div
          className="w-5 h-5 rounded-full shadow-sm transition-transform duration-200"
          style={{
            backgroundColor: '#ffffff',
            transform: checked ? 'translateX(18px)' : 'translateX(0)',
            boxShadow: '0 1px 3px rgba(0,0,0,0.2)',
          }}
        />
      </div>
    </button>
  );
}
