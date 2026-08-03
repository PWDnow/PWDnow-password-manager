# Browser Extension — Enterprise UI, Icon, i18n, and WCAG AAA Design Spec

**Date:** 2026-07-21
**Status:** Approved
**Depends on:** `2026-07-21-browser-extension-design.md` (the working v1 extension this redesigns)
**Code location:** `~/Documents/PWDnow_extension` (same standalone repo as v1).
**Explicitly separate from this spec:** the password-requirements scanner (parsing a signup page's password policy and generating a matching password) — that is its own follow-up spec, agreed with the user as a second, independent project.

## 1. Goal

Replace the v1 extension's completely unstyled popup (bare `<div>`/`<input>`/`<button>`, no CSS at all today) with a UI that:
- Visually matches the PWDnow web app's own design system (same color tokens, same look-and-feel), not a separate brand.
- Has a real toolbar icon (master SVG + generated manifest icon sizes).
- Supports 13 languages with a compact switcher, including right-to-left rendering for Arabic.
- Meets WCAG 2.2 AAA for every criterion that applies to a popup + injected fill/read UI.

## 2. Design tokens (ported, not reinvented)

`PWDnow/web/src/index.css` already defines a light/dark Material-3-style token system, and its own code comments show structural AAA rules already in place for focus, target size, and motion — see `index.css:74-114`. **Contrast is not part of that citation** — those lines contain no contrast-ratio rule; AAA contrast (1.4.6) depends on the actual color token *values*, which is a claim about the palette, not something a CSS rule at a fixed line range can demonstrate (see §6's correction for why this can't be automated either). The extension ports these tokens verbatim rather than inventing new ones, which solves brand consistency and gives the extension the same contrast posture as the web app — audited or not:

```
Light: primary #000000, primary-container #00174b, on-primary-container #ffffff,
       surface #f7f9fb, surface-container #f4f6f8/…/#e9ecef (low/high/highest),
       on-surface-variant #000000, outline-variant #d1d5db, error #991b1b
Dark:  primary #ffffff, primary-container #497cff, on-primary-container #00174b,
       surface #0f0f0f, surface-container #1e1e1e/…/#2a2a2a, on-surface-variant #d4d4d4,
       outline-variant #333333, error #ffb4ab
```

Font stack: the same system-font stack as the web app (`index.css:9`, no external font requests — relevant for CSP and for not leaking to Google Fonts).

Base AAA CSS rules ported verbatim from `index.css`:
- `:focus-visible` → 3px solid outline in `--theme-primary`, 2px offset (AAA 2.4.13 Focus Appearance Enhanced).
- Icon-only buttons get a 44×44 CSS px minimum hit area (AAA 2.5.5 Target Size Enhanced).
- `line-height: 1.65` on `p`/`li`/`dd`, paragraph spacing ≥1.5× line height (AAA 1.4.8 Visual Presentation) — the 80ch measure cap doesn't apply given the popup's ~380px width, so it's omitted.
- `prefers-reduced-motion: reduce` collapses all transitions/animations to near-zero (AAA 2.3.3 Animation from Interactions).

**Build setup:** Tailwind CSS v4 via `@tailwindcss/vite`, added to `wxt.config.ts`'s `vite: () => ({ plugins: [tailwindcss()] })`. New `app.css` with the `@theme`/`@layer base` block above, imported once in `entrypoints/popup/main.tsx`.

## 3. Icon

- `assets/icon.svg` — hand-authored master icon: navy/blue (`#00174b`) rounded-square badge, white shield silhouette, keyhole cutout. This is the checked-in source of truth regardless of packaging mechanism.
- Manifest icons (16/32/48/128px) are generated from this source. The implementer verifies WXT's actual current mechanism for this (some versions auto-generate from a single provided icon at build time) and uses it if available; otherwise a small one-time raster script (`sharp`, dev dependency) produces the PNG set into `assets/`, referenced explicitly in `wxt.config.ts`'s `manifest.icons`.
- A second, separate small SVG icon set for **in-UI** icons (not the toolbar icon): eye / eye-slash (password visibility toggle), copy, refresh (generate), globe (language switcher), check (success), warning-triangle (error). These are plain inline React components (`components/icons/*.tsx`), not an icon-font dependency — YAGNI, only the icons actually used.

## 4. Component redesign

Scope: `entrypoints/popup/App.tsx` (shell/loading state), `ConnectScreen.tsx`, `VaultScreen.tsx`. No `lib/*` logic changes — this is a presentation-layer pass over the same message-passing/state logic already built and reviewed in v1.

- **Loading state**: centered spinner + "Loading…" text, using `aria-live="polite"` so screen readers announce it once, not on every render.
- **Connect screen**: card layout, labeled inputs (visible `<label>`, not placeholder-as-label), password field gets the eye/eye-slash visibility toggle, primary button uses the `primary-container` token, errors render in a distinct banner (icon + text, not color-only) with `role="alert"`.
- **MFA code screen**: same card treatment, single code input, clear "which method" label (e.g. "Enter your authenticator code" vs "Enter your email code" — friendlier than the raw `methods[0]` string).
- **Vault screen**: each matched credential is a row with the site/username, a Fill button, and a "Copy password" affordance (eye/eye-slash + copy icon) so the user isn't forced to Fill to get the value. Empty state (no matches for this hostname) gets a helpful message + a hint to use Generate/Save, not a bare empty list. Generate button shows the generated password in a distinct, monospace, selectable field with its own copy button. Save button gets a clear success confirmation (checkmark + "Saved" text, `aria-live="polite"`), not a silent state change.
- All interactive elements keyboard-reachable in a sensible tab order; icon-only buttons get an `aria-label` (e.g. `aria-label="Copy password"`), not just a bare icon.

## 5. Internationalization

**Languages** (13, matching the user's list exactly — and matching the web app's own existing `web/src/locales/*.json` language codes exactly: `ar, de, en, es, fr, hi, id, it, ja, ko, pt, ru, zh`): English, French, Spanish, German, Italian, Portuguese, Russian, Arabic, Hindi, Chinese, Japanese, Korean, Indonesian.

**Library**: `react-i18next` + `i18next` (matching the web app's stack), but with **bundled static resources**, not the web app's `i18next-http-backend` — an extension has no server to fetch `/locales/{{lng}}.json` from, so each locale's JSON is imported directly and passed to `i18next.init({resources: {...}})`. This also means translations are available instantly and offline, with no loading flash.

**Content strategy**: the web app's existing `web/src/locales/*.json` files already contain translations for common vocabulary (Cancel, Copy, Save, Password, error strings, etc.) in exactly these 13 languages — reused here for consistency with the web app, not because they've been professionally reviewed (they haven't been). The implementer reuses this existing wording for any shared term (for terminology consistency between the web app and the extension) and writes new translations only for extension-specific strings that don't already exist in those files (Connect screen copy, MFA prompts, Fill/Generate/Save button labels not already present, etc.). Every one of the 13 extension locale files must have complete parity — no missing keys, no silent fallback to English for a real language file.

**RTL**: Arabic sets `dir="rtl"` on the popup's root element when active; Tailwind's logical properties (`ps-`/`pe-`/`ms-`/`me-` instead of `pl-`/`pr-`/`ml-`/`mr-`) are used throughout the redesigned components specifically so the mirrored layout works correctly without per-language CSS overrides.

**Switcher**: a globe-icon button in the popup header opens a dropdown listing all 13 languages by their native name (e.g. "Français", "العربية", "中文" — not the English name of the language, so a user can find their own language without already reading English). Auto-detects from `navigator.language` on first run (matched against the 13 supported codes, falling back to English for anything unsupported); an explicit user choice is persisted in `chrome.storage.local` and always wins after that.

## 6. Accessibility (WCAG 2.2 AAA)

Beyond the ported base CSS rules in §2, the redesign explicitly addresses:
- **1.4.6 Contrast (Enhanced, 7:1)**: inherited from the web app's already-shipped, presumably-audited token palette (verbatim hex values, §2) — **correction (found during final review):** axe-core's `color-contrast` rule requires real layout/paint to measure ratios, which jsdom does not provide; under the project's jsdom-based Vitest suite the rule always lands in `incomplete`, never `passes`/`violations`, so `toHaveNoViolations()` cannot and does not actually catch a contrast regression. The automated axe checks in §7 do verify real structural AAA criteria (labeling, nested-interactive, heading order, aria-*) but NOT contrast. Contrast compliance rests solely on token-value fidelity to the audited web app palette, not on any automated check in this suite.
- **2.4.9 Link Purpose (Link Only)** / button purpose: no icon-only control without an accessible name.
- **2.4.10 Section Headings**: each screen has a real `<h1>`/`<h2>` heading, not just visually-styled text.
- **3.3.5 Help**: the MFA screen and error banners give actionable next-step text, not just a status code.
- **1.4.8 Visual Presentation**: ported (§2).
- **2.5.5 Target Size (Enhanced)**: ported (§2), applies to Fill/Copy/Generate/Save/language-switcher buttons.
- Criteria that don't structurally apply to this UI (e.g. 1.2.6 Sign Language, media-alternative criteria — there's no audio/video content anywhere in this extension) are explicitly out of scope, not silently skipped.

## 7. Testing

- **Automated accessibility checks**: add `vitest-axe` (axe-core wrapper for Vitest + Testing Library) as a dev dependency; each redesigned screen's existing RTL test gets an additional assertion that `axe(container)` reports zero violations. This is the concrete verification that AAA labeling/structural requirements (nested-interactive, button-name, heading order, aria-*, image-alt) are actually met, not just asserted in prose. **Contrast is explicitly excluded from this guarantee** — see §6's correction: jsdom cannot execute axe's `color-contrast` rule meaningfully, so contrast compliance is verified only by the token values being byte-identical to the already-shipped, audited web app palette.
- **i18n completeness test**: a test that loads all 13 locale JSON files and asserts they have identical key sets (no missing/extra keys across languages) — catches an incomplete translation file mechanically rather than relying on manual review.
- **RTL smoke test**: a test that renders with the Arabic locale active and asserts `document.dir === 'rtl'`.
- Existing v1 component tests (`ConnectScreen.test.tsx`, `VaultScreen.test.tsx`, `App.test.tsx`) are updated for the new markup (e.g. `getByLabelText` instead of `getByPlaceholderText` now that real `<label>`s exist) but keep asserting the same underlying behavior — this is a presentation-layer pass, not a logic change, so no `lib/*` test should need to change.

## 8. Explicitly deferred

- The password-requirements scanner (separate spec, per the agreed scope split).
- Any change to `lib/*` message-passing/session/crypto logic — untouched by this spec.
- Full support for languages beyond the 13 listed (adding a 14th language later is just adding one more locale JSON file, not an architecture change).
