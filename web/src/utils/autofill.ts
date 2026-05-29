import { useState } from 'react';
import type { FocusEvent } from 'react';
import { BROWSER_AUTOFILL } from './cardUtils';

type AutofillGuardProps =
  | { autoComplete: 'on' }
  | {
      autoComplete: 'off';
      readOnly: boolean;
      onFocus: (e: FocusEvent<HTMLInputElement | HTMLTextAreaElement>) => void;
    };

/**
 * Suppress the browser's built-in autofill on a text <input>/<textarea> when
 * VITE_BROWSER_AUTOFILL=false.
 *
 * Why not just autocomplete="off"? Chromium-based browsers (Chrome, Brave,
 * Edge) deliberately IGNORE autocomplete="off" for profile/contact autofill,
 * so it does nothing for a plain text field like a folder name. The only
 * reliable cross-browser suppression is to render the field readOnly during the
 * browser's autofill scan (it skips non-editable fields) and unlock it the
 * instant the user focuses it. State-based so it survives React re-renders
 * (an imperative removeAttribute would be re-applied on the next controlled
 * onChange render).
 *
 * Call once per field, then spread onto the element:
 *   const nameGuard = useAutofillGuard();
 *   <input {...nameGuard} value={title} onChange={...} />
 *
 * Note: spreading overrides any onFocus already on the element; none of the
 * guarded fields define their own onFocus.
 */
export function useAutofillGuard(): AutofillGuardProps {
  const [unlocked, setUnlocked] = useState(false);

  if (BROWSER_AUTOFILL) {
    return { autoComplete: 'on' };
  }

  return {
    autoComplete: 'off',
    readOnly: !unlocked,
    onFocus: () => {
      if (!unlocked) setUnlocked(true);
    },
  };
}
