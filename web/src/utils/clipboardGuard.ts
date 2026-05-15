export interface ClipboardGuardHandle {
  cancel: () => void;
}

// execCommand never triggers Chrome's clipboard info bar or permission dialogs.
// navigator.clipboard.writeText() does - even for writes in Chrome 126+.
// We use execCommand for all clipboard operations here.
function execWrite(text: string): void {
  const el = document.createElement('textarea');
  el.value = text;
  el.style.cssText = 'position:fixed;top:0;left:0;width:2px;height:2px;padding:0;border:0;outline:0;opacity:0;pointer-events:none;z-index:-1';
  document.body.appendChild(el);
  el.focus();
  el.select();
  try { document.execCommand('copy'); } catch { /* noop */ }
  document.body.removeChild(el);
}

// execCommand('copy') is a no-op on a collapsed (empty) selection - Chrome won't run it.
// Writing a zero-width space produces a non-collapsed selection that executes cleanly.
// The ​ is invisible in every app and effectively "empties" the clipboard.
function clearWithExec(): void {
  execWrite('​');
}

export async function secureClipboard(
  text: string,
  onTick: (secondsLeft: number) => void,
  onDone: () => void,
  seconds = 10
): Promise<ClipboardGuardHandle> {
  execWrite(text);

  let remaining = seconds;
  let cancelled = false;
  onTick(remaining);

  const id = setInterval(() => {
    if (cancelled) { clearInterval(id); return; }
    remaining--;
    if (remaining <= 0) {
      clearInterval(id);
      clearWithExec();
      onDone();
    } else {
      onTick(remaining);
    }
  }, 1000);

  return {
    cancel: () => {
      if (cancelled) return;
      cancelled = true;
      clearInterval(id);
      clearWithExec();
      onDone();
    },
  };
}
