// The workspace dialog's own lifecycle: the delayed-unmount exit, the approval
// flash, and dialog focus management. Kept together because they are all about
// the panel as a dialog, not about the incident it shows.
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';

export function useWorkspaceDialog(detailKey: string | null, onClose: () => void) {
  const [closing, setClosing] = useState(false);
  const [justApproved, setJustApproved] = useState(false);
  const closeTimerRef = useRef<number | null>(null);
  const approveTimerRef = useRef<number | null>(null);
  const sectionRef = useRef<HTMLElement | null>(null);
  const openerRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    setClosing(false);
    if (closeTimerRef.current !== null) {
      window.clearTimeout(closeTimerRef.current);
      closeTimerRef.current = null;
    }
  }, [detailKey]);

  useEffect(() => () => {
    if (closeTimerRef.current !== null) window.clearTimeout(closeTimerRef.current);
    if (approveTimerRef.current !== null) window.clearTimeout(approveTimerRef.current);
  }, []);

  // Play the exit animation, then let the parent unmount. Timer-based (not
  // animationend) so it still closes under prefers-reduced-motion.
  const handleClose = useCallback(() => {
    if (closeTimerRef.current !== null) return;
    setClosing(true);
    closeTimerRef.current = window.setTimeout(() => {
      closeTimerRef.current = null;
      onClose();
    }, 220);
  }, [onClose]);

  const flashApproved = useCallback(() => {
    setJustApproved(true);
    if (approveTimerRef.current !== null) window.clearTimeout(approveTimerRef.current);
    approveTimerRef.current = window.setTimeout(() => {
      approveTimerRef.current = null;
      setJustApproved(false);
    }, 1400);
  }, []);

  // Dialog focus management: remember what opened the workspace (the table row
  // activated by Enter/click), move focus into the dialog so Tab starts on its
  // actions instead of the covered list, and hand focus back on close.
  // useLayoutEffect, not useEffect: the same commit that mounts the dialog also
  // hides `.main` (visibility), and the browser blurs the row during the style
  // recalc that follows — a passive effect would only ever see <body> focused.
  useLayoutEffect(() => {
    if (!detailKey) return undefined;
    openerRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    sectionRef.current?.focus();
    return () => {
      openerRef.current?.focus();
    };
  }, [detailKey]);

  return { closing, justApproved, handleClose, flashApproved, sectionRef };
}
