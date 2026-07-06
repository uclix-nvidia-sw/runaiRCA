import { useCallback, useRef, useState } from 'react';

export function useEditorHistory(initialValue = '') {
  const [value, setValue] = useState(initialValue);
  const historyRef = useRef<string[]>([initialValue]);
  const indexRef = useRef(0);

  const commit = useCallback((next: string) => {
    const current = historyRef.current[indexRef.current];
    if (next === current) {
      setValue(next);
      return;
    }
    const nextHistory = historyRef.current.slice(0, indexRef.current + 1);
    nextHistory.push(next);
    historyRef.current = nextHistory;
    indexRef.current = nextHistory.length - 1;
    setValue(next);
  }, []);

  const reset = useCallback((next: string) => {
    historyRef.current = [next];
    indexRef.current = 0;
    setValue(next);
  }, []);

  const undo = useCallback(() => {
    if (indexRef.current === 0) return false;
    indexRef.current -= 1;
    setValue(historyRef.current[indexRef.current]);
    return true;
  }, []);

  const redo = useCallback(() => {
    if (indexRef.current >= historyRef.current.length - 1) return false;
    indexRef.current += 1;
    setValue(historyRef.current[indexRef.current]);
    return true;
  }, []);

  return { value, setValue: commit, reset, undo, redo };
}
