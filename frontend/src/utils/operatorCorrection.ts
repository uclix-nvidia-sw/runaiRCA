export function parseCorrectionActions(value: string): string[] {
  return value.split(/\r?\n/).map((action) => action.trim()).filter(Boolean);
}
