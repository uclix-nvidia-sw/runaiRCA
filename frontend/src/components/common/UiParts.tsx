import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Clipboard,
  ListChecks,
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';

import { PageInfo } from '../../types';
import { DASHBOARD_PAGE_SIZE } from '../../utils/pagination';

export function ColumnFilter<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: Array<{ label: string; value: T }>;
  onChange: (value: T) => void;
}) {
  const active = value !== 'all';
  return (
    <label className={`column-filter ${active ? 'is-active' : ''}`}>
      <span>{label}</span>
      <select
        aria-label={`Filter ${label}`}
        value={value}
        onChange={(event) => onChange(event.target.value as T)}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>{option.label}</option>
        ))}
      </select>
      <ChevronDown size={12} aria-hidden="true" />
    </label>
  );
}

function metricIconFor(label: string) {
  const normalized = label.toLowerCase();
  if (normalized.includes('resolved')) return CheckCircle2;
  if (normalized.includes('analyzing')) return Activity;
  if (normalized.includes('total') || normalized.includes('groups')) return ListChecks;
  if (normalized.includes('open') || normalized.includes('firing')) return AlertTriangle;
  return Activity;
}

export function Metric({ label, value }: { label: string; value: string | number }) {
  const Icon = metricIconFor(label);
  return (
    <div className="metric">
      <span className="metric-icon" aria-hidden="true"><Icon size={17} /></span>
      <span className="metric-copy">
        <strong>{value}</strong>
        <span>{label}</span>
      </span>
    </div>
  );
}

export function PanelHeader({ title, count }: { title: string; count: number | string }) {
  return (
    <div className="panel-header">
      <h3>{title}</h3>
      <span>{count}</span>
    </div>
  );
}

export function PaginationControls({
  page,
  disabled,
  onPageChange,
}: {
  page: PageInfo;
  disabled?: boolean;
  onPageChange: (page: number) => void;
}) {
  const limit = Math.max(1, page.limit || DASHBOARD_PAGE_SIZE);
  const currentPage = Math.floor(page.offset / limit);
  const totalPages = Math.max(1, Math.ceil(page.total / limit));
  const canGoPrevious = currentPage > 0;
  const canGoNext = page.has_more && currentPage < totalPages - 1;
  const pages = Array.from({ length: totalPages }, (_, index) => index);

  if (page.total <= limit && currentPage === 0) {
    return null;
  }

  return (
    <div className="pagination-bar">
      <button
        className="pagination-arrow"
        disabled={disabled || !canGoPrevious}
        onClick={() => onPageChange(currentPage - 1)}
        type="button"
        aria-label="Previous page"
      >
        <ChevronLeft size={18} />
      </button>
      <div className="pagination-pages">
        {pages.map((pageIndex) => (
          <button
            aria-current={pageIndex === currentPage ? 'page' : undefined}
            className={`pagination-page ${pageIndex === currentPage ? 'active' : ''}`}
            disabled={disabled}
            key={pageIndex}
            onClick={() => onPageChange(pageIndex)}
            type="button"
          >
            {pageIndex + 1}
          </button>
        ))}
      </div>
      <button
        className="pagination-arrow"
        disabled={disabled || !canGoNext}
        onClick={() => onPageChange(currentPage + 1)}
        type="button"
        aria-label="Next page"
      >
        <ChevronRight size={18} />
      </button>
    </div>
  );
}

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const timeoutRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timeoutRef.current !== null) {
        window.clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  const handleClick = useCallback(async () => {
    await copyToClipboard(value);
    setCopied(true);
    if (timeoutRef.current !== null) {
      window.clearTimeout(timeoutRef.current);
    }
    timeoutRef.current = window.setTimeout(() => setCopied(false), 1200);
  }, [value]);

  return (
    <button
      className="copy-button"
      onClick={handleClick}
      type="button"
      title={label}
      aria-label={label}
    >
      {copied ? <CheckCircle2 size={14} /> : <Clipboard size={14} />}
    </button>
  );
}

export function CopyableBlock({
  title,
  value,
  kind,
  highlights,
}: {
  title: string;
  value: string;
  kind: 'code' | 'pre';
  highlights?: string[];
}) {
  return (
    <div className="copyable-block">
      <div className="copyable-head">{title}</div>
      <div className="copyable-frame">
        <CopyButton value={value} label={`Copy ${title}`} />
        {kind === 'code' ? <code>{value}</code> : <pre>{highlightSegments(value, highlights)}</pre>}
      </div>
    </div>
  );
}

async function copyToClipboard(value: string) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // Fall back for local/dev browser contexts where clipboard permission is denied.
    }
  }
  const textarea = document.createElement('textarea');
  textarea.value = value;
  textarea.setAttribute('readonly', 'true');
  textarea.style.position = 'fixed';
  textarea.style.left = '-9999px';
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand('copy');
  document.body.removeChild(textarea);
}

function escapeRegExp(text: string) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function highlightSegments(text: string, extraTerms?: string[]) {
  if (!text) return [text];
  const extras = (extraTerms ?? []).map((term) => term.trim()).filter(Boolean).map(escapeRegExp);
  // Rendering must not independently infer failures from raw YAML/JSON.  The
  // backend emits `artifact.highlights` only after collector-specific polarity
  // checks (for example PodScheduled=False).  With no verified highlights,
  // preserve the result verbatim and show no red markers.
  if (extras.length === 0) return [text];
  // Match a complete marker, not a prefix inside a configuration value such as
  // `PreemptLowerPriority`.
  const source = `(?<![A-Za-z0-9_])(?:${extras.join('|')})(?![A-Za-z0-9_])`;
  let pattern: RegExp;
  try {
    pattern = new RegExp(source, 'gi');
  } catch {
    return [text];
  }
  const nodes: Array<string | JSX.Element> = [];
  let last = 0;
  let match: RegExpExecArray | null;
  let key = 0;
  while ((match = pattern.exec(text)) !== null) {
    if (match[0].length === 0) {
      pattern.lastIndex += 1;
      continue;
    }
    if (match.index > last) nodes.push(text.slice(last, match.index));
    nodes.push(
      <mark className="evidence-mark" key={`hl-${key++}`}>
        {match[0]}
      </mark>,
    );
    last = match.index + match[0].length;
  }
  if (last === 0) return [text];
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}
