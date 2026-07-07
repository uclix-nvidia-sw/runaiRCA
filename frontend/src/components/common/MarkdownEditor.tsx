import {
  Bold,
  Code2,
  Eraser,
  Heading3,
  Italic,
  Link,
  List,
  ListChecks,
  ListOrdered,
  MoreHorizontal,
  Redo2,
  Undo2,
} from 'lucide-react';
import { type KeyboardEvent, type RefObject, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

import { EditorTab } from '../../models/appTypes';

export function MarkdownEditor({
  value,
  setValue,
  undo,
  redo,
  textareaRef,
  tab,
  onTabChange,
  placeholder,
}: {
  value: string;
  setValue: (value: string) => void;
  undo: () => boolean;
  redo: () => boolean;
  textareaRef: RefObject<HTMLTextAreaElement>;
  tab: EditorTab;
  onTabChange: (tab: EditorTab) => void;
  placeholder: string;
}) {
  const [moreOpen, setMoreOpen] = useState(false);

  const applySelectionTransform = (
    transform: (selected: string) => { text: string; cursorOffset?: number },
  ) => {
    const textarea = textareaRef.current;
    if (!textarea) return;

    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const selected = value.slice(start, end);
    const next = transform(selected);
    const nextPos = start + (next.cursorOffset ?? next.text.length);

    textarea.focus();
    textarea.setRangeText(next.text, start, end, 'end');
    setValue(textarea.value);
    textarea.setSelectionRange(nextPos, nextPos);
  };

  const applyLinePrefix = (prefix: string) => {
    const textarea = textareaRef.current;
    if (!textarea) return;

    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const before = value.slice(0, start);
    const selected = value.slice(start, end);
    const lineStart = before.lastIndexOf('\n') + 1;
    const block = `${value.slice(lineStart, start)}${selected}`;
    const prefixed = block
      .split('\n')
      .map((line) => (line.trim() ? `${prefix}${line}` : line || prefix))
      .join('\n');

    textarea.focus();
    textarea.setRangeText(prefixed, lineStart, end, 'end');
    setValue(textarea.value);
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    const isMod = event.metaKey || event.ctrlKey;
    if (!isMod) return;

    const key = event.key.toLowerCase();
    if (key === 'z') {
      event.preventDefault();
      if (event.shiftKey) redo();
      else undo();
      return;
    }
    if (key === 'y') {
      event.preventDefault();
      redo();
      return;
    }
    if (key === 'b') {
      event.preventDefault();
      applySelectionTransform((text) => ({
        text: `**${text || 'bold text'}**`,
        cursorOffset: text ? undefined : 2,
      }));
      return;
    }
    if (key === 'i') {
      event.preventDefault();
      applySelectionTransform((text) => ({
        text: `*${text || 'italic text'}*`,
        cursorOffset: text ? undefined : 1,
      }));
      return;
    }
    if (key === 'k') {
      event.preventDefault();
      applySelectionTransform((text) => ({
        text: `[${text || 'link text'}](https://example.com)`,
        cursorOffset: text ? undefined : 1,
      }));
      return;
    }
    if (key === 'e') {
      event.preventDefault();
      applySelectionTransform((text) => ({
        text: `\`${text || 'code'}\``,
        cursorOffset: text ? undefined : 1,
      }));
      return;
    }
    if (event.shiftKey && key === 'h') {
      event.preventDefault();
      applyLinePrefix('### ');
    }
  };

  const handleMoreAction = (
    action: 'unordered' | 'numbered' | 'task' | 'mention' | 'reference' | 'slash',
  ) => {
    setMoreOpen(false);
    if (action === 'unordered') {
      applyLinePrefix('- ');
      return;
    }
    if (action === 'numbered') {
      applyLinePrefix('1. ');
      return;
    }
    if (action === 'task') {
      applyLinePrefix('- [ ] ');
      return;
    }
    if (action === 'mention') {
      applySelectionTransform((text) => ({ text: text ? `@${text}` : '@mention' }));
      return;
    }
    if (action === 'reference') {
      applySelectionTransform((text) => ({ text: text ? `${text}#123` : 'owner/repo#123' }));
      return;
    }
    applySelectionTransform((text) => ({ text: text ? `/${text}` : '/command' }));
  };

  const clearEditor = () => {
    setValue('');
    setTimeout(() => {
      const textarea = textareaRef.current;
      if (!textarea) return;
      textarea.focus();
      textarea.setSelectionRange(0, 0);
    }, 0);
  };

  return (
    <div className="comment-editor">
      <div className="editor-tabs">
        <button
          className={tab === 'write' ? 'active' : ''}
          onClick={() => onTabChange('write')}
          type="button"
        >
          Write
        </button>
        <button
          className={tab === 'preview' ? 'active' : ''}
          onClick={() => onTabChange('preview')}
          type="button"
        >
          Preview
        </button>
      </div>

      {tab === 'write' && (
        <div className="editor-toolbar">
          <button type="button" className="editor-tool" onClick={() => applyLinePrefix('### ')} title="Heading" aria-label="Heading">
            <Heading3 size={16} />
          </button>
          <button type="button" className="editor-tool" onClick={() => applySelectionTransform((text) => ({ text: `**${text || 'bold text'}**`, cursorOffset: text ? undefined : 2 }))} title="Bold" aria-label="Bold">
            <Bold size={16} />
          </button>
          <button type="button" className="editor-tool" onClick={() => applySelectionTransform((text) => ({ text: `*${text || 'italic text'}*`, cursorOffset: text ? undefined : 1 }))} title="Italic" aria-label="Italic">
            <Italic size={16} />
          </button>
          <button type="button" className="editor-tool" onClick={() => applySelectionTransform((text) => ({ text: `\`${text || 'code'}\``, cursorOffset: text ? undefined : 1 }))} title="Code" aria-label="Code">
            <Code2 size={16} />
          </button>
          <button type="button" className="editor-tool" onClick={() => applySelectionTransform((text) => ({ text: `[${text || 'link text'}](https://example.com)`, cursorOffset: text ? undefined : 1 }))} title="Link" aria-label="Link">
            <Link size={16} />
          </button>
          <span className="editor-divider" />
          <button type="button" className="editor-tool" onClick={undo} title="Undo" aria-label="Undo">
            <Undo2 size={16} />
          </button>
          <button type="button" className="editor-tool" onClick={redo} title="Redo" aria-label="Redo">
            <Redo2 size={16} />
          </button>
          <div className="editor-more">
            <button type="button" className="editor-tool" onClick={() => setMoreOpen((value) => !value)} title="More" aria-label="More markdown tools">
              <MoreHorizontal size={17} />
            </button>
            {moreOpen && (
              <div className="editor-menu">
                <button type="button" onClick={() => handleMoreAction('unordered')}><List size={15} /> Unordered list</button>
                <button type="button" onClick={() => handleMoreAction('numbered')}><ListOrdered size={15} /> Numbered list</button>
                <button type="button" onClick={() => handleMoreAction('task')}><ListChecks size={15} /> Task list</button>
                <button type="button" onClick={() => handleMoreAction('mention')}>@ Mention</button>
                <button type="button" onClick={() => handleMoreAction('reference')}># Reference</button>
                <button type="button" onClick={() => handleMoreAction('slash')}>/ Command</button>
              </div>
            )}
          </div>
          <button type="button" className="editor-tool editor-clear" onClick={clearEditor} title="Clear" aria-label="Clear editor">
            <Eraser size={16} />
          </button>
        </div>
      )}

      {tab === 'write' ? (
        <textarea
          ref={textareaRef}
          value={value}
          onChange={(event) => setValue(event.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={placeholder}
        />
      ) : (
        <div className="comment-preview">
          {value.trim() ? (
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{value}</ReactMarkdown>
          ) : (
            <p className="empty">Nothing to preview.</p>
          )}
        </div>
      )}
    </div>
  );
}
