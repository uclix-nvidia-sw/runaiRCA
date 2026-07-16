import { Bot, Maximize2, MessageSquare, Minimize2, Send, Settings2, X } from 'lucide-react';
import { type KeyboardEvent, useEffect, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

import { type RcaChatController } from './chatSession';

export function FloatingChat({
  chat,
  onDockedChange,
}: {
  chat: RcaChatController;
  onDockedChange: (docked: boolean) => void;
}) {
  const [open, setOpen] = useState(false);
  const [mounted, setMounted] = useState(false);
  const [docked, setDocked] = useState(false);
  const [showContext, setShowContext] = useState(false);
  const listRef = useRef<HTMLDivElement | null>(null);

  // Keep the panel mounted through its close animation, then unmount. Keyed on
  // `open` only: opening mounts immediately; closing arms a timer that a rapid
  // reopen cancels via cleanup. Timer-based (not animationend) so it still
  // unmounts under prefers-reduced-motion, where the exit animation — and its
  // animationend event — never fire.
  useEffect(() => {
    if (open) {
      setMounted(true);
      return undefined;
    }
    const timer = window.setTimeout(() => setMounted(false), 220);
    return () => window.clearTimeout(timer);
  }, [open]);

  useEffect(() => {
    if (!open || !listRef.current) return;
    listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [chat.messages, chat.sending, open]);

  useEffect(() => {
    onDockedChange(open && docked);
  }, [docked, onDockedChange, open]);

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      void chat.send();
    }
  };

  return (
    <>
      {mounted && (
        <section className={`chat-panel ${docked ? 'docked' : ''} ${open ? '' : 'is-closing'}`}>
          <header className="chat-header">
            <div>
              <span className="chat-title"><Bot size={17} /> RCA Chat</span>
              <span className="chat-context-line">{chat.chatContext.label}</span>
            </div>
            <div className="chat-actions">
              <button
                onClick={() => setShowContext((value) => !value)}
                aria-label="Edit chat context"
                title="Edit chat context"
                type="button"
              >
                <Settings2 size={16} />
              </button>
              <button
                onClick={() => setDocked((value) => !value)}
                aria-label={docked ? 'Float chat' : 'Dock chat'}
                title={docked ? 'Float chat' : 'Dock chat'}
                type="button"
              >
                {docked ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
              </button>
              <button onClick={() => setOpen(false)} aria-label="Close chat" title="Close chat" type="button">
                <X size={16} />
              </button>
            </div>
          </header>

          {showContext && (
            <div className="chat-context-editor">
              <label>
                Incident
                <input
                  value={chat.manualIncidentID}
                  onChange={(event) => chat.setManualIncidentID(event.target.value)}
                  placeholder="INC-..."
                />
              </label>
              <label>
                Alert
                <input
                  value={chat.manualAlertID}
                  onChange={(event) => chat.setManualAlertID(event.target.value)}
                  placeholder="ALR-..."
                />
              </label>
              <small>Current page and RCA content are attached automatically.</small>
            </div>
          )}

          <div className="chat-messages" ref={listRef}>
            {chat.messages.map((message) => (
              <div className={`chat-message ${message.role}`} key={message.id}>
                {message.role === 'assistant' ? (
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{message.content}</ReactMarkdown>
                ) : (
                  message.content
                )}
              </div>
            ))}
            {chat.sending && <div className="chat-message assistant pending">Analyzing current RCA context...</div>}
          </div>

          <footer className="chat-compose">
            <textarea
              value={chat.input}
              onChange={(event) => chat.setInput(event.target.value)}
              onKeyDown={onKeyDown}
              rows={2}
              placeholder="Ask a follow-up about root cause, evidence, actions, or similar incidents"
            />
            <button className="primary-button" disabled={chat.sending || !chat.input.trim()} onClick={() => void chat.send()}>
              <Send size={16} /> Send
            </button>
          </footer>
        </section>
      )}
      <button className="chat-fab" onClick={() => setOpen((value) => !value)} aria-label="Open chat">
        {open ? <Minimize2 size={22} /> : <MessageSquare size={22} />}
      </button>
    </>
  );
}
