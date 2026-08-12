import { Bot, MessageSquarePlus, PanelLeftClose, PanelLeftOpen, Radar, Send, Trash2 } from 'lucide-react';
import { type KeyboardEvent, type MouseEvent, useEffect, useMemo, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { visit } from 'unist-util-visit';

import { formatTime } from '../../utils/formatters';
import { type RcaChatController } from '../workspace/chatSession';

// A remark plugin that splits every case-insensitive occurrence of `query`
// out of text nodes into a custom `mark` mdast node, so search matches can
// be highlighted inside fully-rendered markdown (tables, lists, code spans)
// instead of only in plain-text messages. Paired with the `mark` handler
// passed to ReactMarkdown's `remarkRehypeOptions` below, which is what
// actually turns that node into a real <mark> element.
function remarkHighlight(query: string) {
  return (tree: any) => {
    if (!query) return;
    const needle = query.toLowerCase();
    // Collect edits first and apply them after the walk finishes — splicing
    // the tree mid-traversal (even returning the "continue from" index) hits
    // real edge cases in unist-util-visit when the replacement includes more
    // text nodes, since those get walked too and can retrigger the match.
    const edits: Array<{ parent: any; index: number; replacement: any[] }> = [];
    visit(tree, 'text', (node: any, index, parent) => {
      if (!parent || index === undefined || index === null) return;
      const value: string = node.value;
      const lower = value.toLowerCase();
      if (!lower.includes(needle)) return;
      const replacement: any[] = [];
      let cursor = 0;
      let matchIndex = lower.indexOf(needle, cursor);
      while (matchIndex !== -1) {
        if (matchIndex > cursor) replacement.push({ type: 'text', value: value.slice(cursor, matchIndex) });
        replacement.push({
          type: 'mark',
          children: [{ type: 'text', value: value.slice(matchIndex, matchIndex + needle.length) }],
        });
        cursor = matchIndex + needle.length;
        matchIndex = lower.indexOf(needle, cursor);
      }
      if (cursor < value.length) replacement.push({ type: 'text', value: value.slice(cursor) });
      edits.push({ parent, index, replacement });
    });
    for (let i = edits.length - 1; i >= 0; i -= 1) {
      const { parent, index, replacement } = edits[i];
      parent.children.splice(index, 1, ...replacement);
    }
  };
}

const markRehypeHandlers = {
  mark: (state: any, node: any) => ({
    type: 'element',
    tagName: 'mark',
    properties: { className: ['chat-search-highlight'] },
    children: state.all(node),
  }),
};

// Slides the full title into view on hover when it's wider than its row —
// speed scales with how far it has to travel so a long title doesn't feel
// rushed and a short one doesn't crawl.
function ConversationTitle({ title, query }: { title: string; query: string }) {
  const textRef = useRef<HTMLSpanElement | null>(null);

  const handleEnter = (event: MouseEvent<HTMLSpanElement>) => {
    const wrap = event.currentTarget;
    const text = textRef.current;
    if (!text) return;
    const overflow = text.scrollWidth - wrap.clientWidth;
    if (overflow <= 0) return;
    text.style.transitionDuration = `${Math.min(2200, Math.max(400, overflow * 12))}ms`;
    text.style.transform = `translateX(-${overflow}px)`;
  };

  const handleLeave = () => {
    const text = textRef.current;
    if (!text) return;
    text.style.transform = 'translateX(0)';
  };

  return (
    <span className="full-chat-history-title" onMouseEnter={handleEnter} onMouseLeave={handleLeave}>
      <span className="full-chat-history-title-text" ref={textRef}>{highlightMatches(title, query)}</span>
    </span>
  );
}

// Wraps every case-insensitive occurrence of `query` in <mark>. Returns the
// plain string when there's no query so callers don't pay for an array of
// one fragment on the common no-search-active path.
function highlightMatches(text: string, query: string) {
  if (!query) return text;
  const lower = text.toLowerCase();
  const needle = query.toLowerCase();
  const parts: (string | JSX.Element)[] = [];
  let cursor = 0;
  let matchIndex = lower.indexOf(needle, cursor);
  while (matchIndex !== -1) {
    if (matchIndex > cursor) parts.push(text.slice(cursor, matchIndex));
    parts.push(<mark className="chat-search-highlight" key={matchIndex}>{text.slice(matchIndex, matchIndex + needle.length)}</mark>);
    cursor = matchIndex + needle.length;
    matchIndex = lower.indexOf(needle, cursor);
  }
  if (cursor < text.length) parts.push(text.slice(cursor));
  return parts;
}

export function ChatDashboard({
  chat,
  query,
}: {
  chat: RcaChatController;
  query: string;
}) {
  const listRef = useRef<HTMLDivElement | null>(null);
  const matchRef = useRef<HTMLDivElement | null>(null);
  const [historyCollapsed, setHistoryCollapsed] = useState(false);
  const q = query.trim().toLowerCase();
  const conversations = useMemo(
    () => chat.conversations.filter((conversation) =>
      !q || [
        conversation.title,
        conversation.contextLabel,
        conversation.incidentID,
        conversation.alertID,
        ...conversation.messages.map((message) => message.content),
      ].join(' ').toLowerCase().includes(q),
    ),
    [chat.conversations, q],
  );
  const activeMessages = chat.activeConversation?.messages ?? [];
  // The earliest message in the open thread that matches the active search —
  // this is what gets scrolled to the top instead of the usual "stick to the
  // newest message" behavior, so a keyword found mid-conversation surfaces
  // immediately rather than requiring the operator to scroll and hunt for it.
  const firstMatchID = q
    ? activeMessages.find((message) => message.content.toLowerCase().includes(q))?.id ?? null
    : null;

  useEffect(() => {
    if (firstMatchID && matchRef.current) {
      matchRef.current.scrollIntoView({ block: 'start', behavior: 'smooth' });
      return;
    }
    if (!listRef.current || firstMatchID) return;
    listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [activeMessages, chat.sending, firstMatchID]);

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    // A Korean/Japanese IME ends composition with its own Enter keydown. Without
    // this guard that keydown both sends a half-typed message and lands a second
    // send in the same event burst.
    if (event.nativeEvent.isComposing) return;
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      void chat.send();
    }
  };

  return (
    <section className={`full-chat-shell ${historyCollapsed ? 'history-collapsed' : ''}`}>
      <aside className="full-chat-history" aria-label="Chat history">
        <div className="full-chat-history-head">
          {!historyCollapsed && (
            <div>
              <span>History</span>
              <strong>{chat.conversations.length}</strong>
            </div>
          )}
          <div className="full-chat-history-head-actions">
            <button
              type="button"
              onClick={() => setHistoryCollapsed((value) => !value)}
              aria-label={historyCollapsed ? 'Expand chat history' : 'Collapse chat history'}
              title={historyCollapsed ? 'Expand history' : 'Collapse history'}
            >
              {historyCollapsed ? <PanelLeftOpen size={17} /> : <PanelLeftClose size={17} />}
            </button>
            <button type="button" onClick={chat.startNewConversation} aria-label="New chat" title="New chat">
              <MessageSquarePlus size={17} />
            </button>
          </div>
        </div>
        <div className="full-chat-history-list">
          {conversations.map((conversation) => (
            <div
              className={`full-chat-history-row ${conversation.id === chat.activeConversationID ? 'active' : ''}`}
              key={conversation.id}
            >
              <button
                className="full-chat-history-item"
                onClick={() => chat.selectConversation(conversation.id)}
                type="button"
                title={conversation.title}
              >
                <ConversationTitle title={conversation.title} query={q} />
                <small>{conversation.contextLabel} · {formatTime(conversation.updatedAt)}</small>
              </button>
              <button
                className="full-chat-history-delete"
                type="button"
                aria-label={`Delete ${conversation.title}`}
                title="Delete chat"
                onClick={(event) => {
                  event.stopPropagation();
                  if (window.confirm('Delete this chat conversation? This cannot be undone.')) {
                    void chat.deleteConversation(conversation.id);
                  }
                }}
              >
                <Trash2 size={14} />
              </button>
            </div>
          ))}
          {conversations.length === 0 && <p className="empty">No chat history yet.</p>}
        </div>
      </aside>

      <section className={`full-chat-main ${activeMessages.length === 0 ? 'is-empty' : 'has-messages'}`}>
        <div className="chat-usage-notice">
          New question? Press the RCA button — it runs a full analysis and creates an incident. Send replies within the selected incident.
        </div>
        <div className="full-chat-messages" ref={listRef}>
          {activeMessages.length === 0 ? (
            <div className="full-chat-empty">
              <Bot size={32} />
              <h3>What should runaiRCA investigate?</h3>
            </div>
          ) : (
            activeMessages.map((message) => {
              const isMatch = message.id === firstMatchID;
              return (
                <div
                  className={`chat-message ${message.role} ${isMatch ? 'is-search-match' : ''}`}
                  key={message.id}
                  ref={isMatch ? matchRef : undefined}
                >
                  {message.role === 'assistant' ? (
                    <ReactMarkdown
                      remarkPlugins={[remarkGfm, [remarkHighlight, q]]}
                      // `mark` is a deliberate custom mdast node (see remarkHighlight
                      // above), not one of react-markdown's known handler keys.
                      remarkRehypeOptions={{ handlers: markRehypeHandlers as any }}
                    >
                      {message.content}
                    </ReactMarkdown>
                  ) : (
                    highlightMatches(message.content, q)
                  )}
                </div>
              );
            })
          )}
          {chat.sending && <div className="chat-message assistant pending">Analyzing current RCA context...</div>}
        </div>

        <div className="full-chat-compose-card">
          <textarea
            value={chat.input}
            onChange={(event) => chat.setInput(event.target.value)}
            onKeyDown={onKeyDown}
            rows={3}
            placeholder="Ask about incidents, alerts, evidence, or start a new analysis"
          />
          <div className="full-chat-compose-meta">
            <span className="full-chat-context-picker">
              <Bot size={15} />
              <select
                aria-label="Chat context"
                value={chat.contextChoice}
                onChange={(event) => chat.setContextChoice(event.target.value as typeof chat.contextChoice)}
              >
                <option value="auto" disabled hidden>Select an incident…</option>
                {chat.incidents.length > 0 && (
                  <optgroup label="Incidents">
                    {chat.incidents.slice(0, 25).map((incident) => (
                      <option key={incident.incident_id} value={`incident:${incident.incident_id}`}>
                        {incident.incident_id} · {incident.title.slice(0, 48)}
                      </option>
                    ))}
                  </optgroup>
                )}
              </select>
              {chat.contextChoice.startsWith('incident:') && (
                <button
                  className="full-chat-context-clear"
                  type="button"
                  onClick={() => chat.setContextChoice('auto')}
                  aria-label="Clear selected incident"
                  title="Clear selected incident"
                >
                  ✕
                </button>
              )}
            </span>
            {chat.activeConversation && (
              <button
                type="button"
                onClick={() => void chat.deleteConversation(chat.activeConversationID)}
                aria-label="Delete chat"
                title="Delete chat"
              >
                <Trash2 size={15} />
              </button>
            )}
            <button
              className="full-chat-analyze"
              type="button"
              disabled={chat.sending || !chat.input.trim()}
              onClick={() => void chat.send({ analyze: true })}
              aria-label="Run RCA analysis"
              title="Run RCA analysis on this message"
            >
              <Radar size={15} />
              <span>RCA 분석</span>
            </button>
            <button
              className="full-chat-send"
              type="button"
              disabled={chat.sending || !chat.input.trim() || !chat.canSendOrdinary}
              onClick={() => void chat.send()}
              aria-label="Send"
              title="Send"
            >
              <Send size={18} />
            </button>
          </div>
        </div>
      </section>
    </section>
  );
}
