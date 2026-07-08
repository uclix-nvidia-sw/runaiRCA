import { Bot, MessageSquarePlus, Send, Trash2 } from 'lucide-react';
import { type KeyboardEvent, useEffect, useMemo, useRef } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

import { formatTime } from '../../utils/formatters';
import { type RcaChatController } from '../workspace/chatSession';

export function ChatDashboard({
  chat,
  query,
}: {
  chat: RcaChatController;
  query: string;
}) {
  const listRef = useRef<HTMLDivElement | null>(null);
  const q = query.trim().toLowerCase();
  const conversations = useMemo(
    () => chat.conversations.filter((conversation) =>
      !q || [
        conversation.title,
        conversation.contextLabel,
        conversation.incidentID,
        conversation.alertID,
        conversation.messages[conversation.messages.length - 1]?.content ?? '',
      ].join(' ').toLowerCase().includes(q),
    ),
    [chat.conversations, q],
  );
  const activeMessages = chat.activeConversation?.messages ?? [];

  useEffect(() => {
    if (!listRef.current) return;
    listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [activeMessages, chat.sending]);

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      void chat.send();
    }
  };

  return (
    <section className="full-chat-shell">
      <aside className="full-chat-history" aria-label="Chat history">
        <div className="full-chat-history-head">
          <div>
            <span>History</span>
            <strong>{chat.conversations.length}</strong>
          </div>
          <button type="button" onClick={chat.startNewConversation} aria-label="New chat" title="New chat">
            <MessageSquarePlus size={17} />
          </button>
        </div>
        <div className="full-chat-history-list">
          {conversations.map((conversation) => (
            <button
              className={`full-chat-history-item ${conversation.id === chat.activeConversationID ? 'active' : ''}`}
              key={conversation.id}
              onClick={() => chat.selectConversation(conversation.id)}
              type="button"
            >
              <span>{conversation.title}</span>
              <small>{conversation.contextLabel} · {formatTime(conversation.updatedAt)}</small>
            </button>
          ))}
          {conversations.length === 0 && <p className="empty">No chat history yet.</p>}
        </div>
      </aside>

      <section className={`full-chat-main ${activeMessages.length === 0 ? 'is-empty' : 'has-messages'}`}>
        <div className="full-chat-messages" ref={listRef}>
          {activeMessages.length === 0 ? (
            <div className="full-chat-empty">
              <Bot size={32} />
              <h3>What should runaiRCA investigate?</h3>
            </div>
          ) : (
            activeMessages.map((message) => (
              <div className={`chat-message ${message.role}`} key={message.id}>
                {message.role === 'assistant' ? (
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{message.content}</ReactMarkdown>
                ) : (
                  message.content
                )}
              </div>
            ))
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
            <span><Bot size={15} /> {chat.chatContext.label}</span>
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
              className="full-chat-send"
              type="button"
              disabled={chat.sending || !chat.input.trim()}
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
