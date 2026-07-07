import { Bot, Maximize2, MessageSquare, Minimize2, Send, Settings2, X } from 'lucide-react';
import { type KeyboardEvent, useEffect, useMemo, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

import { chat, type ChatRequest } from '../../api';
import { DetailState, MainView, VIEW_COPY } from '../../models/appTypes';
import { AlertRecord, Incident, IncidentDetail } from '../../types';
import { alertOccurrenceCount, sumAlertOccurrences } from '../../utils/formatters';

type ChatMessage = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
};

function makeChatMessage(role: ChatMessage['role'], content: string): ChatMessage {
  return {
    id: `${role}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    role,
    content,
  };
}

export function FloatingChat({
  detail,
  activeView,
  incidents,
  alerts,
  onDockedChange,
  onAnalysisCreated,
}: {
  detail: DetailState;
  activeView: MainView;
  incidents: Incident[];
  alerts: AlertRecord[];
  onDockedChange: (docked: boolean) => void;
  onAnalysisCreated: () => Promise<void> | void;
}) {
  const [open, setOpen] = useState(false);
  const [docked, setDocked] = useState(false);
  const [showContext, setShowContext] = useState(false);
  const [sending, setSending] = useState(false);
  const [input, setInput] = useState('');
  const [conversationID, setConversationID] = useState('');
  const [manualIncidentID, setManualIncidentID] = useState('');
  const [manualAlertID, setManualAlertID] = useState('');
  const [messages, setMessages] = useState<ChatMessage[]>([
    makeChatMessage('assistant', 'Ask about the current RCA, alert, evidence, or Run:AI workload.'),
  ]);
  const listRef = useRef<HTMLDivElement | null>(null);

  const chatContext = useMemo(
    () => buildChatContext(detail, activeView, incidents, alerts),
    [activeView, alerts, detail, incidents],
  );

  useEffect(() => {
    setManualIncidentID(chatContext.incidentID);
    setManualAlertID(chatContext.alertID);
  }, [chatContext.incidentID, chatContext.alertID]);

  useEffect(() => {
    if (!open || !listRef.current) return;
    listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [messages, open, sending]);

  useEffect(() => {
    onDockedChange(open && docked);
  }, [docked, onDockedChange, open]);

  const send = async () => {
    const message = input.trim();
    if (!message || sending) return;

    const payload: ChatRequest = {
      message,
      conversation_id: conversationID,
      language: 'en',
      page: chatContext.page,
      auto: false,
      incident_id: manualIncidentID.trim() || chatContext.incidentID,
      alert_id: manualAlertID.trim() || chatContext.alertID,
      incident_title: chatContext.incidentTitle,
      incident_content: chatContext.incidentContent,
      alert_title: chatContext.alertTitle,
      alert_content: chatContext.alertContent,
      context: chatContext.context,
    };

    setInput('');
    setMessages((previous) => [...previous, makeChatMessage('user', message)]);
    setSending(true);
    try {
      const response = await chat(payload);
      setConversationID(response.conversation_id || conversationID);
      const answer = response.analysis_run
        ? `${response.answer}\n\nAnalysis run ${response.analysis_run.run_id} was created and added to the Analysis Dashboard.`
        : response.answer;
      setMessages((previous) => [...previous, makeChatMessage('assistant', answer)]);
      if (response.analysis_run) {
        void Promise.resolve(onAnalysisCreated()).catch(() => undefined);
      }
    } catch (error) {
      const text = error instanceof Error ? error.message : 'Chat request failed.';
      setMessages((previous) => [...previous, makeChatMessage('assistant', `Error: ${text}`)]);
    } finally {
      setSending(false);
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      void send();
    }
  };

  return (
    <>
      {open && (
        <section className={`chat-panel ${docked ? 'docked' : ''}`}>
          <header className="chat-header">
            <div>
              <span className="chat-title"><Bot size={17} /> RCA Chat</span>
              <span className="chat-context-line">{chatContext.label}</span>
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
                  value={manualIncidentID}
                  onChange={(event) => setManualIncidentID(event.target.value)}
                  placeholder="INC-..."
                />
              </label>
              <label>
                Alert
                <input
                  value={manualAlertID}
                  onChange={(event) => setManualAlertID(event.target.value)}
                  placeholder="ALR-..."
                />
              </label>
              <small>Current page and RCA content are attached automatically.</small>
            </div>
          )}

          <div className="chat-messages" ref={listRef}>
            {messages.map((message) => (
              <div className={`chat-message ${message.role}`} key={message.id}>
                {message.role === 'assistant' ? (
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{message.content}</ReactMarkdown>
                ) : (
                  message.content
                )}
              </div>
            ))}
            {sending && <div className="chat-message assistant pending">Analyzing current RCA context...</div>}
          </div>

          <footer className="chat-compose">
            <textarea
              value={input}
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={onKeyDown}
              rows={2}
              placeholder="Ask a follow-up about root cause, evidence, actions, or similar incidents"
            />
            <button className="primary-button" disabled={sending || !input.trim()} onClick={() => void send()}>
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

function buildChatContext(
  detail: DetailState,
  activeView: MainView,
  incidents: Incident[],
  alerts: AlertRecord[],
) {
  if (detail?.kind === 'incident') {
    const incident = detail.data;
    return {
      page: 'incident_detail',
      label: `Incident ${incident.incident_id}`,
      incidentID: incident.incident_id,
      alertID: '',
      incidentTitle: incident.title,
      incidentContent: incidentChatContent(incident),
      alertTitle: '',
      alertContent: '',
      context: {
        target_type: 'incident',
        incident_id: incident.incident_id,
        severity: incident.severity,
        status: incident.status,
        alerts: incident.alerts.map((alert) => ({
          alert_id: alert.alert_id,
          title: alert.alarm_title,
          status: alert.status,
          severity: alert.severity,
        })),
        capabilities: incident.capabilities,
        missing_data: incident.missing_data,
        warnings: incident.warnings,
        similar_incidents: incident.similar_incidents ?? [],
      },
    };
  }

  if (detail?.kind === 'alert') {
    const alert = detail.data;
    return {
      page: 'alert_detail',
      label: `Alert ${alert.alert_id}`,
      incidentID: alert.incident_id,
      alertID: alert.alert_id,
      incidentTitle: '',
      incidentContent: '',
      alertTitle: alert.alarm_title,
      alertContent: alertChatContent(alert),
      context: {
        target_type: 'alert',
        incident_id: alert.incident_id,
        alert_id: alert.alert_id,
        severity: alert.severity,
        status: alert.status,
        labels: alert.labels,
        annotations: alert.annotations,
        capabilities: alert.capabilities,
        missing_data: alert.missing_data,
        warnings: alert.warnings,
        similar_incidents: alert.similar_incidents ?? [],
      },
    };
  }

  return {
    page: `${activeView}_dashboard`,
    label: `${VIEW_COPY[activeView].title}`,
    incidentID: '',
    alertID: '',
    incidentTitle: '',
    incidentContent: '',
    alertTitle: '',
    alertContent: '',
    context: {
      target_type: 'dashboard',
      active_view: activeView,
      incident_count: incidents.length,
      alert_group_count: alerts.length,
      alert_count: sumAlertOccurrences(alerts),
      open_incidents: incidents.filter((incident) => incident.status !== 'resolved').length,
      firing_alerts: sumAlertOccurrences(alerts.filter((alert) => alert.status !== 'resolved')),
      sample_incidents: incidents.slice(0, 5),
      sample_alerts: alerts.slice(0, 5).map((alert) => ({
        alert_id: alert.alert_id,
        incident_id: alert.incident_id,
        title: alert.alarm_title,
        occurrence_count: alertOccurrenceCount(alert),
        severity: alert.severity,
        status: alert.status,
      })),
    },
  };
}

function incidentChatContent(incident: IncidentDetail) {
  return truncateForChat(
    [
      `Title: ${incident.title}`,
      `Status: ${incident.status}`,
      `Severity: ${incident.severity}`,
      `Summary: ${incident.analysis_summary}`,
      incident.analysis_detail,
      `Missing data: ${incident.missing_data.join(', ') || 'none'}`,
      `Warnings: ${incident.warnings.join(', ') || 'none'}`,
      `Similar incidents: ${(incident.similar_incidents ?? [])
        .map((item) => `${item.incident_id} ${item.analysis_summary}`)
        .join(' | ') || 'none'}`,
    ].join('\n\n'),
  );
}

function alertChatContent(alert: AlertRecord) {
  return truncateForChat(
    [
      `Title: ${alert.alarm_title}`,
      `Status: ${alert.status}`,
      `Severity: ${alert.severity}`,
      `Occurrences: ${alertOccurrenceCount(alert)}`,
      `Labels: ${safeJSONStringify(alert.labels)}`,
      `Annotations: ${safeJSONStringify(alert.annotations)}`,
      `Summary: ${alert.analysis_summary}`,
      alert.analysis_detail,
      `Missing data: ${alert.missing_data.join(', ') || 'none'}`,
      `Warnings: ${alert.warnings.join(', ') || 'none'}`,
    ].join('\n\n'),
  );
}

function truncateForChat(value: string, limit = 8000) {
  if (value.length <= limit) return value;
  return `${value.slice(0, limit)}\n\n[context truncated]`;
}

function safeJSONStringify(value: unknown) {
  const seen = new WeakSet<object>();
  try {
    return JSON.stringify(value, (_key, item) => {
      if (typeof item !== 'object' || item === null) return item;
      if (seen.has(item)) return '[Circular]';
      seen.add(item);
      return item;
    }) ?? String(value);
  } catch {
    return '[Unserializable]';
  }
}
