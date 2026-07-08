import { useCallback, useEffect, useMemo, useState } from 'react';

import {
  chat,
  deleteChatConversation,
  fetchChatConversations,
  type ChatHistoryConversation,
  type ChatRequest,
} from '../../api';
import { type DetailState, type MainView, VIEW_COPY } from '../../models/appTypes';
import { type AlertRecord, type Incident, type IncidentDetail } from '../../types';
import { alertOccurrenceCount, sumAlertOccurrences } from '../../utils/formatters';

export type ChatMessage = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  createdAt: string;
};

export type ChatConversation = {
  id: string;
  title: string;
  contextLabel: string;
  incidentID: string;
  alertID: string;
  messages: ChatMessage[];
  createdAt: string;
  updatedAt: string;
};

export type ChatContextValue = {
  page: string;
  label: string;
  incidentID: string;
  alertID: string;
  incidentTitle: string;
  incidentContent: string;
  alertTitle: string;
  alertContent: string;
  context: Record<string, unknown>;
};

const MAX_CONVERSATIONS = 30;

export function useRcaChat({
  detail,
  activeView,
  incidents,
  alerts,
  onAnalysisCreated,
}: {
  detail: DetailState;
  activeView: MainView;
  incidents: Incident[];
  alerts: AlertRecord[];
  onAnalysisCreated: () => Promise<void> | void;
}) {
  const [conversations, setConversations] = useState<ChatConversation[]>([]);
  const [activeConversationID, setActiveConversationID] = useState('');
  const [manualIncidentID, setManualIncidentID] = useState('');
  const [manualAlertID, setManualAlertID] = useState('');
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);

  const chatContext = useMemo(
    () => buildChatContext(detail, activeView, incidents, alerts),
    [activeView, alerts, detail, incidents],
  );
  const activeConversation = conversations.find((conversation) => conversation.id === activeConversationID) ?? null;
  const welcomeMessage = useMemo(
    () => makeChatMessage('assistant', 'Ask about the current RCA, alert, evidence, or Run:AI workload.'),
    [],
  );
  const messages = activeConversation?.messages ?? [welcomeMessage];

  useEffect(() => {
    setManualIncidentID(chatContext.incidentID);
    setManualAlertID(chatContext.alertID);
  }, [chatContext.incidentID, chatContext.alertID]);

  useEffect(() => {
    let cancelled = false;
    fetchChatConversations({ limit: MAX_CONVERSATIONS, offset: 0 })
      .then((result) => {
        if (cancelled) return;
        const next = result.items.map(fromHistoryConversation);
        setConversations(next);
        setActiveConversationID((current) => current || next[0]?.id || '');
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  const startNewConversation = useCallback(() => {
    setActiveConversationID('');
    setInput('');
  }, []);

  const selectConversation = useCallback((id: string) => {
    setActiveConversationID(id);
    setInput('');
  }, []);

  const deleteConversation = useCallback(async (id: string) => {
    await deleteChatConversation(id);
    setConversations((previous) => previous.filter((conversation) => conversation.id !== id));
    setActiveConversationID((current) => (current === id ? '' : current));
  }, []);

  const send = useCallback(async () => {
    const message = input.trim();
    if (!message || sending) return;

    const now = new Date().toISOString();
    const conversationID = activeConversation?.id || randomID('chat');
    const incidentID = manualIncidentID.trim() || chatContext.incidentID;
    const alertID = manualAlertID.trim() || chatContext.alertID;
    const userMessage = makeChatMessage('user', message);
    const baseConversation: ChatConversation = activeConversation ?? {
      id: conversationID,
      title: titleFromMessage(message),
      contextLabel: chatContext.label,
      incidentID,
      alertID,
      messages: [],
      createdAt: now,
      updatedAt: now,
    };
    const nextConversation: ChatConversation = {
      ...baseConversation,
      contextLabel: chatContext.label,
      incidentID,
      alertID,
      messages: [...baseConversation.messages, userMessage],
      updatedAt: now,
    };

    const payload: ChatRequest = {
      message,
      conversation_id: conversationID,
      language: 'en',
      page: chatContext.page,
      auto: false,
      incident_id: incidentID,
      alert_id: alertID,
      incident_title: chatContext.incidentTitle,
      incident_content: chatContext.incidentContent,
      alert_title: chatContext.alertTitle,
      alert_content: chatContext.alertContent,
      context: chatContext.context,
    };

    setInput('');
    setActiveConversationID(conversationID);
    setConversations((previous) => upsertConversation(previous, nextConversation));
    setSending(true);

    try {
      const response = await chat(payload);
      const responseConversationID = response.conversation_id || conversationID;
      const answer = response.analysis_run
        ? `${response.answer}\n\nAnalysis run ${response.analysis_run.run_id} was created and added to the Analysis Dashboard.`
        : response.answer;
      const assistantMessage = makeChatMessage('assistant', answer);
      setActiveConversationID(responseConversationID);
      setConversations((previous) => {
        const current = previous.find((conversation) => conversation.id === conversationID) ?? nextConversation;
        return upsertConversation(
          previous.filter((conversation) => conversation.id !== conversationID && conversation.id !== responseConversationID),
          {
            ...current,
            id: responseConversationID,
            messages: [...current.messages, assistantMessage],
            updatedAt: new Date().toISOString(),
          },
        );
      });
      if (response.analysis_run) {
        void Promise.resolve(onAnalysisCreated()).catch(() => undefined);
      }
    } catch (error) {
      const text = error instanceof Error ? error.message : 'Chat request failed.';
      const errorMessage = makeChatMessage('assistant', `Error: ${text}`);
      setConversations((previous) => {
        const current = previous.find((conversation) => conversation.id === conversationID) ?? nextConversation;
        return upsertConversation(previous, {
          ...current,
          messages: [...current.messages, errorMessage],
          updatedAt: new Date().toISOString(),
        });
      });
    } finally {
      setSending(false);
    }
  }, [
    activeConversation,
    chatContext,
    input,
    manualAlertID,
    manualIncidentID,
    onAnalysisCreated,
    sending,
  ]);

  return {
    activeConversation,
    activeConversationID,
    chatContext,
    conversations,
    deleteConversation,
    input,
    manualAlertID,
    manualIncidentID,
    messages,
    selectConversation,
    send,
    sending,
    setInput,
    setManualAlertID,
    setManualIncidentID,
    startNewConversation,
  };
}

export type RcaChatController = ReturnType<typeof useRcaChat>;

function makeChatMessage(role: ChatMessage['role'], content: string): ChatMessage {
  return {
    id: randomID(role),
    role,
    content,
    createdAt: new Date().toISOString(),
  };
}

function randomID(prefix: string) {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function titleFromMessage(message: string) {
  const firstLine = message.split(/\s*\n\s*/)[0].trim();
  return firstLine.length > 54 ? `${firstLine.slice(0, 51)}...` : firstLine || 'New chat';
}

function upsertConversation(conversations: ChatConversation[], conversation: ChatConversation) {
  const next = [
    conversation,
    ...conversations.filter((item) => item.id !== conversation.id),
  ].sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  return next.slice(0, MAX_CONVERSATIONS);
}

function fromHistoryConversation(conversation: ChatHistoryConversation): ChatConversation {
  return {
    id: conversation.id,
    title: conversation.title,
    contextLabel: conversation.context_label,
    incidentID: conversation.incident_id ?? '',
    alertID: conversation.alert_id ?? '',
    createdAt: conversation.created_at,
    updatedAt: conversation.updated_at,
    messages: (conversation.messages ?? [])
      .filter((message) => message.role === 'user' || message.role === 'assistant')
      .map((message) => ({
        id: message.id,
        role: message.role,
        content: message.content,
        createdAt: message.created_at,
      })),
  };
}

function buildChatContext(
  detail: DetailState,
  activeView: MainView,
  incidents: Incident[],
  alerts: AlertRecord[],
): ChatContextValue {
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
    label: VIEW_COPY[activeView].title,
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
