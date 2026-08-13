import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { type RcaChatController } from '../workspace/chatSession';
import { ChatDashboard } from './ChatDashboard';

describe('ChatDashboard', () => {
  it('requires an incident for ordinary chat and explains how to start a new RCA', () => {
    const chat = {
      activeConversation: null,
      activeConversationID: '',
      canSendOrdinary: false,
      chatContext: { label: 'RCA Chat' },
      contextChoice: 'auto',
      conversations: [],
      deleteConversation: async () => {},
      incidents: [{ incident_id: 'INC-42', title: 'GPU workload is pending' }],
      input: '',
      selectConversation: () => {},
      send: async () => {},
      sending: false,
      setContextChoice: () => {},
      setInput: () => {},
      startNewConversation: () => {},
    } as unknown as RcaChatController;

    const markup = renderToStaticMarkup(<ChatDashboard chat={chat} query="" />);

    expect(markup).not.toContain('Whole cluster');
    expect(markup).not.toContain('Auto (');
    expect(markup).toContain('Select an incident…');
    expect(markup).toContain('INC-42 · GPU workload is pending');
    expect(markup).toContain('새로운 질문은 RCA 버튼으로');
  });
});
