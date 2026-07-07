import { unified } from 'unified';
import remarkParse from 'remark-parse';
import remarkGfm from 'remark-gfm';
import { AlertRecord, Artifact, IncidentDetail, SimilarIncident } from './types';

type MdNode = {
  type: string;
  value?: string;
  depth?: number;
  ordered?: boolean;
  children?: MdNode[];
};

export type MarkdownBlock =
  | { kind: 'heading'; level: number; text: string }
  | { kind: 'paragraph'; text: string }
  | { kind: 'listItem'; text: string }
  | { kind: 'code'; text: string }
  | { kind: 'tableRow'; text: string };

export function markdownToBlocks(markdown: string): MarkdownBlock[] {
  const tree = unified().use(remarkParse).use(remarkGfm).parse(markdown || '') as MdNode;
  const blocks: MarkdownBlock[] = [];
  for (const child of tree.children ?? []) {
    appendBlock(child, blocks);
  }
  return blocks;
}

export async function exportIncidentDocx(incident: IncidentDetail): Promise<void> {
  const docx = await import('docx');
  const { Document, HeadingLevel, Packer, Paragraph, Table, TableCell, TableRow, TextRun, WidthType } = docx;
  const children = [
    new Paragraph({ text: incident.title || incident.incident_id, heading: HeadingLevel.TITLE }),
    keyValueTable([
      ['Incident ID', incident.incident_id],
      ['Severity', incident.severity],
      ['Incident status', incident.status],
      ['Fired', incident.fired_at],
      ['Alertmanager resolved', incident.resolved_at || '-'],
      ['User approved', incident.user_approved_at || '-'],
    ]),
    new Paragraph({ text: 'Summary', heading: HeadingLevel.HEADING_1 }),
    new Paragraph(incident.analysis_summary || 'No summary captured.'),
    new Paragraph({ text: 'Report', heading: HeadingLevel.HEADING_1 }),
    ...markdownToBlocks(incident.analysis_detail || '').map((block) => blockToParagraph(docx, block)),
    new Paragraph({ text: 'Evidence', heading: HeadingLevel.HEADING_1 }),
    artifactTable(docx, incident.artifacts),
    new Paragraph({ text: 'Alerts', heading: HeadingLevel.HEADING_1 }),
    alertTable(docx, incident.alerts),
    new Paragraph({ text: 'Similar Incidents', heading: HeadingLevel.HEADING_1 }),
    similarTable(docx, incident.similar_incidents),
  ];
  const blob = await Packer.toBlob(new Document({ sections: [{ children }] }));
  downloadBlob(blob, `${safeName(incident.incident_id)}-rca.docx`);

  function keyValueTable(rows: [string, string][]) {
    return new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: rows.map(([key, value]) => new TableRow({
        children: [
          new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: key, bold: true })] })] }),
          new TableCell({ children: [new Paragraph(value)] }),
        ],
      })),
    });
  }
}

function appendBlock(node: MdNode, blocks: MarkdownBlock[]): void {
  if (node.type === 'heading') {
    blocks.push({ kind: 'heading', level: node.depth ?? 2, text: nodeText(node) });
    return;
  }
  if (node.type === 'paragraph') {
    blocks.push({ kind: 'paragraph', text: nodeText(node) });
    return;
  }
  if (node.type === 'code') {
    blocks.push({ kind: 'code', text: node.value ?? '' });
    return;
  }
  if (node.type === 'list') {
    for (const child of node.children ?? []) {
      blocks.push({ kind: 'listItem', text: nodeText(child) });
    }
    return;
  }
  if (node.type === 'table') {
    for (const row of node.children ?? []) {
      blocks.push({ kind: 'tableRow', text: (row.children ?? []).map(nodeText).join(' | ') });
    }
  }
}

function nodeText(node: MdNode): string {
  if (typeof node.value === 'string') return node.value;
  return (node.children ?? []).map(nodeText).join('').trim();
}

function blockToParagraph(docx: typeof import('docx'), block: MarkdownBlock) {
  const { HeadingLevel, Paragraph, TextRun } = docx;
  if (block.kind === 'heading') {
    const heading = block.level <= 2 ? HeadingLevel.HEADING_2 : HeadingLevel.HEADING_3;
    return new Paragraph({ text: block.text, heading });
  }
  if (block.kind === 'listItem') {
    return new Paragraph({ text: block.text, bullet: { level: 0 } });
  }
  if (block.kind === 'code') {
    return new Paragraph({ children: [new TextRun({ text: block.text, font: 'Courier New' })] });
  }
  return new Paragraph(block.text);
}

function artifactTable(docx: typeof import('docx'), artifacts: Artifact[]) {
  const rows = artifacts.length
    ? artifacts.map((item) => [item.agent, item.status, item.summary || item.type])
    : [['-', '-', 'No evidence cards captured.']];
  return simpleTable(docx, ['Agent', 'Status', 'Summary'], rows);
}

function alertTable(docx: typeof import('docx'), alerts: AlertRecord[]) {
  const rows = alerts.length
    ? alerts.map((item) => [item.alert_id, item.status, item.alarm_title])
    : [['-', '-', 'No alerts captured.']];
  return simpleTable(docx, ['Alert', 'Status', 'Title'], rows);
}

function similarTable(docx: typeof import('docx'), items: SimilarIncident[]) {
  const rows = items.length
    ? items.map((item) => [item.incident_id, `${Math.round(item.similarity * 100)}%`, item.analysis_summary || item.title])
    : [['-', '-', 'No similar incidents captured.']];
  return simpleTable(docx, ['Incident', 'Similarity', 'Summary'], rows);
}

function simpleTable(docx: typeof import('docx'), headers: string[], rows: string[][]) {
  const { Paragraph, Table, TableCell, TableRow, TextRun, WidthType } = docx;
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({
        children: headers.map((header) => new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: header, bold: true })] })] })),
      }),
      ...rows.map((row) => new TableRow({
        children: row.map((cell) => new TableCell({ children: [new Paragraph(cell)] })),
      })),
    ],
  });
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function safeName(value: string): string {
  return value.replace(/[^a-z0-9._-]+/gi, '-').replace(/^-+|-+$/g, '') || 'incident';
}
