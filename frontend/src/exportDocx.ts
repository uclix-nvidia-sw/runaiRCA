import { unified } from 'unified';
import remarkParse from 'remark-parse';
import remarkGfm from 'remark-gfm';
import { AlertRecord, Artifact, IncidentDetail, SimilarIncident } from './types';
import { stripAppendixEvidence } from './utils/rcaSections';

type MdNode = {
  type: string;
  value?: string;
  depth?: number;
  ordered?: boolean;
  start?: number;
  checked?: boolean;
  lang?: string;
  url?: string;
  title?: string;
  children?: MdNode[];
};

export type MarkdownBlock =
  | { kind: 'heading'; level: number; children: MdNode[] }
  | { kind: 'paragraph'; children: MdNode[] }
  | { kind: 'list'; ordered: boolean; start?: number; children: MdNode[] }
  | { kind: 'code'; text: string; language?: string }
  | { kind: 'blockquote'; children: MdNode[] }
  | { kind: 'table'; rows: MdNode[] }
  | { kind: 'thematicBreak' };

type DocxModule = typeof import('docx');
type DocxBlockElement = import('docx').Paragraph | import('docx').Table;
type InlineElement = import('docx').TextRun | import('docx').ExternalHyperlink;

const TABLE_WIDTH = 9360;
const BODY_FONT = { ascii: 'Calibri', hAnsi: 'Calibri', eastAsia: 'Malgun Gothic' };
const MONO_FONT = { ascii: 'Consolas', hAnsi: 'Consolas', eastAsia: 'Malgun Gothic' };
const TABLE_HEADER_FILL = 'F2F4F7';
const INLINE_CODE_FILL = 'F2F4F7';
const TABLE_BORDER = { style: 'single' as const, size: 4, color: 'D0D5DD', space: 0 };

export function markdownToBlocks(markdown: string): MarkdownBlock[] {
  const tree = unified().use(remarkParse).use(remarkGfm).parse(markdown || '') as MdNode;
  return (tree.children ?? []).map(toMarkdownBlock).filter((block): block is MarkdownBlock => Boolean(block));
}

export function markdownToDocxElements(docx: DocxModule, markdown: string): DocxBlockElement[] {
  const listInstance = { value: 0 };
  return markdownToBlocks(markdown).flatMap((block) => renderBlock(docx, block, 0, false, listInstance));
}

export async function exportIncidentDocx(incident: IncidentDetail): Promise<void> {
  const docx = await import('docx');
  const {
    AlignmentType,
    Document,
    Footer,
    HeadingLevel,
    LevelFormat,
    PageNumber,
    Packer,
    Paragraph,
    TextRun,
  } = docx;
  const children: DocxBlockElement[] = [
    new Paragraph({ text: incident.title || incident.incident_id, heading: HeadingLevel.TITLE }),
    keyValueTable(docx, metaRows(incident)),
    new Paragraph({ text: 'Summary', heading: HeadingLevel.HEADING_1 }),
    new Paragraph({ text: incident.analysis_summary || 'No summary captured.' }),
    new Paragraph({ text: 'Report', heading: HeadingLevel.HEADING_1 }),
    ...markdownToDocxElements(docx, stripAppendixEvidence(incident.analysis_detail || '')),
    new Paragraph({ text: 'Evidence', heading: HeadingLevel.HEADING_1 }),
    artifactTable(docx, incident.artifacts),
    new Paragraph({ text: 'Alerts', heading: HeadingLevel.HEADING_1 }),
    alertTable(docx, incident.alerts),
    new Paragraph({ text: 'Similar Incidents', heading: HeadingLevel.HEADING_1 }),
    similarTable(docx, incident.similar_incidents),
  ];
  const footer = new Footer({
    children: [new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [
        new TextRun({ text: `${incident.incident_id}  |  `, font: BODY_FONT, size: 18, color: '667085' }),
        new TextRun({ children: [PageNumber.CURRENT], font: BODY_FONT, size: 18, color: '667085' }),
        new TextRun({ text: ' / ', font: BODY_FONT, size: 18, color: '667085' }),
        new TextRun({ children: [PageNumber.TOTAL_PAGES], font: BODY_FONT, size: 18, color: '667085' }),
      ],
    })],
  });
  const blob = await Packer.toBlob(new Document({
    title: incident.title || incident.incident_id,
    styles: documentStyles(),
    numbering: {
      config: [
        listNumbering(docx, 'bullet-list', LevelFormat.BULLET),
        listNumbering(docx, 'ordered-list', LevelFormat.DECIMAL),
      ],
    },
    sections: [{
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1440, right: 1440, bottom: 1440, left: 1440, header: 708, footer: 708 },
        },
      },
      footers: { default: footer },
      children,
    }],
  }));
  downloadBlob(blob, `${safeName(incident.incident_id)}-rca.docx`);

  function keyValueTable(module: DocxModule, rows: [string, string][]) {
    return simpleTable(module, ['Field', 'Value'], rows, [2700, 6660]);
  }
}

function toMarkdownBlock(node: MdNode): MarkdownBlock | null {
  if (node.type === 'heading') return { kind: 'heading', level: node.depth ?? 2, children: node.children ?? [] };
  if (node.type === 'paragraph') return { kind: 'paragraph', children: node.children ?? [] };
  if (node.type === 'code') return { kind: 'code', text: node.value ?? '', language: node.lang };
  if (node.type === 'list') return { kind: 'list', ordered: Boolean(node.ordered), start: node.start, children: node.children ?? [] };
  if (node.type === 'blockquote') return { kind: 'blockquote', children: node.children ?? [] };
  if (node.type === 'table') return { kind: 'table', rows: node.children ?? [] };
  if (node.type === 'thematicBreak') return { kind: 'thematicBreak' };
  return null;
}

function renderBlock(
  docx: DocxModule,
  block: MarkdownBlock,
  listLevel: number,
  quote: boolean,
  listInstance: { value: number },
): DocxBlockElement[] {
  const { HeadingLevel, Paragraph } = docx;
  if (block.kind === 'heading') {
    const heading = block.level <= 1 ? HeadingLevel.HEADING_2 : block.level === 2 ? HeadingLevel.HEADING_2 : HeadingLevel.HEADING_3;
    return [new Paragraph({ heading, children: inlineRuns(docx, block.children, { italics: quote }) })];
  }
  if (block.kind === 'paragraph') {
    return [new Paragraph({
      children: inlineRuns(docx, block.children, { italics: quote }),
      border: quote ? { left: { style: 'single', size: 18, color: 'B8C2CC', space: 8 } } : undefined,
      indent: quote ? { left: 360, right: 120 } : undefined,
    })];
  }
  if (block.kind === 'code') return [codeParagraph(docx, block.text)];
  if (block.kind === 'thematicBreak') {
    return [new Paragraph({ border: { bottom: { style: 'single', size: 6, color: 'D0D5DD', space: 1 } }, spacing: { before: 120, after: 120 } })];
  }
  if (block.kind === 'table') return [markdownTable(docx, block.rows)];
  if (block.kind === 'blockquote') {
    return block.children.flatMap((child) => {
      const nested = toMarkdownBlock(child);
      return nested ? renderBlock(docx, nested, listLevel, true, listInstance) : [];
    });
  }
  return renderList(docx, block, listLevel, listInstance);
}

function renderList(
  docx: DocxModule,
  block: Extract<MarkdownBlock, { kind: 'list' }>,
  listLevel: number,
  listInstance: { value: number },
): DocxBlockElement[] {
  const { Paragraph } = docx;
  const reference = block.ordered ? 'ordered-list' : 'bullet-list';
  const instance = ++listInstance.value;
  const level = Math.min(listLevel, 4);
  return block.children.flatMap((item) => {
    const result: DocxBlockElement[] = [];
    const itemChildren = item.children ?? [];
    let paragraphRendered = false;
    for (const child of itemChildren) {
      if (child.type === 'paragraph') {
        const paragraphChildren = item.checked !== undefined && !paragraphRendered
          ? [{ type: 'text', value: item.checked ? '[x] ' : '[ ] ' } as MdNode, ...(child.children ?? [])]
          : child.children ?? [];
        result.push(new Paragraph({
          style: 'ListParagraph',
          children: inlineRuns(docx, paragraphChildren),
          numbering: { reference, level, instance },
        }));
        paragraphRendered = true;
      } else if (child.type === 'list') {
        const nested = toMarkdownBlock(child);
        if (nested?.kind === 'list') result.push(...renderList(docx, nested, level + 1, listInstance));
      } else {
        const nested = toMarkdownBlock(child);
        if (nested) result.push(...renderBlock(docx, nested, level, false, listInstance));
      }
    }
    if (!paragraphRendered) result.push(new Paragraph({ style: 'ListParagraph', numbering: { reference, level, instance }, text: '' }));
    return result;
  });
}

function inlineRuns(docx: DocxModule, nodes: MdNode[], style: { bold?: boolean; italics?: boolean; strike?: boolean; link?: boolean } = {}): InlineElement[] {
  const { ExternalHyperlink, TextRun, UnderlineType } = docx;
  return nodes.flatMap((node) => {
    if (node.type === 'text') {
      return [new TextRun({
        text: node.value ?? '',
        bold: style.bold,
        italics: style.italics,
        strike: style.strike,
        color: style.link ? '0563C1' : undefined,
        underline: style.link ? { type: UnderlineType.SINGLE, color: '0563C1' } : undefined,
        font: BODY_FONT,
      })];
    }
    if (node.type === 'inlineCode') {
      return [new TextRun({
        text: node.value ?? '',
        bold: style.bold,
        italics: style.italics,
        font: MONO_FONT,
        shading: { type: 'clear', fill: INLINE_CODE_FILL },
      })];
    }
    if (node.type === 'strong') return inlineRuns(docx, node.children ?? [], { ...style, bold: true });
    if (node.type === 'emphasis') return inlineRuns(docx, node.children ?? [], { ...style, italics: true });
    if (node.type === 'delete') return inlineRuns(docx, node.children ?? [], { ...style, strike: true });
    if (node.type === 'link' && node.url) {
      return [new ExternalHyperlink({ link: node.url, children: inlineRuns(docx, node.children ?? [], { ...style, link: true }) })];
    }
    if (node.type === 'break') return [new TextRun({ break: 1 })];
    return node.children ? inlineRuns(docx, node.children, style) : [];
  });
}

function codeParagraph(docx: DocxModule, value: string): import('docx').Paragraph {
  const { Paragraph, TextRun } = docx;
  const lines = value.split('\n');
  const children = lines.flatMap((line, index) => [
    new TextRun({ text: line, font: MONO_FONT, size: 20 }),
    ...(index < lines.length - 1 ? [new TextRun({ break: 1, font: MONO_FONT, size: 20 })] : []),
  ]);
  return new Paragraph({
    children,
    shading: { type: 'clear', fill: 'F8FAFC' },
    border: {
      top: { style: 'single', size: 4, color: 'D0D5DD', space: 4 },
      bottom: { style: 'single', size: 4, color: 'D0D5DD', space: 4 },
      left: { style: 'single', size: 4, color: 'D0D5DD', space: 4 },
      right: { style: 'single', size: 4, color: 'D0D5DD', space: 4 },
    },
    indent: { left: 120, right: 120 },
    spacing: { before: 80, after: 120, line: 240 },
    wordWrap: true,
  });
}

function markdownTable(docx: DocxModule, rows: MdNode[]): import('docx').Table {
  const matrix = rows.map((row) => row.children ?? []);
  const columnCount = Math.max(1, ...matrix.map((row) => row.length));
  const widths = tableColumnWidths(matrix.map((row) => row.map(nodeText)), columnCount);
  return new docx.Table({
    width: { size: TABLE_WIDTH, type: docx.WidthType.DXA },
    columnWidths: widths,
    layout: docx.TableLayoutType.FIXED,
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    borders: tableBorders(docx),
    tableLook: { firstRow: true, noHBand: true, noVBand: true },
    rows: matrix.map((row, rowIndex) => new docx.TableRow({
      tableHeader: rowIndex === 0,
      children: Array.from({ length: columnCount }, (_, index) => tableCell(docx, row[index], widths[index], rowIndex === 0)),
    })),
  });
}

function tableCell(docx: DocxModule, cell: MdNode | undefined, width: number, header: boolean): import('docx').TableCell {
  return new docx.TableCell({
    width: { size: width, type: docx.WidthType.DXA },
    verticalAlign: docx.VerticalAlignTable.CENTER,
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    shading: header ? { type: docx.ShadingType.CLEAR, fill: TABLE_HEADER_FILL } : undefined,
    children: [new docx.Paragraph({
      children: inlineRuns(docx, cell?.children ?? [], { bold: header }),
      spacing: { after: 0, line: 260 },
      wordWrap: true,
      autoSpaceEastAsianText: true,
      run: header ? { bold: true, font: BODY_FONT } : undefined,
    })],
  });
}

function nodeText(node: MdNode): string {
  if (node.type === 'break') return '\n';
  if (typeof node.value === 'string') return node.value;
  return (node.children ?? []).map(nodeText).join('');
}

function tableColumnWidths(rows: string[][], count: number): number[] {
  const weights = Array.from({ length: count }, (_, index) => Math.max(1, ...rows.map((row) => Math.min(48, (row[index] ?? '').length))));
  const total = weights.reduce((sum, weight) => sum + weight, 0);
  const widths = weights.map((weight) => Math.max(900, Math.floor(TABLE_WIDTH * weight / total)));
  widths[widths.length - 1] += TABLE_WIDTH - widths.reduce((sum, width) => sum + width, 0);
  return widths;
}

function documentStyles() {
  return {
    default: {
      document: {
        run: { font: BODY_FONT, size: 22 },
        paragraph: { spacing: { after: 120, line: 280 }, autoSpaceEastAsianText: true },
      },
      title: { run: { font: BODY_FONT, size: 36, bold: true, color: '0B2545' }, paragraph: { spacing: { after: 240 } } },
      heading1: { run: { font: BODY_FONT, size: 32, bold: true, color: '2E74B5' }, paragraph: { spacing: { before: 320, after: 160, line: 280 }, keepNext: true } },
      heading2: { run: { font: BODY_FONT, size: 26, bold: true, color: '2E74B5' }, paragraph: { spacing: { before: 240, after: 120, line: 280 }, keepNext: true } },
      heading3: { run: { font: BODY_FONT, size: 24, bold: true, color: '1F4D78' }, paragraph: { spacing: { before: 160, after: 80, line: 280 }, keepNext: true } },
      listParagraph: { run: { font: BODY_FONT, size: 22 }, paragraph: { spacing: { after: 80, line: 280 } } },
    },
    paragraphStyles: [{ id: 'CodeBlock', name: 'Code Block', basedOn: 'Normal', run: { font: MONO_FONT, size: 20 }, paragraph: { spacing: { before: 80, after: 120, line: 240 } } }],
  };
}

function listNumbering(docx: DocxModule, reference: string, format: (typeof docx.LevelFormat)[keyof typeof docx.LevelFormat]) {
  const bullets = ['•', '◦', '▪', '–', '•'];
  return {
    reference,
    levels: Array.from({ length: 5 }, (_, level) => ({
      level,
      format,
      text: format === docx.LevelFormat.BULLET ? bullets[level] : `%${level + 1}.`,
      alignment: docx.AlignmentType.LEFT,
      style: {
        paragraph: {
          indent: { left: 720 + level * 360, hanging: 360 },
          spacing: { after: 80, line: 280 },
        },
        run: { font: BODY_FONT, size: 22 },
      },
    })),
  };
}

function tableBorders(docx: DocxModule) {
  return {
    top: TABLE_BORDER,
    bottom: TABLE_BORDER,
    left: TABLE_BORDER,
    right: TABLE_BORDER,
    insideHorizontal: TABLE_BORDER,
    insideVertical: TABLE_BORDER,
  } as ConstructorParameters<typeof docx.Table>[0]['borders'];
}

function metaRows(incident: IncidentDetail): [string, string][] {
  const rows: [string, string][] = [
    ['Incident ID', incident.incident_id],
    ['Severity', incident.severity],
    ['Incident status', incident.status],
  ];
  if (incident.root_cause_family) rows.push(['Root-cause family', incident.root_cause_family]);
  const confidence = diagnosticConfidence(incident.confidence_diagnostics);
  if (confidence) rows.push(['Confidence', confidence]);
  rows.push(
    ['Analysis quality', incident.analysis_quality],
    ['Fired', incident.fired_at],
    ['Alertmanager resolved', incident.resolved_at || '-'],
    ['User approved', incident.user_approved_at || '-'],
  );
  return rows;
}

function diagnosticConfidence(diagnostics?: Record<string, unknown>): string | undefined {
  if (!diagnostics) return undefined;
  for (const candidate of [diagnostics.final_candidate, diagnostics.ranking_candidate]) {
    if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
      const value = (candidate as Record<string, unknown>).confidence;
      if (typeof value === 'string' || typeof value === 'number') return String(value);
    }
  }
  return undefined;
}

function artifactTable(docx: DocxModule, artifacts: Artifact[]) {
  const rows = artifacts.length
    ? artifacts.map((item) => [item.agent, item.status, item.summary || item.type])
    : [['-', '-', 'No evidence cards captured.']];
  return simpleTable(docx, ['Agent', 'Status', 'Summary'], rows, [1500, 1500, 6360]);
}

function alertTable(docx: DocxModule, alerts: AlertRecord[]) {
  const rows = alerts.length
    ? alerts.map((item) => [item.alert_id, item.status, item.alarm_title])
    : [['-', '-', 'No alerts captured.']];
  return simpleTable(docx, ['Alert', 'Status', 'Title'], rows, [2400, 1500, 5460]);
}

function similarTable(docx: DocxModule, items: SimilarIncident[]) {
  const rows = items.length
    ? items.map((item) => [item.incident_id, `${Math.round(item.similarity * 100)}%`, item.analysis_summary || item.title])
    : [['-', '-', 'No similar incidents captured.']];
  return simpleTable(docx, ['Incident', 'Similarity', 'Summary'], rows, [2000, 1200, 6160]);
}

function simpleTable(docx: DocxModule, headers: string[], rows: string[][], columnWidths: number[]) {
  const { Paragraph, Table, TableCell, TableLayoutType, TableRow, TextRun, WidthType } = docx;
  return new Table({
    width: { size: TABLE_WIDTH, type: WidthType.DXA },
    columnWidths,
    layout: TableLayoutType.FIXED,
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    borders: tableBorders(docx),
    tableLook: { firstRow: true, noHBand: true, noVBand: true },
    rows: [
      new TableRow({
        tableHeader: true,
        children: headers.map((header, index) => new TableCell({
          width: { size: columnWidths[index], type: WidthType.DXA },
          shading: { type: 'clear', fill: TABLE_HEADER_FILL },
          verticalAlign: docx.VerticalAlignTable.CENTER,
          margins: { top: 80, bottom: 80, left: 120, right: 120 },
          children: [new Paragraph({ children: [new TextRun({ text: header, bold: true, font: BODY_FONT })], spacing: { after: 0, line: 260 } })],
        })),
      }),
      ...rows.map((row) => new TableRow({
        children: row.map((cell, index) => new TableCell({
          width: { size: columnWidths[index], type: WidthType.DXA },
          verticalAlign: docx.VerticalAlignTable.CENTER,
          margins: { top: 80, bottom: 80, left: 120, right: 120 },
          children: [new Paragraph({ text: cell || '-', spacing: { after: 0, line: 260 }, wordWrap: true, autoSpaceEastAsianText: true })],
        })),
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
