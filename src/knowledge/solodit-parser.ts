/**
 * Solodit report parser — extracts individual findings from audit report
 * markdown files in the solodit/solodit_content repository.
 *
 * Structure: Each .md file is a full audit report. Findings are organized as:
 * - H2 headers for severity sections (## High, ## Medium, etc.)
 * - H3 headers for individual findings
 */

export interface RawFinding {
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  impact: string;
  codeSnippets: string[];
  remediation: string;
  auditor: string;
  protocol: string;
  date: string;
  sourceFile: string;
}

interface ReportMetadata {
  auditor: string;
  protocol: string;
  date: string;
}

/**
 * Parse a single solodit report markdown file into individual findings.
 */
export function parseReportFile(filePath: string, content: string): RawFinding[] {
  const metadata = parseFilenameMetadata(filePath);
  const findings: RawFinding[] = [];

  // Split into severity sections by H2 headers
  const sections = splitBySeverity(content);

  for (const section of sections) {
    const sectionFindings = parseSeveritySection(section.severity, section.content, metadata, filePath);
    findings.push(...sectionFindings);
  }

  return findings;
}

interface SeveritySection {
  severity: RawFinding['severity'];
  content: string;
}

function splitBySeverity(content: string): SeveritySection[] {
  const sections: SeveritySection[] = [];
  const severityMap: Record<string, RawFinding['severity']> = {
    'critical': 'critical',
    'high': 'high',
    'medium': 'medium',
    'low': 'low',
    'informational': 'info',
    'info': 'info',
    'gas': 'info',
  };

  // Match ## High, ## Medium, etc.
  const h2Regex = /^##\s+(.+)$/gm;
  const matches: Array<{ index: number; severity: RawFinding['severity'] | null; heading: string }> = [];

  let match;
  while ((match = h2Regex.exec(content)) !== null) {
    const heading = match[1].trim().toLowerCase();
    let severity: RawFinding['severity'] | null = null;

    for (const [key, val] of Object.entries(severityMap)) {
      if (heading.includes(key)) {
        severity = val;
        break;
      }
    }

    matches.push({ index: match.index, severity, heading });
  }

  for (let i = 0; i < matches.length; i++) {
    if (!matches[i].severity) continue;

    const start = matches[i].index;
    const end = i + 1 < matches.length ? matches[i + 1].index : content.length;
    const sectionContent = content.slice(start, end);

    sections.push({
      severity: matches[i].severity!,
      content: sectionContent,
    });
  }

  return sections;
}

function parseSeveritySection(
  severity: RawFinding['severity'],
  sectionContent: string,
  metadata: ReportMetadata,
  sourceFile: string
): RawFinding[] {
  const findings: RawFinding[] = [];

  // Split by H3 headers (individual findings)
  const h3Regex = /^###\s+(.+)$/gm;
  const h3Matches: Array<{ index: number; title: string }> = [];

  let match;
  while ((match = h3Regex.exec(sectionContent)) !== null) {
    h3Matches.push({ index: match.index, title: match[1].trim() });
  }

  for (let i = 0; i < h3Matches.length; i++) {
    const start = h3Matches[i].index;
    const end = i + 1 < h3Matches.length ? h3Matches[i + 1].index : sectionContent.length;
    const findingContent = sectionContent.slice(start, end);

    const finding = parseSingleFinding(
      h3Matches[i].title,
      severity,
      findingContent,
      metadata,
      sourceFile
    );
    if (finding) {
      findings.push(finding);
    }
  }

  return findings;
}

function parseSingleFinding(
  title: string,
  severity: RawFinding['severity'],
  content: string,
  metadata: ReportMetadata,
  sourceFile: string
): RawFinding | null {
  // Skip very short findings (likely just a heading with no content)
  if (content.length < 50) return null;

  // Extract code snippets (```...```)
  const codeSnippets: string[] = [];
  const codeRegex = /```[\s\S]*?```/g;
  let codeMatch;
  while ((codeMatch = codeRegex.exec(content)) !== null) {
    const snippet = codeMatch[0].replace(/^```\w*\n?/, '').replace(/\n?```$/, '').trim();
    if (snippet.length > 10 && snippet.length < 2000) {
      codeSnippets.push(snippet);
    }
  }

  // Extract description — text between title and first sub-section
  const afterTitle = content.replace(/^###\s+.+\n/, '').trim();

  // Try to find labeled sections
  const impactMatch = afterTitle.match(/\*?\*?(?:Impact|Vulnerability Detail|Description)\*?\*?[:\s]*\n([\s\S]*?)(?=\*?\*?(?:Recommendation|Remediation|Fix|Proof|Mitigation|Impact)\*?\*?|\n#{2,}|$)/i);
  const remediationMatch = afterTitle.match(/\*?\*?(?:Recommendation|Remediation|Fix|Mitigation)\*?\*?[:\s]*\n([\s\S]*?)(?=\n#{2,}|$)/i);

  const description = impactMatch
    ? impactMatch[1].trim().slice(0, 1500)
    : afterTitle.replace(/```[\s\S]*?```/g, '[code]').slice(0, 1500);

  const impact = extractImpact(afterTitle);
  const remediation = remediationMatch
    ? remediationMatch[1].trim().slice(0, 500)
    : '';

  return {
    title: cleanTitle(title),
    severity,
    description,
    impact,
    codeSnippets: codeSnippets.slice(0, 3), // Max 3 snippets
    remediation,
    auditor: metadata.auditor,
    protocol: metadata.protocol,
    date: metadata.date,
    sourceFile,
  };
}

function extractImpact(content: string): string {
  const impactMatch = content.match(/\*?\*?Impact\*?\*?[:\s]*\n([\s\S]*?)(?=\*?\*?(?:Recommendation|Remediation|Fix|Proof|Mitigation)\*?\*?|\n#{2,}|$)/i);
  if (impactMatch) return impactMatch[1].trim().slice(0, 500);
  return '';
}

function cleanTitle(title: string): string {
  // Remove common prefixes like [H-01], [M-1], etc.
  return title
    .replace(/^\[?[HMLIChmlicGg]-?\d+\]?\s*[-–—:.]?\s*/, '')
    .replace(/^\d+\.\s*/, '')
    .trim();
}

/**
 * Parse filename to extract auditor, protocol, and date.
 * Solodit filenames follow patterns like:
 *   reports/Trail_of_Bits/2023-03-15-Protocol.md
 *   reports/OpenZeppelin/2024-01-MyProtocol.md
 */
function parseFilenameMetadata(filePath: string): ReportMetadata {
  const parts = filePath.replace(/\\/g, '/').split('/');

  let auditor = 'unknown';
  let protocol = 'unknown';
  let date = '';

  // Look for the reports/ directory in the path
  const reportsIdx = parts.findIndex(p => p === 'reports');
  if (reportsIdx >= 0 && reportsIdx + 1 < parts.length) {
    auditor = parts[reportsIdx + 1].replace(/_/g, ' ');
  }

  // The filename often contains date and protocol
  const filename = parts[parts.length - 1].replace('.md', '');

  // Try to extract date (YYYY-MM-DD or YYYY-MM format)
  const dateMatch = filename.match(/(\d{4}[-_]\d{2}(?:[-_]\d{2})?)/);
  if (dateMatch) {
    date = dateMatch[1].replace(/_/g, '-');
  }

  // Protocol name: everything after the date, or the whole filename
  if (dateMatch) {
    protocol = filename.slice(dateMatch.index! + dateMatch[0].length).replace(/^[-_]+/, '').replace(/[-_]/g, ' ').trim();
  }
  if (!protocol || protocol === 'unknown') {
    protocol = filename.replace(/[-_]/g, ' ').trim();
  }

  return { auditor, protocol, date };
}
