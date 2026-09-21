import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { isAggregatedFinding, ScanResult, VulnerabilitySeverity } from '../types';
import { REPORT_LOCALES, ReportLanguage } from './reportLocales';

const SEVERITY_COLORS: Record<VulnerabilitySeverity, [number, number, number]> = {
  critical: [225, 29, 72], // Rose/Crimson #E11D48
  high: [234, 88, 12],     // Orange #EA580C
  medium: [217, 119, 6],   // Amber #D97706
  low: [37, 99, 235],      // Blue #2563EB
  info: [71, 85, 105],     // Slate #475569
};

export function generatePdfReport(
  scan: ScanResult,
  language: ReportLanguage = 'en'
): void {
  const dict = REPORT_LOCALES[language] || REPORT_LOCALES.en;

  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 14;
  const contentWidth = pageWidth - margin * 2;
  let currentY = 18;

  // Top Primary Brand Accent Bar
  doc.setFillColor(37, 99, 235); // Blue-600
  doc.rect(0, 0, pageWidth, 3.5, 'F');

  // Header Banner Background
  doc.setFillColor(15, 23, 42); // Slate-900
  doc.rect(0, 3.5, pageWidth, 38.5, 'F');

  // Title
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(15);
  doc.text(dict.reportTitle, margin, 18);

  // Subtitle
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(148, 163, 184);
  doc.text(dict.reportSubtitle, margin, 25);

  // Metadata ribbon
  doc.setFontSize(8);
  doc.setTextColor(226, 232, 240);
  const localeDateCode = language === 'id' ? 'id-ID' : 'en-US';
  const scanDate = new Date(scan.startTime).toLocaleString(localeDateCode, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  });
  const durationSec = ((scan.durationMs || 1000) / 1000).toFixed(1);
  doc.text(
    `${dict.targetUrlLabel}: ${scan.targetUrl}    |    ${dict.dateLabel}: ${scanDate}    |    ${dict.durationLabel}: ${durationSec}s    |    ${dict.statusLabel}: ${scan.status.toUpperCase()}`,
    margin,
    34
  );

  currentY = 48;

  // Executive Summary Box
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  
  const critCount = scan.findings.filter(f => f.severity === 'critical').length;
  const highCount = scan.findings.filter(f => f.severity === 'high').length;
  const medCount = scan.findings.filter(f => f.severity === 'medium').length;
  const lowCount = scan.findings.filter(f => f.severity === 'low').length;
  const infoCount = scan.findings.filter(f => f.severity === 'info').length;
  const totalFindings = scan.findings.length;

  const summaryText = dict.executiveSummaryTemplate(
    scan.targetUrl,
    scan.templatesExecuted,
    totalFindings,
    durationSec
  );

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.2);
  const splitSummary = doc.splitTextToSize(summaryText, contentWidth - 8);
  const summaryBoxHeight = Math.max(splitSummary.length * 4.2 + 12, 26);

  doc.roundedRect(margin, currentY, contentWidth, summaryBoxHeight, 2, 2, 'FD');

  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.text(dict.executiveSummaryTitle, margin + 4, currentY + 6.5);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.2);
  doc.setTextColor(51, 65, 85);
  doc.text(splitSummary, margin + 4, currentY + 13);

  currentY += summaryBoxHeight + 8;

  // Severity Distribution Table
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.text(dict.severityBreakdownTitle, margin, currentY);
  currentY += 4;

  const severityTableData = [
    ['CRITICAL', `${critCount}`, 'CVSS 9.0 - 10.0', dict.severityDescriptions.critical],
    ['HIGH', `${highCount}`, 'CVSS 7.0 - 8.9', dict.severityDescriptions.high],
    ['MEDIUM', `${medCount}`, 'CVSS 4.0 - 6.9', dict.severityDescriptions.medium],
    ['LOW', `${lowCount}`, 'CVSS 0.1 - 3.9', dict.severityDescriptions.low],
    ['INFORMATIONAL', `${infoCount}`, 'CVSS 0.0', dict.severityDescriptions.info],
  ];

  autoTable(doc, {
    startY: currentY,
    head: [[
      dict.tableHeaders.severityLevel,
      dict.tableHeaders.count,
      dict.tableHeaders.cvssRange,
      dict.tableHeaders.descriptionImpact,
    ]],
    body: severityTableData,
    theme: 'grid',
    headStyles: {
      fillColor: [30, 41, 59],
      textColor: [255, 255, 255],
      fontSize: 8,
      fontStyle: 'bold',
      cellPadding: 2,
    },
    bodyStyles: {
      fontSize: 7.5,
      textColor: [30, 41, 59],
      cellPadding: 2,
    },
    columnStyles: {
      0: { fontStyle: 'bold', cellWidth: 32 },
      1: { halign: 'center', cellWidth: 16, fontStyle: 'bold' },
      2: { cellWidth: 28 },
      3: { cellWidth: 'auto' },
    },
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 0) {
        if (data.cell.raw === 'CRITICAL') {
          data.cell.styles.textColor = [225, 29, 72];
        } else if (data.cell.raw === 'HIGH') {
          data.cell.styles.textColor = [234, 88, 12];
        } else if (data.cell.raw === 'MEDIUM') {
          data.cell.styles.textColor = [217, 119, 6];
        } else if (data.cell.raw === 'LOW') {
          data.cell.styles.textColor = [37, 99, 235];
        } else {
          data.cell.styles.textColor = [71, 85, 105];
        }
      }
    },
    margin: { left: margin, right: margin },
  });

  // @ts-ignore
  currentY = doc.lastAutoTable.finalY + 10;

  // Detailed Findings Section
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.text(dict.detailedFindingsTitle, margin, currentY);
  currentY += 6;

  if (scan.findings.length === 0) {
    doc.setFillColor(240, 253, 244);
    doc.setDrawColor(187, 247, 208);
    doc.roundedRect(margin, currentY, contentWidth, 18, 2, 2, 'FD');
    doc.setTextColor(22, 101, 52);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.text(dict.noFindingsMessage, margin + 4, currentY + 11);
  } else {
    // Dynamic Layout Engine: Bounding Box Calculation per Finding
    scan.findings.forEach((finding, idx) => {
      const color = SEVERITY_COLORS[finding.severity] || [71, 85, 105];

      // 1. Description lines
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.8);
      const descLines = doc.splitTextToSize(finding.description || 'No description provided.', contentWidth - 12);
      const descH = Math.max(descLines.length * 3.6, 4);

      // 2. Contextual Notes (if elevated)
      let contextLines: string[] = [];
      let contextH = 0;
      if (finding.contextualNotes) {
        doc.setFont('helvetica', 'italic');
        doc.setFontSize(7.2);
        contextLines = doc.splitTextToSize(finding.contextualNotes, contentWidth - 16);
        contextH = Math.max(contextLines.length * 3.4 + 6, 8);
      }

      // 3. Evidence lines
      doc.setFont('courier', 'normal');
      doc.setFontSize(6.8);
      const rawEvidence = finding.evidence ? finding.evidence : 'Match rule condition satisfied';
      const evidenceLines = doc.splitTextToSize(rawEvidence, contentWidth - 16);
      const evidenceBoxH = Math.max(evidenceLines.length * 3.2 + 5, 8);

      // 4. Remediation lines
      doc.setFont('courier', 'normal');
      doc.setFontSize(6.6);
      const rawRem = finding.remediation || 'Apply standard security hardening practices.';
      const remLines = doc.splitTextToSize(rawRem, contentWidth - 16);
      const remBoxH = Math.max(remLines.length * 3.2 + 8, 12);

      // 5. Aggregated Sub-Checks (if present)
      let subChecksH = 0;
      if (isAggregatedFinding(finding)) {
        subChecksH = finding.subFindings.length * 4.2 + 6;
      }

      const headerH = 14;
      const cardPadding = 6;
      const totalCardHeight = headerH + descH + (contextH > 0 ? contextH + 2 : 0) + (subChecksH > 0 ? subChecksH + 2 : 0) + evidenceBoxH + remBoxH + cardPadding;

      // Check remaining page vertical space; add page proactively before starting block
      if (currentY + totalCardHeight > pageHeight - 16) {
        doc.addPage();
        currentY = 16;
      }

      const cardStartY = currentY;

      // Card container background
      doc.setFillColor(255, 255, 255);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, cardStartY, contentWidth, totalCardHeight, 2, 2, 'FD');

      // Left severity accent bar
      doc.setFillColor(color[0], color[1], color[2]);
      doc.rect(margin, cardStartY, 3, totalCardHeight, 'F');

      // Title & Finding Number
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.setTextColor(15, 23, 42);
      const typeBadge = finding.findingType === 'aggregated' ? '[Aggregated Audit]' : '[Atomic Vulnerability]';
      doc.text(`${idx + 1}. ${finding.name} ${typeBadge}`, margin + 6, cardStartY + 6);

      // Severity Badge Pill
      doc.setFillColor(color[0], color[1], color[2]);
      doc.roundedRect(pageWidth - margin - 26, cardStartY + 2.5, 24, 5.2, 1.2, 1.2, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(6.5);
      doc.setFont('helvetica', 'bold');
      doc.text(finding.severity.toUpperCase(), pageWidth - margin - 23.5, cardStartY + 6.1);

      // Metadata line (CWE, OWASP, CVSS v3.1, CVSS Vector)
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.8);
      doc.setTextColor(100, 116, 139);
      const vectorText = finding.cvssVector ? `  |  Vector: ${finding.cvssVector}` : '';
      doc.text(
        `${dict.cweLabel}: ${finding.cweId || 'N/A'}  |  ${dict.categoryLabel}: ${finding.owaspCategory || 'General'}  |  CVSS: ${finding.cvssScore?.toFixed(1) || 'N/A'}${vectorText}`,
        margin + 6,
        cardStartY + 11.2
      );

      // Description text
      let innerY = cardStartY + 15.5;
      doc.setTextColor(51, 65, 85);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.6);
      doc.text(descLines, margin + 6, innerY);
      innerY += descH + 2;

      // Contextual Notes Box (if elevated)
      if (contextH > 0 && contextLines.length > 0) {
        doc.setFillColor(254, 243, 199); // Amber-100
        doc.setDrawColor(251, 191, 36);
        doc.roundedRect(margin + 6, innerY, contentWidth - 12, contextH, 1, 1, 'FD');
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(6.8);
        doc.setTextColor(180, 83, 9); // Amber-800
        doc.text(dict.contextualImpactLabel + ':', margin + 8, innerY + 3.8);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(6.6);
        doc.setTextColor(120, 53, 15);
        doc.text(contextLines, margin + 8, innerY + 7.2);
        innerY += contextH + 2.5;
      }

      // Aggregated Sub-Checks Summary
      if (isAggregatedFinding(finding)) {
        doc.setFillColor(241, 245, 249);
        doc.setDrawColor(203, 213, 225);
        doc.roundedRect(margin + 6, innerY, contentWidth - 12, subChecksH, 1, 1, 'FD');
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(6.8);
        doc.setTextColor(30, 41, 59);
        doc.text(`${dict.aggregatedSubChecksLabel} (${finding.subFindings.length}):`, margin + 8, innerY + 4);
        
        let subY = innerY + 7.5;
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(6.5);
        doc.setTextColor(71, 85, 105);
        finding.subFindings.forEach(sub => {
          doc.text(`• ${sub.name} — ${sub.evidence}`, margin + 10, subY);
          subY += 3.8;
        });
        innerY += subChecksH + 2.5;
      }

      // Evidence Box
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin + 6, innerY, contentWidth - 12, evidenceBoxH, 1, 1, 'FD');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.6);
      doc.setTextColor(71, 85, 105);
      doc.text(`${dict.evidenceLabel} (${finding.matchedAt}):`, margin + 8, innerY + 3.8);

      doc.setFont('courier', 'normal');
      doc.setFontSize(6.4);
      doc.setTextColor(30, 41, 59);
      doc.text(evidenceLines, margin + 8, innerY + 7.5);
      innerY += evidenceBoxH + 3;

      // Technical Remediation Box
      doc.setFillColor(240, 253, 250); // Teal-50
      doc.setDrawColor(204, 251, 241);
      doc.roundedRect(margin + 6, innerY, contentWidth - 12, remBoxH, 1, 1, 'FD');
      
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.8);
      doc.setTextColor(15, 118, 110); // Teal-700
      doc.text(dict.remediationLabel + ':', margin + 8, innerY + 4);

      doc.setFont('courier', 'normal');
      doc.setFontSize(6.4);
      doc.setTextColor(15, 23, 42);
      doc.text(remLines, margin + 8, innerY + 7.8);

      currentY += totalCardHeight + 5;
    });
  }

  // Footer on all pages
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.2);
    doc.setTextColor(148, 163, 184);

    // Divider line
    doc.setDrawColor(226, 232, 240);
    doc.line(margin, pageHeight - 10, pageWidth - margin, pageHeight - 10);

    doc.text(
      dict.footerConfidential,
      margin,
      pageHeight - 5.5
    );
    doc.text(dict.pageOf(i, totalPages), pageWidth - margin - 20, pageHeight - 5.5);
  }

  // Trigger download
  const cleanTarget = scan.targetUrl.replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '_');
  const filename = `Security_Audit_Report_${cleanTarget}_${Date.now()}.pdf`;
  doc.save(filename);
}
