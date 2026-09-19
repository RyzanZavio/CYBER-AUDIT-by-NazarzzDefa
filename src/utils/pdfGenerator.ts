import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { ScanResult, VulnerabilityFinding, VulnerabilitySeverity } from '../types';

const SEVERITY_COLORS: Record<VulnerabilitySeverity, [number, number, number]> = {
  critical: [225, 29, 72], // Rose/Crimson #E11D48
  high: [234, 88, 12],     // Orange #EA580C
  medium: [217, 119, 6],   // Amber #D97706
  low: [37, 99, 235],      // Blue #2563EB
  info: [71, 85, 105],     // Slate #475569
};

export function generatePdfReport(scan: ScanResult, companyName = 'Security Operations Team'): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  let currentY = 18;

  // Header Banner Background
  doc.setFillColor(15, 23, 42); // Slate-900
  doc.rect(0, 0, pageWidth, 42, 'F');

  // Accent Top Bar
  doc.setFillColor(59, 130, 246); // Blue-500
  doc.rect(0, 0, pageWidth, 3, 'F');

  // Title
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.text('CYBERSECURITY VULNERABILITY AUDIT REPORT', 14, 18);

  // Subtitle
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(148, 163, 184); // Slate-400
  doc.text('Automated Penetration & Security Assessment Engine (OWASP · Nuclei · Burp Suite Pro Rules)', 14, 25);

  // Metadata ribbon
  doc.setFontSize(8.5);
  doc.setTextColor(226, 232, 240);
  const scanDate = new Date(scan.startTime).toLocaleString('id-ID', {
    dateStyle: 'medium',
    timeStyle: 'short',
  });
  doc.text(`Target: ${scan.targetUrl}    |    Date: ${scanDate}    |    Status: ${scan.status.toUpperCase()}`, 14, 34);

  currentY = 50;

  // Executive Summary Box
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(14, currentY, pageWidth - 28, 30, 2, 2, 'FD');

  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.text('EXECUTIVE AUDIT SUMMARY', 18, currentY + 7);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(51, 65, 85);

  const critCount = scan.findings.filter(f => f.severity === 'critical').length;
  const highCount = scan.findings.filter(f => f.severity === 'high').length;
  const medCount = scan.findings.filter(f => f.severity === 'medium').length;
  const lowCount = scan.findings.filter(f => f.severity === 'low').length;
  const infoCount = scan.findings.filter(f => f.severity === 'info').length;
  const totalFindings = scan.findings.length;

  const summaryText = `This security assessment was conducted against ${scan.targetUrl} using automated vulnerability scanning heuristics inspired by OWASP Testing Guide, Project Discovery Nuclei YAML rules, and Burp Suite audit profiles. A total of ${scan.templatesExecuted} audit templates were evaluated, resulting in ${totalFindings} finding(s) identified. Immediate remediation is strongly recommended for Critical and High severity issues before production deployment.`;

  const splitSummary = doc.splitTextToSize(summaryText, pageWidth - 36);
  doc.text(splitSummary, 18, currentY + 14);

  currentY += 38;

  // Severity Distribution Table
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.text('VULNERABILITY SEVERITY BREAKDOWN', 14, currentY);
  currentY += 4;

  const severityTableData = [
    ['CRITICAL', `${critCount}`, 'CVSS 9.0 - 10.0', 'Immediate RCE, Secret Exposure, or Full Takeover Risk'],
    ['HIGH', `${highCount}`, 'CVSS 7.0 - 8.9', 'Significant Privilege Escalation, SQLi, or Severe Misconfiguration'],
    ['MEDIUM', `${medCount}`, 'CVSS 4.0 - 6.9', 'Missing Defense-in-Depth Headers, Insecure Cookies, or CORS Flaws'],
    ['LOW', `${lowCount}`, 'CVSS 0.1 - 3.9', 'Information Leakage, Detailed Version Fingerprinting'],
    ['INFORMATIONAL', `${infoCount}`, 'CVSS 0.0', 'Reconnaissance, robots.txt endpoints, safe disclosures'],
  ];

  autoTable(doc, {
    startY: currentY,
    head: [['Severity Level', 'Count', 'CVSS Range', 'Description & Risk Impact']],
    body: severityTableData,
    theme: 'grid',
    headStyles: {
      fillColor: [30, 41, 59],
      textColor: [255, 255, 255],
      fontSize: 8.5,
      fontStyle: 'bold',
    },
    bodyStyles: {
      fontSize: 8,
      textColor: [30, 41, 59],
    },
    columnStyles: {
      0: { fontStyle: 'bold', cellWidth: 32 },
      1: { halign: 'center', cellWidth: 18, fontStyle: 'bold' },
      2: { cellWidth: 30 },
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
    margin: { left: 14, right: 14 },
  });

  // @ts-ignore
  currentY = doc.lastAutoTable.finalY + 12;

  // Detailed Findings Section
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.text('DETAILED AUDIT FINDINGS & REMEDIATION', 14, currentY);
  currentY += 6;

  if (scan.findings.length === 0) {
    doc.setFillColor(240, 253, 244);
    doc.setDrawColor(187, 247, 208);
    doc.roundedRect(14, currentY, pageWidth - 28, 20, 2, 2, 'FD');
    doc.setTextColor(22, 101, 52);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.text('No security vulnerabilities were identified with the active audit templates.', 18, currentY + 12);
  } else {
    // Render each finding
    scan.findings.forEach((finding, idx) => {
      // Check if we need a new page
      if (currentY > pageHeight - 65) {
        doc.addPage();
        currentY = 20;
      }

      const color = SEVERITY_COLORS[finding.severity] || [71, 85, 105];

      // Finding container box
      doc.setFillColor(255, 255, 255);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(14, currentY, pageWidth - 28, 52, 2, 2, 'FD');

      // Severity bar on left
      doc.setFillColor(color[0], color[1], color[2]);
      doc.rect(14, currentY, 3, 52, 'F');

      // Finding Title & Number
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10);
      doc.setTextColor(15, 23, 42);
      doc.text(`${idx + 1}. ${finding.name}`, 20, currentY + 7);

      // Severity Tag
      doc.setFillColor(color[0], color[1], color[2]);
      doc.roundedRect(pageWidth - 45, currentY + 3, 27, 6, 1.5, 1.5, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(7);
      doc.setFont('helvetica', 'bold');
      doc.text(finding.severity.toUpperCase(), pageWidth - 42, currentY + 7.2);

      // Metadata line (CWE, OWASP, CVSS)
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(100, 116, 139);
      doc.text(
        `CWE: ${finding.cweId || 'N/A'}  |  Category: ${finding.owaspCategory || 'General'}  |  CVSS: ${finding.cvssScore?.toFixed(1) || 'N/A'}  |  URL: ${finding.matchedAt}`,
        20,
        currentY + 13
      );

      // Description
      doc.setTextColor(51, 65, 85);
      doc.setFontSize(8);
      const descLines = doc.splitTextToSize(finding.description, pageWidth - 42);
      doc.text(descLines.slice(0, 2), 20, currentY + 19);

      // Evidence Box
      doc.setFillColor(241, 245, 249);
      doc.roundedRect(20, currentY + 26, pageWidth - 40, 11, 1, 1, 'F');
      doc.setFont('courier', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(30, 41, 59);
      const evidenceSnippet = finding.evidence ? `Evidence: ${finding.evidence.replace(/\n/g, ' ')}` : 'Evidence: Match rule condition satisfied';
      const evidenceLines = doc.splitTextToSize(evidenceSnippet, pageWidth - 46);
      doc.text(evidenceLines.slice(0, 2), 23, currentY + 31);

      // Remediation guidance
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(15, 118, 110); // Teal
      doc.text('Remediation:', 20, currentY + 42);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(51, 65, 85);
      const remText = finding.remediation || 'Review configuration headers, sanitize input/output, and restrict permissions as per OWASP recommendations.';
      const remLines = doc.splitTextToSize(remText, pageWidth - 60);
      doc.text(remLines.slice(0, 2), 38, currentY + 42);

      currentY += 56;
    });
  }

  // Footer on all pages
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184);

    // Divider line
    doc.setDrawColor(226, 232, 240);
    doc.line(14, pageHeight - 12, pageWidth - 14, pageHeight - 12);

    doc.text(
      `Confidential Security Report — Generated by DevSecOps Automated Audit Scanner`,
      14,
      pageHeight - 7
    );
    doc.text(`Page ${i} of ${totalPages}`, pageWidth - 32, pageHeight - 7);
  }

  // Trigger download
  const cleanTarget = scan.targetUrl.replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '_');
  const filename = `security_audit_report_${cleanTarget}_${Date.now()}.pdf`;
  doc.save(filename);
}
