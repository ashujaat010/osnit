import { GoogleGenAI } from "@google/genai";
import { ScanRecord } from "../src/types";

// Lazy-initialize Gemini AI Client to prevent startup crashes when API key is missing
let aiClient: GoogleGenAI | null = null;

function getGeminiClient(): GoogleGenAI | null {
  if (!aiClient) {
    const key = process.env.GEMINI_API_KEY;
    if (key && key !== "MY_GEMINI_API_KEY") {
      aiClient = new GoogleGenAI({
        apiKey: key,
        httpOptions: {
          headers: {
            "User-Agent": "aistudio-build",
          }
        }
      });
    }
  }
  return aiClient;
}

export interface AiAnalysisResult {
  summary: string;
  threatMatrix: {
    vulnerability: string;
    impact: string;
    severity: "Low" | "Medium" | "High" | "Critical";
    remediation: string;
  }[];
  phishingSusceptibility: string;
  complianceInsight: string;
}

export async function generateSecurityAnalysis(scan: Partial<ScanRecord>): Promise<AiAnalysisResult> {
  const client = getGeminiClient();

  if (!client) {
    console.warn("GEMINI_API_KEY is not configured or using placeholder. Falling back to local static rules.");
    return getFallbackAnalysis(scan);
  }

  // Structure an in-depth context payload for Gemini
  const dns = scan.dnsInfo;
  const emailVal = scan.emailValidation;
  const breaches = scan.breaches || [];
  
  const systemPrompt = `You are an elite Senior Cybersecurity Analyst and Red Team Specialist. 
Analyze the provided email/domain OSINT reconnaissance scan records and deliver a highly professional, detailed, defensive security posture assessment.
Output your response in valid JSON format ONLY, conforming strictly to this JSON Schema structure:
{
  "summary": "High-level professional executive summary of the target's current email/domain security health. (approx 200 words)",
  "threatMatrix": [
    {
      "vulnerability": "Specific configuration weakness or leak detected (e.g., 'Weak SPF policy', 'Exposed credentials in LinkedIn breach')",
      "impact": "How a threat actor could exploit this vulnerability in an active campaign",
      "severity": "Low | Medium | High | Critical",
      "remediation": "Clear, step-by-step technical implementation to secure the loophole"
    }
  ],
  "phishingSusceptibility": "In-depth analysis of how susceptible this domain/email is to business email compromise (BEC), domain spoofing, and spear-phishing campaigns based on DNS and leaks.",
  "complianceInsight": "Assessment of standard framework compliance (GDPR, ISO 27001, SOC 2, HIPAA) regarding the current misconfigurations."
}`;

  const scanDetails = {
    target: scan.target,
    type: scan.type,
    emailDetails: emailVal ? {
      syntaxValid: emailVal.syntaxValid,
      isDisposable: emailVal.isDisposable,
      provider: emailVal.disposableProvider,
      mxValid: emailVal.mxValid
    } : null,
    dnsDetails: dns ? {
      mxRecords: dns.mxRecords,
      hasMx: dns.hasMx,
      spf: dns.spfRecord,
      dmarc: dns.dmarcRecord,
      txtRecords: dns.txtRecords,
      nameServers: dns.whois?.nameServers
    } : null,
    breachRecords: breaches.map(b => ({
      name: b.name,
      domain: b.domain,
      leakDate: b.breachDate,
      leakedFields: b.compromisedData,
      severity: b.severity
    })),
    precalculatedRiskScore: scan.securityScore?.riskScore
  };

  try {
    const response = await client.models.generateContent({
      model: "gemini-3.5-flash",
      contents: `Perform security audit for target scan: ${JSON.stringify(scanDetails, null, 2)}`,
      config: {
        systemInstruction: systemPrompt,
        responseMimeType: "application/json",
        temperature: 0.2
      }
    });

    const text = response.text;
    if (!text) {
      throw new Error("No text content returned from Gemini model.");
    }

    const parsed: AiAnalysisResult = JSON.parse(text.trim());
    return parsed;
  } catch (err) {
    console.error("Failed to generate AI analysis via Gemini:", err);
    return getFallbackAnalysis(scan);
  }
}

// Fallback audit report engine if Gemini API is disabled
function getFallbackAnalysis(scan: Partial<ScanRecord>): AiAnalysisResult {
  const dns = scan.dnsInfo;
  const breaches = scan.breaches || [];
  const target = scan.target || "the target";
  const matrix: AiAnalysisResult["threatMatrix"] = [];

  // Analyze SPF
  if (!dns || !dns.spfRecord) {
    matrix.push({
      vulnerability: "Missing SPF DNS Record",
      impact: "Attackers can send unauthorized emails pretending to originate from this domain, causing severe reputational damage.",
      severity: "High",
      remediation: "Deploy a DNS TXT record defining valid mail servers. For example: v=spf1 include:_spf.google.com ~all"
    });
  } else if (dns.spfRecord.includes("~all")) {
    matrix.push({
      vulnerability: "Permissive SPF Softfail Config",
      impact: "Softfail (~all) prompts downstream servers to accept unauthorized mails but mark them as suspicious instead of hard-rejecting them.",
      severity: "Medium",
      remediation: "Incorporate strict hardfail restrictions in your DNS record by changing '~all' to '-all'."
    });
  }

  // Analyze DMARC
  if (!dns || !dns.dmarcRecord) {
    matrix.push({
      vulnerability: "Missing DMARC Authentication Policy",
      impact: "Receiving mail servers cannot determine how to handle unauthenticated spoofed emails, letting phishing campaigns pass to targets' inboxes.",
      severity: "Critical",
      remediation: "Create a TXT record at '_dmarc." + target + "' with an initial monitoring policy: 'v=DMARC1; p=none; pct=100; rua=mailto:dmarc@yourdomain.com'"
    });
  } else if (dns.dmarcRecord.toLowerCase().includes("p=none")) {
    matrix.push({
      vulnerability: "Inert DMARC Policy (p=none)",
      impact: "Monitoring-only policy (p=none) fails to instruct recipient mailservers to quarantine or reject forged messages.",
      severity: "Medium",
      remediation: "Harden the policy from 'p=none' to 'p=quarantine' or 'p=reject' once configuration holds stable."
    });
  }

  // Analyze breaches
  if (breaches.length > 0) {
    matrix.push({
      vulnerability: `Credential Leak Associated with Identity`,
      impact: "Attackers can perform credential stuffing attacks or targeted spear-phishing on administrative platforms.",
      severity: "High",
      remediation: "Immediately cycle all active passwords on leaked sites, deploy FIDO2 hardware MFA keys, and audit unauthorized logins."
    });
  }

  // Construct standard responses
  const hasVulnerabilities = matrix.length > 0;
  const summary = hasVulnerabilities 
    ? `The OSINT reconnaissance scan for ${target} revealed notable administrative and authentication security gaps. The main posture liabilities revolve around unhardened email routing policies (SPF/DMARC) and exposed credentials in historical breaches, which significantly increases exposure to impersonation campaigns.`
    : `The OSINT defensive audit on ${target} indicates a strong, well-configured security posture. Standard DNS security headers (SPF, DMARC) are present and active, and no high-severity credential leaks were associated with this domain.`;

  const phishingSusceptibility = hasVulnerabilities
    ? "High risk of successful social engineering. Due to missing or soft DNS validation policies, external threat groups can craft believable emails matching this domain's exact headers. Furthermore, the circulating credentials from leaks provide attackers with historical vectors to plan tailored spear-phishing messages."
    : "Low risk. Destructive domain-spoofing is restricted by current SPF and DMARC enforcement policies, reducing the risk of unauthorized external mail delivery pretending to be this organization.";

  const complianceInsight = hasVulnerabilities
    ? "Fails to meet security controls under ISO 27001 (A.12.6.1 - Technical Vulnerability Management) and GDPR (Article 32 - Security of Processing), which mandate strong technical configurations to ensure data integrity and confidentiality."
    : "Meets standard data security directives under SOC 2 trust principles and ISO 27001, utilizing secure, monitored, and authenticated outbound communications.";

  return {
    summary,
    threatMatrix: matrix.length > 0 ? matrix : [{
      vulnerability: "No major vulnerabilities detected",
      impact: "None identified",
      severity: "Low",
      remediation: "Continue periodic automated security scans to monitor registry alterations."
    }],
    phishingSusceptibility,
    complianceInsight
  };
}
