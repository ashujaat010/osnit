import React, { useState } from "react";
import { 
  ShieldCheck, AlertTriangle, Download, Sparkles, Database, FileText, 
  Terminal, Globe, Mail, Clock, HelpCircle, CheckCircle2, ChevronRight,
  ShieldAlert, Shield, ArrowLeft, ExternalLink, RefreshCw
} from "lucide-react";
import { ScanRecord } from "../types";

interface ReportViewerProps {
  scan: ScanRecord;
  authToken: string;
  onBack: () => void;
}

export default function ReportViewer({ scan, authToken, onBack }: ReportViewerProps) {
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [aiReport, setAiReport] = useState<any | null>(null);

  const triggerAiAnalysis = async () => {
    setAiLoading(true);
    setAiError(null);
    try {
      const response = await fetch(`/api/scan/${scan.id}/ai-analysis`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${authToken}`
        }
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Failed to generate AI Security report.");
      }
      setAiReport(data);
    } catch (err: any) {
      setAiError(err.message);
    } finally {
      setAiLoading(false);
    }
  };

  const downloadExport = async (format: "json" | "csv" | "html") => {
    try {
      const response = await fetch(`/api/reports/${scan.id}/export/${format}`, {
        headers: {
          "Authorization": `Bearer ${authToken}`
        }
      });
      if (!response.ok) throw new Error("Could not download file.");
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `OSINT_Audit_${scan.target}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error(err);
    }
  };

  const getScoreColor = (score: number) => {
    if (score <= 20) return "text-green-400 bg-green-950/30 border-green-800/30";
    if (score <= 50) return "text-amber-400 bg-amber-950/30 border-amber-800/30";
    return "text-red-400 bg-red-950/30 border-red-800/30";
  };

  return (
    <div id="report-viewer-container" className="space-y-6">
      
      {/* Top action navigation */}
      <div className="flex items-center justify-between">
        <button
          onClick={onBack}
          className="flex items-center gap-2 px-3 py-1.5 bg-gray-900 hover:bg-gray-800 border border-gray-800 rounded-lg text-xs font-mono text-gray-400 hover:text-white transition"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          BACK TO DASHBOARD
        </button>

        {/* Download actions */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => downloadExport("html")}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-900 hover:bg-gray-800 border border-gray-800 rounded-lg text-xs font-mono text-gray-300 hover:text-white transition"
          >
            <Download className="w-3.5 h-3.5" />
            HTML
          </button>
          <button
            onClick={() => downloadExport("json")}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-900 hover:bg-gray-800 border border-gray-800 rounded-lg text-xs font-mono text-gray-300 hover:text-white transition"
          >
            <Download className="w-3.5 h-3.5" />
            JSON
          </button>
          <button
            onClick={() => downloadExport("csv")}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-900 hover:bg-gray-800 border border-gray-800 rounded-lg text-xs font-mono text-gray-300 hover:text-white transition"
          >
            <Download className="w-3.5 h-3.5" />
            CSV
          </button>
        </div>
      </div>

      {/* Primary Poster Headline */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 bg-blue-600/5 rounded-full blur-3xl -mr-20 -mt-20 pointer-events-none" />
        
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2">
            <div className="flex items-center gap-2.5">
              <span className="text-xs font-mono bg-blue-950/80 border border-blue-500/20 text-blue-400 px-2.5 py-0.5 rounded uppercase font-semibold">
                AUDIT REPORT
              </span>
              <div className="flex items-center gap-1.5 text-xs text-gray-500 font-mono">
                <Clock className="w-3.5 h-3.5" />
                {new Date(scan.timestamp).toUTCString()}
              </div>
            </div>
            <h1 className="text-2xl md:text-3xl font-sans font-bold text-white tracking-tight flex items-center gap-2">
              {scan.type === "email" ? <Mail className="w-7 h-7 text-blue-500" /> : <Globe className="w-7 h-7 text-indigo-500" />}
              {scan.target}
            </h1>
            <p className="text-sm text-gray-400 font-mono">
              SEC_HASH_ID: {scan.id.substring(0, 18).toUpperCase()}
            </p>
          </div>

          {/* Large Badge Index Score */}
          <div className="flex items-center gap-4 shrink-0">
            <div className="text-right">
              <div className="text-[10px] font-mono text-gray-500 uppercase tracking-widest">SECURITY GRADE</div>
              <div className="text-3xl font-sans font-black text-center text-white mt-1">
                {scan.securityScore.grade}
              </div>
            </div>
            <div className={`border rounded-xl p-4 flex flex-col items-center justify-center text-center ${getScoreColor(scan.securityScore.riskScore)}`}>
              <span className="text-[9px] font-mono tracking-widest uppercase mb-1">RISK INDEX</span>
              <span className="text-2xl font-bold font-mono">{scan.securityScore.riskScore}/100</span>
            </div>
          </div>
        </div>
      </div>

      {/* Grid: Indicators and DNS checks */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Indicators Panel */}
        <div className="lg:col-span-1 bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider border-b border-gray-800 pb-2 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-blue-500" />
            SECURITY INDICATORS
          </h3>
          <div className="space-y-3 max-h-[380px] overflow-y-auto pr-1">
            {scan.securityScore.indicators.map((indicator, idx) => (
              <div key={idx} className="bg-gray-950 p-3 rounded-lg border border-gray-800/80 space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${
                    indicator.status === "safe" ? "bg-green-500" : indicator.status === "warning" ? "bg-amber-500" : "bg-red-500"
                  }`} />
                  <span className="text-xs font-mono font-bold text-white">{indicator.label}</span>
                </div>
                <p className="text-[11px] text-gray-400 leading-normal">{indicator.description}</p>
              </div>
            ))}
          </div>
        </div>

        {/* DNS Policy configuration details */}
        <div className="lg:col-span-2 bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider border-b border-gray-800 pb-2 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-indigo-400" />
            SENDER AUTHENTICATION SECURITY
          </h3>

          {scan.dnsInfo ? (
            <div className="space-y-4">
              
              {/* SPF status card */}
              <div className="bg-gray-950 p-3.5 rounded-lg border border-gray-800">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-mono font-bold text-white">SPF (SENDER POLICY FRAMEWORK)</span>
                  {scan.dnsInfo.spfRecord ? (
                    <span className="text-[10px] font-mono text-green-400 bg-green-950/20 px-2 py-0.5 rounded border border-green-800/30">PUBLISHED</span>
                  ) : (
                    <span className="text-[10px] font-mono text-red-400 bg-red-950/20 px-2 py-0.5 rounded border border-red-800/30">MISSING</span>
                  )}
                </div>
                <div className="bg-gray-900 p-2 rounded text-xs font-mono text-gray-300 break-all border border-gray-850">
                  {scan.dnsInfo.spfRecord || "No SPF record found in DNS TXT configurations."}
                </div>
                <p className="text-[10px] text-gray-400 mt-1.5 leading-normal">
                  SPF authorizes which SMTP servers are allowed to mail from this domain.
                </p>
              </div>

              {/* DMARC status card */}
              <div className="bg-gray-950 p-3.5 rounded-lg border border-gray-800">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-mono font-bold text-white">DMARC AUTHENTICATION POLICY</span>
                  {scan.dnsInfo.dmarcRecord ? (
                    <span className="text-[10px] font-mono text-green-400 bg-green-950/20 px-2 py-0.5 rounded border border-green-800/30">ACTIVE</span>
                  ) : (
                    <span className="text-[10px] font-mono text-red-400 bg-red-950/20 px-2 py-0.5 rounded border border-red-800/30">VULNERABLE</span>
                  )}
                </div>
                <div className="bg-gray-900 p-2 rounded text-xs font-mono text-gray-300 break-all border border-gray-850">
                  {scan.dnsInfo.dmarcRecord || "No DMARC records solved under _dmarc." + scan.dnsInfo.domain}
                </div>
                <p className="text-[10px] text-gray-400 mt-1.5 leading-normal">
                  DMARC mandates how recipient servers handle failed SPF/DKIM checks (none, quarantine, reject).
                </p>
              </div>

              {/* WHOIS meta info */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 bg-gray-950 p-3.5 rounded-lg border border-gray-800 text-xs font-mono">
                <div>
                  <div className="text-gray-500">REGISTRAR AUTHORITY</div>
                  <div className="text-white font-medium mt-0.5">{scan.dnsInfo.whois.registrar}</div>
                </div>
                <div>
                  <div className="text-gray-500">NAMESERVERS</div>
                  <div className="text-white font-medium mt-0.5 max-w-xs truncate" title={scan.dnsInfo.whois.nameServers.join(", ")}>
                    {scan.dnsInfo.whois.nameServers.join(", ")}
                  </div>
                </div>
                <div>
                  <div className="text-gray-500">REGISTRATION DATE</div>
                  <div className="text-white mt-0.5">{new Date(scan.dnsInfo.whois.creationDate).toDateString()}</div>
                </div>
                <div>
                  <div className="text-gray-500">EXPIRATION DATE</div>
                  <div className="text-white mt-0.5">{new Date(scan.dnsInfo.whois.expiryDate).toDateString()}</div>
                </div>
              </div>

            </div>
          ) : (
            <div className="p-12 text-center text-gray-500 font-mono text-xs">
              No direct DNS metadata resolved.
            </div>
          )}

        </div>
      </div>

      {/* Vulnerabilities and Mitigations */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
        <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider border-b border-gray-800 pb-2 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-amber-500" />
          MISCONFIGURATION DETECTION & DEFENSIVE MITIGATIONS
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-3">
            <h4 className="text-xs font-mono font-bold text-gray-300">DETECTED Posture Gaps</h4>
            {scan.securityScore.vulnerabilitiesDetected.length === 0 ? (
              <div className="bg-green-950/10 border border-green-800/20 text-green-300 text-xs rounded-lg p-3 font-mono">
                ✓ No critical configuration gaps detected.
              </div>
            ) : (
              scan.securityScore.vulnerabilitiesDetected.map((vuln, i) => (
                <div key={i} className="bg-red-950/10 border border-red-500/20 text-red-200 text-xs rounded-lg p-3 font-mono flex items-start gap-2">
                  <span className="text-red-400 font-bold">🚨</span>
                  <span>{vuln}</span>
                </div>
              ))
            )}
          </div>

          <div className="space-y-3">
            <h4 className="text-xs font-mono font-bold text-gray-300">DEFENSIVE REMEDIATIONS</h4>
            <div className="space-y-2">
              {scan.securityScore.recommendations.map((rec, i) => (
                <div key={i} className="bg-gray-950 p-3 rounded-lg border border-gray-800 text-xs font-mono flex items-start gap-2 text-gray-300">
                  <span className="text-blue-400">✓</span>
                  <span>{rec}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* OSINT Harvesting Footprint & GitHub Public check */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Left: OSINT search endpoints */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider border-b border-gray-800 pb-2 flex items-center gap-2">
            <Database className="w-4 h-4 text-blue-400" />
            HARVESTING FOOTPRINT FOOTPRINT (OSINT)
          </h3>
          {scan.osint ? (
            <div className="space-y-4">
              
              <div className="space-y-2">
                <span className="text-xs font-mono text-gray-400 uppercase">INDEXED SEARCH TARGETS</span>
                <div className="space-y-1.5">
                  {scan.osint.indexedSources.map((src, i) => (
                    <div key={i} className="bg-gray-950 py-1.5 px-3 rounded text-xs font-mono text-gray-300 border border-gray-850">
                      {src}
                    </div>
                  ))}
                </div>
              </div>

              <div className="space-y-2">
                <span className="text-xs font-mono text-gray-400 uppercase">PUBLIC CONTACT EXPOSURE (Susceptible channels)</span>
                <div className="space-y-1.5">
                  {scan.osint.publicContactLeaks.map((leak, i) => (
                    <div key={i} className="bg-gray-950 py-1.5 px-3 rounded text-xs font-mono text-red-400 border border-red-950/20 flex items-center justify-between">
                      <span className="truncate">{leak}</span>
                      <span className="text-[10px] text-red-500 font-bold shrink-0">EXPOSED</span>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          ) : (
            <div className="p-8 text-center text-gray-500 font-mono text-xs">
              No public OSINT profiles harvested.
            </div>
          )}
        </div>

        {/* Right: GitHub profile lookup */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider border-b border-gray-800 pb-2 flex items-center gap-2">
            <Globe className="w-4 h-4 text-indigo-400" />
            GITHUB PROFILE API SEARCH DISCLOSURES
          </h3>
          
          {scan.osint?.githubProfile ? (
            <div className="space-y-4">
              
              <div className="flex items-center gap-3 bg-gray-950 p-3.5 rounded-lg border border-gray-800">
                <div className="w-10 h-10 rounded-full bg-blue-600/10 border border-blue-500/20 flex items-center justify-center text-blue-400 font-bold font-sans text-lg">
                  {scan.osint.githubProfile.username?.charAt(0).toUpperCase()}
                </div>
                <div>
                  <div className="text-xs font-mono text-white font-bold flex items-center gap-1.5">
                    {scan.osint.githubProfile.username}
                    <a 
                      href={`https://github.com/${scan.osint.githubProfile.username}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:text-blue-300 transition"
                    >
                      <ExternalLink className="w-3.5 h-3.5 inline" />
                    </a>
                  </div>
                  <div className="text-[10px] font-mono text-gray-500">PUBLIC PROFILE GATHERED</div>
                </div>
              </div>

              {/* GitHub Stats metrics */}
              <div className="grid grid-cols-3 gap-3 text-center text-xs font-mono">
                <div className="bg-gray-950 p-2.5 rounded border border-gray-850">
                  <div className="text-gray-500 text-[10px]">REPOSITORIES</div>
                  <div className="text-white font-bold mt-0.5">{scan.osint.githubProfile.publicRepos}</div>
                </div>
                <div className="bg-gray-950 p-2.5 rounded border border-gray-850">
                  <div className="text-gray-500 text-[10px]">PUBLIC GISTS</div>
                  <div className="text-white font-bold mt-0.5">{scan.osint.githubProfile.publicGists}</div>
                </div>
                <div className="bg-gray-950 p-2.5 rounded border border-gray-850">
                  <div className="text-gray-500 text-[10px]">FOLLOWERS</div>
                  <div className="text-white font-bold mt-0.5">{scan.osint.githubProfile.followers}</div>
                </div>
              </div>

              {scan.osint.githubProfile.bio && (
                <div className="bg-gray-950 p-3 rounded text-xs font-mono text-gray-400 leading-normal border border-gray-850">
                  <span className="text-gray-500 block text-[10px] uppercase mb-1">PROFILE BIO</span>
                  "{scan.osint.githubProfile.bio}"
                </div>
              )}

              {scan.osint.githubProfile.associatedEmailsFound.length > 0 && (
                <div className="space-y-1.5">
                  <span className="text-[10px] font-mono text-gray-500 uppercase">PUBLIC REPO EXPOSED EMAILS</span>
                  <div className="bg-red-950/10 border border-red-500/20 p-2.5 rounded text-xs font-mono text-red-200">
                    {scan.osint.githubProfile.associatedEmailsFound.join(", ")}
                  </div>
                </div>
              )}

            </div>
          ) : (
            <div className="p-12 text-center text-gray-500 font-mono text-xs border-dashed border border-gray-800 rounded-lg">
              No matching active GitHub profile exposed with associated public commits for this email address.
            </div>
          )}
        </div>

      </div>

      {/* Breach checks awareness index */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
        <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider border-b border-gray-800 pb-2 flex items-center gap-2">
          <Database className="w-4 h-4 text-red-500" />
          CREDENTIAL BREACH AWARENESS DATABASE
        </h3>

        {scan.breaches.length === 0 ? (
          <div className="p-8 text-center text-green-400 bg-green-950/10 border border-green-800/20 rounded-lg font-mono text-xs flex items-center justify-center gap-2">
            <Shield className="w-4 h-4 text-green-400" />
            No public compromised breach references resolved for this user address in indexed leaks databases.
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-gray-800">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-gray-950 text-gray-400 border-b border-gray-800">
                <tr>
                  <th className="p-3">BREACHED SOURCE</th>
                  <th className="p-3">BREACH DATE</th>
                  <th className="p-3">COMPROMISED ATTRIBUTES</th>
                  <th className="p-3">SEVERITY</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 bg-gray-950">
                {scan.breaches.map((breach, idx) => (
                  <tr key={idx} className="hover:bg-gray-900/60 transition">
                    <td className="p-3 font-sans font-bold text-white">
                      {breach.name}
                    </td>
                    <td className="p-3 text-gray-400">
                      {breach.breachDate}
                    </td>
                    <td className="p-3 text-gray-400">
                      {breach.compromisedData.join(", ")}
                    </td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        breach.severity === "Critical" 
                          ? "bg-red-950/40 text-red-400 border border-red-900/30 animate-pulse" 
                          : breach.severity === "High" 
                            ? "bg-orange-950/40 text-orange-400 border border-orange-900/30"
                            : "bg-amber-950/40 text-amber-400 border border-amber-900/30"
                      }`}>
                        {breach.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Gemini AI deep technical audit analysis */}
      <div id="gemini-ai-card" className="bg-gray-900 border border-gray-800 rounded-xl p-6 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-80 bg-indigo-600/5 rounded-full blur-3xl -mr-32 -mt-32 pointer-events-none" />
        
        <div className="flex items-center justify-between border-b border-gray-800 pb-4 mb-5">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-indigo-950 text-indigo-400 border border-indigo-800/30">
              <Sparkles className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h3 className="text-base font-sans font-bold text-white flex items-center gap-1.5">
                Gemini AI Security Audit Specialist
              </h3>
              <p className="text-xs text-gray-400 font-mono">AUTOMATED ADVANCED MITIGATION ENGINE</p>
            </div>
          </div>
          {!aiReport && !aiLoading && (
            <button
              onClick={triggerAiAnalysis}
              className="bg-indigo-600 hover:bg-indigo-500 text-white font-mono text-xs px-4 py-2 rounded-lg transition shadow-lg shadow-indigo-900/20 flex items-center gap-1.5 shrink-0"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              RUN AI ANALYSIS
            </button>
          )}
        </div>

        {aiLoading && (
          <div className="p-12 text-center text-gray-400 font-mono text-xs space-y-4">
            <span className="w-8 h-8 border-3 border-indigo-500/20 border-t-indigo-400 rounded-full animate-spin inline-block" />
            <div className="space-y-1">
              <p className="text-indigo-400 font-bold">GEMINI AUDITING AGENT AT WORK...</p>
              <p className="text-gray-600 text-[10px]">Evaluating SPF limits, breach hashes, and spoof vectors...</p>
            </div>
          </div>
        )}

        {aiError && (
          <div className="bg-red-950/20 border border-red-500/30 text-red-200 text-xs rounded-lg p-3.5 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
            <span className="font-mono">AI generation error: {aiError}</span>
          </div>
        )}

        {aiReport && (
          <div className="space-y-6 text-xs font-mono">
            
            {/* AI Executive Summary */}
            <div className="bg-gray-950 p-4 rounded-lg border border-indigo-950/30 space-y-2">
              <span className="text-[10px] text-indigo-400 uppercase font-bold tracking-wider">AI EXECUTIVE AUDIT REPORT SUMMARY</span>
              <p className="text-gray-300 leading-relaxed font-sans text-sm">{aiReport.summary}</p>
            </div>

            {/* AI Threat Impact matrix */}
            <div className="space-y-2">
              <span className="text-[10px] text-indigo-400 uppercase font-bold tracking-wider block">THREAT SCENARIO IMPACT MATRIX</span>
              <div className="overflow-x-auto rounded-lg border border-gray-800">
                <table className="w-full text-left font-mono">
                  <thead className="bg-gray-950 text-gray-500 text-[11px] border-b border-gray-800">
                    <tr>
                      <th className="p-3 font-normal">EXPOSED VULNERABILITY</th>
                      <th className="p-3 font-normal">EXPLOITATION IMPACT METHOD</th>
                      <th className="p-3 font-normal">SEVERITY</th>
                      <th className="p-3 font-normal">REMEDIATION REPAIR</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800 bg-gray-950/50">
                    {aiReport.threatMatrix.map((matrix: any, i: number) => (
                      <tr key={i} className="hover:bg-gray-900/30 transition">
                        <td className="p-3 font-bold text-white leading-normal">{matrix.vulnerability}</td>
                        <td className="p-3 text-gray-400 leading-normal">{matrix.impact}</td>
                        <td className="p-3">
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                            matrix.severity === "Critical" ? "bg-red-950/50 text-red-400" :
                            matrix.severity === "High" ? "bg-orange-950/50 text-orange-400" :
                            matrix.severity === "Medium" ? "bg-amber-950/50 text-amber-400" : "bg-gray-800 text-gray-400"
                          }`}>
                            {matrix.severity}
                          </span>
                        </td>
                        <td className="p-3 text-green-400 leading-normal">{matrix.remediation}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Phishing BEC susceptibility analysis */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-gray-950 p-4 rounded-lg border border-gray-800 space-y-2">
                <span className="text-[10px] text-indigo-400 uppercase font-bold tracking-wider">PHISHING SUSCEPTIBILITY & BEC IMPACT</span>
                <p className="text-gray-300 leading-relaxed font-sans text-xs">{aiReport.phishingSusceptibility}</p>
              </div>

              <div className="bg-gray-950 p-4 rounded-lg border border-gray-800 space-y-2">
                <span className="text-[10px] text-indigo-400 uppercase font-bold tracking-wider">GOVERNANCE & COMPLIANCE GAP INSIGHT</span>
                <p className="text-gray-300 leading-relaxed font-sans text-xs">{aiReport.complianceInsight}</p>
              </div>
            </div>

          </div>
        )}

        {!aiReport && !aiLoading && !aiError && (
          <div className="text-center p-6 border border-dashed border-gray-800 rounded-lg text-gray-500 text-xs font-mono">
            Trigger Gemini AI to execute deep network misconfiguration scanning, security compliance checks, and detailed red-team impact matrices.
          </div>
        )}
      </div>

    </div>
  );
}
