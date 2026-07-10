import React, { useState, useEffect } from "react";
import { Search, Mail, Globe, AlertTriangle, ShieldAlert, CheckCircle } from "lucide-react";

interface ScanFormProps {
  onScanCompleted: (scan: any) => void;
  authToken: string;
}

export default function ScanForm({ onScanCompleted, authToken }: ScanFormProps) {
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState<"email" | "domain">("email");
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [stepMessage, setStepMessage] = useState("");
  const [scanSteps, setScanSteps] = useState<{ label: string; status: "pending" | "running" | "done" }[]>([]);

  // Simple scan steps animation logs to capture OSINT feedback
  const stepsConfig = {
    email: [
      "Validating email syntax formatting",
      "Scanning ephemeral/disposable domain lists",
      "Resolving MX Mail Exchange mail exchangers",
      "Querying known public data breach indices",
      "Performing public GitHub API checks",
      "Compiling reputation intelligence scorecards"
    ],
    domain: [
      "Validating host domain connection status",
      "Resolving public IPv4 A addresses",
      "Querying authoritative nameservers (NS)",
      "Checking TXT SPF records",
      "Verifying DMARC security controls policies",
      "Calculating risk posture grade metric"
    ]
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const cleanedTarget = target.trim();

    if (!cleanedTarget) {
      setError("Please specify a target address or domain first.");
      return;
    }

    // Basic syntax sanity checking
    if (scanType === "email") {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(cleanedTarget)) {
        setError("Invalid email format. E.g. contact@domain.com");
        return;
      }
    } else {
      const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}$/;
      if (!domainRegex.test(cleanedTarget)) {
        setError("Invalid domain format. E.g. company.com");
        return;
      }
    }

    // Trigger loader state
    setScanning(true);
    
    // Set up step trackers
    const activeSteps = stepsConfig[scanType].map((label, idx) => ({
      label,
      status: idx === 0 ? ("running" as const) : ("pending" as const)
    }));
    setScanSteps(activeSteps);

    // Simulate animated step progression on the frontend for smooth terminal feel
    for (let i = 0; i < activeSteps.length; i++) {
      setStepMessage(activeSteps[i].label + "...");
      setScanSteps(prev => prev.map((s, idx) => {
        if (idx === i) return { ...s, status: "running" as const };
        if (idx < i) return { ...s, status: "done" as const };
        return s;
      }));
      await new Promise(resolve => setTimeout(resolve, 800));
    }

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${authToken}`
        },
        body: JSON.stringify({ target: cleanedTarget, type: scanType })
      });

      if (!response.ok) {
        let errorMsg = "The server could not process the scan.";
        try {
          const text = await response.text();
          try {
            const parsed = JSON.parse(text);
            errorMsg = parsed.error || errorMsg;
          } catch (_) {
            errorMsg = `Server error (${response.status}): ${text.substring(0, 150)}`;
          }
        } catch (_) {}
        throw new Error(errorMsg);
      }

      const data = await response.json();

      setScanSteps(prev => prev.map(s => ({ ...s, status: "done" as const })));
      setStepMessage("Scan successfully compiled!");
      
      // Delay briefly to allow user to see completed state
      await new Promise(resolve => setTimeout(resolve, 500));
      onScanCompleted(data);
      setTarget("");
    } catch (err: any) {
      setError(err.message);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div id="scan-form-container" className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-lg">
      <div className="flex items-center justify-between mb-6 border-b border-gray-800 pb-4">
        <div>
          <h2 className="text-lg font-sans font-semibold text-white">Passive Security Audit Scanner</h2>
          <p className="text-xs text-gray-400 font-mono">EDUCATIONAL & DEFENSIVE CONSOLE ONLY</p>
        </div>
        <div className="flex items-center gap-1.5 bg-gray-950 p-1 rounded-lg border border-gray-800">
          <button
            type="button"
            onClick={() => !scanning && setScanType("email")}
            className={`px-3 py-1 text-xs font-mono rounded-md transition flex items-center gap-1.5 ${
              scanType === "email" 
                ? "bg-blue-600 text-white" 
                : "text-gray-400 hover:text-white"
            }`}
          >
            <Mail className="w-3.5 h-3.5" />
            EMAIL CHECK
          </button>
          <button
            type="button"
            onClick={() => !scanning && setScanType("domain")}
            className={`px-3 py-1 text-xs font-mono rounded-md transition flex items-center gap-1.5 ${
              scanType === "domain" 
                ? "bg-blue-600 text-white" 
                : "text-gray-400 hover:text-white"
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            DOMAIN CHECK
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-950/20 border border-red-500/30 text-red-200 text-xs rounded-lg p-3.5 mb-5 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
          <span className="font-mono">{error}</span>
        </div>
      )}

      {!scanning ? (
        <form onSubmit={handleScan} className="flex gap-3">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
              {scanType === "email" ? (
                <Mail className="w-5 h-5 text-gray-500" />
              ) : (
                <Globe className="w-5 h-5 text-gray-500" />
              )}
            </div>
            <input
              type="text"
              required
              disabled={scanning}
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={scanType === "email" ? "Enter email (e.g. employee@company.com)" : "Enter domain (e.g. company.com)"}
              className="w-full bg-gray-950/80 border border-gray-800 rounded-lg py-3 pl-11 pr-4 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 font-mono transition"
            />
          </div>
          <button
            type="submit"
            disabled={scanning}
            className="bg-blue-600 hover:bg-blue-500 text-white font-mono font-medium px-6 rounded-lg transition duration-200 flex items-center gap-2 shadow-lg shadow-blue-900/20 shrink-0"
          >
            <Search className="w-4 h-4" />
            RUN AUDIT
          </button>
        </form>
      ) : (
        /* Scanning / Loading Screen Logs Panel */
        <div className="bg-gray-950 rounded-lg border border-gray-800 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-gray-900 pb-3">
            <div className="flex items-center gap-2.5">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-500 animate-ping shrink-0" />
              <span className="text-xs font-mono text-blue-400">ACTIVE RECONNAISSANCE GATHERING: {target}</span>
            </div>
            <span className="text-[10px] font-mono text-gray-500">THREAD_ID: {Math.floor(Math.random() * 9000) + 1000}</span>
          </div>

          <div className="space-y-2">
            {scanSteps.map((step, idx) => (
              <div key={idx} className="flex items-center justify-between text-xs font-mono">
                <span className={`${
                  step.status === "done" 
                    ? "text-gray-500 line-through" 
                    : step.status === "running" 
                      ? "text-blue-400" 
                      : "text-gray-600"
                }`}>
                  {step.status === "running" ? "▶ " : "  "} {step.label}
                </span>
                <span>
                  {step.status === "done" && <CheckCircle className="w-4 h-4 text-green-500 inline" />}
                  {step.status === "running" && <span className="w-3.5 h-3.5 border-2 border-blue-500/20 border-t-blue-400 rounded-full animate-spin inline-block" />}
                  {step.status === "pending" && <span className="text-gray-700 text-[10px]">WAITING</span>}
                </span>
              </div>
            ))}
          </div>

          <div className="bg-gray-900/50 p-2.5 rounded border border-gray-800/50 text-center">
            <span className="text-xs font-mono text-gray-400">{stepMessage}</span>
          </div>
        </div>
      )}
    </div>
  );
}
