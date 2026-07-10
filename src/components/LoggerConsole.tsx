import React, { useState, useEffect } from "react";
import { Terminal, Shield, AlertCircle, RefreshCw, Search, CheckCircle } from "lucide-react";
import { AuditLog } from "../types";

interface LoggerConsoleProps {
  authToken: string;
}

export default function LoggerConsole({ authToken }: LoggerConsoleProps) {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<"all" | "success" | "error">("all");
  const [search, setSearch] = useState("");

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const response = await fetch("/api/logs", {
        headers: { "Authorization": `Bearer ${authToken}` }
      });
      if (response.ok) {
        const data = await response.json();
        setLogs(data);
      }
    } catch (err) {
      console.error("Failed to load audit logs", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000); // Poll logs every 5 seconds for a dynamic feel!
    return () => clearInterval(interval);
  }, [authToken]);

  const filteredLogs = logs.filter(log => {
    const matchesSearch = log.details.toLowerCase().includes(search.toLowerCase()) || 
                          log.action.toLowerCase().includes(search.toLowerCase());
    const matchesFilter = filter === "all" || log.status === filter;
    return matchesSearch && matchesFilter;
  });

  return (
    <div id="logger-console-container" className="bg-gray-950 border border-gray-800 rounded-xl overflow-hidden shadow-2xl">
      
      {/* Console Header */}
      <div className="bg-gray-900 px-5 py-3 border-b border-gray-800 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-2">
          <Terminal className="w-5 h-5 text-blue-400 animate-pulse" />
          <div>
            <h3 className="text-sm font-mono font-bold text-white tracking-tight">OSINT SYSTEM AUDIT SHELL</h3>
            <span className="text-[10px] font-mono text-gray-500">LIVE EVENTS COMPLIANCE RECORDING</span>
          </div>
        </div>
        
        {/* Actions */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 bg-gray-950 p-1 rounded-lg border border-gray-800 shrink-0">
            <button
              onClick={() => setFilter("all")}
              className={`px-2 py-0.5 text-[10px] font-mono rounded transition ${
                filter === "all" ? "bg-gray-850 text-blue-400" : "text-gray-500 hover:text-white"
              }`}
            >
              ALL
            </button>
            <button
              onClick={() => setFilter("success")}
              className={`px-2 py-0.5 text-[10px] font-mono rounded transition ${
                filter === "success" ? "bg-green-950/40 text-green-400" : "text-gray-500 hover:text-white"
              }`}
            >
              OK
            </button>
            <button
              onClick={() => setFilter("error")}
              className={`px-2 py-0.5 text-[10px] font-mono rounded transition ${
                filter === "error" ? "bg-red-950/40 text-red-400" : "text-gray-500 hover:text-white"
              }`}
            >
              ERR
            </button>
          </div>

          <button
            onClick={fetchLogs}
            disabled={loading}
            className="p-1.5 bg-gray-950 hover:bg-gray-850 rounded border border-gray-800 text-gray-500 hover:text-white transition"
            title="Refresh logs console"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-blue-400" : ""}`} />
          </button>
        </div>
      </div>

      {/* Filter and Search Panel */}
      <div className="p-3 bg-gray-900/50 border-b border-gray-800/60">
        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 w-4 h-4 text-gray-600" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Query logs database (e.g. user_registration, scan)..."
            className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-1.5 pl-9 text-xs text-blue-400 placeholder-gray-700 focus:outline-none focus:border-blue-500/50 font-mono transition"
          />
        </div>
      </div>

      {/* Terminal Output */}
      <div className="p-4 bg-gray-950 font-mono text-[11px] leading-relaxed max-h-[300px] overflow-y-auto space-y-2 select-text scrollbar-thin scrollbar-thumb-gray-800">
        {filteredLogs.length === 0 ? (
          <div className="text-gray-600 italic text-center py-6">
            // No audit events matched query filter...
          </div>
        ) : (
          filteredLogs.map((log) => (
            <div key={log.id} className="flex items-start gap-2 select-text hover:bg-gray-900/20 py-0.5 px-1 rounded transition">
              <span className="text-gray-600 shrink-0 select-none">
                [{new Date(log.timestamp).toLocaleTimeString()}]
              </span>
              
              <span className={`shrink-0 select-none font-bold ${log.status === "success" ? "text-green-500" : "text-red-500"}`}>
                {log.status === "success" ? "SUCCESS" : "ERROR"}
              </span>

              <span className="text-blue-500 shrink-0 font-semibold uppercase">
                [{log.action}]
              </span>

              <span className="text-gray-300 flex-1 break-all select-text">
                {log.details}
              </span>

              {log.userEmail && (
                <span className="text-gray-600 shrink-0 text-[10px] hidden md:inline select-none">
                  (Operator: {log.userEmail})
                </span>
              )}
            </div>
          ))
        )}
      </div>

      {/* Footer statistics */}
      <div className="bg-gray-900/80 px-4 py-2 border-t border-gray-800 text-[10px] font-mono text-gray-500 flex items-center justify-between">
        <span>ACTIVE SHELL POOL CONSOLE</span>
        <span>TOTAL RECORDED EVENTS: {logs.length}</span>
      </div>

    </div>
  );
}
