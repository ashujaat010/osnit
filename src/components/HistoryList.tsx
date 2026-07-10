import React, { useState } from "react";
import { Mail, Globe, Calendar, Trash2, ChevronRight, Eye, ShieldAlert, ArrowUpDown, Search } from "lucide-react";
import { ScanRecord } from "../types";

interface HistoryListProps {
  scans: ScanRecord[];
  onSelectScan: (scan: ScanRecord) => void;
  onDeleteScan: (id: string) => void;
  loading: boolean;
}

export default function HistoryList({ scans, onSelectScan, onDeleteScan, loading }: HistoryListProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState<"all" | "email" | "domain">("all");
  const [sortOrder, setSortOrder] = useState<"desc" | "asc">("desc");

  const filteredScans = scans
    .filter(scan => {
      const matchesSearch = scan.target.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesType = filterType === "all" || scan.type === filterType;
      return matchesSearch && matchesType;
    })
    .sort((a, b) => {
      const dateA = new Date(a.timestamp).getTime();
      const dateB = new Date(b.timestamp).getTime();
      return sortOrder === "desc" ? dateB - dateA : dateA - dateB;
    });

  const getScoreColor = (score: number) => {
    if (score <= 20) return "text-green-400 bg-green-950/20 border-green-800/30";
    if (score <= 50) return "text-amber-400 bg-amber-950/20 border-amber-800/30";
    return "text-red-400 bg-red-950/20 border-red-800/30";
  };

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case "A": return "text-green-400";
      case "B": return "text-teal-400";
      case "C": return "text-amber-400";
      case "D": return "text-orange-400";
      case "F": return "text-red-400 font-bold animate-pulse";
      default: return "text-gray-400";
    }
  };

  return (
    <div id="history-list-container" className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden shadow-lg">
      
      {/* Header and Controls */}
      <div className="p-5 border-b border-gray-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <h3 className="text-base font-sans font-semibold text-white">Recent Security Audits</h3>
            <p className="text-xs text-gray-400 font-mono">HISTORIC SCAN METRICS PERSISTENCE</p>
          </div>
          <div className="flex items-center gap-1.5 bg-gray-950 p-1 rounded-lg border border-gray-800">
            <button
              onClick={() => setFilterType("all")}
              className={`px-2.5 py-1 text-xs font-mono rounded transition ${
                filterType === "all" ? "bg-gray-800 text-white" : "text-gray-400 hover:text-white"
              }`}
            >
              ALL
            </button>
            <button
              onClick={() => setFilterType("email")}
              className={`px-2.5 py-1 text-xs font-mono rounded transition ${
                filterType === "email" ? "bg-gray-800 text-white" : "text-gray-400 hover:text-white"
              }`}
            >
              EMAILS
            </button>
            <button
              onClick={() => setFilterType("domain")}
              className={`px-2.5 py-1 text-xs font-mono rounded transition ${
                filterType === "domain" ? "bg-gray-800 text-white" : "text-gray-400 hover:text-white"
              }`}
            >
              DOMAINS
            </button>
          </div>
        </div>

        {/* Search Input */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2.5 w-4.5 h-4.5 text-gray-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search target domains or email addresses..."
              className="w-full bg-gray-950/80 border border-gray-800 rounded-lg py-2 pl-10 pr-4 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 font-mono transition"
            />
          </div>
          <button
            onClick={() => setSortOrder(prev => prev === "desc" ? "asc" : "desc")}
            className="flex items-center justify-center gap-1.5 px-3 py-2 bg-gray-950 hover:bg-gray-800 border border-gray-800 rounded-lg text-xs font-mono text-gray-400 hover:text-white transition"
          >
            <ArrowUpDown className="w-3.5 h-3.5" />
            {sortOrder === "desc" ? "NEWEST" : "OLDEST"}
          </button>
        </div>
      </div>

      {/* List Body */}
      {loading ? (
        <div className="p-8 text-center text-gray-500 font-mono text-xs">
          <span className="w-6 h-6 border-2 border-blue-500/20 border-t-blue-400 rounded-full animate-spin inline-block mb-2" />
          <p>Retrieving database records...</p>
        </div>
      ) : filteredScans.length === 0 ? (
        <div className="p-12 text-center text-gray-500 font-mono text-xs border-dashed border-2 border-gray-800 m-4 rounded-lg">
          <ChevronRight className="w-8 h-8 text-gray-700 mx-auto mb-2" />
          <p className="font-semibold text-gray-400 mb-1">No scanned assets discovered</p>
          <p className="text-gray-600">Run a defensive email or domain audit above to populate history logs.</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-gray-950 text-gray-400 border-b border-gray-800">
              <tr>
                <th className="p-4 font-normal">AUDIT TARGET</th>
                <th className="p-4 font-normal">TYPE</th>
                <th className="p-4 font-normal">RISK INDEX</th>
                <th className="p-4 font-normal text-center">GRADE</th>
                <th className="p-4 font-normal hidden md:table-cell">TIMESTAMP</th>
                <th className="p-4 font-normal text-right">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {filteredScans.map((scan) => (
                <tr key={scan.id} className="hover:bg-gray-800/40 transition group">
                  {/* Target and Icon */}
                  <td className="p-4 font-sans font-medium text-white max-w-xs truncate">
                    <div className="flex items-center gap-2.5">
                      <div className="p-1.5 rounded bg-gray-950 border border-gray-800">
                        {scan.type === "email" ? (
                          <Mail className="w-3.5 h-3.5 text-blue-400" />
                        ) : (
                          <Globe className="w-3.5 h-3.5 text-indigo-400" />
                        )}
                      </div>
                      <span className="truncate">{scan.target}</span>
                    </div>
                  </td>

                  {/* Scan Type Badge */}
                  <td className="p-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold tracking-wide border uppercase ${
                      scan.type === "email" 
                        ? "text-blue-400 bg-blue-950/20 border-blue-800/20" 
                        : "text-indigo-400 bg-indigo-950/20 border-indigo-800/20"
                    }`}>
                      {scan.type}
                    </span>
                  </td>

                  {/* Risk Score */}
                  <td className="p-4">
                    <div className={`inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs border font-bold ${getScoreColor(scan.securityScore.riskScore)}`}>
                      <ShieldAlert className="w-3.5 h-3.5" />
                      {scan.securityScore.riskScore}/100
                    </div>
                  </td>

                  {/* Grade */}
                  <td className="p-4 text-center">
                    <span className={`text-lg font-bold font-sans ${getGradeColor(scan.securityScore.grade)}`}>
                      {scan.securityScore.grade}
                    </span>
                  </td>

                  {/* Timestamp */}
                  <td className="p-4 text-gray-500 hidden md:table-cell">
                    <div className="flex items-center gap-1.5 text-[11px]">
                      <Calendar className="w-3.5 h-3.5" />
                      {new Date(scan.timestamp).toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" })}
                    </div>
                  </td>

                  {/* Actions */}
                  <td className="p-4 text-right">
                    <div className="flex items-center justify-end gap-2.5">
                      <button
                        onClick={() => onSelectScan(scan)}
                        className="p-1.5 rounded bg-gray-950 hover:bg-blue-600/20 hover:text-blue-400 text-gray-400 border border-gray-800 transition flex items-center gap-1 text-[11px]"
                        title="Analyze report"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        REPORT
                      </button>
                      <button
                        onClick={() => onDeleteScan(scan.id)}
                        className="p-1.5 rounded bg-gray-950 hover:bg-red-600/20 hover:text-red-400 text-gray-500 border border-gray-800 transition"
                        title="Delete record"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
