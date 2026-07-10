import React, { useState, useEffect } from "react";
import { 
  Shield, LogOut, ShieldAlert, CheckCircle, Database, AlertCircle, 
  Activity, Users, FileText, ChevronRight, BarChart3, HelpCircle 
} from "lucide-react";
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell 
} from "recharts";

import { ScanRecord, DashboardStats } from "../types";
import ScanForm from "./ScanForm";
import HistoryList from "./HistoryList";
import ReportViewer from "./ReportViewer";
import LoggerConsole from "./LoggerConsole";

interface DashboardProps {
  authToken: string;
  user: any;
  onLogout: () => void;
}

export default function Dashboard({ authToken, user, onLogout }: DashboardProps) {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanRecord | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchDashboardData = async () => {
    try {
      // 1. Fetch dashboard stats
      const statsRes = await fetch("/api/analytics/stats", {
        headers: { "Authorization": `Bearer ${authToken}` }
      });
      const statsData = await statsRes.json();
      setStats(statsData);

      // 2. Fetch historic scans
      const scansRes = await fetch("/api/scans/history", {
        headers: { "Authorization": `Bearer ${authToken}` }
      });
      const scansData = await scansRes.json();
      setScans(scansData);
    } catch (err) {
      console.error("Failed to fetch dashboard data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, [authToken]);

  const handleScanCompleted = (newScan: ScanRecord) => {
    // Automatically trigger data updates on successful scan completion
    fetchDashboardData();
    setSelectedScan(newScan); // Auto-focus on newest scan result
  };

  const handleDeleteScan = async (scanId: string) => {
    if (!confirm("Are you sure you want to delete this historic scan record?")) {
      return;
    }
    try {
      const res = await fetch(`/api/scans/${scanId}`, {
        method: "DELETE",
        headers: { "Authorization": `Bearer ${authToken}` }
      });
      if (res.ok) {
        fetchDashboardData();
        if (selectedScan?.id === scanId) {
          setSelectedScan(null);
        }
      }
    } catch (err) {
      console.error("Failed to delete record:", err);
    }
  };

  // Convert stats distribution to Recharts friendly format
  const chartData = stats ? [
    { name: "Safe (0-20)", count: stats.riskDistribution.safe, color: "#10b981" },
    { name: "Low (21-40)", count: stats.riskDistribution.low, color: "#14b8a6" },
    { name: "Medium (41-60)", count: stats.riskDistribution.medium, color: "#f59e0b" },
    { name: "High (61-80)", count: stats.riskDistribution.high, color: "#f97316" },
    { name: "Critical (81+)", count: stats.riskDistribution.critical, color: "#ef4444" }
  ] : [];

  const getScoreColor = (score: number) => {
    if (score <= 20) return "text-green-400";
    if (score <= 50) return "text-amber-400";
    return "text-red-400";
  };

  return (
    <div id="dashboard-container" className="min-h-screen bg-gray-950 text-gray-100 flex flex-col font-sans">
      
      {/* Top Navbar */}
      <header className="bg-gray-900 border-b border-gray-800 px-6 py-4 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-650/15 border border-blue-500/30 text-blue-400 flex items-center justify-center shadow-lg shadow-blue-900/10">
              <Shield className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h1 className="text-base font-sans font-bold text-white tracking-tight">OSINT EMAIL RECON CONSOLE</h1>
              <span className="text-[10px] font-mono text-gray-500 tracking-wider">DEFENSIVE CYBER AUDITING COCKPIT</span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className="text-xs font-mono text-white font-medium">CONSOLE ACTIVE</div>
              <div className="text-[9px] font-mono text-gray-500">OPERATOR LEVEL</div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 space-y-6">
        
        {selectedScan ? (
          /* Detailed Report View Mode */
          <ReportViewer 
            scan={selectedScan} 
            authToken={authToken} 
            onBack={() => {
              setSelectedScan(null);
              fetchDashboardData();
            }} 
          />
        ) : (
          /* Dashboard Main Overview Mode */
          <>
            
            {/* Quick Stats Grid */}
            <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
              
              {/* Stat Card 1: Total Scans */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4.5 flex items-center gap-4 shadow">
                <div className="p-3 bg-blue-950/40 rounded-lg border border-blue-800/30 text-blue-400 shrink-0">
                  <Activity className="w-5 h-5" />
                </div>
                <div className="space-y-0.5 truncate">
                  <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Passive Audits</div>
                  <div className="text-xl font-mono font-bold text-white">
                    {stats ? stats.totalScans : "0"}
                  </div>
                </div>
              </div>

              {/* Stat Card 2: Average Risk Index */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4.5 flex items-center gap-4 shadow">
                <div className="p-3 bg-red-950/40 rounded-lg border border-red-800/30 text-red-400 shrink-0">
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div className="space-y-0.5 truncate">
                  <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Avg Posture Risk</div>
                  <div className="text-xl font-mono font-bold text-white">
                    {stats ? `${stats.averageRiskScore}/100` : "0%"}
                  </div>
                </div>
              </div>

              {/* Stat Card 3: Disposable Emails Detected */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4.5 flex items-center gap-4 shadow">
                <div className="p-3 bg-orange-950/40 rounded-lg border border-orange-800/30 text-orange-400 shrink-0">
                  <Users className="w-5 h-5" />
                </div>
                <div className="space-y-0.5 truncate">
                  <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Temporary domains</div>
                  <div className="text-xl font-mono font-bold text-white">
                    {stats ? stats.disposableDetected : "0"}
                  </div>
                </div>
              </div>

              {/* Stat Card 4: Critical Breach Exposures */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4.5 flex items-center gap-4 shadow">
                <div className="p-3 bg-red-950/40 rounded-lg border border-red-800/30 text-red-500 shrink-0">
                  <Database className="w-5 h-5" />
                </div>
                <div className="space-y-0.5 truncate">
                  <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Breach Exposures</div>
                  <div className="text-xl font-mono font-bold text-white">
                    {stats ? stats.criticalBreachesCount : "0"}
                  </div>
                </div>
              </div>

              {/* Stat Card 5: Deliverability / Domain scans */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4.5 flex items-center gap-4 shadow col-span-2 lg:col-span-1">
                <div className="p-3 bg-teal-950/40 rounded-lg border border-teal-800/30 text-teal-400 shrink-0">
                  <CheckCircle className="w-5 h-5" />
                </div>
                <div className="space-y-0.5 truncate">
                  <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Checked Domains</div>
                  <div className="text-xl font-mono font-bold text-white">
                    {stats ? stats.domainScansCount : "0"}
                  </div>
                </div>
              </div>

            </div>

            {/* Middle Grid: Scanner and Visual Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              
              {/* Scan Trigger Portal */}
              <div className="lg:col-span-2 space-y-6">
                <ScanForm authToken={authToken} onScanCompleted={handleScanCompleted} />

                {/* Scanned records catalog list */}
                <HistoryList 
                  scans={scans} 
                  loading={loading} 
                  onSelectScan={setSelectedScan} 
                  onDeleteScan={handleDeleteScan} 
                />
              </div>

              {/* Side Panels: Visual Analytics & Audits logger terminal */}
              <div className="lg:col-span-1 space-y-6">
                
                {/* Visual posture chart */}
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow">
                  <div className="border-b border-gray-800 pb-3 mb-4">
                    <h3 className="text-sm font-sans font-semibold text-white flex items-center gap-2">
                      <BarChart3 className="w-4 h-4 text-blue-400" />
                      Risk Posture Inventory
                    </h3>
                    <span className="text-[10px] font-mono text-gray-500 uppercase">THREAT LEVEL SPREAD</span>
                  </div>

                  <div className="h-48 w-full font-mono text-[11px]">
                    {stats && stats.totalScans > 0 ? (
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={chartData} margin={{ top: 10, right: 10, left: -25, bottom: 5 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                          <XAxis dataKey="name" stroke="#6b7280" tickLine={false} />
                          <YAxis stroke="#6b7280" tickLine={false} allowDecimals={false} />
                          <Tooltip 
                            contentStyle={{ backgroundColor: "#111827", borderColor: "#374151" }} 
                            labelStyle={{ color: "#9ca3af" }}
                            itemStyle={{ color: "#ffffff" }}
                          />
                          <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]}>
                            {chartData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.color} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    ) : (
                      <div className="h-full flex items-center justify-center text-center text-gray-600 italic">
                        No scan data inventory available. Check target accounts.
                      </div>
                    )}
                  </div>
                </div>

                {/* Audit Logger terminal feed */}
                <LoggerConsole authToken={authToken} />

              </div>

            </div>

          </>
        )}

      </main>

      {/* Corporate Compliance Footer */}
      <footer className="bg-gray-900 border-t border-gray-800 px-6 py-4 mt-12">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between text-[11px] font-mono text-gray-500 gap-3 text-center md:text-left">
          <span>© 2026 EMAIL HARVESTING & RECONNAISSANCE INTELLIGENCE SYSTEM. SECURITY TRAINING LABS.</span>
          <span className="text-gray-600 leading-normal max-w-md">
            This module operates on public records strictly adhering to ethical reconnaissance. No private bypasses or aggressive automated active scrapers are supported.
          </span>
        </div>
      </footer>

    </div>
  );
}
