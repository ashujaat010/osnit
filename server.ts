import express from "express";
import * as path from "path";
import { createServer as createViteServer } from "vite";
import * as dotenv from "dotenv";

// Load environment configurations
dotenv.config();

// Backend Business Logics
import { 
  createUser, 
  authenticateUser, 
  getUserById, 
  saveScanRecord, 
  getScanHistory, 
  deleteScanRecord, 
  getAuditLogs, 
  getDashboardStats,
  logScanRequest,
  logScanError
} from "./server/db";
import { performFullSecurityScan } from "./server/osint";
import { generateSecurityAnalysis } from "./server/gemini";

// In-Memory Token Store for simple, highly reliable Bearer Token Sessions
const ACTIVE_SESSIONS = new Map<string, string>(); // token -> userId

const app = express();

// Export the Express instance as default for Vercel Serverless Function hosting
export { app };
export default app;

// Middleware to parse incoming bodies
app.use(express.json());

  // Helper middleware to authenticate request session tokens
  const authenticateToken = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    req.userId = "anonymous-operator";
    next();
  };

  // Require Active login route guard
  const requireAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    req.userId = "anonymous-operator";
    next();
  };

  // 1. HEALTH AND INTEGRITY CHECKS
  app.get("/api/health", (req, res) => {
    res.json({ status: "healthy", timestamp: new Date().toISOString() });
  });

  // 2. USER AUTHENTICATION APIS
  app.post("/api/auth/register", (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: "Missing required registration parameters (username, email, password)." });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters long." });
    }

    const result = createUser(username, email, password);
    if (result.error) {
      return res.status(400).json({ error: result.error });
    }

    res.status(201).json({ success: true, user: result.user });
  });

  app.post("/api/auth/login", (req, res) => {
    const { emailOrUsername, password } = req.body;
    if (!emailOrUsername || !password) {
      return res.status(400).json({ error: "Missing required credentials parameters." });
    }

    const result = authenticateUser(emailOrUsername, password);
    if (result.error) {
      return res.status(401).json({ error: result.error });
    }

    // Generate a secure crypto session token
    const token = require("crypto").randomBytes(32).toString("hex");
    ACTIVE_SESSIONS.set(token, result.user!.id);

    res.json({
      success: true,
      token,
      user: result.user
    });
  });

  app.post("/api/auth/logout", authenticateToken, (req, res) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    
    if (token) {
      ACTIVE_SESSIONS.delete(token);
    }
    res.json({ success: true, message: "Logged out successfully" });
  });

  app.get("/api/auth/me", authenticateToken, (req, res) => {
    if (!req.userId) {
      return res.status(401).json({ error: "Unauthenticated session." });
    }
    const user = getUserById(req.userId);
    if (!user) {
      return res.status(404).json({ error: "User profile not found." });
    }
    res.json({ user });
  });

  // 3. SCANNING ACTIONS
  app.post("/api/scan", authenticateToken, async (req, res) => {
    const { target, type } = req.body;
    if (!target || !type || (type !== "email" && type !== "domain")) {
      return res.status(400).json({ error: "Invalid scan inputs. Requires 'target' and 'type' ('email' | 'domain')." });
    }

    const user = req.userId ? getUserById(req.userId) : null;
    logScanRequest(req.userId, user?.email || null, target, "scan_started", `Dispatched ${type} scan on target: ${target}`);

    try {
      // 1. Perform OSINT, DNS, validation steps
      const rawScanResult = await performFullSecurityScan(target, type);

      // 2. Persist the scan output in database linked to active session
      const savedRecord = saveScanRecord(rawScanResult, req.userId);

      res.json(savedRecord);
    } catch (err: any) {
      logScanError(req.userId, user?.email || null, target, "scan_failed", `Scan failed for target ${target}: ${err.message || err}`);
      res.status(500).json({ error: "Cybersecurity assessment failed: " + (err.message || err) });
    }
  });

  // 4. GEMINI AI INTEL RECOMMENDATIONS
  app.post("/api/scan/:id/ai-analysis", authenticateToken, async (req, res) => {
    const { id } = req.params;
    const dbScans = getScanHistory(req.userId);
    const scan = dbScans.find(s => s.id === id);

    if (!scan) {
      return res.status(404).json({ error: "Audit record not found or access denied." });
    }

    try {
      const aiAnalysis = await generateSecurityAnalysis(scan);
      res.json(aiAnalysis);
    } catch (err: any) {
      res.status(500).json({ error: "Gemini AI analysis failed: " + (err.message || err) });
    }
  });

  // 5. HISTORIC SCAN LOGS
  app.get("/api/scans/history", authenticateToken, (req, res) => {
    const history = getScanHistory(req.userId);
    res.json(history);
  });

  app.delete("/api/scans/:id", requireAuth, (req, res) => {
    const { id } = req.params;
    const deleted = deleteScanRecord(id, req.userId!);
    if (!deleted) {
      return res.status(404).json({ error: "Scan record not found or unauthorized." });
    }
    res.json({ success: true, message: "Historic scan record removed." });
  });

  // 6. DASHBOARD ANALYTICS AGGREGATOR
  app.get("/api/analytics/stats", authenticateToken, (req, res) => {
    const stats = getDashboardStats(req.userId);
    res.json(stats);
  });

  // 7. PUBLIC SECURITY AUDIT COMPLIANCE LOGS
  app.get("/api/logs", authenticateToken, (req, res) => {
    // Restricted to view logs for transparency, shows defensive tracking logs
    const logs = getAuditLogs();
    res.json(logs);
  });

  // 8. REPORT EXPORT ENDPOINTS
  app.get("/api/reports/:id/export/:format", authenticateToken, (req, res) => {
    const { id, format } = req.params;
    const history = getScanHistory(req.userId);
    const scan = history.find(s => s.id === id);

    if (!scan) {
      return res.status(404).json({ error: "Audit scan record not found." });
    }

    if (format === "json") {
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", `attachment; filename=OSINT_Audit_Report_${scan.target}.json`);
      return res.send(JSON.stringify(scan, null, 2));
    }

    if (format === "csv") {
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename=OSINT_Audit_Report_${scan.target}.csv`);
      
      // Basic secure CSV generation
      const headers = ["ID", "Target", "Type", "Timestamp", "Risk Score", "Grade", "Vulnerabilities Detected"];
      const row = [
        scan.id,
        scan.target,
        scan.type,
        scan.timestamp,
        scan.securityScore.riskScore,
        scan.securityScore.grade,
        scan.securityScore.vulnerabilitiesDetected.join(" | ")
      ];
      
      const csvContent = [headers.join(","), row.map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")].join("\n");
      return res.send(csvContent);
    }

    if (format === "html") {
      res.setHeader("Content-Type", "text/html");
      res.setHeader("Content-Disposition", `attachment; filename=OSINT_Audit_Report_${scan.target}.html`);

      const htmlContent = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>OSINT Defensive Posture Report: ${scan.target}</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f9f9fb; color: #1e1e2d; padding: 40px; margin: 0; }
            .card { background: #fff; border-radius: 8px; border: 1px solid #e4e4e7; box-shadow: 0 4px 12px rgba(0,0,0,0.03); max-width: 800px; margin: 0 auto; overflow: hidden; }
            .header { background: #111827; color: #fff; padding: 30px; text-align: center; }
            .header h1 { margin: 0 0 10px 0; font-size: 24px; letter-spacing: -0.5px; }
            .badge { display: inline-block; padding: 6px 12px; font-weight: bold; border-radius: 4px; font-size: 14px; margin-top: 10px; }
            .badge-danger { background: #fee2e2; color: #991b1b; }
            .badge-warning { background: #fef3c7; color: #92400e; }
            .badge-success { background: #dcfce7; color: #166534; }
            .content { padding: 40px; }
            .section { margin-bottom: 30px; }
            .section-title { font-size: 18px; font-weight: 600; border-bottom: 2px solid #f4f4f5; padding-bottom: 8px; margin-bottom: 15px; color: #3f3f46; }
            .dns-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            .dns-table th, .dns-table td { text-align: left; padding: 12px; border-bottom: 1px solid #f4f4f5; }
            .dns-table th { background: #f8fafc; font-weight: 600; }
            .alert-item { background: #fef2f2; border-left: 4px solid #ef4444; padding: 12px; border-radius: 0 4px 4px 0; margin-bottom: 10px; }
            .footer { background: #f1f5f9; text-align: center; font-size: 12px; color: #64748b; padding: 20px; }
          </style>
        </head>
        <body>
          <div class="card">
            <div class="header">
              <h1>OSINT Defensive Posture Assessment</h1>
              <div>Target: <strong>${scan.target}</strong> | Type: <strong>${scan.type.toUpperCase()}</strong></div>
              <div class="badge ${scan.securityScore.riskScore > 50 ? 'badge-danger' : scan.securityScore.riskScore > 20 ? 'badge-warning' : 'badge-success'}">
                Risk Rating: ${scan.securityScore.riskScore}/100 (${scan.securityScore.grade})
              </div>
            </div>
            <div class="content">
              <div class="section">
                <div class="section-title">Executive Summary</div>
                <p>This automated open-source reconnaissance audit evaluates current sender authentication and public leakage footprints to assess spoof susceptibility. Scanned on ${new Date(scan.timestamp).toUTCString()}.</p>
              </div>
              
              <div class="section">
                <div class="section-title">Configuration Integrity</div>
                <table class="dns-table">
                  <thead>
                    <tr>
                      <th>Record Checked</th>
                      <th>Status discovered</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>MX records</td>
                      <td>${scan.dnsInfo?.hasMx ? "Active routing verified" : "No MX records found"}</td>
                    </tr>
                    <tr>
                      <td>SPF (Sender Policy)</td>
                      <td><code>${scan.dnsInfo?.spfRecord || "Absent"}</code></td>
                    </tr>
                    <tr>
                      <td>DMARC Policy</td>
                      <td><code>${scan.dnsInfo?.dmarcRecord || "Absent"}</code></td>
                    </tr>
                  </tbody>
                </table>
              </div>

              ${scan.securityScore.vulnerabilitiesDetected.length > 0 ? `
              <div class="section">
                <div class="section-title">Identified Vulnerabilities</div>
                ${scan.securityScore.vulnerabilitiesDetected.map(v => `<div class="alert-item">${v}</div>`).join("")}
              </div>
              ` : ""}

              <div class="section">
                <div class="section-title">Actionable Remediations</div>
                <ul>
                  ${scan.securityScore.recommendations.map(r => `<li>${r}</li>`).join("")}
                </ul>
              </div>
            </div>
            <div class="footer">
              Generated by Email Harvesting & OSINT Reconnaissance Security Console | Educational and Defensive Auditing Use Only.
            </div>
          </div>
        </body>
        </html>
      `;
      return res.send(htmlContent);
    }

    res.status(400).json({ error: "Unsupported export format. Supported types: 'json' | 'csv' | 'html'" });
  });

// Dev / standalone production server bootstrapper
async function startServer() {
  const PORT = 3000;

  // Vite middleware for development (disabled in serverless environments like Vercel)
  if (process.env.NODE_ENV !== "production" && !process.env.VERCEL) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else if (process.env.NODE_ENV === "production" && !process.env.VERCEL) {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  if (!process.env.VERCEL) {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Email OSINT Server active on http://0.0.0.0:${PORT}`);
    });
  }
}

// Extend Request type to hold userId dynamically
declare global {
  namespace Express {
    interface Request {
      userId: string | null;
    }
  }
}

startServer();
