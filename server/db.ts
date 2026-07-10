import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { User, ScanRecord, AuditLog, DashboardStats } from "../src/types";

const DB_DIR = process.env.VERCEL 
  ? "/tmp/database" 
  : path.join(process.cwd(), "database");
const DB_FILE = path.join(DB_DIR, "db.json");

interface DatabaseSchema {
  users: UserRecord[];
  scans: ScanRecord[];
  logs: AuditLog[];
}

interface UserRecord extends User {
  passwordHash: string;
  salt: string;
}

let memoryDB: DatabaseSchema = {
  users: [],
  scans: [],
  logs: []
};

let useMemoryDB = false;

// Ensure the database directory exists and initialize file
function initDatabase() {
  try {
    if (!fs.existsSync(DB_DIR)) {
      fs.mkdirSync(DB_DIR, { recursive: true });
    }
    if (!fs.existsSync(DB_FILE)) {
      const initialData: DatabaseSchema = {
        users: [],
        scans: [],
        logs: [],
      };
      fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2), "utf8");
      memoryDB = initialData;
    }
  } catch (err) {
    console.error("Failed to initialize database file. Falling back to memory DB:", err);
    useMemoryDB = true;
  }
}

// Read database contents
function readDB(): DatabaseSchema {
  if (useMemoryDB) {
    return memoryDB;
  }
  initDatabase();
  if (useMemoryDB) {
    return memoryDB;
  }
  try {
    const raw = fs.readFileSync(DB_FILE, "utf8");
    const parsed = JSON.parse(raw);
    memoryDB = parsed;
    return parsed;
  } catch (err) {
    console.error("Failed to read database file, using in-memory store:", err);
    useMemoryDB = true;
    return memoryDB;
  }
}

// Write database contents safely
function writeDB(data: DatabaseSchema) {
  memoryDB = data;
  if (useMemoryDB) {
    return;
  }
  try {
    if (!fs.existsSync(DB_DIR)) {
      fs.mkdirSync(DB_DIR, { recursive: true });
    }
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), "utf8");
  } catch (err) {
    console.error("Failed to write to database file, using in-memory store:", err);
    useMemoryDB = true;
  }
}

// Cryptography helper for passwords
export function hashPassword(password: string): { hash: string; salt: string } {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
  return { hash, salt };
}

export function verifyPassword(password: string, hash: string, salt: string): boolean {
  const testHash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
  return hash === testHash;
}

// User Management Actions
export function createUser(username: string, email: string, password: string): { user?: User; error?: string } {
  const db = readDB();
  
  // Check duplicate username or email
  const lowerEmail = email.toLowerCase().trim();
  const lowerUsername = username.toLowerCase().trim();
  
  if (db.users.some(u => u.email.toLowerCase() === lowerEmail)) {
    addAuditLogInternal("SYSTEM", "user_registration_failed", null, null, "error", `Email ${email} already registered`);
    return { error: "Email address is already registered." };
  }
  if (db.users.some(u => u.username.toLowerCase() === lowerUsername)) {
    addAuditLogInternal("SYSTEM", "user_registration_failed", null, null, "error", `Username ${username} already taken`);
    return { error: "Username is already taken." };
  }

  const { hash, salt } = hashPassword(password);
  const newUser: UserRecord = {
    id: crypto.randomUUID(),
    username: username.trim(),
    email: lowerEmail,
    createdAt: new Date().toISOString(),
    passwordHash: hash,
    salt: salt,
  };

  db.users.push(newUser);
  writeDB(db);

  addAuditLogInternal(newUser.id, "user_registration_success", newUser.id, newUser.email, "success", `User ${username} successfully registered`);

  const { passwordHash, salt: _, ...userDto } = newUser;
  return { user: userDto };
}

export function authenticateUser(emailOrUsername: string, password: string): { user?: User; error?: string } {
  const db = readDB();
  const target = emailOrUsername.toLowerCase().trim();
  
  const userRecord = db.users.find(
    u => u.email.toLowerCase() === target || u.username.toLowerCase() === target
  );

  if (!userRecord) {
    addAuditLogInternal("SYSTEM", "user_authentication_failed", null, null, "error", `Failed login attempt for identifier: ${emailOrUsername}`);
    return { error: "Invalid username or password." };
  }

  const isValid = verifyPassword(password, userRecord.passwordHash, userRecord.salt);
  if (!isValid) {
    addAuditLogInternal(userRecord.id, "user_authentication_failed", userRecord.id, userRecord.email, "error", `Invalid password supplied for user: ${userRecord.username}`);
    return { error: "Invalid username or password." };
  }

  addAuditLogInternal(userRecord.id, "user_authentication_success", userRecord.id, userRecord.email, "success", `User ${userRecord.username} logged in successfully`);

  const { passwordHash: _, salt: __, ...userDto } = userRecord;
  return { user: userDto };
}

export function getUserById(userId: string): User | null {
  if (userId === "anonymous-operator") {
    return {
      id: "anonymous-operator",
      username: "Operator",
      email: "operator@recon.local",
      createdAt: new Date().toISOString(),
    };
  }
  const db = readDB();
  const user = db.users.find(u => u.id === userId);
  if (!user) return null;
  const { passwordHash: _, salt: __, ...userDto } = user;
  return userDto;
}

// Scan Storage Actions
export function saveScanRecord(scan: Omit<ScanRecord, "id" | "timestamp" | "userId">, userId: string | null): ScanRecord {
  const db = readDB();
  
  const fullRecord: ScanRecord = {
    ...scan,
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    userId: userId,
  };

  db.scans.push(fullRecord);
  writeDB(db);

  const userEmail = userId ? db.users.find(u => u.id === userId)?.email || null : null;
  addAuditLogInternal(
    userId || "ANONYMOUS",
    "scan_completed",
    userId,
    userEmail,
    "success",
    `Completed ${scan.type} audit on target: ${scan.target} (Risk: ${scan.securityScore.riskScore}/100)`
  );

  return fullRecord;
}

export function deleteScanRecord(scanId: string, userId: string | null): boolean {
  const db = readDB();
  const index = db.scans.findIndex(s => s.id === scanId);
  if (index === -1) return false;
  
  const scan = db.scans[index];
  db.scans.splice(index, 1);
  writeDB(db);

  addAuditLogInternal(
    "ANONYMOUS",
    "scan_deleted",
    null,
    null,
    "success",
    `Deleted historic scan record for target: ${scan.target}`
  );

  return true;
}

export function getScanHistory(userId: string | null): ScanRecord[] {
  const db = readDB();
  return [...db.scans].reverse();
}

// Audit Logs Utilities
function addAuditLogInternal(
  systemUser: string,
  action: string,
  userId: string | null,
  userEmail: string | null,
  status: "success" | "error",
  details: string
): AuditLog {
  const db = readDB();
  
  const log: AuditLog = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    action,
    userId,
    userEmail,
    target: systemUser,
    status,
    details,
  };

  db.logs.push(log);
  // Keep logs at max 1000 records to conserve filesystem size
  if (db.logs.length > 1000) {
    db.logs.shift();
  }
  writeDB(db);
  return log;
}

export function logScanRequest(userId: string | null, userEmail: string | null, target: string, action: string, details: string) {
  addAuditLogInternal(userId || "ANONYMOUS", action, userId, userEmail, "success", details);
}

export function logScanError(userId: string | null, userEmail: string | null, target: string, action: string, errorMsg: string) {
  addAuditLogInternal(userId || "ANONYMOUS", action, userId, userEmail, "error", errorMsg);
}

export function getAuditLogs(): AuditLog[] {
  const db = readDB();
  return db.logs.slice(-100).reverse(); // Return last 100 logs
}

// Statistical calculation engine for dashboard reporting
export function getDashboardStats(userId: string | null): DashboardStats {
  const db = readDB();
  const scans = db.scans;

  const totalScans = scans.length;
  const emailScans = scans.filter(s => s.type === "email");
  const domainScans = scans.filter(s => s.type === "domain");
  
  let disposableDetected = 0;
  let criticalBreachesCount = 0;
  let totalRiskScore = 0;

  const distribution = {
    safe: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };

  scans.forEach(scan => {
    totalRiskScore += scan.securityScore.riskScore;
    
    // Risk distribution aggregates
    const score = scan.securityScore.riskScore;
    if (score <= 20) distribution.safe++;
    else if (score <= 40) distribution.low++;
    else if (score <= 60) distribution.medium++;
    else if (score <= 80) distribution.high++;
    else distribution.critical++;

    // Aggregate disposable emails
    if (scan.emailValidation?.isDisposable) {
      disposableDetected++;
    }

    // Aggregate critical breaches
    scan.breaches.forEach(breach => {
      if (breach.severity === "Critical" || breach.severity === "High") {
        criticalBreachesCount++;
      }
    });
  });

  const averageRiskScore = totalScans > 0 ? Math.round(totalRiskScore / totalScans) : 0;
  const recentScans = scans.slice(-10).reverse();

  return {
    totalScans,
    emailScansCount: emailScans.length,
    domainScansCount: domainScans.length,
    disposableDetected,
    criticalBreachesCount,
    averageRiskScore,
    riskDistribution: distribution,
    recentScans,
  };
}
