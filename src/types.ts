export interface User {
  id: string;
  email: string;
  username: string;
  createdAt: string;
}

export interface DomainDnsInfo {
  domain: string;
  hasMx: boolean;
  mxRecords: string[];
  spfRecord: string | null;
  dmarcRecord: string | null;
  txtRecords: string[];
  aRecords: string[];
  whois: {
    registrar: string;
    creationDate: string;
    expiryDate: string;
    nameServers: string[];
    status: string[];
  };
}

export interface EmailValidationResult {
  email: string;
  syntaxValid: boolean;
  isDisposable: boolean;
  disposableProvider: string | null;
  domain: string;
  mxValid: boolean;
}

export interface BreachInfo {
  name: string;
  domain: string;
  breachDate: string;
  description: string;
  compromisedData: string[];
  severity: "Low" | "Medium" | "High" | "Critical";
}

export interface OsintResult {
  indexedSources: string[];
  githubProfile: {
    username: string | null;
    publicRepos: number;
    publicGists: number;
    followers: number;
    bio: string | null;
    associatedEmailsFound: string[];
  } | null;
  associatedHandles: string[];
  publicContactLeaks: string[];
}

export interface SecurityScorecard {
  riskScore: number; // 0 (Excellent) to 100 (Critical Risk)
  grade: "A" | "B" | "C" | "D" | "F";
  indicators: {
    label: string;
    status: "safe" | "warning" | "danger";
    description: string;
  }[];
  recommendations: string[];
  vulnerabilitiesDetected: string[];
}

export interface ScanRecord {
  id: string;
  target: string;
  type: "email" | "domain";
  userId: string | null;
  timestamp: string;
  emailValidation: EmailValidationResult | null;
  dnsInfo: DomainDnsInfo | null;
  breaches: BreachInfo[];
  osint: OsintResult | null;
  securityScore: SecurityScorecard;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  action: string;
  userId: string | null;
  userEmail: string | null;
  target: string | null;
  status: "success" | "error";
  details: string;
}

export interface DashboardStats {
  totalScans: number;
  emailScansCount: number;
  domainScansCount: number;
  disposableDetected: number;
  criticalBreachesCount: number;
  averageRiskScore: number;
  riskDistribution: {
    safe: number;      // 0-20
    low: number;       // 21-40
    medium: number;    // 41-60
    high: number;      // 61-80
    critical: number;  // 81-100
  };
  recentScans: ScanRecord[];
}
