import React, { useState } from "react";
import { Shield, Lock, Mail, User as UserIcon, Terminal, AlertTriangle } from "lucide-react";

interface AuthScreenProps {
  onAuthSuccess: (token: string, user: any) => void;
}

export default function AuthScreen({ onAuthSuccess }: AuthScreenProps) {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    const endpoint = isLogin ? "/api/auth/login" : "/api/auth/register";
    const body = isLogin 
      ? { emailOrUsername: email || username, password } 
      : { username, email, password };

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "An error occurred during authentication.");
      }

      if (isLogin) {
        onAuthSuccess(data.token, data.user);
      } else {
        // Automatically switch to login on successful register
        setIsLogin(true);
        setError("Account created successfully! Please log in.");
        setPassword("");
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div id="auth-screen-container" className="min-h-screen flex items-center justify-center bg-gray-950 text-gray-100 p-4">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-blue-950/20 via-gray-950 to-gray-950 pointer-events-none" />
      
      <div id="auth-card" className="relative w-full max-w-md bg-gray-900 border border-gray-800 rounded-xl shadow-2xl overflow-hidden p-8 z-10">
        
        {/* Tech Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-blue-950 border border-blue-500/30 text-blue-400 mb-3">
            <Shield className="w-6 h-6 animate-pulse" />
          </div>
          <h1 className="text-2xl font-sans font-bold tracking-tight text-white mb-1">
            OSINT Recon Portal
          </h1>
        </div>

        {/* Warning Badge */}
        <div className="bg-blue-950/20 border border-blue-800/30 rounded-lg p-3 mb-6 flex items-start gap-3">
          <Terminal className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
          <span className="text-xs text-gray-300 leading-relaxed font-mono">
            This platform executes passive security posture checks. Unauthorized active harvesting is restricted.
          </span>
        </div>

        {/* Error / Info Alerts */}
        {error && (
          <div className="bg-red-950/30 border border-red-500/30 text-red-200 text-xs rounded-lg p-3 mb-6 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <span className="font-mono">{error}</span>
          </div>
        )}

        {/* Auth Forms */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {!isLogin && (
            <div className="space-y-1.5">
              <label className="block text-xs font-mono text-gray-400">USERNAME</label>
              <div className="relative">
                <UserIcon className="absolute left-3 top-2.5 w-4.5 h-4.5 text-gray-500" />
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g. sec_admin"
                  className="w-full bg-gray-950/80 border border-gray-800 rounded-lg py-2 pl-10 pr-4 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>
            </div>
          )}

          <div className="space-y-1.5">
            <label className="block text-xs font-mono text-gray-400">
              {isLogin ? "EMAIL OR USERNAME" : "EMAIL ADDRESS"}
            </label>
            <div className="relative">
              <Mail className="absolute left-3 top-2.5 w-4.5 h-4.5 text-gray-500" />
              <input
                type={isLogin ? "text" : "email"}
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder={isLogin ? "admin@company.com or username" : "admin@company.com"}
                className="w-full bg-gray-950/80 border border-gray-800 rounded-lg py-2 pl-10 pr-4 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 font-mono"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-mono text-gray-400">PASSWORD</label>
            <div className="relative">
              <Lock className="absolute left-3 top-2.5 w-4.5 h-4.5 text-gray-500" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-gray-950/80 border border-gray-800 rounded-lg py-2 pl-10 pr-4 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 font-mono"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white font-mono font-medium text-sm py-2.5 rounded-lg transition duration-200 mt-2 shadow-lg shadow-blue-900/30 flex items-center justify-center gap-2"
          >
            {loading ? (
              <span className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : isLogin ? (
              "INITIALIZE SESSION"
            ) : (
              "REGISTER SECURITY profile"
            )}
          </button>
        </form>

        {/* Footer toggle */}
        <div className="text-center mt-6 pt-6 border-t border-gray-800">
          <button
            type="button"
            onClick={() => {
              setIsLogin(!isLogin);
              setError(null);
            }}
            className="text-xs text-blue-400 hover:text-blue-300 font-mono transition"
          >
            {isLogin 
              ? "CREATE NEW MILITARY-GRADE ACCOUNT" 
              : "EXISTING OPERATIONS USER? LOGIN HERE"}
          </button>
        </div>
      </div>
    </div>
  );
}
