import React, { useState, useEffect } from "react";
import AuthScreen from "./components/AuthScreen";
import Dashboard from "./components/Dashboard";
import { Shield } from "lucide-react";

export default function App() {
  const [authToken, setAuthToken] = useState<string | null>("anonymous-token");
  const [currentUser, setCurrentUser] = useState<any | null>({
    id: "anonymous-operator",
    username: "Operator",
    email: "operator@recon.local",
    createdAt: new Date().toISOString()
  });

  const handleLogout = () => {
    // Simply reset session to default or reload
    window.location.reload();
  };

  return (
    <div id="app-root-viewport" className="bg-gray-950 min-h-screen">
      <Dashboard 
        authToken={authToken!} 
        user={currentUser!} 
        onLogout={handleLogout} 
      />
    </div>
  );
}
