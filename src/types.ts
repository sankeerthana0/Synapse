export interface RagDocument {
  id: string;
  title: string;
  category: 'malware' | 'network' | 'iam' | 'policy' | 'exploit';
  content: string;
  tags: string[];
}

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ThreatAnalysis {
  severity: SeverityLevel;
  confidence: number;
  indicatorsOfCompromise: string[];
  vulnerabilitiesMatched: string[];
  recommendedMitigation: string;
  mitigationSteps: string[];
}

export interface ThreatSummary {
  executiveSummary: string;
  technicalDetails: string;
  keyRisks: string[];
}

export interface ThreatAlert {
  title: string;
  channel: 'Slack' | 'PagerDuty' | 'Email' | 'Security-Center';
  priority: 'P1' | 'P2' | 'P3' | 'P4';
  payload: Record<string, any>;
  messageText: string;
}

export interface ThreatEvaluation {
  accuracyScore: number; // 0-10
  relevanceScore: number; // 0-10
  faithfulnessScore: number; // 0-10
  criticism: string;
  details: string;
}

export interface ThreatReport {
  id: string;
  timestamp: string;
  rawText: string;
  source: string;
  status: 'pending' | 'retrieved' | 'analyzed' | 'summarized' | 'alerted' | 'evaluated' | 'completed' | 'failed';
  matchedDocs: Array<{ doc: RagDocument; score: number }>;
  analysis?: ThreatAnalysis;
  summary?: ThreatSummary;
  alert?: ThreatAlert;
  evaluation?: ThreatEvaluation;
}

export interface AgentLog {
  agentName: string;
  timestamp: string;
  status: 'active' | 'completed' | 'failed';
  message: string;
  output?: any;
}

export interface GraphTrace {
  currentThreadId: string;
  nodes: {
    id: string;
    label: string;
    status: 'idle' | 'running' | 'completed' | 'failed';
    durationMs?: number;
    agentName: string;
  }[];
  edges: {
    from: string;
    to: string;
    condition?: string;
  }[];
  logs: AgentLog[];
}
