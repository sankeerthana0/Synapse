import express from 'express';
import path from 'path';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI, Type } from '@google/genai';
import { RagDocument, ThreatReport, SeverityLevel, ThreatAnalysis, ThreatSummary, ThreatAlert, ThreatEvaluation } from './src/types';
import { initialRagDocuments, initialThreatReports } from './src/dbPreset';

// Load environment variables (.env)
dotenv.config();

// Memory store of threat reports starts with preset samples
let dbThreatReports: ThreatReport[] = [...initialThreatReports];
let dbRagDocuments: RagDocument[] = [...initialRagDocuments];

const PORT = 3000;

// Similarity Matcher - Simulates FAISS / ChromaDB Jaccard Term-Overlap similarity token lookup
function runRAGSearch(query: string, docs: RagDocument[]): Array<{ doc: RagDocument; score: number }> {
  const tokenize = (text: string): string[] => {
    return text.toLowerCase()
      .replace(/[^a-z0-9\s]/gi, ' ')
      .split(/\s+/)
      .filter(t => t.length > 2 && !['the', 'and', 'for', 'with', 'that', 'from', 'log', 'incident', 'request', 'status', 'attempts', 'detected'].includes(t));
  };

  const queryTokens = tokenize(query);
  if (queryTokens.length === 0) {
    return docs.map(d => ({ doc: d, score: 0 }));
  }

  const matches = docs.map(doc => {
    const docText = `${doc.title} ${doc.content} ${doc.tags.join(' ')}`;
    const docTokens = tokenize(docText);
    const docSet = new Set(docTokens);
    
    let intersectionCount = 0;
    queryTokens.forEach(token => {
      if (docSet.has(token)) {
        intersectionCount += 1;
      }
    });

    const unionTokens = new Set([...queryTokens, ...docTokens]);
    const score = unionTokens.size > 0 ? intersectionCount / unionTokens.size : 0;
    
    // Scale or weight if there's any strict matches on explicit headers or categories
    let weightedScore = score * 3.5; // Scale to representative match range 0.0 - 1.0
    if (weightedScore > 0.95) weightedScore = 0.95;
    
    // Add structural weight on category matching
    const queryLower = query.toLowerCase();
    if (queryLower.includes(doc.category)) weightedScore += 0.1;
    doc.tags.forEach(tag => {
      if (queryLower.includes(tag.toLowerCase())) weightedScore += 0.15;
    });

    if (weightedScore > 1.0) weightedScore = 1.0;
    // Round to 2 decimal places
    weightedScore = Math.round(weightedScore * 100) / 100;

    return { doc, score: weightedScore };
  });

  // Sort descending by similarity score, filter positive matches
  return matches
    .sort((a, b) => b.score - a.score)
    .filter(m => m.score > 0.05); // threshold minimum match
}

// Lazy Gemini API Client instantiation (prevents app crashes if API key is missing on start)
let aiClient: GoogleGenAI | null = null;
function getGeminiClient(): GoogleGenAI {
  if (!aiClient) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error("GEMINI_API_KEY is not defined in system environment path.");
    }
    aiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build'
        }
      }
    });
  }
  return aiClient;
}

// Utility to safely cleanse and extract JSON structure out of markdown response blocks
function parseJSONResponse(text: string): any {
  let cleaned = text.trim();
  // Remove markdown tags if formatted as ```json or ```
  if (cleaned.startsWith('```json')) {
    cleaned = cleaned.substring(7);
  } else if (cleaned.startsWith('```')) {
    cleaned = cleaned.substring(3);
  }
  if (cleaned.endsWith('```')) {
    cleaned = cleaned.substring(0, cleaned.length - 3);
  }
  cleaned = cleaned.trim();
  return JSON.parse(cleaned);
}

async function startServer() {
  const app = express();
  app.use(express.json());

  // FastAPI Endpoint matching - OpenAPI / Swagger specifications
  app.get('/api/openapi.json', (req, res) => {
    res.json({
      openapi: "3.0.2",
      info: {
        title: "Multi-Agent Threat Intelligence API",
        description: "FastAPI-exposed threat telemetry pipeline containing automated LangGraph orchestrations, FAISS vector index context retrieval, and self-evaluation models.",
        version: "1.0.0"
      },
      paths: {
        "/api/threats": {
          "get": {
            "summary": "Retrieve Threat History",
            "description": "Returns list of all analyzed incidents paired with their RAG matching documents and pipeline evaluation scores.",
            "responses": {
              "200": { "description": "Successful Response" }
            }
          }
        },
        "/api/threats/analyze": {
          "post": {
            "summary": "Process Threat Ingress",
            "description": "Trigger multi-agent state graph pipeline orchestrating FAISS, Analysis Agent, Summarization, and Alerting workflow nodes.",
            "requestBody": {
              "required": true,
              "content": {
                "application/json": {
                  "schema": {
                    "type": "object",
                    "properties": {
                      "rawText": { "type": "string", "example": "Unauthorized root SSH connections from 185.220.101.5 on port 22..." },
                      "source": { "type": "string", "example": "SIEM Fireeye Sensor" }
                    },
                    "required": ["rawText"]
                  }
                }
              }
            },
            "responses": {
              "201": { "description": "Threat Successfully Analyzed" }
            }
          }
        },
        "/api/rag/documents": {
          "get": { "summary": "Get FAISS Index Records" },
          "post": { "summary": "Insert Guidelines Playbook Records" }
        }
      }
    });
  });

  // REST API Endpoints

  // Check state of API and Gemini authentication keys
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'healthy',
      gemini_configured: !!process.env.GEMINI_API_KEY,
      threat_history_count: dbThreatReports.length,
      kb_playbook_count: dbRagDocuments.length,
      framework: 'FastAPI (Express Bridge)',
      orchestrated_agents: ['FAISS-RAG', 'Analysis-Agent', 'Summarizer-Agent', 'Alerting-Agent', 'LLM-Evaluator']
    });
  });

  // Get index items of vector store (RAG playbooks)
  app.get('/api/rag/documents', (req, res) => {
    res.json(dbRagDocuments);
  });

  // Add new security policy record to database
  app.post('/api/rag/documents', (req, res) => {
    const { title, category, content, tags } = req.body;
    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required parameters.' });
    }
    const newDoc: RagDocument = {
      id: `rag-user-${Date.now()}`,
      title,
      category: category || 'policy',
      content,
      tags: tags || []
    };
    dbRagDocuments.unshift(newDoc);
    res.status(201).json(newDoc);
  });

  // Retrieve analysed threats list
  app.get('/api/threats', (req, res) => {
    res.json(dbThreatReports);
  });

  // Fetch individual threat item details
  app.get('/api/threats/:id', (req, res) => {
    const report = dbThreatReports.find(r => r.id === req.params.id);
    if (!report) {
      return res.status(404).json({ error: 'Threat report matching that ID was not found.' });
    }
    res.json(report);
  });

  // Delete log history item
  app.delete('/api/threats/:id', (req, res) => {
    const lengthBefore = dbThreatReports.length;
    dbThreatReports = dbThreatReports.filter(r => r.id !== req.params.id);
    if (dbThreatReports.length === lengthBefore) {
      return res.status(404).json({ error: 'System record not found.' });
    }
    res.json({ success: true, message: 'Threat record removed from registry.' });
  });

  // Reset database seeding to template presets
  app.post('/api/threats/seed', (req, res) => {
    dbThreatReports = [...initialThreatReports];
    dbRagDocuments = [...initialRagDocuments];
    res.json({ success: true, message: 'Telemetry databases re-seeded completely.', dbThreatReports, dbRagDocuments });
  });

  // Core Multi-Agent Orchestration LangGraph Simulation Endpoint
  app.post('/api/threats/analyze', async (req, res) => {
    const { rawText, source } = req.body;
    if (!rawText || !rawText.trim()) {
      return res.status(400).json({ error: "Input telemetry log body ('rawText') cannot be empty." });
    }

    const threatId = `threat-${Date.now()}`;
    const incidentSource = source || 'System Ingress Gate';

    // Step 1: LangGraph Node - Ingestion & FAISS Vector RAG Lookup
    console.log(`[LangGraph Node: FAISS RAG] Querying vector index databases for threat metrics...`);
    const matchedDocs = runRAGSearch(rawText, dbRagDocuments);
    const topMatches = matchedDocs.slice(0, 2);

    const ragContextText = topMatches.length > 0 
      ? topMatches.map(m => `### Playbook: ${m.doc.title} (Relevance Score: ${m.score})\n${m.doc.content}`).join('\n\n')
      : 'No reference playbooks or security guidelines found matching threat description.';

    // Initialize state container representing threat report state passing through edges
    const activeReport: ThreatReport = {
      id: threatId,
      timestamp: new Date().toISOString(),
      rawText,
      source: incidentSource,
      status: 'retrieved',
      matchedDocs: topMatches
    };

    // Check if Gemini API behaves correctly or is missing
    let geminiInstance: GoogleGenAI;
    try {
      geminiInstance = getGeminiClient();
    } catch (err: any) {
      return res.status(500).json({
        error: "Gemini API Configuration issue",
        message: err.message,
        missing_credentials: true,
        report_preview: {
          ...activeReport,
          status: 'failed',
          analysis: {
            severity: 'MEDIUM',
            confidence: 0.5,
            indicatorsOfCompromise: ['Unable to extract due to connection status'],
            vulnerabilitiesMatched: ['Offline Fallback Analyzer triggered'],
            recommendedMitigation: 'Please configure your GEMINI_API_KEY inside Settings > Secrets dashboard to activate full-agent workflows.',
            mitigationSteps: ['Configure GEMINI_API_KEY environment variable.']
          }
        }
      });
    }

    try {
      // Step 2: LangGraph Node - Analysis Agent (Gemini AI parsing logs + security policies)
      console.log(`[LangGraph Node: Analysis Agent] Evaluating severity and matches...`);
      const analysisPrompt = `
        You are an advanced Cyber Security Analysis Agent inside an orchestrated LangGraph system.
        Analyze the raw threat report and logs, incorporating matching organizational playbooks to evaluate details.

        RAW THREAT REPORT / LOG:
        """
        ${rawText}
        """

        RETRIEVED RAG SECURITY PLAYBOOK CONTEXT:
        """
        ${ragContextText}
        """

        Task: Analyze the incident. Extract Indicators of Compromise (IPs, emails, domains, malicious payloads, anomalous port numbers), match vulnerabilities (such as specific CVEs or attack types), dictate of severe level (LOW, MEDIUM, HIGH, or CRITICAL), provide a summarized recommendation, and list exact command-line or administrative mitigation steps.

        You MUST respond strictly with a valid JSON object matching this TypeScript type:
        {
          severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
          confidence: number; // Decimal confidence score from 0.0 to 1.0
          indicatorsOfCompromise: string[]; // List of specific indicators
          vulnerabilitiesMatched: string[]; // Vulnerabilities matched (CVE or descriptive types)
          recommendedMitigation: string; // Brief executive summary of policy action
          mitigationSteps: string[]; // List of specific sequential actions to take
        }

        Do not enclose with conversational fluff or explanation sentences. Output absolute JSON exclusively.
      `;

      const analysisResponse = await geminiInstance.models.generateContent({
        model: "gemini-3.5-flash",
        contents: analysisPrompt,
        config: {
          responseMimeType: "application/json"
        }
      });

      const parsedAnalysis: ThreatAnalysis = parseJSONResponse(analysisResponse.text || "{}");
      activeReport.analysis = parsedAnalysis;
      activeReport.status = 'analyzed';

      // Step 3: LangGraph Node - Summarization Agent
      console.log(`[LangGraph Node: Summarizer Agent] Constructing technical & executive report sections...`);
      const summaryPrompt = `
        You are a specialized Cyber Security Summarization Agent.
        Review the raw incident telemetry log and structural threat analysis metrics, then translate them into an executive security summaries report.

        RAW INCIDENT:
        """
        ${rawText}
        """

        THREAT ANALYSIS METRICS:
        ${JSON.stringify(parsedAnalysis, null, 2)}

        Task: Formulate high-level, human-readable executive summaries, technical assessments, and specific strategic operational risks that security officers must prioritize.

        You MUST respond strictly with a valid JSON format matching this schema:
        {
          executiveSummary: string; // High-level executive brief (3-4 sentences)
          technicalDetails: string; // Explanations of payloads, port entries, and targets (4-5 sentences)
          keyRisks: string[]; // List of three highly specific threat outcome risks
        }

        Ensure valid JSON block. Output nothing else.
      `;

      const summaryResponse = await geminiInstance.models.generateContent({
        model: "gemini-3.5-flash",
        contents: summaryPrompt,
        config: {
          responseMimeType: "application/json"
        }
      });

      const parsedSummary: ThreatSummary = parseJSONResponse(summaryResponse.text || "{}");
      activeReport.summary = parsedSummary;
      activeReport.status = 'summarized';

      // Step 4: LangGraph Node - Alerting Agent (Generate structured notifications payloads)
      console.log(`[LangGraph Node: Alerting Agent] Determining trigger formats and text templates...`);
      const alertPrompt = `
        You are an orchestrated Alerting Agent responsible for translating security findings into automated monitoring tool payloads (Slack, PagerDuty, Webhook).

        SEVERITY ASSESSMENT: ${parsedAnalysis.severity}
        EXECUTIVE SUMMARY: ${parsedSummary.executiveSummary}
        INDICATORS OF COMPROMISE: ${parsedAnalysis.indicatorsOfCompromise.join(', ')}

        Task: Based on threat characteristics, choose the most appropriate delivery channel ('Slack' | 'PagerDuty' | 'Email' | 'Security-Center').
        Configure priority ('P1' for Critical, 'P2' for High, 'P3' for Medium, 'P4' for Low).
        Formulate a custom Slack or terminal message payload with precise labels and trigger status.

        You MUST respond strictly with a valid JSON format:
        {
          title: string; // Incident alert title
          channel: 'Slack' | 'PagerDuty' | 'Email' | 'Security-Center';
          priority: 'P1' | 'P2' | 'P3' | 'P4';
          payload: {
            alert_id: string;
            timestamp: string;
            source_device: string;
            mitigation_lead: string;
            additional_context: Record<string, any>;
          };
          messageText: string; // Tailored instant message template with status emojis
        }

        Ensure absolute strict compliance to this JSON architecture. Output only valid JSON.
      `;

      const alertResponse = await geminiInstance.models.generateContent({
        model: "gemini-3.5-flash",
        contents: alertPrompt,
        config: {
          responseMimeType: "application/json"
        }
      });

      const parsedAlert: ThreatAlert = parseJSONResponse(alertResponse.text || "{}");
      activeReport.alert = parsedAlert;
      activeReport.status = 'alerted';

      // Step 5: LangGraph Node - Evaluation Pipeline (Score generated findings against RAG references and telemetry inputs)
      console.log(`[LangGraph Node: Evaluator Pipeline] Scoring relevance, accuracy, and faithfulness...`);
      const evaluationPrompt = `
        You are an independent Senior security Validator leading the Evaluation Pipeline in this system.
        Evaluate the orchestrated response generated by the security agents. Match findings against RAG playbooks to check faithfulness.

        RAW INGESTION TELEMETRY:
        """
        ${rawText}
        """

        REFERENCED RAG GUIDELINE:
        """
        ${ragContextText}
        """

        GENERATED ANALYSIS FINDINGS:
        """
        ${JSON.stringify(parsedAnalysis, null, 2)}
        """

        GENERATED SUMMARIES:
        """
        ${JSON.stringify(parsedSummary, null, 2)}
        """

        Task: Rate the accuracy, relevance, and context faithfulness of the generated analysis on a scale of 0 to 10 (where 10 is perfect alignment with playbooks and telemetry logs, and 0 is severe hallucinations or incorrect technical diagnostics).
        Identify technical criticism or suggestions to make the logs clearer.

        You MUST respond strictly in valid JSON format:
        {
          accuracyScore: number; // Integer score 0-10
          relevanceScore: number; // Integer score 0-10
          faithfulnessScore: number; // Integer score 0-10 (Faithful to RAG playbooks without introducing unapproved steps)
          criticism: string; // Concrete technical assessment of pipeline response
          details: string; // Explanation metrics breakdown (3-4 sentences)
        }

        Strictly output valid JSON only.
      `;

      const evaluationResponse = await geminiInstance.models.generateContent({
        model: "gemini-3.5-flash",
        contents: evaluationPrompt,
        config: {
          responseMimeType: "application/json"
        }
      });

      const parsedEvaluation: ThreatEvaluation = parseJSONResponse(evaluationResponse.text || "{}");
      activeReport.evaluation = parsedEvaluation;
      activeReport.status = 'completed';

      // Store in memory list
      dbThreatReports.unshift(activeReport);
      res.status(201).json(activeReport);

    } catch (pipelineErr: any) {
      console.error("Multi-Agent LangGraph Pipeline execution error:", pipelineErr);
      activeReport.status = 'failed';
      res.status(500).json({
        error: "Pipeline Execution Interruption",
        message: pipelineErr.message,
        partialReport: activeReport
      });
    }
  });

  // Vite host integration middleware setup
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[Secure Server] Listening on port ${PORT}`);
    console.log(`[FastAPI Docs Router] Serving api definition at /api/openapi.json`);
  });
}

startServer();
