```mermaid
flowchart TD
    Start([Start Threat Hunt]) --> LoadIOCs[Load Threat Intelligence IOCs]
    LoadIOCs --> ParseIOCs[Parse and Categorize IOCs]
    
    subgraph "Indicator Processing"
        ParseIOCs --> |IP Addresses| IPList[IP Address List]
        ParseIOCs --> |Domains| DomainList[Domain List]
        ParseIOCs --> |URLs| URLList[URL List]
        ParseIOCs --> |File Hashes| HashList[File Hash List]
        ParseIOCs --> |Email Addresses| EmailList[Email Address List]
    end
    
    IPList --> QuerySIEM1[Query SIEM for IPs]
    DomainList --> QueryDNS[Query DNS Logs]
    URLList --> QueryProxy[Query Web Proxy]
    HashList --> QueryEDR[Query EDR/EPP]
    EmailList --> QueryEmail[Query Email Security]
    
    subgraph "Security System Queries"
        QuerySIEM1 --> SIEMResults[SIEM Results]
        QueryDNS --> DNSResults[DNS Results]
        QueryProxy --> ProxyResults[Proxy Results]
        QueryEDR --> EDRResults[EDR Results]
        QueryEmail --> EmailResults[Email Results]
    end
    
    SIEMResults --> AggregateResults[Aggregate Results]
    DNSResults --> AggregateResults
    ProxyResults --> AggregateResults
    EDRResults --> AggregateResults
    EmailResults --> AggregateResults
    
    AggregateResults --> AnalyzeFindings[Analyze Findings]
    AnalyzeFindings --> MatchFound{Matches Found?}
    
    MatchFound -->|No Matches| NoThreat[No Threat Detected]
    MatchFound -->|Matches Found| ThreatDetected[Potential Threat Detected]
    
    NoThreat --> DocumentResults1[Document Results]
    DocumentResults1 --> End1([End Hunt - No Threats])
    
    ThreatDetected --> PrioritizeFindings[Prioritize Findings]
    PrioritizeFindings --> InvestigateEndpoints[Investigate Affected Endpoints]
    
    InvestigateEndpoints --> QueryDetailedLogs[Query Detailed Logs]
    InvestigateEndpoints --> CollectForensics[Collect Forensic Data]
    InvestigateEndpoints --> AnalyzeProcesses[Analyze Running Processes]
    InvestigateEndpoints --> CheckConnections[Check Network Connections]
    
    QueryDetailedLogs --> DetectedActivity{Malicious Activity Confirmed?}
    CollectForensics --> DetectedActivity
    AnalyzeProcesses --> DetectedActivity
    CheckConnections --> DetectedActivity
    
    DetectedActivity -->|Yes| ConfirmedThreat[Confirmed Threat]
    DetectedActivity -->|No| FalsePositive[False Positive]
    
    ConfirmedThreat --> TriggerIR[Trigger Incident Response]
    ConfirmedThreat --> CreateCase[Create Security Case]
    ConfirmedThreat --> DocumentThreat[Document Threat Details]
    
    FalsePositive --> UpdateIntel[Update Intelligence]
    FalsePositive --> DocumentFalsePositive[Document False Positive]
    
    TriggerIR --> End2([End Hunt - Response Initiated])
    CreateCase --> End2
    DocumentThreat --> End2
    
    UpdateIntel --> End3([End Hunt - Intel Updated])
    DocumentFalsePositive --> End3
    
    subgraph "Advanced Investigation"
        InvestigateEndpoints
        QueryDetailedLogs
        CollectForensics
        AnalyzeProcesses
        CheckConnections
    end
    
    class Start,End1,End2,End3 start-end;
    class MatchFound,DetectedActivity decision;
    class Indicator Processing subgraph-highlight1;
    class Security System Queries subgraph-highlight2;
    class Advanced Investigation subgraph-highlight3;
    
    classDef start-end fill:#66ffcc,stroke:#333,stroke-width:2px;
    classDef decision fill:#ffcc99,stroke:#333,stroke-width:2px;
    classDef subgraph-highlight1 fill:#e6f7ff,stroke:#333,stroke-width:1px;
    classDef subgraph-highlight2 fill:#fff2e6,stroke:#333,stroke-width:1px;
    classDef subgraph-highlight3 fill:#e6ffe6,stroke:#333,stroke-width:1px;
```
