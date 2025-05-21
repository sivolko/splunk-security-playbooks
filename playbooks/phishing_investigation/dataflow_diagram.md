```mermaid
flowchart TD
    Start([Phishing Email Reported]) --> ParseEmail[Parse Email]
    ParseEmail --> ExtractData[Extract Indicators]
    
    subgraph "Email Analysis"
        ExtractData --> |Headers| AnalyzeHeaders[Analyze Email Headers]
        ExtractData --> |URLs| ExtractURLs[Extract URLs]
        ExtractData --> |Attachments| ExtractAttachments[Extract Attachments]
        ExtractData --> |Sender| ExtractSender[Extract Sender Info]
    end
    
    AnalyzeHeaders --> CheckSPF{Check SPF/DKIM}
    CheckSPF -->|Failed| MarkSuspicious1[Mark Suspicious]
    CheckSPF -->|Passed| AnalyzeOrigin[Analyze Origin]
    
    AnalyzeOrigin --> CheckReputation1{Check IP Reputation}
    CheckReputation1 -->|Malicious| MarkSuspicious2[Mark Suspicious]
    CheckReputation1 -->|Clean| ContinueAnalysis1[Continue Analysis]
    
    ExtractURLs --> DeobfuscateURLs[Deobfuscate URLs]
    DeobfuscateURLs --> URLReputation{Check URL Reputation}
    URLReputation -->|Malicious| MarkMalicious1[Mark Malicious]
    URLReputation -->|Suspicious| MarkSuspicious3[Mark Suspicious]
    URLReputation -->|Clean| MarkClean1[Mark Clean]
    
    ExtractAttachments --> FileAnalysis[Analyze Files]
    FileAnalysis --> StaticAnalysis[Static Analysis]
    FileAnalysis --> DynamicAnalysis[Dynamic Analysis]
    
    StaticAnalysis --> CheckHash{Check Hash Reputation}
    CheckHash -->|Malicious| MarkMalicious2[Mark Malicious]
    CheckHash -->|Unknown| SubmitSandbox[Submit to Sandbox]
    CheckHash -->|Clean| MarkClean2[Mark Clean]
    
    SubmitSandbox --> SandboxResults{Sandbox Results}
    SandboxResults -->|Malicious| MarkMalicious3[Mark Malicious]
    SandboxResults -->|Suspicious| MarkSuspicious4[Mark Suspicious]
    SandboxResults -->|Clean| MarkClean3[Mark Clean]
    
    ExtractSender --> SenderReputation{Check Sender Reputation}
    SenderReputation -->|Known Bad| MarkSuspicious5[Mark Suspicious]
    SenderReputation -->|New Sender| MarkForReview[Mark for Review]
    SenderReputation -->|Known Good| MarkClean4[Mark Clean]
    
    MarkSuspicious1 --> RiskAssessment[Risk Assessment]
    MarkSuspicious2 --> RiskAssessment
    MarkSuspicious3 --> RiskAssessment
    MarkSuspicious4 --> RiskAssessment
    MarkSuspicious5 --> RiskAssessment
    MarkMalicious1 --> RiskAssessment
    MarkMalicious2 --> RiskAssessment
    MarkMalicious3 --> RiskAssessment
    MarkClean1 --> RiskAssessment
    MarkClean2 --> RiskAssessment
    MarkClean3 --> RiskAssessment
    MarkClean4 --> RiskAssessment
    MarkForReview --> RiskAssessment
    ContinueAnalysis1 --> RiskAssessment
    
    RiskAssessment --> ThreatDetermination{Threat Level}
    
    ThreatDetermination -->|High| HighThreatActions[High Threat Actions]
    ThreatDetermination -->|Medium| MediumThreatActions[Medium Threat Actions]
    ThreatDetermination -->|Low| LowThreatActions[Low Threat Actions]
    ThreatDetermination -->|Benign| BenignActions[Benign Actions]
    
    subgraph "Response Actions"
        HighThreatActions --> QuarantineEmail1[Quarantine Email]
        HighThreatActions --> BlockURLs1[Block URLs/Domains]
        HighThreatActions --> BlockSender1[Block Sender]
        HighThreatActions --> SearchSimilar1[Search Similar Emails]
        HighThreatActions --> AlertIR1[Alert IR Team]
        
        MediumThreatActions --> QuarantineEmail2[Quarantine Email]
        MediumThreatActions --> BlockURLs2[Block URLs/Domains]
        MediumThreatActions --> SearchSimilar2[Search Similar Emails]
        MediumThreatActions --> NotifyAnalyst1[Notify Analyst]
        
        LowThreatActions --> QuarantineEmail3[Quarantine Email]
        LowThreatActions --> WarnUser1[Warn User]
        LowThreatActions --> NotifyAnalyst2[Notify Analyst]
        
        BenignActions --> ReturnEmail[Return Email to User]
        BenignActions --> DocumentDecision[Document Decision]
    end
    
    QuarantineEmail1 --> DocumentIncident[Document Incident]
    BlockURLs1 --> DocumentIncident
    BlockSender1 --> DocumentIncident
    SearchSimilar1 --> DocumentIncident
    AlertIR1 --> DocumentIncident
    
    QuarantineEmail2 --> DocumentIncident
    BlockURLs2 --> DocumentIncident
    SearchSimilar2 --> DocumentIncident
    NotifyAnalyst1 --> DocumentIncident
    
    QuarantineEmail3 --> DocumentIncident
    WarnUser1 --> DocumentIncident
    NotifyAnalyst2 --> DocumentIncident
    
    ReturnEmail --> DocumentIncident
    DocumentDecision --> DocumentIncident
    
    DocumentIncident --> CloseIncident([Close Incident])
    
    class Start,CloseIncident start-end;
    class CheckSPF,URLReputation,CheckHash,SandboxResults,SenderReputation,ThreatDetermination decision;
    class Email Analysis subgraph-highlight;
    class Response Actions subgraph-actions;
    
    classDef start-end fill:#66ffcc,stroke:#333,stroke-width:2px;
    classDef decision fill:#ffcc99,stroke:#333,stroke-width:2px;
    classDef subgraph-highlight fill:#e6f7ff,stroke:#333,stroke-width:1px;
    classDef subgraph-actions fill:#fff2e6,stroke:#333,stroke-width:1px;
```
