```mermaid
flowchart TD
    Start([Account Lock Event Detected]) --> ExtractData[Extract User and Account Details]
    ExtractData --> QueryLogs[Query Authentication Logs]
    QueryLogs --> AnalyzePatterns[Analyze Login Patterns and IP Sources]
    
    AnalyzePatterns --> Decision{Analyze Lock Reason}
    Decision -->|Legitimate User Error| UserError[User Error Path]
    Decision -->|Suspicious Activity| Suspicious[Suspicious Activity Path]
    Decision -->|Inconclusive| Inconclusive[Need More Information]
    
    UserError --> Notify[Notify User]
    Notify --> ResetNeeded{Password Reset Needed?}
    ResetNeeded -->|Yes| ResetPwd[Reset Password]
    ResetNeeded -->|No| Unlock[Unlock Account]
    ResetPwd --> Unlock
    Unlock --> Document1[Document Incident]
    Document1 --> End1([Close Incident])
    
    Suspicious --> MaintainLock[Maintain Account Lock]
    MaintainLock --> AlertSOC[Alert SOC Team]
    AlertSOC --> CheckCompromise{Check for Compromise}
    CheckCompromise -->|Not Compromised| CreateCase[Create Security Case]
    CheckCompromise -->|Compromised| InitiateIR[Initiate Incident Response]
    CreateCase --> Document2[Document Incident]
    InitiateIR --> IRPlaybook[Trigger Incident Response Playbook]
    Document2 --> End2([Close Incident with Recommendations])
    IRPlaybook --> End3([Follow IR Procedure])
    
    Inconclusive --> GatherMoreData[Gather Additional Data]
    GatherMoreData --> ContactUser[Contact User for Information]
    ContactUser --> Reassess[Reassess Situation]
    Reassess --> Decision
    
    subgraph Authentication Analysis
    ExtractData
    QueryLogs
    AnalyzePatterns
    end
    
    subgraph Response Paths
    UserError
    Suspicious
    Inconclusive
    end
    
    subgraph Actions
    Notify
    ResetPwd
    Unlock
    MaintainLock
    AlertSOC
    GatherMoreData
    ContactUser
    end
    
    class Start,End1,End2,End3 start-end;
    class Decision,ResetNeeded,CheckCompromise decision;
    class Authentication Analysis subgraph-highlight;
    class Response Paths subgraph-path;
    class Actions subgraph-actions;
    
    classDef start-end fill:#66ffcc,stroke:#333,stroke-width:2px;
    classDef decision fill:#ffcc99,stroke:#333,stroke-width:2px;
    classDef subgraph-highlight fill:#e6f7ff,stroke:#333,stroke-width:1px;
    classDef subgraph-path fill:#fff2e6,stroke:#333,stroke-width:1px;
    classDef subgraph-actions fill:#f5f5f5,stroke:#333,stroke-width:1px;
```
