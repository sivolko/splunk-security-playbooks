# AD/LDAP Account Locking Playbook

## Description

This playbook is designed to handle Active Directory (AD) or LDAP account locking incidents. It automates the investigation and response process when user accounts get locked due to authentication failures or suspicious activities.

## Playbook Type
Response

## Playbook Workflow

The playbook follows this general workflow:

1. Trigger on account locking event detection
2. Gather account information and recent activities
3. Analyze authentication failures
4. Determine if the lock is due to legitimate user error or potential attack
5. Execute appropriate response actions
6. Create comprehensive incident documentation

## Implementation Requirements

- Splunk SOAR with appropriate permissions
- Active Directory/LDAP integration
- Authentication logs ingestion

## Dataflow Diagram

Below is the detailed dataflow of the playbook's execution:

```
[Account Lock Event] --> [Extract User Details]
                      --> [Query Authentication Logs]
                      --> [Analyze Login Patterns]
                           |
                           +--> [Legitimate User Error?] -- Yes --> [Notify User]
                           |                                     --> [Reset Password if Needed]
                           |                                     --> [Unlock Account]
                           |
                           +--> [Suspicious Activity?] -- Yes --> [Maintain Lock]
                                                               --> [Escalate to SOC]
                                                               --> [Additional Investigation]
```

## Implementation Steps

1. Configure Splunk SOAR to trigger this playbook on account locking events
2. Ensure proper integration with AD/LDAP services
3. Set up appropriate notification channels
4. Customize response actions based on your organization's security policies

## Code Overview

The playbook code handles:
- AD/LDAP queries to gather account information
- Authentication log retrieval and analysis
- Decision logic to differentiate between user error and potential attacks
- Automated response actions including account unlocking or escalation
- Documentation and notification processes
