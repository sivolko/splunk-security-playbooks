# Splunk Security Playbooks

This repository contains a collection of Splunk SOAR (Security Orchestration, Automation, and Response) playbooks with detailed dataflow diagrams. These playbooks are designed to automate security operations and incident response workflows.

## What are Splunk SOAR Playbooks?

Splunk SOAR playbooks automate security actions at machine speed. They execute a sequence of actions across security tools in seconds, compared to hours if performed manually. Playbooks help security teams:

- Automate repetitive security tasks
- Standardize security workflows
- Accelerate incident response
- Reduce mean time to resolution (MTTR)
- Free up analysts to focus on strategic tasks

## Repository Structure

Each playbook in this repository includes:

1. A detailed README with purpose and implementation details
2. The playbook code (in Python or JSON format)
3. A dataflow diagram showing the playbook's workflow
4. Implementation instructions

## Available Playbooks

This repository includes implementations of various Splunk SOAR playbooks:

1. [AD/LDAP Account Locking](./playbooks/ad_ldap_account_locking/)
2. [Phishing Investigation and Response](./playbooks/phishing_investigation/)
3. [Risk Notable Protect Assets and Users](./playbooks/risk_notable_protect_assets_and_users/)
4. [Risk Notable Review Indicators](./playbooks/risk_notable_review_indicators/)
5. [Start Investigation](./playbooks/start_investigation/)
6. [Threat Hunting](./playbooks/threat_hunting/)
7. [Internal Host WinRM Investigation](./playbooks/internal_host_winrm_investigation/)
8. [Identifier Reputation Analysis](./playbooks/identifier_reputation_analysis/)

## How to Use

To use these playbooks:

1. Clone this repository
2. Review the dataflow diagram to understand the playbook's workflow
3. Follow the implementation instructions in each playbook's README file
4. Import the playbook into your Splunk SOAR environment
5. Configure the playbook according to your environment

## Contributing

Contributions to this repository are welcome! Please feel free to submit pull requests for new playbooks or improvements to existing ones.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
