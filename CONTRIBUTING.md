# Contributing to Splunk Security Playbooks

Thank you for your interest in contributing to the Splunk Security Playbooks repository! This document provides guidelines and instructions for contributing.

## How to Contribute

1. **Fork the repository**: Create a fork of this repository to your GitHub account.

2. **Clone the fork**: Clone your fork to your local machine.
   ```
   git clone https://github.com/YOUR-USERNAME/splunk-security-playbooks.git
   ```

3. **Create a branch**: Create a new branch for your feature or fix.
   ```
   git checkout -b feature/your-feature-name
   ```

4. **Make changes**: Implement your changes, following the structure and guidelines below.

5. **Commit changes**: Commit your changes with clear, descriptive commit messages.
   ```
   git commit -m "Add detailed description of changes"
   ```

6. **Push changes**: Push your changes to your forked repository.
   ```
   git push origin feature/your-feature-name
   ```

7. **Create Pull Request**: Open a pull request from your fork to the main repository.

## Playbook Structure

When adding a new playbook, please follow this structure:

```
playbooks/
└── your_playbook_name/
    ├── README.md           # Description, purpose, and implementation details
    ├── playbook_code.py    # Python code for the playbook
    ├── dataflow_diagram.md # Mermaid diagram showing the playbook workflow
    └── implementation/     # Optional: Additional implementation files
```

### README.md Requirements

Each playbook README should include:

1. Title and description
2. Playbook type
3. General workflow description
4. Implementation requirements
5. Implementation steps
6. Code overview

### Dataflow Diagram Requirements

Dataflow diagrams should:

1. Be created using Mermaid syntax
2. Show the complete workflow of the playbook
3. Include decision points and branching paths
4. Use appropriate styling for different node types
5. Be organized with logical subgraphs where appropriate

## Style Guidelines

- Use clear, descriptive names for functions and variables
- Include comments for complex sections of code
- Follow Python PEP 8 style guide for Python code
- Use markdown formatting consistently in documentation

## Testing

Before submitting a pull request, please:

1. Test your playbook in a test SOAR environment if possible
2. Ensure diagrams render correctly on GitHub
3. Verify all links in documentation work correctly

## Questions?

If you have questions or need clarification, please open an issue in the repository.

Thank you for contributing!
