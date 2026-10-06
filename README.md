L.A.Y.E.R.S. (Logical Analyst for Your Extension Risk Surface) is an open-source browser extension security scanning engine designed to identify potential vulnerabilities, misconfigurations, and security risks in browser extensions before they are installed or deployed.

The tool performs multi-layered static analysis across key components of an extension and generates a risk score to help users make informed security decisions.

<img width="1500" height="460" alt="layers-lockup-light" src="https://github.com/user-attachments/assets/eea00f50-22fe-4fa9-b43c-726181972149" />


## What L.A.Y.E.R.S. Does

L.A.Y.E.R.S. scans browser extensions on various parameters, including:
- JavaScript Analysis – Detects insecure patterns, dangerous APIs, and suspicious behaviors
- Secret Scanning – Identifies hardcoded API keys, tokens, and credentials
- URL Extraction & Analysis – Flags suspicious, external, or risky endpoints
- Permission Analysis – Evaluates requested permissions against risk levels
- Manifest Analysis – Reviews manifest configuration for insecure settings
- HTML Scanning – Detects inline scripts, injection risks, and unsafe constructs

## Risk Scoring System

L.A.Y.E.R.S. includes a built-in scoring engine that:

- Assigns weighted risk values across findings
- Generates an overall extension risk score

## Rough Arch Diagram for Layers

<img width="2400" height="1792" alt="arch diagram" src="https://github.com/user-attachments/assets/a303e1c0-3ebf-4b5f-8e07-7d6f05db1694" />

## Who Is This For?

- Security researchers
- AppSec teams
- Browser extension developers
- Enterprise security teams
- Anyone who wants to evaluate extension risk before installation

## CONTRIBUTOS/CO-AUTHORS

- Krishna Chaganti (https://www.linkedin.com/in/kchaganti)
- Anurag Mishra (https://github.com/anuragmishr06)
  
## ACKNOWLEDGEMENTS

Shoutout to all the amazing researchers who have worked on browser extension security previously
Please feel free to contribute to the tool.
