# Beyond the Banner: AI-Powered Network Traffic Analysis for Privacy Risk Detection

## Abstract

The pervasive and opaque processing of personal data by technology vendors poses substantial challenges for organisations seeking to verify privacy claims and ensure regulatory compliance. Current privacy assessments, particularly within Data Protection Impact Assessments (DPIAs), often rely on vendor-provided information, leaving the actual technical behaviour of systems insufficiently scrutinised. SURF, the national research and education network of the Netherlands, conducts state-of-the-art technical testing of network traffic to validate vendor practices. However, existing tools such as Burp Suite, mitmproxy, HTTP Toolkit, and WireShark, originally designed for cybersecurity, require extensive manual effort to identify privacy-relevant data flows, rendering large-scale analysis inefficient and error-prone.

This thesis aims to address this gap by developing an open-source, AI-enhanced tool specifically tailored for privacy-focused network traffic analysis. The tool automates the classification of personal data, maps and categorises data flows, identifies tracking behaviours (including cross-site identifiers and fingerprinting), and detects consent violations. It introduces automated endpoint mapping with risk scoring, multi-context tracking analysis, and human-in-the-loop verification to ensure transparency and accuracy. The approach prioritises the observation of actual data flows over stated policies, which enables reproducible, evidence-based assessments that strengthen organisational positions in negotiations with vendors and support proactive data protection strategies.

By integrating automation into technical privacy research, this work aims to advance the scalability, accuracy, and legal robustness of DPIAs, and offers a methodological shift from trust-based to evidence-based privacy verification. The resulting tool will aid privacy professionals in their analysises and provide privacy-conscious vendors with a means to audit their own practices, thus contributing to a more accountable digital ecosystem. 

## Development

Install the package locally in editable mode:

```bash
pip install -e .
```

Run the CLI:

```bash
data-flow-analyser healthcheck
```
