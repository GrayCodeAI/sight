# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes |
| 0.2.x   | Yes |
| < 0.2   | No  |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Email: security@graycode.ai

### Response Timeline
- Acknowledgment: 48 hours
- Initial assessment: 5 business days
- Fix: 7-30 days depending on severity

## Security Considerations

- sight is a library — it does not make network calls itself
- LLM provider calls are made by the consumer (via Provider interface)
- Diff content is passed to the LLM; consumers are responsible for redacting secrets
- No credentials are stored or transmitted by sight itself
