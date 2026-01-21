# Documentation

This documentation describes the App Attest Backend Verification Service. Read these chapters in order for a complete understanding of the system.

## Reading Order

1. **[Overview](./01-Overview.md)** - What this service does and its scope
2. **[Concepts](./02-Concepts.md)** - Key terms and their meanings
3. **[Protocol Flow](./03-Protocol-Flow.md)** - How the three-endpoint flow works
4. **[Verification Semantics](./04-Verification-Semantics.md)** - What "verified" means and does not provide
5. **[Examples](./05-Examples.md)** - API usage examples
6. **[Security Composition](./06-Security-Composition.md)** - Integrating verification into a secure system
7. **[Observable Properties](./07-Observable-Properties.md)** - Measurable protocol behavior
8. **[Testing](./08-Testing.md)** - How to test the service

## Technical Reference

- **[Implementation Details](./09-Implementation-Details.md)** - Current implementation specifics
- **[Cryptographic Verification](./10-Cryptographic-Verification.md)** - Signature verification mechanics
- **[Identity Bindings](./11-Identity-Bindings.md)** - Binding enforcement details
- **[Logging](./12-Logging.md)** - Logging format and forensic analysis

## Appendices

- **[Common Issues](./A1-Common-Issues.md)** - Troubleshooting guide
- **[Signature Format](./A2-Signature-Format.md)** - DER vs raw signature handling
- **[Platform Notes](./A3-Platform-Notes.md)** - Linux verification limitations
- **[Build System](./A4-Build-System.md)** - Build and deployment details
