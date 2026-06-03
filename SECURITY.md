# Security Policy

Raxcell is an execution-enforcement sandbox SDK. Security reports should be handled with care because the project directly affects command execution boundaries for agent runtimes.

## Supported Versions

`0.1.x` is the first Linux-focused development line.

## Reporting Security Issues

Please report suspected vulnerabilities privately through GitHub Security Advisories on the `Praxis-Agent-Architecture/Raxcell` repository.

Do not open public issues for sandbox escapes, filesystem isolation bypasses, network isolation bypasses, token/ACL issues, or denial-of-service bugs until a maintainer has reviewed the report.

## Current Security Scope

In `0.1.0`, Linux bubblewrap is the only executable backend.

In scope:

- filesystem read/write isolation failures;
- network-deny failures;
- timeout failures;
- incorrect `POLICY_DECISION_REQUIRED` handoff;
- backend artifact mismatch with actual execution;
- unsafe fail-open behavior.

Out of scope for `0.1.0` executable claims:

- native macOS execution;
- native Windows execution;
- upstream runtime approval policy;
- model or prompt behavior.
