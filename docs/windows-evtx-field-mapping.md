# Windows EVTX Field Mapping Reference

## Overview

This document specifies all verified Sigma field to Wazuh Windows decoded event field mappings. Every mapping is documented with its source, verification method, and confidence level.

Wazuh decodes Windows EventChannel logs into two primary namespaces:
- `win.system.*` - Fields from the Event/System XML element (event metadata)
- `win.eventdata.*` - Fields from Event/EventData element (provider-specific data)

Unknown Windows fields in Sigma rules are **not** silently lowercased. Instead, conversion fails in strict mode with a clear error message referencing this document.

## Mapping Table

| Sigma Field | Wazuh Field | Namespace | Category | Confidence | Verification Source | Evidence | Notes |
|-------------|-------------|-----------|----------|-----------|---------------------|----------|-------|
| EventID | win.system.eventID | system | Metadata | Verified | Windows Documentation | Doc Only | Numeric event ID from Event/System/EventID |
| event_id | win.system.eventID | system | Metadata | Verified | Repository Legacy | Doc Only | Alias for EventID |
| Provider_Name | win.system.providerName | system | Metadata | Verified | Windows Documentation | Doc Only | Provider name from Event/System/Provider@Name |
| Channel | win.system.channel | system | Metadata | Verified | Windows Documentation | Doc Only | Event log channel name from Event/System/Channel |
| ComputerName | win.system.computer | system | Metadata | Verified | Windows Documentation | Doc Only | Computer name from Event/System/Computer |
| Hostname | win.system.computer | system | Metadata | Verified | Repository Legacy | Doc Only | Alias for ComputerName |
| Image | win.eventdata.image | eventdata | Process | Verified | Decoded Fixture | sysmon_event_1 | Process image path from Sysmon Event 1, 3, etc. **Exact camelCase required.** |
| CommandLine | win.eventdata.commandLine | eventdata | Process | Verified | Decoded Fixture | sysmon_event_1 | Process command line from Sysmon Event 1. **Exact camelCase required.** |
| ParentImage | win.eventdata.parentImage | eventdata | Process | Verified | Decoded Fixture | sysmon_event_1 | Parent process image from Sysmon Event 1. **Exact camelCase required.** |
| ParentCommandLine | win.eventdata.parentCommandLine | eventdata | Process | Verified | Decoded Fixture | sysmon_event_1 | Parent process command line from Sysmon Event 1. **Exact camelCase required.** |
| ProcessId | win.eventdata.processId | eventdata | Process | Verified | Decoded Fixture | sysmon_event_1, sysmon_event_3, sysmon_event_11, sysmon_event_13 | Process ID from Sysmon. **Exact camelCase required.** |
| ParentProcessId | win.eventdata.parentProcessId | eventdata | Process | Verified | Decoded Fixture | sysmon_event_1 | Parent process ID from Sysmon. **Exact camelCase required.** |
| User | win.eventdata.user | eventdata | Process | Verified | Decoded Fixture | sysmon_event_1 | User name from Sysmon Event 1. Not always present. **Exact camelCase required.** |
| TargetFilename | win.eventdata.targetFilename | eventdata | File | Verified | Decoded Fixture | sysmon_event_11 | File path from Sysmon Event 11, 23, 26. **Exact camelCase required.** |
| SourceIp | win.eventdata.sourceIp | eventdata | Network | Verified | Decoded Fixture | sysmon_event_3, security_event_5157 | Source IP from Sysmon Event 3 (Network Connection). **Exact camelCase required.** |
| DestinationIp | win.eventdata.destinationIp | eventdata | Network | Verified | Decoded Fixture | sysmon_event_3, security_event_5157 | Destination IP from Sysmon Event 3. **Exact camelCase required.** |
| SourcePort | win.eventdata.sourcePort | eventdata | Network | Verified | Decoded Fixture | sysmon_event_3 | Source port from Sysmon Event 3. **Exact camelCase required.** |
| DestinationPort | win.eventdata.destinationPort | eventdata | Network | Verified | Decoded Fixture | sysmon_event_3 | Destination port from Sysmon Event 3. **Exact camelCase required.** |
| Protocol | win.eventdata.protocol | eventdata | Network | Verified | Decoded Fixture | sysmon_event_3 | Network protocol from Sysmon Event 3. **Exact camelCase required.** |
| Registry | win.eventdata.registryPath | eventdata | Registry | Verified | Decoded Fixture | sysmon_event_13 | Registry path from Sysmon Event 12, 13, 14. **Exact camelCase required.** |
| RegistryPath | win.eventdata.registryPath | eventdata | Registry | Verified | Decoded Fixture | sysmon_event_13 | Alias for Registry. **Exact camelCase required.** |
| Details | win.eventdata.details | eventdata | Registry | Verified | Decoded Fixture | sysmon_event_13 | Registry value data from Sysmon Event 13. **Exact camelCase required.** |
| Hashes | win.eventdata.hashes | eventdata | Hash | Verified | Decoded Fixture | sysmon_event_1 | Multi-hash string from Sysmon Event 1. **Exact camelCase required.** |
| MD5 | win.eventdata.md5 | eventdata | Hash | Verified | Decoded Fixture | sysmon_event_1 | MD5 hash from Sysmon. Extracted from Hashes field. **Exact camelCase required.** |
| SHA1 | win.eventdata.sha1 | eventdata | Hash | Verified | Decoded Fixture | sysmon_event_1 | SHA1 hash from Sysmon. Extracted from Hashes field. **Exact camelCase required.** |
| SHA256 | win.eventdata.sha256 | eventdata | Hash | Verified | Decoded Fixture | sysmon_event_1 | SHA256 hash from Sysmon. Extracted from Hashes field. **Exact camelCase required.** |
| Imphash | win.eventdata.imphash | eventdata | Hash | Verified | Decoded Fixture | sysmon_event_1 | Import hash from Sysmon Event 1. **Exact camelCase required.** |
| LogonType | win.eventdata.logonType | eventdata | Authentication | Verified | Decoded Fixture | security_event_4624 | Logon type from Security Event 4624. Values: 0=System, 2=Interactive, 3=Network, etc. **Exact camelCase required.** |
| LogonGuid | win.eventdata.logonGuid | eventdata | Authentication | Verified | Decoded Fixture | security_event_4624 | Logon GUID from Security Event 4624. Unique session identifier. **Exact camelCase required.** |
| TargetUserName | win.eventdata.targetUserName | eventdata | Authentication | Verified | Decoded Fixture | security_event_4624 | Target user name (account being logged in to) from Security events. **Exact camelCase required.** |
| SubjectUserName | win.eventdata.subjectUserName | eventdata | Authentication | Verified | Decoded Fixture | security_event_4624 | Subject user name (account performing the action) from Security events. **Exact camelCase required.** |
| TargetHostname | win.eventdata.targetHostname | eventdata | Network | High | Decoded Fixture | security_event_5157 | Target hostname from firewall/network events. **Exact camelCase required.** |
| Domain | win.eventdata.domain | eventdata | Authentication | High | Decoded Fixture | security_event_4624 | Domain name from Security events. **Exact camelCase required.** |
| DomainName | win.eventdata.domainName | eventdata | Authentication | High | Decoded Fixture | security_event_4624 | Alias for Domain. **Exact camelCase required.** |
| Account | win.eventdata.accountName | eventdata | Authentication | High | Doc Only | N/A | Account name from Security events. **Exact camelCase required.** |
| ServiceName | win.eventdata.serviceName | eventdata | Service | High | Doc Only | N/A | Service name from Security Event 4697 and others. **Exact camelCase required.** |
| CallerProcessName | win.eventdata.callerProcessName | eventdata | Network | High | Decoded Fixture | security_event_5157 | Calling process name from firewall events. **Exact camelCase required.** |
| NewProcessName | win.eventdata.newProcessName | eventdata | Process | Verified | Doc Only | N/A | New process name from Security Event 4688. **Exact camelCase required.** |
| QueryName | win.eventdata.queryName | eventdata | DNS | Verified | Decoded Fixture | dns_client_event_3008 | DNS query name from Microsoft-Windows-DNS-Client Event 3008. **Exact camelCase required.** |
| ProcessPath | win.eventdata.processPath | eventdata | Process | High | Doc Only | N/A | Process image path (alternative field name). **Exact camelCase required.** |
| ExceptionCode | win.eventdata.exceptionCode | eventdata | Process | High | Decoded Fixture | application_error_1000 | Exception code from Sysmon Event 5 (Process Terminated). **Exact camelCase required.** |
| AuthenticationPackageName | win.eventdata.authenticationPackageName | eventdata | Authentication | High | Decoded Fixture | security_event_4624 | Authentication package name from Security Event 4624. **Exact camelCase required.** |
| IpAddress | win.eventdata.ipAddress | eventdata | Network | High | Decoded Fixture | security_event_4624 | IP address from Security Event 4624 and others. **Exact camelCase required.** |
| IpPort | win.eventdata.ipPort | eventdata | Network | High | Decoded Fixture | security_event_4624 | IP port from Security Event 4624. **Exact camelCase required.** |
| WorkstationName | win.eventdata.workstationName | eventdata | Authentication | High | Decoded Fixture | security_event_4624 | Workstation name from Security Event 4624. **Exact camelCase required.** |
| LogonProcessName | win.eventdata.logonProcessName | eventdata | Authentication | High | Decoded Fixture | security_event_4624 | Logon process name from Security Event 4624. **Exact camelCase required.** |
| SubjectUserSid | win.eventdata.subjectUserSid | eventdata | Authentication | High | Decoded Fixture | security_event_4624 | Subject user SID from Security events. **Exact camelCase required.** |
| TargetUserSid | win.eventdata.targetUserSid | eventdata | Authentication | High | Decoded Fixture | security_event_4624 | Target user SID from Security events. **Exact camelCase required.** |

## Field Namespace Breakdown

### System Namespace (win.system.*)

System fields are decoded from the Event/System XML element and contain event metadata:

- `eventID` - Numeric event identifier
- `providerName` - Provider/source name
- `channel` - Log channel name
- `computer` - Computer name where event occurred

These fields are typically constant across all events from a given source.

### EventData Namespace (win.eventdata.*)

EventData fields are decoded from the Event/EventData XML element and contain provider-specific data:

- Process creation events: image, commandLine, parentImage, processId, user, etc.
- Network connection events: sourceIp, destinationIp, sourcePort, destinationPort, protocol, etc.
- File operations: targetFilename, etc.
- Registry operations: registryPath, details, etc.
- Authentication events: targetUserName, logonType, domain, etc.
- DNS queries: queryName, etc.

## Special Cases and Notes

### Capitalization

**All Wazuh Windows decoded field names use exact camelCase.** For example:

- `win.eventdata.commandLine` ✓ (correct)
- `win.eventdata.commandline` ✗ (wrong - won't match decoder)
- `commandLine` ✗ (wrong - missing namespace prefix)

Generated Wazuh rules **must** use the exact capitalization shown in this table.

### Security vs. Sysmon Fields

Some fields appear in both Security and Sysmon events but with different structures:

- **User** appears in Sysmon Event 1 but may be empty in some cases
- **TargetUserName**, **LogonType**, **LogonGuid** are specific to Security Event 4624
- **Image**, **CommandLine**, **ParentImage** are from Sysmon Event 1

The context (service: sysmon vs service: security) should match the logsource in your Sigma rule.

### Hashes and Hash Fields

- **Hashes**: Full multi-hash field from Sysmon (e.g., "MD5=ABC...,SHA1=DEF...,SHA256=GHI...")
- **MD5, SHA1, SHA256, Imphash**: Individual hash components, extracted by Wazuh decoder

Prefer individual hash fields for matching single algorithms; use Hashes for multi-algorithm searches.

### Parent Rules and Channel Scoping

Parent rules (if_sid) scope rules to specific event channels:

- Parent 60000: Generic Windows events
- Parent 60001: Security channel
- Parent 60002: System channel
- Parent 60003: Application channel
- Parent 60004: Sysmon
- Parent 60005: Windows Defender

Do **not** add a redundant `<field name="win.system.channel">` when the parent rule already scopes to that channel.

## Adding New Mappings

When adding a new field mapping:

1. **Verify the field exists** in actual Wazuh decoded JSON from the target event type
2. **Document the exact camelCase** from the decoder output
3. **Cite a source**: Windows documentation, Wazuh documentation, or a fixture path
4. **Set appropriate confidence**: verified (tested), high (documented), or provisional (uncertain)
5. **Add service/category context** if the field is not universal

Example:

```python
FieldMapping(
    sigma_field="QueryName",
    wazuh_field="win.eventdata.queryName",
    namespace=FieldNamespace.EVENTDATA,
    products=("windows",),
    services=("dns-client",),
    documentation_reference="https://docs.microsoft.com/...",
    verification_source=VerificationSource.DECODED_FIXTURE,
    confidence=ConfidenceLevel.VERIFIED,
    notes="DNS query name from Microsoft-Windows-DNS-Client Event 3008. Exact camelCase required.",
)
```

## Testing Field Mappings

To verify a field mapping:

1. Generate a real Windows event of the target type
2. Forward it to Wazuh
3. View the decoded JSON in the Wazuh dashboard (decoded field structure)
4. Confirm the field name matches exactly
5. Update the mapping documentation with the fixture

## Unsupported Fields

If a Sigma field is not listed in this table:

- **In strict mode** (default): Conversion fails with an error message recommending this document
- **In warn mode**: Rule is skipped with a warning; no invalid field is emitted
- **In legacy mode** (unsafe): Field is lowercased and emitted (may not match decoder)

To support a new field:

1. Verify it exists in decoded Wazuh JSON
2. Document it in this table
3. Add it to `src/wazuh_sigma/fields/windows.py`
4. Add tests in `tests/test_fields_windows.py`

## References

- [Wazuh Windows EventChannel Decoder](https://github.com/wazuh/wazuh/blob/master/ruleset/decoders/windows.xml)
- [Microsoft Windows Event Log Documentation](https://docs.microsoft.com/en-us/windows/win32/wes/windows-event-log)
- [Sysmon Event Descriptions](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Windows Security Auditing](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
