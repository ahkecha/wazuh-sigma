# Wazuh Parent Rule Mapping Reference

## Overview

Parent rules in Wazuh scope generated Sigma rules to specific event channels or event types. This document specifies the verified parent rule mappings used by the Sigma-to-Wazuh converter.

**Current Version**: `wazuh-4.14-windows-parent-v1` (Wazuh 4.14.x)

## Parent Rule Strategy

Parent rules provide two critical functions:

1. **Event Stream Scoping**: Restricts rule matching to events from specific channels (Security, System, Application, Sysmon, etc.)
2. **Decoder Validation**: Ensures the Wazuh Windows EventChannel decoder is invoked before field matching

Generated Sigma rules use `<if_sid>` to reference parent rules based on log source context (product, service, category).

## Parent Rule Mappings

| Rule ID | Log Source | Channel | Event Types | Wazuh Version | Notes |
|---------|-----------|---------|-------------|---------------|----|
| 60000 | windows (generic) | All/Mixed | Generic Windows events | 4.14+ | Fallback parent for Windows rules without specific service/category |
| 60001 | service: security | Security | Authentication, authorization, system/object access | 4.14+ | Security event log events |
| 60002 | service: system | System | System events, driver loading, etc. | 4.14+ | System event log events |
| 60003 | service: application | Application | Application-generated events | 4.14+ | Application event log events |
| 60004 | service: sysmon | Sysmon | Process creation, network connections, file ops, registry ops | 4.14+ | Sysmon log events |
| 60005 | service: windefend, windows-defender | Windows Defender | Malware detection, threat events | 4.14+ | Windows Defender event log |
| 60018 | service: wmi | WMI | WMI events | 4.14+ | Windows Management Instrumentation log |

## Category-Based Parent Rules (Sysmon)

When a log source includes a category, category-specific parent rules are selected if available:

| Category | Parent Rule(s) | Event Type |
|----------|----------------|-----------|
| process_creation | 61603 | Sysmon Event 1 |
| file_change | 61604 | Sysmon Event 2 (file creation time changed) |
| network_connection | 61605 | Sysmon Event 3 |
| driver_load | 61608 | Sysmon Event 6 |
| image_load | 61609 | Sysmon Event 7 |
| create_remote_thread | 61610 | Sysmon Event 8 |
| raw_access_thread | 61611 | Sysmon Event 9 |
| process_access | 61612 | Sysmon Event 10 |
| file_event | 61613 | Sysmon Event 11 (file created/detected) |
| registry_event | 61614, 61615, 61616 | Sysmon Event 12/13/14 (registry operations) |
| registry_add | 61614 | Sysmon Event 12 (registry object added) |
| registry_delete | 61614 | Sysmon Event 12 (registry object deleted) |
| registry_rename | 61616 | Sysmon Event 14 (registry object renamed) |
| registry_set | 61615 | Sysmon Event 13 (registry value set) |
| create_stream_hash | 61617 | Sysmon Event 15 |
| pipe_created | 61645, 61646 | Sysmon Event 17/18 |
| wmi_event | 61647, 61648, 61649 | Sysmon Event 19/20/21 |
| dns_query | 61650 | Sysmon Event 22 |
| file_delete | 61651, 61654 | Sysmon Event 23/26 |
| process_tampering | 61653 | Sysmon Event 25 |

## PowerShell Parent Rules

| Category | Parent Rule | Event Type |
|----------|-------------|-----------|
| ps_script | 91802 | PowerShell script block logging Event 4104 |
| ps_module | 91801 | PowerShell module logging Event 4103 |
| ps_classic_start | 91801 | PowerShell classic provider start |
| ps_classic_provider_start | 91801 | PowerShell classic provider start |

## Rule Resolution Logic

The converter selects parent rules using this priority:

1. **Category-specific rules** (e.g., process_creation → 61603)
2. **Service-specific rules** (e.g., service: sysmon → 60004)
3. **Product-level rules** (e.g., product: windows → 60000)
4. **Default fallback** (60000)

Example:

```yaml
logsource:
  product: windows
  service: sysmon
  category: process_creation
```

Resolution:
1. Try category:process_creation → 61603 ✓ (selected)

Example:

```yaml
logsource:
  product: windows
  service: security
```

Resolution:
1. Try service:security → 60001 ✓ (selected)

Example:

```yaml
logsource:
  product: windows
```

Resolution:
1. Try product:windows → 60000 ✓ (selected)

## Important Notes

### Parent Rule Stability

These mappings are based on Wazuh 4.14.x. If you're using a different Wazuh version:

1. Check the native Wazuh ruleset for the actual rule IDs
2. Override parent rules in your `pipeline.yml`:
   ```yaml
   wazuh:
     parent_rules:
       product:
         windows: 60000
       service:
         security: 60001
   ```

### When Parent Rules Are Sufficient

Do **not** add redundant field filters when a parent rule already scopes the event stream:

❌ **Wrong** - Redundant field filter:
```xml
<rule>
  <if_sid>60001</if_sid>  <!-- Already scopes to Security -->
  <field name="win.system.channel">Security</field>  <!-- Redundant! -->
</rule>
```

✓ **Correct** - Parent rule is sufficient:
```xml
<rule>
  <if_sid>60001</if_sid>  <!-- Scopes to Security -->
</rule>
```

### When Parent Rules Are Not Sufficient

Add explicit field filters when you need to differentiate within a parent's scope:

✓ **Correct** - Field filter differentiates within Security parent:
```xml
<rule>
  <if_sid>60001</if_sid>  <!-- Scopes to Security channel -->
  <field name="win.system.eventID">4688</field>  <!-- Specific event type -->
</rule>
```

## Backward Compatibility

When upgrading from earlier versions:

- If you have custom parent rule mappings, they continue to work if the rule IDs remain valid
- If Wazuh deprecates or renames parent rules, update `pipeline.yml` to the new IDs
- Test rule deployment with `wazuh-analysisd -t` after changing parent rules

## Testing Parent Rule Mappings

To verify parent rules are working:

1. Generate rules with a parent rule reference:
   ```bash
   sigma-convert -d examples/sigma -o build/test.xml
   ```

2. Check the generated XML contains `<if_sid>` elements:
   ```bash
   grep -E "<if_sid>[0-9]+</if_sid>" build/test.xml
   ```

3. Load the rules into Wazuh and run the native validator:
   ```bash
   docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-analysisd -t
   ```

4. Verify that no parent rule ID errors appear

## References

- [Wazuh Ruleset Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
- [Wazuh Rule Structure](https://documentation.wazuh.com/current/user-manual/ruleset/syntax-rules.html)
- [Wazuh Parent Rules](https://github.com/wazuh/wazuh/tree/master/ruleset/rules)
