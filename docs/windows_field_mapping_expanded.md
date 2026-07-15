# Windows Field Mapping — Expanded Edition

This document catalogs all fields observed in Windows event fixtures extracted from archive analysis.
Each field is mapped to its context (provider, channel, event ID) and data type.

## Overview

- **Total Event Groups**: 137
- **Total Events Analyzed**: 30,000
- **Total Unique Field Schemas**: 137
- **Generated**: 2026-07-13T19:16:34.596756+00:00

## Field Index by Provider


### Microsoft-Windows-ActiveDirectory_DomainService

**Channel**: Directory Service

#### Event 1162 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

#### Event 3027 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `data` (string)

#### Event 3033 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)


### Microsoft-Windows-Bits-Client

**Channel**: Microsoft-Windows-Bits-Client/Operational

#### Event 3 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `clientProcessStartKey` (string)
- `jobId` (string)
- `jobOwner` (string)
- `jobTitle` (string)
- `processId` (string)
- `processPath` (string)

#### Event 61 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `additionalInfoHr` (string)
- `bandwidthLimit` (string)
- `bytesTotal` (string)
- `bytesTransferred` (string)
- `bytesTransferredFromPeer` (string)
- `fileLength` (string)
- `fileTime` (string)
- `hr` (string)
- `id` (string)
- `ignoreBandwidthLimitsOnLan` (string)
- `name` (string)
- `peerContextInfo` (string)
- `peerProtocolFlags` (string)
- `transferId` (string)
- `url` (string)

#### Event 306 (58 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

#### Event 16403 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `clientProcessStartKey` (string)
- `fileCount` (string)
- `jobId` (string)
- `jobOwner` (string)
- `jobTitle` (string)
- `localName` (string)
- `processId` (string)
- `remoteName` (string)
- `user` (string)


### Microsoft-Windows-CertificateServicesClient-CertEnroll

**Channel**: Application

#### Event 86 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `context` (string)
- `errorCode` (string)
- `messageText` (string)
- `method` (string)
- `stage` (string)
- `url` (string)


### Microsoft-Windows-GroupPolicy

**Channel**: Microsoft-Windows-GroupPolicy/Operational

#### Event 4006 (44 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `isAsyncProcessing` (string)
- `isBackgroundProcessing` (string)
- `isDomainJoined` (string)
- `isMachine` (string)
- `isServiceRestart` (string)
- `policyActivityId` (string)
- `principalSamName` (string)
- `reasonForSyncProcessing` (string)

#### Event 4007 (2 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `isAsyncProcessing` (string)
- `isBackgroundProcessing` (string)
- `isDomainJoined` (string)
- `isMachine` (string)
- `isServiceRestart` (string)
- `policyActivityId` (string)
- `principalSamName` (string)
- `reasonForSyncProcessing` (string)

#### Event 4016 (44 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `applicableGPOList` (string)
- `cSEExtensionId` (string)
- `cSEExtensionName` (string)
- `descriptionString` (string)
- `gPOListStatusString` (string)
- `isExtensionAsyncProcessing` (string)
- `isGPOListChanged` (string)

#### Event 4017 (134 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `operationDescription` (string)
- `parameter` (string)

#### Event 4017 (46 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `operationDescription` (string)

#### Event 4126 (46 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `isMachine` (string)

#### Event 4257 (46 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `isAsyncProcessing` (string)
- `isBackgroundProcessing` (string)
- `isMachine` (string)

#### Event 4326 (46 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

#### Event 5016 (44 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `cSEElaspedTimeInMilliSeconds` (string)
- `cSEExtensionId` (string)
- `cSEExtensionName` (string)
- `errorCode` (string)

#### Event 5017 (180 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `errorCode` (string)
- `operationDescription` (string)
- `operationElaspedTimeInMilliSeconds` (string)
- `parameter` (string)

#### Event 5126 (46 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `gPODownloadTimeElapsedInMilliseconds` (string)
- `isAsyncProcessing` (string)
- `isBackgroundProcessing` (string)
- `isMachine` (string)
- `numberOfGPOsApplicable` (string)
- `numberOfGPOsDownloaded` (string)

#### Event 5257 (46 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `isMachine` (string)
- `policyDownloadTimeElapsedInMilliseconds` (string)

#### Event 5308 (46 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `dCIPAddress` (string)
- `dCName` (string)

#### Event 5309 (44 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `machineRole` (string)
- `networkName` (string)

#### Event 5309 (2 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `machineRole` (string)

#### Event 5310 (46 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `dCDomainName` (string)
- `dCName` (string)
- `principalCNName` (string)
- `principalDomainName` (string)

#### Event 5311 (46 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `policyProcessingMode` (string)

#### Event 5312 (44 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `descriptionString` (string)
- `gPOInfoList` (string)

#### Event 5312 (2 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `descriptionString` (string)

#### Event 5313 (44 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `descriptionString` (string)

#### Event 5313 (2 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `descriptionString` (string)
- `gPOInfoList` (string)

#### Event 5315 (46 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `nextPolicyApplicationTime` (string)
- `nextPolicyApplicationTimeUnit` (string)
- `principalSamName` (string)

#### Event 5320 (276 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `infoDescription` (string)

#### Event 5326 (46 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `dCDiscoveryTimeInMilliSeconds` (string)
- `errorCode` (string)

#### Event 5340 (46 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `policyApplicationMode` (string)

#### Event 6314 (46 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `bandwidthInkbps` (string)
- `errorCode` (string)
- `isSlowLink` (string)
- `linkDescription` (string)
- `policyApplicationMode` (string)
- `thresholdInkbps` (string)

#### Event 8006 (44 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `errorCode` (string)
- `isConnectivityFailure` (string)
- `isMachine` (string)
- `policyElaspedTimeInSeconds` (string)
- `principalSamName` (string)

#### Event 8007 (2 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `errorCode` (string)
- `isConnectivityFailure` (string)
- `isMachine` (string)
- `policyElaspedTimeInSeconds` (string)
- `principalSamName` (string)


### Microsoft-Windows-Kernel-General

**Channel**: System

#### Event 16 (2 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `dirtyPages` (string)
- `hiveName` (string)
- `hiveNameLength` (string)
- `keysUpdated` (string)


### Microsoft-Windows-MSDTC 2

**Channel**: Application

#### Event 4202 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `param1` (string)
- `param10` (string)
- `param11` (string)
- `param12` (string)
- `param2` (string)
- `param3` (string)
- `param4` (string)
- `param5` (string)
- `param6` (string)
- `param7` (string)
- `param8` (string)
- `param9` (string)


### Microsoft-Windows-PowerShell

**Channel**: Microsoft-Windows-PowerShell/Operational

#### Event 4104 (326 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `messageNumber` (string)
- `messageTotal` (string)
- `scriptBlockId` (string)
- `scriptBlockText` (string)

#### Event 4104 (176 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `messageNumber` (string)
- `messageTotal` (string)
- `path` (string)
- `scriptBlockId` (string)
- `scriptBlockText` (string)

#### Event 40961 (20 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

#### Event 40962 (19 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

#### Event 53504 (19 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `param1` (string)
- `param2` (string)


### Microsoft-Windows-Security-Auditing

**Channel**: Security

#### Event 4624 (913 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `authenticationPackageName` (string)
- `elevatedToken` (string)
- `impersonationLevel` (string)
- `ipAddress` (string)
- `ipPort` (string)
- `keyLength` (string)
- `logonGuid` (string)
- `logonProcessName` (string)
- `logonType` (string)
- `processId` (string)
- `subjectLogonId` (string)
- `subjectUserSid` (string)
- `targetDomainName` (string)
- `targetLinkedLogonId` (string)
- `targetLogonId` (string)
- `targetUserName` (string)
- `targetUserSid` (string)
- `virtualAccount` (string)

#### Event 4624 (389 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `authenticationPackageName` (string)
- `elevatedToken` (string)
- `impersonationLevel` (string)
- `keyLength` (string)
- `logonGuid` (string)
- `logonProcessName` (string)
- `logonType` (string)
- `processId` (string)
- `processName` (string)
- `subjectDomainName` (string)
- `subjectLogonId` (string)
- `subjectUserName` (string)
- `subjectUserSid` (string)
- `targetDomainName` (string)
- `targetLinkedLogonId` (string)
- `targetLogonId` (string)
- `targetUserName` (string)
- `targetUserSid` (string)
- `virtualAccount` (string)

#### Event 4624 (48 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `authenticationPackageName` (string)
- `elevatedToken` (string)
- `impersonationLevel` (string)
- `keyLength` (string)
- `logonGuid` (string)
- `logonProcessName` (string)
- `logonType` (string)
- `processId` (string)
- `subjectLogonId` (string)
- `subjectUserSid` (string)
- `targetDomainName` (string)
- `targetLinkedLogonId` (string)
- `targetLogonId` (string)
- `targetUserName` (string)
- `targetUserSid` (string)
- `virtualAccount` (string)

#### Event 4624 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `authenticationPackageName` (string)
- `elevatedToken` (string)
- `impersonationLevel` (string)
- `ipAddress` (string)
- `ipPort` (string)
- `keyLength` (string)
- `logonGuid` (string)
- `logonProcessName` (string)
- `logonType` (string)
- `processId` (string)
- `processName` (string)
- `subjectDomainName` (string)
- `subjectLogonId` (string)
- `subjectUserName` (string)
- `subjectUserSid` (string)
- `targetDomainName` (string)
- `targetLinkedLogonId` (string)
- `targetLogonId` (string)
- `targetUserName` (string)
- `targetUserSid` (string)
- `virtualAccount` (string)
- `workstationName` (string)

#### Event 4624 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `authenticationPackageName` (string)
- `elevatedToken` (string)
- `impersonationLevel` (string)
- `ipAddress` (string)
- `ipPort` (string)
- `keyLength` (string)
- `lmPackageName` (string)
- `logonGuid` (string)
- `logonProcessName` (string)
- `logonType` (string)
- `processId` (string)
- `subjectLogonId` (string)
- `subjectUserSid` (string)
- `targetDomainName` (string)
- `targetLinkedLogonId` (string)
- `targetLogonId` (string)
- `targetUserName` (string)
- `targetUserSid` (string)
- `virtualAccount` (string)
- `workstationName` (string)

#### Event 4634 (919 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `logonType` (string)
- `targetDomainName` (string)
- `targetLogonId` (string)
- `targetUserName` (string)
- `targetUserSid` (string)

#### Event 4648 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `ipAddress` (string)
- `ipPort` (string)
- `logonGuid` (string)
- `processId` (string)
- `processName` (string)
- `subjectDomainName` (string)
- `subjectLogonId` (string)
- `subjectUserName` (string)
- `subjectUserSid` (string)
- `targetDomainName` (string)
- `targetInfo` (string)
- `targetLogonGuid` (string)
- `targetServerName` (string)
- `targetUserName` (string)

#### Event 4662 (7 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `accessList` (string)
- `accessMask` (string)
- `handleId` (string)
- `objectName` (string)
- `objectServer` (string)
- `objectType` (string)
- `operationType` (string)
- `properties` (string)
- `subjectDomainName` (string)
- `subjectLogonId` (string)
- `subjectUserName` (string)
- `subjectUserSid` (string)

#### Event 4672 (1333 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `privilegeList` (string)
- `subjectDomainName` (string)
- `subjectLogonId` (string)
- `subjectUserName` (string)
- `subjectUserSid` (string)

#### Event 4673 (35 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `objectServer` (string)
- `privilegeList` (string)
- `processId` (string)
- `processName` (string)
- `service` (string)
- `subjectDomainName` (string)
- `subjectLogonId` (string)
- `subjectUserName` (string)
- `subjectUserSid` (string)

#### Event 4674 (112 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `accessMask` (string)
- `handleId` (string)
- `objectServer` (string)
- `privilegeList` (string)
- `processId` (string)
- `processName` (string)
- `subjectDomainName` (string)
- `subjectLogonId` (string)
- `subjectUserName` (string)
- `subjectUserSid` (string)

#### Event 4722 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `subjectDomainName` (string)
- `subjectLogonId` (string)
- `subjectUserName` (string)
- `subjectUserSid` (string)
- `targetDomainName` (string)
- `targetSid` (string)
- `targetUserName` (string)

#### Event 4728 (2 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `memberSid` (string)
- `subjectDomainName` (string)
- `subjectLogonId` (string)
- `subjectUserName` (string)
- `subjectUserSid` (string)
- `targetDomainName` (string)
- `targetSid` (string)
- `targetUserName` (string)

#### Event 4729 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `memberSid` (string)
- `subjectDomainName` (string)
- `subjectLogonId` (string)
- `subjectUserName` (string)
- `subjectUserSid` (string)
- `targetDomainName` (string)
- `targetSid` (string)
- `targetUserName` (string)

#### Event 4732 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `memberSid` (string)
- `subjectDomainName` (string)
- `subjectLogonId` (string)
- `subjectUserName` (string)
- `subjectUserSid` (string)
- `targetDomainName` (string)
- `targetSid` (string)
- `targetUserName` (string)

#### Event 4769 (3 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `ipAddress` (string)
- `ipPort` (string)
- `logonGuid` (string)
- `serviceName` (string)
- `serviceSid` (string)
- `status` (string)
- `targetDomainName` (string)
- `targetUserName` (string)
- `ticketEncryptionType` (string)
- `ticketOptions` (string)

#### Event 4770 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `ipAddress` (string)
- `ipPort` (string)
- `serviceName` (string)
- `serviceSid` (string)
- `targetDomainName` (string)
- `targetUserName` (string)
- `ticketEncryptionType` (string)
- `ticketOptions` (string)

#### Event 4776 (4 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `packageName` (string)
- `status` (string)
- `targetUserName` (string)
- `workstation` (string)

#### Event 4798 (170 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `callerProcessId` (string)
- `callerProcessName` (string)
- `subjectDomainName` (string)
- `subjectLogonId` (string)
- `subjectUserName` (string)
- `subjectUserSid` (string)
- `targetDomainName` (string)
- `targetSid` (string)
- `targetUserName` (string)

#### Event 4799 (101 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `callerProcessId` (string)
- `callerProcessName` (string)
- `subjectDomainName` (string)
- `subjectLogonId` (string)
- `subjectUserName` (string)
- `subjectUserSid` (string)
- `targetDomainName` (string)
- `targetSid` (string)
- `targetUserName` (string)

#### Event 5379 (4 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `clientProcessId` (string)
- `countOfCredentialsReturned` (string)
- `processCreationTime` (string)
- `readOperation` (string)
- `returnCode` (string)
- `subjectDomainName` (string)
- `subjectLogonId` (string)
- `subjectUserName` (string)
- `subjectUserSid` (string)
- `targetName` (string)
- `type` (string)


### Microsoft-Windows-Security-SPP

**Channel**: Application

#### Event 900 (10 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `data` (string)

#### Event 902 (14 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `data` (string)

#### Event 903 (14 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

#### Event 1003 (11 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `data` (string)

#### Event 1037 (12 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `data` (string)

#### Event 1066 (11 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `data` (string)

#### Event 16384 (229 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `data` (string)

#### Event 16394 (198 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)


### Microsoft-Windows-Sysmon

**Channel**: Microsoft-Windows-Sysmon/Operational

#### Event 1 (749 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `commandLine` (string)
- `company` (string)
- `currentDirectory` (string)
- `description` (string)
- `fileVersion` (string)
- `hashes` (string)
- `image` (string)
- `integrityLevel` (string)
- `logonGuid` (string)
- `logonId` (string)
- `originalFileName` (string)
- `parentCommandLine` (string)
- `parentImage` (string)
- `parentProcessGuid` (string)
- `parentProcessId` (string)
- `parentUser` (string)
- `processGuid` (string)
- `processId` (string)
- `product` (string)
- `ruleName` (string)
- `terminalSessionId` (string)
- `user` (string)
- `utcTime` (string)

#### Event 1 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `commandLine` (string)
- `currentDirectory` (string)
- `hashes` (string)
- `image` (string)
- `integrityLevel` (string)
- `logonGuid` (string)
- `logonId` (string)
- `parentCommandLine` (string)
- `parentImage` (string)
- `parentProcessGuid` (string)
- `parentProcessId` (string)
- `parentUser` (string)
- `processGuid` (string)
- `processId` (string)
- `ruleName` (string)
- `terminalSessionId` (string)
- `user` (string)
- `utcTime` (string)

#### Event 2 (5 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `creationUtcTime` (string)
- `image` (string)
- `previousCreationUtcTime` (string)
- `processGuid` (string)
- `processId` (string)
- `ruleName` (string)
- `targetFilename` (string)
- `user` (string)
- `utcTime` (string)

#### Event 3 (1645 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `destinationIp` (string)
- `destinationIsIpv6` (string)
- `destinationPort` (string)
- `image` (string)
- `initiated` (string)
- `processGuid` (string)
- `processId` (string)
- `protocol` (string)
- `ruleName` (string)
- `sourceIp` (string)
- `sourceIsIpv6` (string)
- `sourcePort` (string)
- `user` (string)
- `utcTime` (string)

#### Event 5 (4 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `image` (string)
- `processGuid` (string)
- `processId` (string)
- `user` (string)
- `utcTime` (string)

#### Event 7 (2355 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `company` (string)
- `description` (string)
- `fileVersion` (string)
- `hashes` (string)
- `image` (string)
- `imageLoaded` (string)
- `originalFileName` (string)
- `processGuid` (string)
- `processId` (string)
- `product` (string)
- `ruleName` (string)
- `signature` (string)
- `signatureStatus` (string)
- `signed` (string)
- `user` (string)
- `utcTime` (string)

#### Event 7 (198 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `company` (string)
- `description` (string)
- `fileVersion` (string)
- `hashes` (string)
- `image` (string)
- `imageLoaded` (string)
- `originalFileName` (string)
- `processGuid` (string)
- `processId` (string)
- `product` (string)
- `signature` (string)
- `signatureStatus` (string)
- `signed` (string)
- `user` (string)
- `utcTime` (string)

#### Event 7 (90 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `company` (string)
- `description` (string)
- `fileVersion` (string)
- `hashes` (string)
- `image` (string)
- `imageLoaded` (string)
- `originalFileName` (string)
- `processGuid` (string)
- `processId` (string)
- `product` (string)
- `ruleName` (string)
- `signatureStatus` (string)
- `signed` (string)
- `user` (string)
- `utcTime` (string)

#### Event 10 (9832 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `callTrace` (string)
- `grantedAccess` (string)
- `ruleName` (string)
- `sourceImage` (string)
- `sourceProcessGUID` (string)
- `sourceProcessId` (string)
- `sourceThreadId` (string)
- `sourceUser` (string)
- `targetImage` (string)
- `targetProcessGUID` (string)
- `targetProcessId` (string)
- `targetUser` (string)
- `utcTime` (string)

#### Event 11 (1998 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `creationUtcTime` (string)
- `image` (string)
- `processGuid` (string)
- `processId` (string)
- `ruleName` (string)
- `targetFilename` (string)
- `user` (string)
- `utcTime` (string)

#### Event 11 (135 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `creationUtcTime` (string)
- `image` (string)
- `processGuid` (string)
- `processId` (string)
- `targetFilename` (string)
- `user` (string)
- `utcTime` (string)

#### Event 12 (46 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `eventType` (string)
- `image` (string)
- `processGuid` (string)
- `processId` (string)
- `targetObject` (string)
- `user` (string)
- `utcTime` (string)

#### Event 12 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `eventType` (string)
- `image` (string)
- `processGuid` (string)
- `processId` (string)
- `ruleName` (string)
- `targetObject` (string)
- `user` (string)
- `utcTime` (string)

#### Event 13 (1118 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `details` (string)
- `eventType` (string)
- `image` (string)
- `processGuid` (string)
- `processId` (string)
- `targetObject` (string)
- `user` (string)
- `utcTime` (string)

#### Event 13 (497 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `details` (string)
- `eventType` (string)
- `image` (string)
- `processGuid` (string)
- `processId` (string)
- `ruleName` (string)
- `targetObject` (string)
- `user` (string)
- `utcTime` (string)

#### Event 15 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `contents` (string)
- `creationUtcTime` (string)
- `hash` (string)
- `image` (string)
- `processGuid` (string)
- `processId` (string)
- `ruleName` (string)
- `targetFilename` (string)
- `user` (string)
- `utcTime` (string)

#### Event 17 (148 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `eventType` (string)
- `image` (string)
- `pipeName` (string)
- `processGuid` (string)
- `processId` (string)
- `user` (string)
- `utcTime` (string)

#### Event 18 (47 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `eventType` (string)
- `image` (string)
- `pipeName` (string)
- `processGuid` (string)
- `processId` (string)
- `user` (string)
- `utcTime` (string)

#### Event 22 (47 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `image` (string)
- `processGuid` (string)
- `processId` (string)
- `queryName` (string)
- `queryResults` (string)
- `queryStatus` (string)
- `user` (string)
- `utcTime` (string)

#### Event 22 (6 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `image` (string)
- `processGuid` (string)
- `processId` (string)
- `queryName` (string)
- `queryStatus` (string)
- `user` (string)
- `utcTime` (string)

#### Event 25 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `image` (string)
- `processGuid` (string)
- `processId` (string)
- `type` (string)
- `user` (string)
- `utcTime` (string)

#### Event 26 (63 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `hashes` (string)
- `image` (string)
- `isExecutable` (string)
- `processGuid` (string)
- `processId` (string)
- `targetFilename` (string)
- `user` (string)
- `utcTime` (string)

#### Event 29 (23 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `hashes` (string)
- `image` (string)
- `processGuid` (string)
- `processId` (string)
- `targetFilename` (string)
- `user` (string)
- `utcTime` (string)

#### Event 29 (11 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `hashes` (string)
- `image` (string)
- `processGuid` (string)
- `processId` (string)
- `ruleName` (string)
- `targetFilename` (string)
- `user` (string)
- `utcTime` (string)

#### Event 255 (3 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `description` (string)
- `iD` (string)
- `utcTime` (string)


### Microsoft-Windows-TPM-WMI

**Channel**: System

#### Event 1025 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)


### Microsoft-Windows-TaskScheduler

**Channel**: Microsoft-Windows-TaskScheduler/Operational

#### Event 100 (14 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `instanceId` (string)
- `taskName` (string)
- `userContext` (string)

#### Event 102 (14 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `instanceId` (string)
- `taskName` (string)
- `userContext` (string)

#### Event 107 (17 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `instanceId` (string)
- `taskName` (string)

#### Event 129 (14 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `path` (string)
- `priority` (string)
- `processID` (string)
- `taskName` (string)

#### Event 140 (44 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `taskName` (string)
- `userName` (string)

#### Event 200 (14 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `actionName` (string)
- `enginePID` (string)
- `taskInstanceId` (string)
- `taskName` (string)

#### Event 201 (14 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `actionName` (string)
- `enginePID` (string)
- `resultCode` (string)
- `taskInstanceId` (string)
- `taskName` (string)


### Microsoft-Windows-WMI-Activity

**Channel**: Microsoft-Windows-WMI-Activity/Operational

#### Event 5857 (797 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

#### Event 5858 (348 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

#### Event 5860 (162 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)


### Microsoft-Windows-Windows Defender

**Channel**: Microsoft-Windows-Windows Defender/Operational

#### Event 1000 (2 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `domain` (string)
- `low CPU Priority for Scans` (string)
- `product Name` (string)
- `product Version` (string)
- `sID` (string)
- `scan ID` (string)
- `scan Only If Idle` (string)
- `scan Parameters` (string)
- `scan Parameters Index` (string)
- `scan Trigger` (string)
- `scan Trigger Index` (string)
- `scan Type` (string)
- `scan Type Index` (string)
- `thread Priority` (string)
- `user` (string)

#### Event 1001 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `domain` (string)
- `product Name` (string)
- `product Version` (string)
- `sID` (string)
- `scan ID` (string)
- `scan Parameters` (string)
- `scan Parameters Index` (string)
- `scan Time Hours` (string)
- `scan Time Minutes` (string)
- `scan Time Seconds` (string)
- `scan Type` (string)
- `scan Type Index` (string)
- `user` (string)

#### Event 1013 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `domain` (string)
- `product Name` (string)
- `product Version` (string)
- `sID` (string)
- `timestamp` (string)
- `user` (string)

#### Event 1116 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `action ID` (string)
- `action Name` (string)
- `additional Actions ID` (string)
- `additional Actions String` (string)
- `category ID` (string)
- `category Name` (string)
- `detection ID` (string)
- `detection Time` (string)
- `detection User` (string)
- `engine Version` (string)
- `error Code` (string)
- `error Description` (string)
- `execution ID` (string)
- `execution Name` (string)
- `fWLink` (string)
- `origin ID` (string)
- `origin Name` (string)
- `path` (string)
- `post Clean Status` (string)
- `pre Execution Status` (string)
- `process Name` (string)
- `product Name` (string)
- `product Version` (string)
- `security intelligence Version` (string)
- `severity ID` (string)
- `severity Name` (string)
- `source ID` (string)
- `source Name` (string)
- `state` (string)
- `status Code` (string)
- `threat ID` (string)
- `threat Name` (string)
- `type ID` (string)
- `type Name` (string)

#### Event 1117 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `action ID` (string)
- `action Name` (string)
- `additional Actions ID` (string)
- `additional Actions String` (string)
- `category ID` (string)
- `category Name` (string)
- `detection ID` (string)
- `detection Time` (string)
- `detection User` (string)
- `engine Version` (string)
- `error Code` (string)
- `error Description` (string)
- `execution ID` (string)
- `execution Name` (string)
- `fWLink` (string)
- `origin ID` (string)
- `origin Name` (string)
- `path` (string)
- `post Clean Status` (string)
- `pre Execution Status` (string)
- `process Name` (string)
- `product Name` (string)
- `product Version` (string)
- `remediation User` (string)
- `security intelligence Version` (string)
- `severity ID` (string)
- `severity Name` (string)
- `source ID` (string)
- `source Name` (string)
- `state` (string)
- `status Code` (string)
- `threat ID` (string)
- `threat Name` (string)
- `type ID` (string)
- `type Name` (string)

#### Event 1150 (7 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `engine version` (string)
- `platform version` (string)
- `product Name` (string)
- `security intelligence version` (string)

#### Event 1151 (36 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `aS security intelligence creation time` (string)
- `aS security intelligence version` (string)
- `aV security intelligence creation time` (string)
- `aV security intelligence version` (string)
- `bM state` (string)
- `engine up-to-date` (string)
- `engine version` (string)
- `iOAV state` (string)
- `last AS security intelligence age` (string)
- `last AV security intelligence age` (string)
- `last full scan age` (string)
- `last full scan end time` (string)
- `last full scan source` (string)
- `last full scan start time` (string)
- `last quick scan age` (string)
- `last quick scan end time` (string)
- `last quick scan source` (string)
- `last quick scan start time` (string)
- `latest engine version` (string)
- `latest platform version` (string)
- `nRI engine version` (string)
- `nRI security intelligence version` (string)
- `oA state` (string)
- `platform up-to-date` (string)
- `platform version` (string)
- `product Name` (string)
- `product status` (string)
- `rTP state` (string)

#### Event 2000 (5 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `current Engine Version` (string)
- `current security intelligence Version` (string)
- `domain` (string)
- `previous Engine Version` (string)
- `previous security intelligence Version` (string)
- `product Name` (string)
- `product Version` (string)
- `sID` (string)
- `security intelligence Type` (string)
- `security intelligence Type Index` (string)
- `update Type` (string)
- `update Type Index` (string)
- `user` (string)

#### Event 2010 (9 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `cloud protection intelligence Compilation Timestamp` (string)
- `cloud protection intelligence Type` (string)
- `cloud protection intelligence Type Index` (string)
- `cloud protection intelligence Version` (string)
- `current Engine Version` (string)
- `current security intelligence Version` (string)
- `persistence Limit Type` (string)
- `persistence Limit Type Index` (string)
- `persistence Limit Value` (string)
- `persistence Path` (string)
- `product Name` (string)
- `product Version` (string)
- `security intelligence Type Index` (string)

#### Event 5007 (5 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `new Value` (string)
- `old Value` (string)
- `product Name` (string)
- `product Version` (string)

#### Event 5007 (2 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `new Value` (string)
- `product Name` (string)
- `product Version` (string)


### Microsoft-Windows-Windows Firewall With Advanced Security

**Channel**: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall

#### Event 2006 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `modifyingApplication` (string)
- `modifyingUser` (string)
- `ruleId` (string)
- `ruleName` (string)

#### Event 2099 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `action` (string)
- `active` (string)
- `applicationPath` (string)
- `direction` (string)
- `edgeTraversal` (string)
- `embeddedContext` (string)
- `errorCode` (string)
- `flags` (string)
- `localAddresses` (string)
- `localOnlyMapped` (string)
- `localPorts` (string)
- `looseSourceMapped` (string)
- `modifyingApplication` (string)
- `modifyingUser` (string)
- `origin` (string)
- `profiles` (string)
- `protocol` (string)
- `remoteAddresses` (string)
- `remotePorts` (string)
- `ruleId` (string)
- `ruleName` (string)
- `ruleStatus` (string)
- `schemaVersion` (string)
- `securityOptions` (string)


### Microsoft-Windows-WindowsUpdateClient

**Channel**: System

#### Event 19 (3 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `serviceGuid` (string)
- `updateGuid` (string)
- `updateRevisionNumber` (string)
- `updateTitle` (string)

#### Event 43 (2 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `updateGuid` (string)
- `updateRevisionNumber` (string)
- `updateTitle` (string)

#### Event 44 (5 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `updateGuid` (string)
- `updateRevisionNumber` (string)
- `updateTitle` (string)


### NTDS ISAM

**Channel**: Directory Service

#### Event 700 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `data` (string)

#### Event 701 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `data` (string)


### PowerShell

**Channel**: Windows PowerShell

#### Event 400 (11 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `data` (string)

#### Event 400 (8 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)

**EventData Fields**:
- `data` (string)

#### Event 403 (11 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `data` (string)

#### Event 403 (8 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)

**EventData Fields**:
- `data` (string)

#### Event 600 (66 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `data` (string)

#### Event 600 (50 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)

**EventData Fields**:
- `data` (string)


### Service Control Manager

**Channel**: System

#### Event 7036 (2196 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `binary` (string)
- `param1` (string)
- `param2` (string)

#### Event 7040 (416 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `param1` (string)
- `param2` (string)
- `param3` (string)
- `param4` (string)

#### Event 7045 (1 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `eventSourceName` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerGuid` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `accountName` (string)
- `imagePath` (string)
- `serviceName` (string)
- `serviceType` (string)
- `startType` (string)


### edgeupdate

**Channel**: Application

#### Event 0 (4 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `opcode` (string)
- `processID` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)
- `threadID` (string)
- `version` (string)

**EventData Fields**:
- `data` (string)

#### Event 0 (2 occurrences)

**System Fields**:
- `channel` (string)
- `computer` (string)
- `eventID` (string)
- `eventRecordID` (string)
- `keywords` (string)
- `level` (string)
- `message` (string)
- `providerName` (string)
- `severityValue` (string)
- `systemTime` (string)
- `task` (string)

**EventData Fields**:
- `data` (string)


## Usage

To use these field mappings in Sigma rules:

```yaml
logsource:
  product: windows
  service: <service>
  category: <category>

detection:
  selection:
    EventID: <event_id>
    <field>: <value>

filter:
  condition: selection
```

## Notes

- Field names are case-sensitive
- Data types are inferred from fixture values
- Multiple schemas may exist for the same event ID (see fixtures for exact structures)
- All fields are extracted from real Wazuh decoded Windows events

## Verification

All fields in this mapping have been extracted from actual Windows event fixtures and verified
against the Wazuh Windows EventChannel decoder output.
