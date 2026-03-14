# OTX Feed

A ThreatConnect Organization Job App that imports [AlienVault Open Threat Exchange (OTX)](https://otx.alienvault.com/) subscribed pulses into ThreatConnect as Report groups with associated indicators and metadata.

## Description

The app fetches pulses from the OTX API (subscribed feed), creates Report groups in ThreatConnect with attributes (description, author, TLP, tags, targeted countries, references, etc.), links Adversary groups where applicable, and creates associated indicators. It uses TcEx batch for group and indicator creation and supports incremental runs via a persisted `last_run` value.

## Inputs

| Input | Type | Description |
|-------|------|-------------|
| **ThreatConnect Owner** | Choice | Destination owner in ThreatConnect for created groups and indicators. |
| **OTX API Key** | String | API key for OTX (required for authenticated requests). |
| **Last Run** | String | Initial value: `"N Days Ago"` (e.g. `"7 Days Ago"`) or an ISO date/datetime. After each run, the app persists the completion time for the next run’s `modified_since` filter. |
| **Logging Level** | Choice | Optional; one of `debug`, `info`, `warning`, `error`. |

## Requirements

- Python 3.11
- TcEx SDK 4.x
- Valid OTX API key (from OTX account)
- ThreatConnect API access (owner, API credentials, path)

## Release Notes

### 1.0.0 (2021-04-22)

* Initial Release
