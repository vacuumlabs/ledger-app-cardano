# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [8.1.0]

### Added

- Support for proposal procedures (transaction body key 20): all seven governance
  action types are parsed, displayed and hashed. `cost_models` (protocol_param_update
  key 18) is rejected because it cannot be reviewed on a device screen.

### Changed

- The sign-tx init APDU carries a proposal procedures count. Clients gate this field on
  the device version, so app 8.0.x keeps working with clients that do not send it.

## [8.0.0]

Complete rewrite of the Cardano Ledger app.

### Changed

- Replaced the previous codebase with a modernized architecture.
- Dropped support for Ledger Nano S.
- Switched to NBGL-only UI flows across supported devices.

### Fixed

- Added voter path validation for Plutus signing mode (previously any path was silently accepted).

### Added

- Support for combined Conway delegation certificates.
