<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# PHP Shell Injection Companion Changelog

## [Unreleased]

## [0.1.0]

### Added

- Warning on `eval`/`exec`/`shell_exec`/`system`/`passthru`/`popen`
  calls whose argument is an interpolated or concatenated string --
  a documented command/code injection risk (CWE-78/CWE-95) per PHP's
  own official manual, not covered by "PHP Inspections (EA Extended)".
- 100% static text analysis, no PHP plugin dependency, no network
  calls, no telemetry. Free.

[Unreleased]: https://github.com/GapHunterLabs/php-shell-injection-companion/compare/0.1.0...HEAD
[0.1.0]: https://github.com/GapHunterLabs/php-shell-injection-companion/commits/0.1.0
