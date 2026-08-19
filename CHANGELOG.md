# Changelog

## 1.1.0

- Refactored the monolithic script into a modular package.
- Added `pyproject.toml` packaging.
- Added the `headerhunter` console command.
- Added URL validation.
- Added rule validation.
- Added HSTS minimum-value checks.
- Reused one HTTPX client per scan.
- Preserved result ordering.
- Enabled TLS verification by default.
- Added explicit `--insecure` lab option.
- Escaped report content before HTML rendering.
- Added automated tests.
- Added a localhost test server.
