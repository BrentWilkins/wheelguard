# External services

This document records the assumptions Wheelguard makes about third-party services. Recheck them before materially
increasing traffic, redistributing third-party data, or offering Wheelguard with contractual availability guarantees.

## OSV.dev

Status checked: 2026-09-02

Wheelguard queries `https://api.osv.dev/v1/querybatch` for known vulnerabilities in Python package versions.

- The public API currently requires no API key or billing account.
- The official API documentation currently states that the API has no rate limit.
- OSV publishes a 99.9% availability objective for its website and API. This is an operational objective, not a paid or
  contractual SLA for Wheelguard.
- The official documentation reviewed does not state a restriction against company or commercial use. This is an
  operational assumption, not legal advice or a contractual grant from Google.
- Queries disclose package names and versions to OSV.dev. Organizations should decide whether that dependency inventory
  is sensitive before enabling OSV queries.
- OSV aggregates sources under several licenses, including CC-BY, CC0, MIT, Apache-2.0, and others. Do not assume the
  aggregated database has one uniform license. Review the relevant source licenses before redistributing advisory data.

Wheelguard reduces its dependence and load on OSV.dev by batching version queries, caching successful results in D1,
using stale cached results during temporary failures, and periodically rescanning only recently active projects.
Wheelguard exposes advisory identifiers in package metadata but does not redistribute a bulk copy of the OSV database.

For substantially higher request volume, stricter privacy requirements, or contractual availability requirements,
consider mirroring the public OSV data exports and operating the lookup service under the organization's own controls.

Official references:

- [OSV API documentation](https://google.github.io/osv.dev/api/)
- [OSV FAQ and service objectives](https://google.github.io/osv.dev/faq/)
- [OSV data sources and licenses](https://google.github.io/osv.dev/data/)

