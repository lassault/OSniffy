# OSniffy

OSniffy is a packet ingestion and visualization tool with two modes:

- **Sniffer mode**: live raw-socket capture, parse, and ingest.
- **Reader mode**: process `.pcap` captures in batches and ingest.

Data is stored in MySQL and visualized in Grafana.

## Supported baseline (May 2026)

- **Python**: 3.11, 3.12, 3.13
- **Primary OS**: Linux (full support including live raw socket capture)
- **Optional OS**: Windows (reader mode and module compatibility; live capture is best-effort)

## Architecture boundaries

- `osniffy.protocol`: packet frame models + parser (Ethernet/ARP/IPv4/ICMP/TCP/UDP)
- `osniffy.db`: persistence + schema bootstrap + batching + time-range query
- `osniffy.dashboard`: Grafana datasource/dashboard provisioning + browser opening
- `osniffy.reader` / `osniffy.sniffer`: capture/read execution flows
- `osniffy.cli`: argument parsing, startup validation, logging, and exit codes

## As-is behavior specification

### CLI

```bash
osniffy --sniffer [--skip-dashboard] [--env-file FILE] [--log-level LEVEL]
osniffy --reader FILE [--skip-dashboard] [--env-file FILE] [--log-level LEVEL]
```

- `--sniffer` and `--reader` are mutually exclusive and one is required.
- Sniffer mode requires elevated privileges on Linux (`root` / `CAP_NET_RAW`).
- Reader mode validates that `FILE` exists.
- Exit codes:
  - `0`: success
  - `1`: runtime error
  - `2`: configuration error

### Parsed packet fields

Each stored packet includes:

- `srcMAC`, `dstMAC`, `etherType`
- `srcIP`, `dstIP`
- `protocol`
- `srcPort`, `dstPort`
- `timestamp`

Only parsed/recognized ARP/ICMP/TCP/UDP flows are labeled; unsupported protocols are safely ignored.

### Database schema

Table columns:

- `packetID` (PK, auto increment)
- `srcMAC`, `dstMAC`, `etherType`
- `srcIP`, `dstIP`
- `protocol`
- `srcPort`, `dstPort`
- `timestamp`

Indexes are created on:

- `timestamp`
- `protocol`
- `srcIP` (prefix)
- `dstIP` (prefix)

### Grafana flow

- Preferred: declarative provisioning from `grafana/provisioning/`.
- Fallback: runtime API provisioning using `GRAFANA_API_KEY`.
- Reader mode opens dashboard with capture-derived `from/to` timestamps.
- Sniffer mode opens dashboard with `now-5m -> now` and refresh.

## Setup

```bash
cp .env.example .env
# fill credentials
pip install -e ".[dev]"
```

## Run

```bash
# reader mode
osniffy --reader /path/to/capture.pcap

# sniffer mode (Linux)
sudo osniffy --sniffer
```

## Development quality gates

```bash
ruff check osniffy/ tests/
ruff format --check osniffy/ tests/
mypy osniffy/
pytest
```

## Grafana declarative provisioning

Mount these paths into Grafana:

- `grafana/provisioning/datasources`
- `grafana/provisioning/dashboards`
- `grafana/dashboards`

## Security notes

- Use separate DB users for ingest (write) and Grafana (read-only).
- Never commit real secrets; use local `.env` or external secret stores.
- Live capture requires privileged socket access; prefer isolated hosts/containers.
- Optional (Windows): set `OSNIFFY_CAPTURE_BIND` to a specific local interface IP.
