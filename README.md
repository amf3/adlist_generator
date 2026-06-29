# adlist_generator

Downloads and merges public DNS blocklists, deduplicates them using a hierarchical
approach (blocking `tracker.com` automatically covers `ads1.tracker.com`,
`ads2.tracker.com`, and any future subdomains), and writes the result as
[Unbound DNS](https://nlnetlabs.nl/projects/unbound/about/) configuration files.

Also supports local split-horizon DNS: A, AAAA, CNAME, SRV records and automatic
PTR records. Additionally generates a `manifest.reversed` and `build_summary.txt` suitable
for tracking upstream list changes in git.

The generator runs standalone or as a Docker build stage, producing a minimal Unbound
container with configs baked in at image build time.

## How it works

```
configs/
  adlists_sources.yml     # which public blocklists to fetch and their format
  local_dns.yml           # your local A/AAAA/CNAME/PTR records (optional)
  server_config.yml       # Unbound server directives
        ↓
  adlist_generator        # Fetches adlists, parses, deduplicates, and writes configs
        ↓
dist/                     # Directory created at run time
  unbound.conf            # main config with conditional includes
  adblock.conf            # always_nxdomain zones from merged blocklists
  local_records.conf      # local authority records
  manifest.reversed       # audit log in reversed-label order, with source attribution
  build_summary.txt       # per-list stats, overlap matrix, and list recommendations
```

## Requirements

- Python 3.11+
- pip dependencies from `requirements.txt`
- Alternatively Docker buildx or Buildah

## Setup

```bash
git clone https://github.com/amf3/adlist_generator
cd adlist_generator
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

The generator expects a `configs/` directory with up to three YAML files.
`configs.example/` contains annotated starting points for each.

```bash
cp -r configs.example configs
# Edit configs/ to match your environment
```

Generate JSON schemas for editor validation (optional but recommended):

```bash
python -m src.main --dump-schema
```

This writes schema files to `configs/`. Add the schema header to your YAML files
for inline validation in VS Code or any editor with YAML language server support:

```yaml
# yaml-language-server: $schema=./server_config.schema.json
```

## Running

From the project root:

```bash
python -m src.main
```

Both the config and output directories are configurable:

```bash
python -m src.main --config-dir ./my-configs --output-dir ./output
python -m src.main --help
```

## Building with Docker

Before building, ensure your `configs/` directory exists and is populated.
See the **Setup** section above, or copy from `configs.example/` as a starting point.

```bash
cp -r configs.example configs
# Edit configs/ to match your environment
```

The included Dockerfile uses a two stage build: a Python builder stage fetches the
blocklists and generates the configs, then copies the output into a minimal Unbound
runtime image.

```bash
docker buildx build -t unbound-dns .
docker run -p 53:53/udp -p 53:53/tcp unbound-dns
```

Note: the base images in the Dockerfile are specific to this project's build
environment. Substitute your own Python and Unbound base images as needed.

## Managing your configs and output on a public fork

The generator, your configuration, and its output are all intentionally kept separate.

Your `configs/` directory contains your network's hostnames, IP addresses, and DNS
policy. Your `dist/` directory contains the generated output from those configs —
the manifest, build summary, and Unbound config files. Both are specific to your
environment and neither belongs in a public repo.

The included `.gitignore` excludes both directories. When you fork or clone this
repo, create your `configs/` locally from `configs.example/` and never commit either:

```bash
cp -r configs.example configs
```

If you want to version your configs and generated output, which is recommended 
since `dist/manifest.reversed` and `dist/build_summary.txt` are useful for forensics,
keep them together in a private repo and point the generator at them:

```bash
python -m src.main \
  --config-dir ~/private/dns-configs/configs \
  --output-dir ~/private/dns-configs/dist
```

Then commit both directories in that private repo. If an app breaks or ads appear,
`git log -p dist/manifest.reversed` shows exactly which upstream list introduced the
domain and when, and `dist/build_summary.txt` shows the list overlap and redundancy
stats from that build.

This lets you pull upstream generator changes without merge conflicts against your
personal files, and keeps your network topology out of a public repo.

## Directory structure

```
adlist_generator/
├── src/
│   ├── main.py           # entry point and pipeline orchestration
│   ├── parsers.py        # hosts / domain / adblock format parsers
│   ├── schemas.py        # Pydantic models for config validation
│   ├── trie.py           # hierarchical deduplication
│   ├── writer.py         # Unbound config file renderer
│   └── reporter.py       # build summary generation
├── tests/
├── configs.example/      # annotated sample configs
├── dist/                 # generated output (partially committed, see above)
├── Dockerfile
└── requirements.txt
```

## Contact

Open a GitHub issue for bugs or questions.
