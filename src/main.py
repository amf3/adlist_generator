# src/main.py
import sys
import os
import argparse
import yaml

from .schemas import LocalDNSConfig, UnboundServerSettings, AdlistConfig
from .parsers import DomainNormalizer
from .trie import ReversedDomainTrie
from .writer import ConfigurationWriter
from .reporter import write_build_summary


def run_pipeline(
    sources_path: str, local_dns_path: str, server_config_path: str, output_dir: str
):
    print("Loading server configuration...")

    try:
        with open(server_config_path) as f:
            server_settings = UnboundServerSettings(**yaml.safe_load(f))
    except Exception as e:
        print(f"Error: server configuration invalid: {e}", file=sys.stderr)
        sys.exit(1)

    local_zones = []
    if os.path.exists(local_dns_path):
        try:
            with open(local_dns_path) as f:
                loaded = yaml.safe_load(f)
                if loaded and "local_dns" in loaded:
                    local_dns_config = LocalDNSConfig(**loaded)
                    local_zones = local_dns_config.local_dns
        except Exception as e:
            print(
                f"Warning: local_dns.yml failed schema validation: {e}. Skipping local entries."
            )
    else:
        print(f"Info: '{local_dns_path}' not found. Proceeding without local entries.")

    adlist_sources = []
    if os.path.exists(sources_path):
        try:
            with open(sources_path) as f:
                loaded = yaml.safe_load(f)
                adlist_config = AdlistConfig(**loaded)
                adlist_sources = adlist_config.sources
        except Exception as e:
            print(
                f"Warning: adlists_sources.yml failed schema validation: {e}. Skipping."
            )
    else:
        print(f"Info: '{sources_path}' not found. Proceeding without adlist sources.")

    os.makedirs(output_dir, exist_ok=True)
    trie = ReversedDomainTrie()
    normalizer = DomainNormalizer(config_list=[s.model_dump() for s in adlist_sources])

    if adlist_sources:
        print("Ingesting adlist sources...")
        trie.ingest_stream(normalizer.yield_all_domains())

    if local_zones:
        print("Injecting local DNS records...")
        trie.inject_local_dns(local_zones)

    print("Serializing trie...")
    finalized_dataset = trie.serialize_pruned_tree()

    adblock_entries = [
        item
        for item in finalized_dataset
        if item[1] == "always_nxdomain" and not item[2]
    ]
    local_record_entries = [item for item in finalized_dataset if item[3] == "local"]

    print("Writing configuration files...")
    writer = ConfigurationWriter(
        server_settings=server_settings,
        finalized_data=finalized_dataset,
        local_zones=trie._local_zones,
    )

    writer.write_master_unbound_conf(output_dir)
    writer.write_compiled_adblock_conf(os.path.join(output_dir, "adblock.conf"))
    writer.write_local_records_conf(os.path.join(output_dir, "local_records.conf"))
    writer.write_git_manifest(os.path.join(output_dir, "manifest.reversed"))

    write_build_summary(
        filepath=os.path.join(output_dir, "build_summary.txt"),
        source_stats=normalizer.source_stats,
        subsumption_counts=dict(trie.subsumption_counts),
        self_subsumption_counts=dict(trie.self_subsumption_counts),
        final_blocked_count=len(adblock_entries),
        local_record_count=len(local_record_entries),
    )

    print(f"\nDone. Output staged in: ./{output_dir}/")


def run_schema_export():
    """Generates JSON schema files for all three configuration files."""
    import json

    target_dir = "./configs"
    os.makedirs(target_dir, exist_ok=True)

    schemas = [
        (AdlistConfig, "adlists_sources.schema.json", "adlists_sources.yml"),
        (LocalDNSConfig, "local_dns.schema.json", "local_dns.yml"),
        (UnboundServerSettings, "server_config.schema.json", "server_config.yml"),
    ]

    for model, filename, config_file in schemas:
        schema = model.model_json_schema()
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        output_path = os.path.join(target_dir, filename)
        with open(output_path, "w") as f:
            json.dump(schema, f, indent=2)
        print(f"Written: {output_path}")
        print(f"  Add '# yaml-language-server: $schema=./{filename}' to {config_file}")


def main():
    parser = argparse.ArgumentParser(description="Unbound DNS configuration compiler")
    parser.add_argument(
        "--dump-schema",
        action="store_true",
        help="Export JSON validation schemas to configs/.",
    )
    parser.add_argument(
        "--config-dir",
        default="./configs",
        help="Directory containing configuration files. (Default: ./configs)",
    )
    parser.add_argument(
        "--output-dir",
        default="./dist",
        help="Directory for generated output files. (Default: ./dist)",
    )

    args = parser.parse_args()

    if args.dump_schema:
        run_schema_export()
        sys.exit(0)

    sources_path = os.path.join(args.config_dir, "adlists_sources.yml")
    local_dns_path = os.path.join(args.config_dir, "local_dns.yml")
    server_config_path = os.path.join(args.config_dir, "server_config.yml")

    run_pipeline(
        sources_path=sources_path,
        local_dns_path=local_dns_path,
        server_config_path=server_config_path,
        output_dir=args.output_dir,
    )


if __name__ == "__main__":
    main()
