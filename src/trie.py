# src/trie.py
from typing import Iterable, Any, Dict, List, Tuple
from collections import defaultdict
import ipaddress


class ReversedDomainTrie:
    """
    A trie keyed on reversed domain labels for efficient hierarchical deduplication.

    Domains are tokenized and reversed before insertion so that parent zones
    share a common prefix in the tree. This makes top-down pruning trivial:
    once a parent node is marked blocked, any child node is redundant and can
    be skipped at insertion time or dropped during serialization.

    Example: 'ads.example.com' becomes ['com', 'example', 'ads'] in the trie.

    Local DNS records are injected as zone groups rather than individual
    hostname entries. Each zone carries a shared policy; hostnames within it
    carry only resource records. The writer emits one local-zone directive
    per zone and one local-data directive per record, which allows Unbound
    to follow CNAME chains internally within a transparent zone.

    Internal node metadata uses dunder keys (__policy__, __records__,
    __source__, __zone__) to avoid collisions with domain label tokens.
    """

    def __init__(self):
        self.root: Dict[str, Any] = {}
        self.subsumption_counts: Dict[str, int] = defaultdict(int)
        self.self_subsumption_counts: Dict[str, int] = defaultdict(int)
        # Ordered list of (zone_name, policy) for writer zone header emission.
        # Preserves declaration order from local_dns.yml.
        self._local_zones: List[Tuple[str, str]] = []

    def _tokenize_and_reverse(self, domain: str) -> List[str]:
        """Split 'ads.example.com' into ['com', 'example', 'ads']."""
        clean_domain = domain.strip().rstrip(".")
        if not clean_domain:
            return []
        tokens = clean_domain.split(".")
        tokens.reverse()
        return tokens

    def insert_block_domain(self, domain: str, source_url: str) -> None:
        """
        Insert a domain from a public adlist.

        If a parent zone is already marked always_nxdomain, the child is
        redundant and insertion short-circuits, incrementing the subsumption
        count for the child's source list.

        If the domain is inserted at a node that already has children, those
        children are pruned and their source attributions are used to update
        the appropriate subsumption counters.
        """
        tokens = self._tokenize_and_reverse(domain)
        if not tokens:
            return

        current_node = self.root

        for token in tokens:
            if current_node.get("__policy__") == "always_nxdomain":
                self.subsumption_counts[source_url] += 1
                return
            if token not in current_node:
                current_node[token] = {}
            current_node = current_node[token]

        current_node["__policy__"] = "always_nxdomain"
        current_node["__source__"] = source_url

        keys_to_drop = [
            k
            for k in current_node
            if k not in ("__policy__", "__records__", "__source__")
        ]
        for k in keys_to_drop:
            self._count_and_prune(current_node[k], source_url)
            del current_node[k]

    def _count_and_prune(self, node: Dict[str, Any], parent_source: str) -> None:
        if "__policy__" in node:
            child_source = node.get("__source__", parent_source)
            if child_source == parent_source:
                self.self_subsumption_counts[parent_source] += 1
            else:
                self.subsumption_counts[child_source] += 1
        for key, child in node.items():
            if not key.startswith("__"):
                self._count_and_prune(child, parent_source)

    def ingest_stream(self, domain_iterator: Iterable[Tuple[str, str]]) -> None:
        """Consume a (domain, source_url) iterator, building the trie incrementally."""
        for domain, source_url in domain_iterator:
            self.insert_block_domain(domain, source_url)

    def inject_local_dns(self, local_zones: List[Any]) -> None:
        """
        Insert validated LocalZone entries from local_dns.yml.

        Each zone is registered in _local_zones so the writer can emit the
        correct local-zone header. Individual hostname records are inserted
        into the trie as local-data entries without per-hostname zone policies
        — the zone policy is authoritative for the entire zone.

        PTR records are synthesized for any A/AAAA entry with auto_ptr=True.
        """
        for zone in local_zones:
            zone_name = zone.zone.rstrip(".")
            self._local_zones.append((zone.zone, zone.policy))

            for record in zone.records:
                tokens = self._tokenize_and_reverse(record.domain)
                if not tokens:
                    continue

                current_node = self.root
                for token in tokens:
                    if token not in current_node:
                        current_node[token] = {}
                    current_node = current_node[token]

                current_node["__source__"] = "local"
                current_node["__zone__"] = zone.zone
                current_node["__records__"] = {}

                record_dump = record.records.model_dump(exclude_none=True)
                for record_type, value in record_dump.items():
                    current_node["__records__"][record_type] = str(value)

                    if record.auto_ptr and record_type in ("A", "AAAA"):
                        self._insert_ptr_record(str(value), record.domain)

    def _insert_ptr_record(self, ip_str: str, target_domain: str) -> None:
        """
        Synthesize a reverse PTR record and insert it into the trie.

        PTR records are inserted without a zone association — they live in
        the in-addr.arpa / ip6.arpa namespace and are emitted as bare
        local-data entries by the writer.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            ptr_domain = ip_obj.reverse_pointer
            tokens = self._tokenize_and_reverse(ptr_domain)

            current_node = self.root
            for token in tokens:
                if token not in current_node:
                    current_node[token] = {}
                current_node = current_node[token]

            current_node["__source__"] = "local"
            current_node["__records__"] = {"PTR": f"{target_domain}."}
        except ValueError as e:
            print(f"Warning: could not generate PTR record for '{ip_str}': {e}")

    def serialize_pruned_tree(self) -> List[Tuple[str, str, Dict[str, Any], str]]:
        """
        Walk the trie depth-first and return all policy nodes as flat tuples.

        Returns (domain, policy, records, source_url) tuples sorted in
        reversed-label order. Local record nodes no longer carry a policy
        in the trie (policy lives on the zone); they are returned with an
        empty policy string so the writer can distinguish them from adblock
        entries and emit them as local-data without a local-zone directive.

        Nodes marked always_nxdomain do not recurse into children.
        """
        finalized: List[Tuple[str, str, Dict[str, Any], str]] = []
        self._dfs_walk(self.root, [], finalized)
        return finalized

    def _dfs_walk(
        self,
        current_node: Dict[str, Any],
        current_path: List[str],
        output_list: List[Tuple[str, str, Dict[str, Any], str]],
    ) -> None:
        policy = current_node.get("__policy__", "")
        records = current_node.get("__records__", {})
        source = current_node.get("__source__", "unknown")

        if policy or records:
            domain_tokens = list(current_path)
            domain_tokens.reverse()
            reconstructed_domain = ".".join(domain_tokens)
            output_list.append((reconstructed_domain, policy, records, source))

            if policy == "always_nxdomain":
                return

        sorted_keys = sorted(k for k in current_node if not k.startswith("__"))
        for next_token in sorted_keys:
            current_path.append(next_token)
            self._dfs_walk(current_node[next_token], current_path, output_list)
            current_path.pop()
