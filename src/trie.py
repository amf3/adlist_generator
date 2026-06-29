from typing import Iterable, Any, Generator, Dict, List, Tuple
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

    Each node stores the source URL that introduced it so attribution survives
    through to the manifest and build summary. Subsumption prune counts are
    tracked per source URL so the summary can show how many domains each list
    contributed that were made redundant by a parent zone from another list.

    Internal node metadata uses dunder keys (__policy__, __records__,
    __source__) to avoid collisions with domain label tokens.
    """

    def __init__(self):
        self.root: Dict[str, Any] = {}
        # source_url -> count of domains from that source pruned by subsumption
        self.subsumption_counts: Dict[str, int] = defaultdict(int)
        # count of domains pruned because a parent from the SAME node arrived later
        self.self_subsumption_counts: Dict[str, int] = defaultdict(int)

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
                # A parent zone already blocks this domain.
                self.subsumption_counts[source_url] += 1
                return

            if token not in current_node:
                current_node[token] = {}
            current_node = current_node[token]

        current_node["__policy__"] = "always_nxdomain"
        current_node["__source__"] = source_url

        # Prune any children accumulated before this parent arrived.
        # Walk the subtree to count pruned domains per source.
        keys_to_drop = [
            k
            for k in current_node
            if k not in ("__policy__", "__records__", "__source__")
        ]
        for k in keys_to_drop:
            self._count_and_prune(current_node[k], source_url)
            del current_node[k]

    def _count_and_prune(self, node: Dict[str, Any], parent_source: str) -> None:
        """
        Recursively count domains in a subtree being pruned, attributing each
        to the correct subsumption counter based on whether the parent and child
        came from the same source or different sources.
        """
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

    def inject_local_dns(self, local_entries: List[Any]) -> None:
        """
        Insert user-configured local authority entries from validated Pydantic models.

        Local entries override any existing block policy at that node.
        If auto_ptr is set, a corresponding PTR record is synthesized in the
        in-addr.arpa / ip6.arpa subtree.
        """
        for entry in local_entries:
            tokens = self._tokenize_and_reverse(entry.domain)
            if not tokens:
                continue

            current_node = self.root
            for token in tokens:
                if token not in current_node:
                    current_node[token] = {}
                current_node = current_node[token]

            current_node["__policy__"] = entry.policy
            current_node["__source__"] = "local"
            current_node["__records__"] = {}

            record_dump = entry.records.model_dump(exclude_none=True)
            for record_type, value in record_dump.items():
                current_node["__records__"][record_type] = str(value)

                if entry.auto_ptr and record_type in ("A", "AAAA"):
                    self._insert_ptr_record(str(value), entry.domain)

    def _insert_ptr_record(self, ip_str: str, target_domain: str) -> None:
        """
        Synthesize a reverse PTR record for a given IP and insert it into the trie.

        Uses ipaddress.ip_address.reverse_pointer to derive the in-addr.arpa
        or ip6.arpa zone name.
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

            current_node["__policy__"] = "static"
            current_node["__source__"] = "local"
            current_node["__records__"] = {"PTR": f"{target_domain}."}
        except ValueError as e:
            print(f"Warning: could not generate PTR record for '{ip_str}': {e}")

    def serialize_pruned_tree(self) -> List[Tuple[str, str, Dict[str, Any], str]]:
        """
        Walk the trie depth-first and return all policy nodes as flat tuples.

        Returns a list of (domain, policy, records, source_url) tuples,
        sorted in reversed-label order (grouped by TLD, then SLD, etc.).
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
        policy = current_node.get("__policy__")
        records = current_node.get("__records__", {})
        source = current_node.get("__source__", "unknown")

        if policy:
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
