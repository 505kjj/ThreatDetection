"""Domain and numeric structural grouping for the captured development cohort."""

from collections import Counter, defaultdict
from math import floor, log2

from replay import FEATURES, GROUPS

AXES = ("elements", "links", "scripts", "depth")
FAMILY_COLUMNS = tuple(key for key in FEATURES if key not in GROUPS["title"])


def bucket(key, value):
    if key == "links_external_ratio":
        return floor(value * 8)
    if key == "depth" or value < 4:
        return int(value)
    return 2 + floor(log2(value))


def signatures(row):
    dom = row["dom"]
    exact = tuple(dom[key] for key in FEATURES)
    family = tuple(bucket(key, dom[key]) for key in FAMILY_COLUMNS)
    return exact, family


class Components:
    def __init__(self, size):
        self.parent = list(range(size))
        self.size = [1] * size

    def find(self, item):
        while item != self.parent[item]:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, first, second):
        first, second = self.find(first), self.find(second)
        if first == second:
            return
        if self.size[first] < self.size[second]:
            first, second = second, first
        self.parent[second] = first
        self.size[first] += self.size[second]


def grouped_views(pools):
    # Preserve validation membership. Quarantine conflicts from earlier views.
    order = ("validation", "calibration", "tuning", "train")
    rows = [row for view in order for row in pools[view]]
    groups = Components(len(rows))
    representatives = {}
    families = {}
    for index, row in enumerate(rows):
        for key in ("group", "alias", "family", "exact"):
            token = row["identity"][key]
            if token:
                groups.union(index, representatives.setdefault((key, token), index))
        family = signatures(row)[1]
        groups.union(index, families.setdefault(family, index))
    # A near match differs by one adjacent bin on one size axis. Keep the
    # remaining structural and form relationships fixed, including zeros.
    positions = [FAMILY_COLUMNS.index(key) for key in AXES]
    for family, index in families.items():
        for i in positions:
            if family[i] > 1:
                previous = family[:i] + (family[i] - 1,) + family[i + 1:]
                if previous in families:
                    groups.union(index, families[previous])
    owners = {}
    counts = Counter(groups.find(i) for i in range(len(rows)))
    family_view = {part: {"removed": [0, 0], "kept": [0, 0]} for part in order}
    retained = {part: [] for part in order}
    for i, row in enumerate(rows):
        root = groups.find(i)
        part = row["partition"]
        keep = owners.setdefault(root, part) == part
        family_view[part]["kept" if keep else "removed"][row["label"]] += 1
        if keep:
            retained[part].append(row | {"structuralComponent": root})
    test_sets = [{row["structuralComponent"] for row in retained[part]} for part in order]
    if sum(map(len, test_sets)) != len(set.union(*test_sets)):
        raise ValueError("Structural components crossed retained partitions")
    return retained, {"components": len(counts), "largestComponent": max(counts.values(), default=0),
                      "numericFamilies": len(families), "byPartitionNegativePositive": family_view}


def collision_audit(train, validation):
    index = defaultdict(list)
    for row in train:
        index[signatures(row)[0]].append(row)
    matches = Counter()
    vectors = set()
    domains = set()
    for row in validation:
        signature = signatures(row)[0]
        peers = index.get(signature)
        if not peers:
            continue
        vectors.add(signature)
        domains.add(row["identity"]["group"])
        matches["rows"] += 1
        matches["positive" if row["label"] else "negative"] += 1
        matches["unanimousSameLabel" if {peer["label"] for peer in peers} == {row["label"]}
                else "hasOppositeLabelPeer"] += 1
        matches["hasPassword"] += row["dom"]["inputs_password"] > 0
        matches["hasPaymentMetadata"] += row["dom"]["inputs_payment"] > 0
        matches["smallDomAtMost20"] += row["dom"]["elements"] <= 20
    return dict(matches) | {"distinctVectors": len(vectors), "validationDomains": len(domains),
                            "largestMatchingTrainVector": max((len(index[key]) for key in vectors), default=0)}
