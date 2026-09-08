#!/usr/bin/env python3
"""Apply the connector registrations that scripts/add_connector.sh misses.

WHY THIS EXISTS
---------------
`add_connector.sh` covers 18 of the ~30 files a connector must touch. The rest
are silently skipped, because the script has no `set -e` and its `sed`
expressions are anchored on text that has since moved:

  * `crates/api_models/src/connector_enums.rs` is now a one-line re-export
    (`pub use common_enums::connector_enums::Connector;`). The real 515-line
    enum lives in `crates/common_enums/src/connector_enums.rs`, which the
    script never edits, so `s/\\(pub enum Connector {\\)/.../` matches nothing.

  * `crates/euclid/src/enums.rs` no longer declares `pub enum Connector`; it
    imports it and declares `RoutableConnectors` instead. Same dead sed.

  * `crates/router/src/types/api/connector_mapping.rs` and
    `crates/router/src/types/connector_transformers.rs` appear ONLY in the
    script's opening `git checkout` list and its closing `rm *-e` list. There
    is no sed for either: the housekeeping outlived the edits.

The result is a tree where 18 files register a connector that the dispatch
match, the enum and the routing conversions have never heard of. It does not
compile, and `add_connector.sh` still exits 0 and prints "Successfully
created connector".

This script is deliberately loud where that one is quiet: every anchor must
match exactly once, or it aborts without writing anything.

USAGE
-----
    python3 scripts/pinnacle_register_connector.py <connector_name>

Run it AFTER `add_connector.sh`, on a clean tree. It is idempotent.
"""

import re
import sys
from pathlib import Path

# Anchor connector. `Shift4` is used because each of the four shapes below
# occurs exactly once per file for it, which lets every insertion be verified
# rather than assumed. Ordering inside the enums is cosmetic - the compiler
# does not care - so we insert next to the anchor rather than alphabetically.
SITES = [
    dict(
        file="crates/common_enums/src/connector_enums.rs",
        anchor=r"^    Shift4,$",
        span=1,
        text="    __PASCAL__,",
        what="Connector enum member",
    ),
    dict(
        file="crates/common_enums/src/connector_enums.rs",
        anchor=r"^            \| Self::Shift4$",
        span=1,
        text="            | Self::__PASCAL__",
        what="separate-authentication connector list",
    ),
    dict(
        file="crates/euclid/src/enums.rs",
        anchor=r"^    Shift4,$",
        span=1,
        text="    __PASCAL__,",
        what="RoutableConnectors enum member",
    ),
    dict(
        file="crates/euclid/src/enums.rs",
        anchor=r"^            Connector::Shift4 => Ok\(Self::Shift4\),$",
        span=1,
        text="            Connector::__PASCAL__ => Ok(Self::__PASCAL__),",
        what="TryFrom<Connector> for RoutableConnectors",
    ),
    dict(
        file="crates/euclid/src/enums.rs",
        anchor=r"^            RoutableConnectors::Shift4 => Self::Shift4,$",
        span=1,
        text="            RoutableConnectors::__PASCAL__ => Self::__PASCAL__,",
        what="From<RoutableConnectors> for Connector",
    ),
    dict(
        # The 160-arm match that turns a connector name into a boxed impl.
        # Shift4's arm is three lines; insert after the closing brace.
        file="crates/router/src/types/api/connector_mapping.rs",
        anchor=r"^                enums::Connector::Shift4 => \{$",
        span=3,
        text=(
            "                enums::Connector::__PASCAL__ => {\n"
            "                    Ok(ConnectorEnum::Old(Box::new(connector::__PASCAL__::new())))\n"
            "                }"
        ),
        what="convert_connector dispatch match",
    ),
    dict(
        file="crates/router/src/types/connector_transformers.rs",
        anchor=r"^            api_enums::Connector::Shift4 => Self::Shift4,$",
        span=1,
        text="            api_enums::Connector::__PASCAL__ => Self::__PASCAL__,",
        what="Connector -> RoutableConnectors conversion",
    ),
    dict(
        # add_connector.sh DOES add the `pub <name>: Option<ConnectorTomlConfig>`
        # field to this file, but not the match arm that reads it back, so the
        # crate fails with E0004 non-exhaustive patterns.
        file="crates/connector_configs/src/connector.rs",
        anchor=r"^            Connector::Shift4 => Ok\(connector_data\.shift4\),$",
        span=1,
        text="            Connector::__PASCAL__ => Ok(connector_data.__NAME__),",
        what="connector_configs TOML lookup match",
    ),
    dict(
        # Auth-type validation performed when a merchant connector account is
        # created. Without an arm here the merchant can never be onboarded.
        file="crates/router/src/core/connector_validation.rs",
        anchor=r"^            api_enums::Connector::Shift4 => \{$",
        span=4,
        text=(
            "            api_enums::Connector::__PASCAL__ => {\n"
            "                __NAME__::transformers::__PASCAL__AuthType::try_from(self.auth_type)?;\n"
            "                Ok(())\n"
            "            }"
        ),
        what="merchant-connector-account auth validation",
    ),
    dict(
        # A SECOND copy of the dispatch match, identical in shape to the one in
        # connector_mapping.rs. Both are exhaustive, so both must be updated.
        file="crates/router/src/types/api/feature_matrix.rs",
        anchor=r"^                enums::Connector::Shift4 => \{$",
        span=3,
        text=(
            "                enums::Connector::__PASCAL__ => {\n"
            "                    Ok(ConnectorEnum::Old(Box::new(connector::__PASCAL__::new())))\n"
            "                }"
        ),
        what="feature_matrix dispatch match",
    ),
]


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <connector_name>", file=sys.stderr)
        return 2

    name = sys.argv[1].lower()
    pascal = name[:1].upper() + name[1:]
    root = Path(__file__).resolve().parent.parent

    # Resolve every edit before writing any of them, so a bad anchor leaves the
    # tree untouched instead of half-registered.
    planned, skipped = [], []
    for site in SITES:
        path = root / site["file"]
        if not path.exists():
            print(f"ERROR: missing file {site['file']}", file=sys.stderr)
            return 1

        lines = path.read_text(encoding="utf-8").splitlines()
        new_text = site["text"].replace("__PASCAL__", pascal).replace("__NAME__", name)

        if new_text.splitlines()[0] in lines:
            skipped.append(site["what"])
            continue

        hits = [i for i, ln in enumerate(lines) if re.match(site["anchor"], ln)]
        if len(hits) != 1:
            print(
                f"ERROR: anchor {site['anchor']!r} matched {len(hits)} lines in "
                f"{site['file']} (expected exactly 1). Refusing to guess.",
                file=sys.stderr,
            )
            return 1

        planned.append((path, hits[0] + site["span"], new_text, site["what"]))

    # Apply bottom-up per file so earlier insertions do not shift later offsets.
    for path in {p for p, _, _, _ in planned}:
        edits = sorted(
            [e for e in planned if e[0] == path], key=lambda e: e[1], reverse=True
        )
        lines = path.read_text(encoding="utf-8").splitlines()
        for _, at, text, _ in edits:
            lines[at:at] = text.splitlines()
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    for _, _, _, what in planned:
        print(f"  registered: {what}")
    for what in skipped:
        print(f"  already present, skipped: {what}")
    print(f"\n{len(planned)} inserted, {len(skipped)} skipped, for '{pascal}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
