#!/usr/bin/env python3
"""Parse and validate a mecmcp-family packaging/conformance.toml.

Emits shell-safe KEY=value lines for eval. Exits 2 on any invalid manifest,
so a typo cannot silently disable a rule.
"""
import sys
import tomllib

REQUIRED = {
    "binary": str, "installer": str, "service": str,
    "config_dir": str, "tokens": str,
    "build_info": bool, "units": list, "must_survive_override": list,
}
OPTIONAL = {
    "skip_build_env": (str, bool),
    "placeholders": dict,
    "audit_entrypoint": (str, bool),
    "audit_hmac_flag": (str, bool),
}

# Keys whose value is resolved against the package staging directory by
# verify-package.sh. An absolute value is silently joined onto $STAGING there,
# which reports "not found" for a path that exists -- so reject it here with a
# message that says what is actually wrong.
STAGING_RELATIVE = ("binary", "installer")


def die(message):
    print(f"manifest error: {message}", file=sys.stderr)
    raise SystemExit(2)


def type_name(kind):
    if isinstance(kind, tuple):
        return " or ".join(one.__name__ for one in kind)
    return kind.__name__


def check_framing(where, value, forbid_tab=False):
    """Reject characters that would break the reader's own output framing.

    Scalar output is one KEY=value line per key and the caller assigns each
    line to a shell variable, so an embedded newline forges a second
    assignment -- a `tokens` value ending in "\\nCONF_BINARY=/bin/sh" would
    redirect R2 at a file that exists. List output is one item per line, and
    placeholder output is TOKEN<TAB>VALUE, so the same reasoning applies
    there.
    """
    if not isinstance(value, str):
        die(f"{where} must be a string (quote the value); got {type(value).__name__}")
    if "\n" in value or "\r" in value:
        die(
            f"{where} must not contain a newline. The reader emits one value "
            "per line and the caller assigns each line to a shell variable, "
            "so an embedded newline would forge a second assignment."
        )
    if forbid_tab and "\t" in value:
        die(f"{where} must not contain a tab; placeholders are emitted as TOKEN<TAB>VALUE")


def validate(data):
    unknown = set(data) - set(REQUIRED) - set(OPTIONAL)
    if unknown:
        die(f"unknown key(s): {', '.join(sorted(unknown))}")

    for key, kind in REQUIRED.items():
        if key not in data:
            die(f"missing required key: {key}")
        if not isinstance(data[key], kind):
            die(f"{key} must be {type_name(kind)}")

    # Optional keys were declared and never enforced, so `skip_build_env = true`
    # -- a bool -- satisfied the provenance ordering guard below while emitting
    # an EMPTY CONF_SKIP_BUILD_ENV, which silently disabled R3's rustc clause.
    for key, kind in OPTIONAL.items():
        if key in data and not isinstance(data[key], kind):
            die(f"{key} must be {type_name(kind)}")

    skip_build = data.get("skip_build_env", False)
    if skip_build is True:
        die(
            "skip_build_env = true is not a value. It must name the environment "
            "variable the packager honours to accept a prebuilt binary, e.g. "
            'skip_build_env = "SVC_SKIP_BUILD", or be false when the repo has no '
            "such path. A bare true satisfies the provenance ordering guard while "
            "naming nothing, which disables R3's rustc check."
        )
    if isinstance(skip_build, str):
        if not skip_build:
            die(
                'skip_build_env = "" is not a value. It must name the environment '
                "variable the packager honours to accept a prebuilt binary, or be "
                "false when the repo has no such path."
            )
        check_framing("skip_build_env", skip_build)

    for key in REQUIRED:
        if REQUIRED[key] is str:
            check_framing(key, data[key])

    for key in STAGING_RELATIVE:
        if data[key].startswith("/"):
            die(
                f"{key} must be a path inside the package staging directory, not "
                f"an absolute path: {data[key]}. verify-package.sh resolves it "
                "against --staging."
            )

    for name in ("units", "must_survive_override"):
        for index, item in enumerate(data[name]):
            check_framing(f"{name}[{index}]", item)
    for index, unit in enumerate(data["units"]):
        if unit.startswith("/"):
            die(
                f"units[{index}] must be a path inside the package staging "
                f"directory, not an absolute path: {unit}"
            )

    for token, value in data.get("placeholders", {}).items():
        check_framing(f"placeholder token {token!r}", token, forbid_tab=True)
        check_framing(f"placeholder value for {token!r}", value, forbid_tab=True)

    if data["build_info"] and not skip_build:
        die(
            "build_info = true requires skip_build_env. A repo with no supported "
            "way to package a CI-built binary cannot produce an honest BUILD-INFO, "
            "and demanding one is what produced the forged file in #355."
        )

    # audit_entrypoint follows the same false-sentinel shape as skip_build_env:
    # `true` is truthy but names nothing, and an empty string is indistinguishable
    # from "not set" in a shell eval, so both are rejected rather than silently
    # accepted as "R7 has nothing to check".
    audit_entrypoint = data.get("audit_entrypoint", False)
    if audit_entrypoint is True:
        die(
            "audit_entrypoint = true is not a value. It must name the path "
            "(inside the staging directory) to the container entrypoint script "
            "that generates the audit HMAC key when absent and always passes "
            "--audit-hmac-key-file to the binary, or be false when this repo's "
            "container image has not been migrated yet (R7 warns instead of "
            "failing until it has, see #376)."
        )
    if isinstance(audit_entrypoint, str):
        if not audit_entrypoint:
            die(
                'audit_entrypoint = "" is not a value. Name the entrypoint '
                "script path, or use false."
            )
        check_framing("audit_entrypoint", audit_entrypoint)
        if audit_entrypoint.startswith("/"):
            die(
                "audit_entrypoint must be a path inside the package staging "
                f"directory, not an absolute path: {audit_entrypoint}"
            )

    # audit_hmac_flag is the no-shell alternative to audit_entrypoint: a
    # distroless image has no shell to run a key-generating wrapper in (R7's
    # original design), so the binary generates its own key and the flag that
    # proves it (e.g. --audit-hmac-key-file) is baked directly into the
    # image's ENTRYPOINT array instead. Same false-sentinel shape as the other
    # two optional strings, for the same reason.
    audit_hmac_flag = data.get("audit_hmac_flag", False)
    if audit_hmac_flag is True:
        die(
            "audit_hmac_flag = true is not a value. It must name the flag "
            "(e.g. \"--audit-hmac-key-file\") that the image's ENTRYPOINT "
            "always passes to the binary, or be false when this repo's "
            "container image has not been migrated yet (R7 warns instead of "
            "failing until it has, see #376)."
        )
    if isinstance(audit_hmac_flag, str):
        if not audit_hmac_flag:
            die(
                'audit_hmac_flag = "" is not a value. Name the flag, or use '
                "false."
            )
        check_framing("audit_hmac_flag", audit_hmac_flag)
        if audit_entrypoint:
            die(
                "audit_entrypoint and audit_hmac_flag are mutually exclusive "
                "-- a repo either ships a key-generating entrypoint script "
                "(audit_entrypoint) or bakes a self-generating binary's flag "
                "straight into ENTRYPOINT (audit_hmac_flag), never both."
            )
        if audit_hmac_flag not in data["must_survive_override"]:
            die(
                f"audit_hmac_flag = {audit_hmac_flag!r} must also appear in "
                "must_survive_override. R7 does not re-verify the flag "
                "reaches the container's argv by itself -- it relies on R6 "
                "doing that, which only checks flags must_survive_override "
                "names."
            )

    return skip_build, audit_entrypoint, audit_hmac_flag


def main():
    if len(sys.argv) not in (2, 4) or (len(sys.argv) == 4 and sys.argv[2] != "--list"):
        die("usage: read-manifest.py <conformance.toml> [--list units|must_survive_override|placeholders]")
    try:
        with open(sys.argv[1], "rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        die(f"no such file: {sys.argv[1]}")
    except tomllib.TOMLDecodeError as error:
        die(f"not valid TOML: {error}")

    skip_build, audit_entrypoint, audit_hmac_flag = validate(data)

    if len(sys.argv) == 4:
        name = sys.argv[3]
        if name == "placeholders":
            for token, value in data.get("placeholders", {}).items():
                print(f"{token}\t{value}")
        elif name in ("units", "must_survive_override"):
            for item in data[name]:
                print(item)
        else:
            die(f"unknown list: {name}")
        return

    # Scalars only. Lists are never squeezed through eval.
    print("\n".join([
        f"CONF_BINARY={data['binary']}",
        f"CONF_INSTALLER={data['installer']}",
        f"CONF_SERVICE={data['service']}",
        f"CONF_CONFIG_DIR={data['config_dir']}",
        f"CONF_TOKENS={data['tokens']}",
        f"CONF_BUILD_INFO={'true' if data['build_info'] else 'false'}",
        f"CONF_SKIP_BUILD_ENV={skip_build if isinstance(skip_build, str) else ''}",
        f"CONF_AUDIT_ENTRYPOINT={audit_entrypoint if isinstance(audit_entrypoint, str) else ''}",
        f"CONF_AUDIT_HMAC_FLAG={audit_hmac_flag if isinstance(audit_hmac_flag, str) else ''}",
    ]))


if __name__ == "__main__":
    main()
