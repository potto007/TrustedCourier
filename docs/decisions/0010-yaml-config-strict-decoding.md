---
status: accepted
date: 2026-09-14
decision-makers: Paul Otto
---

# The config file is YAML, decoded strictly

## Context and Problem Statement

Operators keep Backends, Secret Names, Policies, and listener settings in a config file reviewed in Git (ADR-0001). A typo in that file can silently widen or narrow access. What format, and how forgiving is the loader?

## Considered Options

* YAML
* TOML
* HCL
* JSON

## Decision Outcome

Chosen option: "YAML, decoded strictly", because it is what AI engineers already write for docker compose and Kubernetes, and it nests Policies and Secret Names readably.

* Decoding rejects unknown fields, so a misspelled key fails loudly instead of being ignored.
* Duplicate mapping keys (such as a Policy defined twice) are rejected.
* Policies are a mapping keyed by Policy name, so names are unique by construction.
* Validation produces an immutable snapshot or an error; TrustedCourier refuses to start on an invalid config.
* Relative paths in the file resolve against the file's directory.
* The decoder is `go.yaml.in/yaml/v3`, the maintained continuation of `gopkg.in/yaml.v3`.

JSON was rejected for lacking comments; HCL for being unfamiliar outside HashiCorp tools; TOML for awkward deep nesting of per-Secret-Name settings.

### Consequences

* Good, because typos in access rules stop the process rather than silently changing behavior.
* Bad, because YAML's implicit typing (such as `no` as a boolean) can surprise; strict typed decoding surfaces most of those as errors.
