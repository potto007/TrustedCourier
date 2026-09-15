---
status: accepted
date: 2026-09-15
decision-makers: Paul Otto
---

# Config reload swaps whole snapshots and changes only access

## Context and Problem Statement

Operators change Policies, Secret Names, and Upstreams in the config file (ADR-0010) and need those changes to take effect without a restart, which would cut off Deliveries under way. A broken file must never take down Delivery. Some keys cannot change in a running process without more machinery: `data_dir` opens the database, `admin` and `agent_api` bind listeners, `backend_plugins` launches and pins plugin processes, and `audit` loads the signing key and sets the checkpoint cadence. How does a reload apply a file, and what happens to the keys it cannot apply?

## Considered Options

* Apply the keys that can change and ignore, or warn about, the rest
* Refuse a reload that changes a key that needs a restart
* Make every key reloadable

## Decision Outcome

Chosen option: "refuse a reload that changes a key that needs a restart", because a reload that reports success while part of the file is not in effect leaves the Operator reading a config the server is not running, the silent mismatch strict decoding exists to prevent.

* `tc reload` calls `POST /v1/config/reload` on the admin API. The server loads the file it started from and validates it exactly as at startup. Any error, including a changed `data_dir`, `admin`, `agent_api`, `backend_plugins`, or `audit`, refuses the whole reload with the reason, and the running snapshot stays in effect. Keys are compared after validation, so restating a default is no change.
* A valid file becomes a new immutable snapshot, swapped in atomically. Reloads are serialized.
* Every Agent API request takes one snapshot when it starts and uses only that one to find the Agent Token's credential slot, authorize, resolve the Secret Name, and pick the Upstream. A Delivery under way finishes on the snapshot it started with, so a reload never mixes two configs in one Delivery, and a long stream keeps its access until it ends.
* A new request sees the new snapshot at once. Removing a Policy removes its access from every Agent Token that names it on the next request; the tokens keep the name, which grants nothing unless a Policy by that name returns.
* Routes whose Upstream host and CA roots are unchanged keep their transport, and so their connections. Transports no route uses any more have their idle connections closed.

Ignoring the unappliable keys was rejected for the mismatch above; warning was rejected because a warning in a server log is easy to miss and the reload still exits 0. Making every key reloadable was deferred: rebinding listeners, restarting plugins, and swapping the audit signing key each need their own design, and no requirement asks for them yet.

### Consequences

* Good, because a typo in a reloaded file changes nothing, as a typo at startup starts nothing.
* Good, because in-flight Deliveries are neither cut off nor switched to a config they were not authorized under.
* Bad, because a Delivery that streams for a long time keeps access a reload removed until it ends.
* Bad, because changing a Backend Plugin, listener, or audit setting still takes a restart, and a file with such a change cannot reload its other changes until it is restored.
* As ADR-0012 foresaw, deleting a Secret Name that a Policy still lists is refused on reload, so both must change together.
