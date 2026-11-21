# API

ffs serves a read-only JSON API under `/api/v1` on the web UI's listener (`listen`, default `127.0.0.1:8080`). The web UI uses only this API, so everything it shows can be read here too. The contract is an OpenAPI 3.1 document, served unchanged at `/api/v1/openapi.yaml` and kept in the repository at `api/openapi.yaml`. Generated clients are not published.

## Access

Reach the API the same way as the web UI:

```sh
kubectl -n ffs port-forward deploy/ffs 8080
```

The API has no authentication. To serve it beyond a port-forward, put an authenticating proxy in front; see [Exposing the web UI](configuration.md#exposing-the-web-ui).

- Only `GET` and `HEAD` are served. Any other method is `405 Method Not Allowed` with `Allow: GET, HEAD`.
- A request whose `Host` is not `localhost`, an IP literal or a name in `allowedHosts` is `421 Misdirected Request`.
- Responses under `/api/` carry `Cache-Control: no-store`. They are gzip-compressed when the client accepts it; the event stream never is.

## Responses

Every successful body and every problem document carries `cluster`, the cluster name, and `generatedAt`, the time the answer was built (RFC 3339, UTC). The event stream and the plain-text `421` and `405` answers do not; the `421` never names the cluster.

No response contains a Secret, its contents, or the name of a pull secret.

Counts are findings: one finding is one workload affected by one advisory. The explorer endpoints for workloads, images and packages count those entities instead, including clean, pending and unresolvable ones.

## Scopes

Most operations take a `scope` parameter that narrows the answer:

| Scope | Meaning |
|---|---|
| `cluster` | The whole cluster. The default. |
| `namespace:<namespace>` | One namespace. |
| `workload:<kind>/<namespace>/<name>` | One workload, for example `workload:Deployment/shop/web`. The namespace part is empty for owners without one (`workload:Cluster//test`). In the path of `/api/v1/workloads/{kind}/{namespace}/{name}`, such a namespace is written `-`. |
| `image:<digest>` | One image, by any image ID, including placeholders such as `unknown:registry.example.com/app:1.0`. In the path of `/api/v1/images/{digest}`, percent-encode the ID as one segment. |
| `nodegroup:<id>` | One node group, by its key as the API's links give it, its label or its ID. |
| `node:<name>` | One node. |
| `controlplane` | The Kubernetes control plane and the container runtime. |

A malformed scope, or one an operation does not accept, is `400` with the code `invalid_scope`. An unknown node, node group or workload is `404` with the code `not_found`. The operations table lists the scopes each operation accepts where it does not accept them all.

## Filters, facets and sorting

The explorer endpoints (`/findings`, `/workloads`, `/images` and `/packages`) filter, count and sort on the server.

- Array parameters are comma-joined: `priority=urgent,high`. Values of one parameter match any of them, except `signal`, where every listed signal must hold. Different parameters must all match.
- `/findings` returns open findings unless `state` says otherwise. `state=resolved` covers findings resolved in the last 30 days.
- `facets=<names>` adds per-value counts under every filter except that facet's own, so a selected value never hides its siblings. Each value carries `selected` when the query chose it. The facet names are:

  | Endpoint | Facets |
  |---|---|
  | `/findings` | `state`, `priority`, `fix`, `signal`, `ecosystem`, `namespace`, `kind` |
  | `/workloads` | `kind`, `namespace`, `signal`, `priority`, `coverage` |
  | `/images` | `status`, `source`, `coverage`, `namespace`, `priority` |
  | `/packages` | `ecosystem`, `priority` |

- The `epss` signal is the EPSS bump: the finding's EPSS score reached `priority.epssBump` and has not fallen below 90% of it since, so a finding can keep it at a score just under the threshold.
- An upgrade fix's `label` is its target, as a user would write it: `nginx:1.30.7`, `ghcr.io/org/app:2.1.0 (new digest)` for a refresh of the running tag, or `kubernetes v1.35.10`. `fromTag` (empty for an image referenced by digest only) and `toTag` carry the tags.
- The `kind` facet of `/findings` lists the cluster-level owners as `cluster-level:Cluster`, `cluster-level:ContainerRuntime` and `cluster-level:Nodes`, each with a `label`, apart from workloads of the same kind. `kind=` takes either form.
- `group` on `/findings` takes `advisory`, `workload`, `image`, `package`, `namespace` or `fix`. A grouped response fills `groupRows` and leaves `rows` empty; `total` then counts groups and `findings` the findings across them.
- `sort` takes one of these values. A leading `-` means descending.

  | Endpoint | Sort values |
  |---|---|
  | `/findings` | `-priority` (default), `-severity`, `-published`, `-epss`, `advisory`, `workload`, `namespace` |
  | `/workloads` | `-risk` (default), `name`, `namespace`, `-findings` |
  | `/images` | `-risk` (default), `repo`, `-workloads` |
  | `/packages` | `-risk` (default), `name`, `-images` |

An unknown facet, sort or group is `400` with the code `invalid_parameter`.

## Pagination

- `limit` is the page size, from 1 to 200 (default 50).
- `next` is an opaque cursor, or `null` on the last page. Pass it back as `cursor`, with the same parameters, for the next page.
- `total` counts every match, not just the page.
- Pages are keyset-based: rows written between two page reads do not cause rows that existed on both reads to repeat or be skipped.
- A cursor from a different query, or a damaged one, is `400` with the code `invalid_cursor`. Start again without `cursor`.

## Errors

Errors are RFC 9457 problem documents, `application/problem+json`, with `type`, `title`, `status`, `detail`, `code`, and the `cluster` and `generatedAt` extension members:

```json
{
  "type": "about:blank",
  "title": "Bad Request",
  "status": 400,
  "detail": "scope: \"pod:web\" is not a scope",
  "instance": "/api/v1/findings",
  "code": "invalid_scope",
  "cluster": "test",
  "generatedAt": "2026-11-19T00:00:00Z"
}
```

| Code | Status | Meaning |
|---|---|---|
| `invalid_parameter` | 400 | A parameter is malformed, out of range or not one of its values. |
| `invalid_scope` | 400 | The scope is malformed, or the operation does not accept it. |
| `invalid_cursor` | 400 | The cursor does not decode, or belongs to another query. |
| `not_found` | 404 | The object does not exist, or the path is not an operation. |
| `too_many_streams` | 503 | Too many event streams are open. |
| `internal` | 500 | The server failed. The detail is generic; the controller log holds the cause. |

## Live updates

`/api/v1/stream` is a `text/event-stream` of change notifications. The web UI refetches what a change affects instead of polling.

- At connect it sends `retry: 3000`.
- Each change is an event with an `id:` line, `event: changed`, and a `data:` line holding `{"seq","kinds","scopes"}`, for example `{"seq":"1879f2a3c4d5e6f7-42","kinds":["findings","inventory"],"scopes":["cluster","namespace:shop","workload:Deployment/shop/web"]}`.
- Kinds are `findings`, `inventory`, `images`, `feeds`, `nodes`, `exceptions` and `all`. A scope is one of the scope forms above, `*` for every scope, or `<kind>:*` for every scope of one kind.
- Changes are coalesced over 2 seconds.
- A `: ping` comment comes every 25 seconds.
- A client that reconnects with `Last-Event-ID` is sent the events it missed while the server still holds them (the last 256). For any other ID, for example one from before the controller restarted, the stream sends one `{"kinds":["all"],"scopes":["*"]}` event, which means refetch everything.
- At most 64 streams are open at once; beyond that the answer is `503` with the code `too_many_streams`.

## Operations

| Path | Returns |
|---|---|
| `/api/v1/summary` | Headline numbers for a scope: reachable workloads, open findings by priority, fixable and exploited counts, coverage and feed freshness. |
| `/api/v1/scope` | The navigation rail of a scope: its card, view counts, related objects and trust footer. |
| `/api/v1/exposure` | The exposure table of the cluster or a namespace, grouped by entry point, namespace or node (`group`), with `expand` for folded rows. Scopes: `cluster`, `namespace`. |
| `/api/v1/findings` | The findings explorer: a page of findings or groups, with facets. |
| `/api/v1/transitions` | The finding history of a scope, newest first. Scopes: `cluster`, `namespace`, `workload`, `controlplane`. |
| `/api/v1/advisories/{id}` | One advisory by ID or alias: severities by source, KEV and EPSS, timeline, affected workloads by fix and affected packages. |
| `/api/v1/workloads` | The workloads explorer, with facets. Scopes: `cluster`, `namespace`. |
| `/api/v1/workloads/{kind}/{namespace}/{name}` | One workload: containers, exposure, privilege and service account, counts, upgrades and best fix. |
| `/api/v1/images` | The images explorer, with status, coverage and gaps per image, and facets. Scopes: `cluster`, `namespace`, `workload`. |
| `/api/v1/images/{digest}` | One image: tags, status, SBOM source, ecosystems, counts, the workloads using it, upgrades, coverage and end-of-life data. |
| `/api/v1/images/{digest}/packages` | A page of one image's packages, searchable with `q` and filtered by `ecosystem`. |
| `/api/v1/packages` | The packages explorer: package versions in the scope's images, with facets. Scopes: `cluster`, `namespace`, `workload`, `image`. |
| `/api/v1/nodegroups` | The control plane and the node groups, with node agent status. |
| `/api/v1/nodegroups/{id}` | One node group: members, drift against other groups (`compare`), counts and cached images. `id` is the group's key: its stable name, with `-<arch>`, `-nodeinfo@<member node>` or `@<member node>` added when other groups share the name. The key survives package updates, and a key with a member node opens the group of that name that holds the node; a label or ID, or a key without its member node, is also accepted. |
| `/api/v1/nodes/{name}` | One node: its group, node agent status, counts and cached images. |
| `/api/v1/coverage` | The coverage funnel and every coverage gap, with a remedy code; see [coverage.md](coverage.md#gaps-and-what-to-do). Scopes: `cluster`, `namespace`, `workload`. |
| `/api/v1/feeds` | Feed freshness, and the data sources with their licences and attribution. |
| `/api/v1/exceptions` | Exceptions with what they match. |
| `/api/v1/settings` | The effective settings that shape findings, without registry, listener or storage settings. |
| `/api/v1/search` | Objects matching `q` (1 to 100 characters), for the web UI's search: workloads, namespaces, images, advisories, packages, node groups (by name, or holding a matching host-only package), nodes, and the Control plane and Nodes pages (hit kinds `controlplane` and `nodes`, whose `id` is the cluster name), at most 20. Labels starting with `q` come first, the kinds taking turns, and `truncated` is set when more matched. |
| `/api/v1/stream` | Change notifications; see [Live updates](#live-updates). |

Each row of `/api/v1/nodegroups` counts its members by node agent state in `agents`: `reporting` (the host inventory is stored), `reportingWithoutInventory` (the agent reports, but the host inventory is not stored or not current; the node shows the `host_not_inventoried` gap), `stale`, `never`, `disabled`, and `unsupported` (the node agent does not schedule on the node; it shows the `node_agent_unsupported` gap).

## Examples

The urgent and high findings grouped by advisory, with priority and fix facets:

```sh
curl -s 'http://127.0.0.1:8080/api/v1/findings?priority=urgent,high&group=advisory&facets=priority,fix' | jq '.total, .groupRows[0]'
```

The next page of the same query:

```sh
NEXT=$(curl -s 'http://127.0.0.1:8080/api/v1/findings?priority=urgent,high&group=advisory' | jq -r '.next')
curl -s --get 'http://127.0.0.1:8080/api/v1/findings?priority=urgent,high&group=advisory' --data-urlencode "cursor=$NEXT"
```

An image whose ID is a placeholder, percent-encoded as one path segment:

```sh
curl -s 'http://127.0.0.1:8080/api/v1/images/'"$(jq -rn --arg d 'unknown:registry.example.com/app:1.0' '$d|@uri')"
```

The event stream:

```sh
curl -N http://127.0.0.1:8080/api/v1/stream
```
