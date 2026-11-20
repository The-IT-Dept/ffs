# Alerts

An `AlertTarget` sends findings to Slack, Discord, Microsoft Teams or a signed webhook. AlertTargets are cluster-scoped; creating one is an admin action (ClusterRole `ffs-admin`).

## AlertTarget

| Field | Default | Meaning |
|---|---|---|
| `spec.type` | required | `slack`, `discord`, `teams` or `webhook`. |
| `spec.secretRef.name` | required | Secret in the ffs namespace holding the destination. |
| `spec.secretRef.urlKey` | `url` | Secret key holding the destination URL. |
| `spec.secretRef.signingSecretKey` | `signingSecret` | Secret key holding the signing secret. Webhook targets only. |
| `spec.immediate.minPriority` | `urgent` | Lowest priority sent immediately. |
| `spec.digest.schedule` | `0 9 * * *` | When the digest is sent, as a five-field cron expression. |
| `spec.digest.timeZone` | `UTC` | IANA time zone the schedule is read in. |
| `spec.digest.minPriority` | `medium` | Lowest priority listed in the digest as new or escalated. |
| `spec.digest.includeResolved` | `true` | List resolved findings in the digest. |
| `spec.namespaces` | all | Send only findings in these namespaces. |
| `spec.namespaceSelector` | all | Send only findings in namespaces whose labels match. Cluster-level findings (Kubernetes, container runtime) are sent only when neither filter is set. When a matching namespace is deleted, the resolutions of findings already sent from it are still sent; new findings there are not. |
| `spec.quietHours.intervals` | none | Times when immediate alerts are held, in Alertmanager `time_intervals` form: `times` (`startTime`/`endTime` as `HH:MM`, end exclusive, `24:00` allowed), `weekdays` (`monday:friday`), `daysOfMonth` (`1:5`, `-1` for the last day), `months` (`january:march` or `1:3`), `years` (`2026:2027`) and `location` (IANA zone, default UTC). An interval matches when all of its non-empty fields match. |
| `spec.quietHours.allowUrgent` | `true` | Send `urgent` alerts during quiet hours. |
| `spec.notifyOnFeedStale` | `false` | Send one alert when a vulnerability feed goes stale. |
| `spec.paused` | `false` | Stop all deliveries, including retries. Nothing that happens while paused is sent later; alerts queued before the pause wait until it is lifted. |
| `spec.allowPrivate` | `false` | Allow delivery to private and carrier-grade NAT addresses, and to plain `http` URLs. |

The status shows `lastDelivery`, `lastError` and a `Ready` condition. Its reason is `Registered` when deliveries are working, `Paused`, or one of `SecretNotFound`, `SecretUnreadable`, `SecretInvalid`, `InvalidSpec`, `DeliveryFailing` (three or more consecutive failures) and `EndpointGone`.

### Secret keys

| Type | Keys |
|---|---|
| `slack` | `url`: a Slack incoming webhook URL. |
| `discord` | `url`: a Discord webhook URL. |
| `teams` | `url`: a Microsoft Teams Workflows webhook URL. |
| `webhook` | `url`: your HTTPS endpoint. `signingSecret`: `whsec_` followed by the base64 of 24 to 64 random bytes, for example `echo "whsec_$(openssl rand -base64 32)"`. |

The key names can be changed with `spec.secretRef.urlKey` and `spec.secretRef.signingSecretKey`. URLs must use `https` unless `allowPrivate` is set.

### Example

```yaml
# The Secret lives in the ffs namespace. signingSecret is "whsec_" followed by the base64 of 24 to
# 64 random bytes, for example: echo "whsec_$(openssl rand -base64 32)"
apiVersion: v1
kind: Secret
metadata:
  name: webhook-incidents
  namespace: ffs
type: Opaque
stringData:
  url: https://incidents.example.com/hooks/ffs
  signingSecret: whsec_REPLACE-WITH-GENERATED-SECRET
---
apiVersion: ffs.theitdept.au/v1alpha1
kind: AlertTarget
metadata:
  name: webhook-incidents
spec:
  type: webhook
  secretRef:
    name: webhook-incidents
  immediate:
    minPriority: high
  digest:
    schedule: "0 * * * *"
    minPriority: low
    includeResolved: true
  namespaces:
    - shop
    - payments
  notifyOnFeedStale: true
```

A Slack example is in [examples/alerttarget-slack.yaml](examples/alerttarget-slack.yaml).

## When alerts are sent

- **Immediate.** A finding that is created at, or moves to, a priority at or above `immediate.minPriority` is sent at once. Findings that arrive together are grouped into one message per advisory. A provisional finding (found through OSV before the Grype database has an opinion) is sent immediately only when it is `urgent`, and the message says the distro fix state is pending.
- **Digest.** On the digest schedule, if anything changed since the last digest, one summary is sent with new findings and escalations at or above `digest.minPriority`, fixes that became available and resolved findings (when `includeResolved` is true) for findings reported at or above `digest.minPriority`, and feed health. It also lists the suggested upgrades that became available for findings already reported at or above `digest.minPriority` or `immediate.minPriority`: an immediate alert goes out before ffs has scored upgrade candidates, so this is where its upgrade arrives. Anything already sent immediately is not repeated. If nothing changed, nothing is sent.
- **Never twice.** For each finding and target, ffs records the highest priority already sent. A finding alerts again only when it escalates above that priority or reopens (a regression, or an expired Exception). A newly available fix or upgrade is reported in the digest only.
- **Resolutions.** When a finding the target was told about resolves, the resolution is sent immediately if the finding had been sent at or above `immediate.minPriority`. Otherwise it is listed in the next digest when `includeResolved` is true.
- **Baseline.** When ffs first starts, or a target is first created, the findings that already exist do not each alert. The target gets one summary of what ffs is watching, with the number of findings, the workloads they are in and the count at each priority ("40 findings in 12 workloads: 3 urgent, 5 high, 32 medium"), and the top items. A digest's summary counts the findings it lists the same way. Normal rules apply after that. On first start the summary, and every other alert, waits until the running images are catalogued and matched and the Grype database has synced once. An image waiting to retry after a failed attempt counts as not yet catalogued. A large cluster's first catalogue can take longer than an hour, and ffs keeps waiting while it is making progress. Once an hour has passed since ffs read the cluster's workloads, alerts start anyway when cataloguing has made no progress for 30 minutes (or for the catalogue timeout plus 5 minutes, if that is longer), and the controller log says what was still pending. Feed-stale alerts never wait.
- **Quiet hours.** During a quiet-hours interval, immediate alerts are held until the interval ends. `urgent` alerts are still sent unless `quietHours.allowUrgent` is false. Digests run on their own schedule.
- **Feed staleness.** With `notifyOnFeedStale: true`, a feed that passes its staleness threshold sends one alert, which is not repeated until the feed recovers and goes stale again.
- **Excepted findings** send nothing.

## Webhook format

Webhook targets receive a POST with `Content-Type: application/cloudevents+json; charset=utf-8`: a CloudEvents 1.0 event in structured JSON mode.

| Attribute | Value |
|---|---|
| `specversion` | `1.0` |
| `id` | Stable message ID. A retried delivery keeps the same ID; use it to drop duplicates. |
| `source` | `/ffs/<cluster name>` |
| `type` | One of the event types below. |
| `time` | When the message was created. |
| `subject` | The advisory ID, for immediate alerts. |
| `datacontenttype` | `application/json` |
| `data` | The message: see the table below. |

| `data` field | Value |
|---|---|
| `kind` | `immediate`, `digest`, `baseline` or `feedStale`. |
| `cluster`, `target`, `title` | The cluster name, the AlertTarget name and the message title. |
| `items` | One per advisory, highest priority first: `event`, `advisoryId`, `title`, `priority`, `reasons`, `owners`, `nodeGroups` (node findings: the affected node groups, at most three, then `+N more`), `packages`, `fixedIn`, `suggestion`, `published`, `observed`, `links`, `provisional`, and `truncatedOwners` and `truncatedPackages` when some owners or packages were left out (see below). |
| `truncated` | How many items were left out of `items`, `0` when none. |
| `summary` | Baselines and digests: `findings` (how many findings the message covers), `workloads` (how many workloads they are in) and `counts` (`urgent`, `high`, `medium`, `low`: findings at each priority). |
| `feeds` | Digests and feed-stale alerts: `name`, `lastSuccess`, `staleAfterSeconds`, `stale`. |
| `dashboardUrl` | `config.dashboardURL`, when set. |

A message lists at most 200 items, and its payload is kept within 256 KiB. When a message would be larger, each item's `owners` and `packages` are cut, to 100, then 25, then 5, and then the last items (the lowest priority) are left out. What is left out is counted in `truncatedOwners`, `truncatedPackages` and `truncated`; the title and the summary count everything. Slack and Teams messages show at most 20 items and Discord messages 10, each with at most 10 workloads and 10 packages, and they say how many more there are.

| Event type | Sent for |
|---|---|
| `au.theitdept.ffs.finding.detected.v1` | New and reopened findings. |
| `au.theitdept.ffs.finding.escalated.v1` | Findings whose priority went up. |
| `au.theitdept.ffs.finding.resolved.v1` | Resolved findings. |
| `au.theitdept.ffs.digest.v1` | Scheduled digests and the baseline summary. |
| `au.theitdept.ffs.feed.stale.v1` | A feed that went stale. |

### Verifying the signature

Every request is signed as specified by [Standard Webhooks](https://www.standardwebhooks.com/) v1, with three headers:

- `webhook-id`: the message ID (the same as the CloudEvents `id`);
- `webhook-timestamp`: Unix seconds when the request was signed;
- `webhook-signature`: `v1,<base64 signature>`.

To verify a request:

1. Take the signing secret, remove the `whsec_` prefix and base64-decode the rest. That is the HMAC key.
2. Compute HMAC-SHA256 over `<webhook-id>.<webhook-timestamp>.<raw request body>`, using the body bytes exactly as received.
3. Base64-encode the result and compare it, in constant time, with each space-separated `v1,<base64>` entry in `webhook-signature`.
4. Reject the request if `webhook-timestamp` is more than 5 minutes from your current time.

Any Standard Webhooks library does all of this for you.

## Delivery

- Each request times out after 15 seconds. Redirects are not followed.
- Failed deliveries are retried with exponential backoff and jitter: 5 seconds doubling to at most 15 minutes. A delivery is given up when a send fails 24 hours or more after its first attempt, so an endpoint that is down for less than a day still gets every alert. A longer `Retry-After` from the endpoint (on 429, 408 and 5xx responses) is honoured, up to 1 hour. Messages to one target are sent in order, and while a target is backing off nothing else is sent to it.
- Messages queued together go out by priority: `urgent`, `high`, `medium` and `low` (a message counts at its highest priority), then feed-stale alerts, then resolutions.
- Other 4xx and 3xx responses fail the delivery without retrying.
- HTTP 410 Gone disables the target; its `Ready` condition shows `EndpointGone`. Changing the AlertTarget or its Secret enables it again.
- Every delivery and its outcome is kept in a delivery log for `retention.resolved`. Delivery is at least once, so a receiver can see the same `webhook-id` twice.
- **SSRF guard.** Loopback, link-local, unspecified and multicast addresses, and cloud metadata endpoints, are always refused. Private (RFC 1918, IPv6 unique local) and carrier-grade NAT addresses, the pod CIDRs of the cluster's nodes, and the ranges in [`alertTargets.blockedCIDRs`](configuration.md#ffs-configuration) are refused unless the target sets `allowPrivate: true`. Pod CIDRs that are globally routable IPv6 are covered too. The Service CIDR is not on the nodes: when it is not a private range, add it to `alertTargets.blockedCIDRs`. The check applies to every address the host resolves to, and again when connecting.
- `HTTPS_PROXY` and `NO_PROXY` are honoured. Through a proxy, ffs does not resolve the endpoint's host itself: the proxy does, so the host need not resolve inside the cluster. The SSRF guard then checks only an endpoint given as an IP address, so limit what the proxy can reach.
- Discord messages never mention anyone (`allowed_mentions` is empty). Text from vulnerability feeds, images and advisories is escaped in Discord and Teams messages, so markdown in it shows as written.
