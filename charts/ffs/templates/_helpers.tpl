{{- define "ffs.fullname" -}}
{{- if contains "ffs" .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-ffs" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "ffs.selectorLabels" -}}
app.kubernetes.io/name: ffs
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ffs.labels" -}}
{{ include "ffs.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "ffs.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{- define "ffs.config" -}}
{{- $c := deepCopy .Values.config -}}
{{- $_ := set $c "namespace" .Release.Namespace -}}
{{- $_ = set $c "deploymentName" (include "ffs.fullname" .) -}}
{{- $reg := get $c "registry" | default dict -}}
{{- $_ = set $reg "readPullSecrets" .Values.rbac.readPullSecrets -}}
{{- $_ = set $c "registry" $reg -}}
{{- if .Values.web.service.enabled -}}
{{- $svc := printf "%s-web" (include "ffs.fullname" .) -}}
{{- $ns := .Release.Namespace -}}
{{- $names := list $svc (printf "%s.%s" $svc $ns) (printf "%s.%s.svc" $svc $ns) (printf "%s.%s.svc.cluster.local" $svc $ns) -}}
{{- $_ = set $c "allowedHosts" (concat (get $c "allowedHosts" | default list) $names | uniq) -}}
{{- end -}}
{{- $na := .Values.nodeAgent -}}
{{- $maxReport := include "ffs.bytes" (list "nodeAgent.maxReportBytes" $na.maxReportBytes) | int64 -}}
{{- if or (lt $maxReport 1048576) (gt $maxReport 201326592) -}}
{{- fail (printf "nodeAgent.maxReportBytes (%d bytes) must be between 1 MiB and 192 MiB, the most the controller reads of reports at once" $maxReport) -}}
{{- end -}}
{{- $_ = set $c "nodeAgent" (dict "enabled" $na.enabled "listen" (printf ":%d" (int $na.port)) "certDir" "/etc/ffs/agent-tls"
  "namespace" (include "ffs.agentNamespace" .) "serviceAccount" (include "ffs.agentServiceAccount" .)
  "maxReportBytes" $maxReport
  "reportInterval" $na.reportInterval "imageListInterval" $na.imageListInterval "staleAfter" $na.staleAfter
  "runtimeGrace" $na.runtimeGrace "workPerReport" (int $na.workPerReport) "workTimeout" $na.workTimeout
  "exposedNodes" $na.exposedNodes "architectures" $na.architectures "nodeSelector" $na.nodeSelector "tolerations" $na.tolerations) -}}
{{- toYaml $c -}}
{{- end -}}

{{- define "ffs.agentNamespace" -}}
{{- default (printf "%s-agent" .Release.Namespace) .Values.nodeAgent.namespace | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ffs.agentServiceAccount" -}}
{{- printf "%s-agent" (include "ffs.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- /*
ffs.bytes renders a byte count from a number or a Kubernetes quantity, whole or with a decimal fraction of
up to six digits ("18Gi", "15G", "1.5Gi", "0.5Gi", ".5Gi", "1.Gi", "01Gi"). A fraction of a byte is rounded
up, as Kubernetes rounds a memory quantity, for a quantity string and for a number in a values file alike. It is called with (list "<value path>" <value>) and fails the render on anything else.
The digits are read with atoi, which is decimal, because int64 reads a leading 0 as octal ("1.05Gi").
*/ -}}
{{- define "ffs.bytes" -}}
{{- $name := index . 0 -}}
{{- $v := index . 1 -}}
{{- if kindIs "float64" $v -}}
{{- $whole := int64 $v -}}
{{- if gt $v (float64 $whole) }}{{ add1 $whole }}{{ else }}{{ $whole }}{{ end -}}
{{- else if or (kindIs "int64" $v) (kindIs "int" $v) -}}
{{- int64 $v -}}
{{- else -}}
{{- $s := toString $v | trim -}}
{{- $re := "^([0-9]*)(?:\\.([0-9]{0,6}))?(k|M|G|T|P|E|Ki|Mi|Gi|Ti|Pi|Ei)?$" -}}
{{- if or (not (regexMatch $re $s)) (not (regexMatch "[0-9]" (regexReplaceAll $re $s "${1}${2}"))) -}}
{{- fail (printf "%s must be a byte count or a quantity such as 18Gi, not %q" $name $s) -}}
{{- end -}}
{{- $units := dict "" 1 "k" 1000 "M" 1000000 "G" 1000000000 "T" 1000000000000 "P" 1000000000000000 "E" 1000000000000000000 "Ki" 1024 "Mi" 1048576 "Gi" 1073741824 "Ti" 1099511627776 "Pi" 1125899906842624 "Ei" 1152921504606846976 -}}
{{- $unit := get $units (regexReplaceAll $re $s "${3}") | int64 -}}
{{- $bytes := mul (regexReplaceAll $re $s "${1}" | default "0" | atoi) $unit -}}
{{- with regexReplaceAll $re $s "${2}" -}}
{{- $scale := printf "1%s" (repeat (len .) "0") | atoi -}}
{{- $bytes = add $bytes (div (add (mul (atoi .) $unit) (sub $scale 1)) $scale) -}}
{{- end -}}
{{- $bytes -}}
{{- end -}}
{{- end -}}

{{- /*
ffs.goMemLimitOf is a GOMEMLIMIT of 90% of a memory limit, in bytes, from (list "<value path>" <limit>). The
rest is for what the Go runtime does not count: the controller's SQLite page caches and sort buffers, which
live outside the Go heap, and the kernel's own accounting. At 100% a container can be OOM-killed before the
garbage collector has tried to stay under its limit.
*/ -}}
{{- define "ffs.goMemLimitOf" -}}
{{- $limit := include "ffs.bytes" . | int64 -}}
{{- div (mul $limit 9) 10 -}}
{{- end -}}

{{- /*
ffs.goMemLimitEnv is a container's GOMEMLIMIT environment variable, from (dict "container" <container name>
"path" "<value path of its resources>" "resources" <its resources>): ffs.goMemLimitOf its memory limit, or
without one the limit from the downward API, which is then the node's allocatable memory.
*/ -}}
{{- define "ffs.goMemLimitEnv" -}}
- name: GOMEMLIMIT
{{- with dig "limits" "memory" "" (.resources | default dict) }}
  value: {{ include "ffs.goMemLimitOf" (list (printf "%s.limits.memory" $.path) .) | quote }}
{{- else }}
  valueFrom:
    resourceFieldRef:
      containerName: {{ .container }}
      resource: limits.memory
{{- end }}
{{- end -}}

{{- /*
ffs.workerMemLimit is a cataloguer's --worker-memory-limit in bytes, from (list "<value path>" <limit>
<concurrent jobs>): the container's memory limit less 128Mi for the catalog server, shared by the workers
that run at once. A worker inherits the server's GOMEMLIMIT otherwise, as if it had the container to itself.
The server's 128Mi covers its own heap and the answer of a worker that is still running, which it buffers:
up to the 64 MiB SBOM limit plus coverage.
*/ -}}
{{- define "ffs.workerMemLimit" -}}
{{- $name := index . 0 -}}
{{- $limit := include "ffs.bytes" (list $name (index . 1)) | int64 -}}
{{- $jobs := max (index . 2 | int64) 1 -}}
{{- $worker := div (sub $limit 134217728) $jobs -}}
{{- if lt $worker 67108864 -}}
{{- fail (printf "%s must be at least 128Mi plus 64Mi per concurrent catalog job (%d): the catalog server keeps 128Mi" $name $jobs) -}}
{{- end -}}
{{- $worker -}}
{{- end -}}

{{- /*
ffs.scratchLimit is catalog.scratchLimit in bytes. It must be above zero, which the cataloguer
would read as unlimited, and below catalog.scratchSizeLimit, so a job is refused before the
kubelet evicts the pod for filling the scratch volume.
*/ -}}
{{- define "ffs.scratchLimit" -}}
{{- $limit := include "ffs.bytes" (list "catalog.scratchLimit" .Values.catalog.scratchLimit) | int64 -}}
{{- if le $limit 0 -}}
{{- fail "catalog.scratchLimit must be greater than 0: the catalog container reads 0 as unlimited scratch" -}}
{{- end -}}
{{- with .Values.catalog.scratchSizeLimit -}}
{{- $size := include "ffs.bytes" (list "catalog.scratchSizeLimit" .) | int64 -}}
{{- if ge $limit $size -}}
{{- fail (printf "catalog.scratchLimit (%d bytes) must be below catalog.scratchSizeLimit (%d bytes)" $limit $size) -}}
{{- end -}}
{{- end -}}
{{- $limit -}}
{{- end -}}

{{- define "ffs.agentSelectorLabels" -}}
app.kubernetes.io/name: ffs-agent
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ffs.agentLabels" -}}
{{ include "ffs.agentSelectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- /*
ffs.httpPort is the port of config.listen, where the web UI and API listen.
*/ -}}
{{- define "ffs.httpPort" -}}
{{- $listen := toString .Values.config.listen -}}
{{- $port := regexFind "[0-9]+$" (regexFind ":[0-9]+$" $listen) -}}
{{- if not $port -}}
{{- fail (printf "config.listen must be an address with a port number, such as 0.0.0.0:8080, not %q" $listen) -}}
{{- end -}}
{{- if has ($port | int) (list 8081 8443) -}}
{{- fail (printf "config.listen must not use port %s: the controller serves health on 8081 and metrics on 8443" $port) -}}
{{- end -}}
{{- $port -}}
{{- end -}}

{{- /*
ffs.listenLoopback is "true" when config.listen binds a loopback address only, so the web UI and API are
reachable only from inside the pod (kubectl port-forward), and "" otherwise.
*/ -}}
{{- define "ffs.listenLoopback" -}}
{{- $host := regexReplaceAll ":[0-9]*$" (toString .Values.config.listen) "" -}}
{{- if or (hasPrefix "127." $host) (eq $host "localhost" "[::1]") -}}
true
{{- end -}}
{{- end -}}

{{- /*
ffs.v001Defaults is "true" when the values carry v0.0.1's defaults instead of this chart's, and "" otherwise. helm upgrade
--reuse-values replaces the chart's defaults with the previous release's values, v0.0.1's defaults included. Those lack
keys that this chart's defaults have: networkPolicy.enabled and config.feeds.grypedb.diffMinImages. A user who sets one
of them in that upgrade, as the deprecation notice asks for networkPolicy.enabled, still lacks the other.
*/ -}}
{{- define "ffs.v001Defaults" -}}
{{- $np := .Values.networkPolicy | default dict -}}
{{- $grype := dig "feeds" "grypedb" (dict) (.Values.config | default dict) | default dict -}}
{{- if or (not (hasKey $np "enabled")) (not (hasKey $grype "diffMinImages")) -}}
true
{{- end -}}
{{- end -}}

{{- /*
ffs.legacyNetworkPolicy is "true" when the deprecated nodeAgent.networkPolicy.enabled is set, and "" otherwise.
It has no default, so it is set only when the user sets it, and it must then be true or false. null, which is how
Helm unsets a key, leaves it unset, for nodeAgent.networkPolicy and for its enabled key. With v0.0.1's defaults
(ffs.v001Defaults), true is v0.0.1's default for it, which the user need not have set, and the same as
networkPolicy.enabled's default: it counts as unset, so it neither prints the deprecation notice nor overrides
networkPolicy.enabled. false differs from that default, so it was set.
*/ -}}
{{- define "ffs.legacyNetworkPolicy" -}}
{{- $np := dig "networkPolicy" (dict) (.Values.nodeAgent | default dict) -}}
{{- if kindIs "invalid" $np -}}
{{- $np = dict -}}
{{- end -}}
{{- if not (kindIs "map" $np) -}}
{{- fail "nodeAgent.networkPolicy must be a map with an enabled key; it is deprecated, so set networkPolicy.enabled instead" -}}
{{- end -}}
{{- $enabled := dig "enabled" nil $np -}}
{{- if not (kindIs "invalid" $enabled) -}}
{{- if not (kindIs "bool" $enabled) -}}
{{- fail (printf "nodeAgent.networkPolicy.enabled must be true or false, not %q; it is deprecated, so set networkPolicy.enabled instead" (toString $enabled)) -}}
{{- end -}}
{{- if not (and $enabled (include "ffs.v001Defaults" .)) -}}
true
{{- end -}}
{{- end -}}
{{- end -}}

{{- /*
ffs.networkPolicy is "true" when the chart creates the ffs pod's NetworkPolicy, and "" otherwise: networkPolicy.enabled,
unless the deprecated nodeAgent.networkPolicy.enabled is set, which wins until it is removed in v0.0.3. networkPolicy.enabled
is true by default, so a false there was set on purpose, and the render fails if the deprecated key says true.
*/ -}}
{{- define "ffs.networkPolicy" -}}
{{- /* values without a top-level networkPolicy (helm upgrade --reuse-values from v0.0.1) default to true */ -}}
{{- $np := .Values.networkPolicy | default dict -}}
{{- $enabled := true -}}
{{- if hasKey $np "enabled" -}}
{{- $enabled = $np.enabled -}}
{{- end -}}
{{- if include "ffs.legacyNetworkPolicy" . -}}
{{- $legacy := dig "networkPolicy" "enabled" false .Values.nodeAgent -}}
{{- if and $legacy (not $enabled) -}}
{{- fail "networkPolicy.enabled is false but the deprecated nodeAgent.networkPolicy.enabled is true: unset nodeAgent.networkPolicy.enabled and set networkPolicy.enabled only" -}}
{{- end -}}
{{- $enabled = $legacy -}}
{{- end -}}
{{- if $enabled -}}
true
{{- end -}}
{{- end -}}

{{- /*
ffs.logLevel is controller.logLevel, the controller's --zap-log-level: info, or debug to add its debug (V(1))
messages. Values without it (helm upgrade --reuse-values from v0.0.1) give info.
*/ -}}
{{- define "ffs.logLevel" -}}
{{- $level := .Values.controller.logLevel | default "info" | toString | trim -}}
{{- if not (has $level (list "info" "debug")) -}}
{{- fail (printf "controller.logLevel must be info or debug, not %q" $level) -}}
{{- end -}}
{{- $level -}}
{{- end -}}

{{- /*
ffs.metricsSelectorLabels are the labels of the metrics Service, which the ServiceMonitor selects: the other Services of
the release carry ffs.selectorLabels too.
*/ -}}
{{- define "ffs.metricsSelectorLabels" -}}
{{ include "ffs.selectorLabels" . }}
app.kubernetes.io/component: metrics
{{- end -}}

{{- /*
ffs.agentPort is nodeAgent.port, which must differ from the controller's other ports.
*/ -}}
{{- define "ffs.agentPort" -}}
{{- $port := int .Values.nodeAgent.port -}}
{{- $http := include "ffs.httpPort" . | int -}}
{{- if has $port (list $http 8081 8443) -}}
{{- fail (printf "nodeAgent.port must not be one of the controller's other ports (%d, 8081, 8443)" $http) -}}
{{- end -}}
{{- $port -}}
{{- end -}}

{{- /*
ffs.agentHostFrom resolves what the agent mounts from (dict "nodes" <Node objects> "agent" .Values.nodeAgent).
It returns JSON {"distribution", "packageDatabases", "imageBased"}; read it with fromJson.

distribution: a value other than auto is used as given. With no nodes, auto is containerd; otherwise each
node votes (kubeletVersion +k3s, +rke2, containerRuntimeVersion cri-o://, else containerd) and the most
votes win, ties in the order containerd, k3s, rke2, crio.
packageDatabases: a list is used as given, and an empty list means an image-based OS. With no nodes, auto
is dpkg and rpm; otherwise each node's osImage names its family, and the result is the union in the order
dpkg, rpm, apk, image-based only when every node runs an image-based OS.
*/ -}}
{{- define "ffs.agentHostFrom" -}}
{{- $nodes := .nodes | default list -}}
{{- $a := .agent -}}
{{- $dists := list "containerd" "k3s" "rke2" "crio" -}}
{{- $dist := toString $a.distribution -}}
{{- if ne $dist "auto" -}}
{{- if not (has $dist $dists) -}}
{{- fail "nodeAgent.distribution must be auto, containerd, k3s, rke2 or crio" -}}
{{- end -}}
{{- else if not $nodes -}}
{{- $dist = "containerd" -}}
{{- else -}}
{{- $votes := dict "containerd" 0 "k3s" 0 "rke2" 0 "crio" 0 -}}
{{- range $nodes -}}
{{- $kubelet := dig "status" "nodeInfo" "kubeletVersion" "" . | toString -}}
{{- $runtime := dig "status" "nodeInfo" "containerRuntimeVersion" "" . | toString -}}
{{- $vote := "containerd" -}}
{{- if contains "+k3s" $kubelet -}}
{{- $vote = "k3s" -}}
{{- else if contains "+rke2" $kubelet -}}
{{- $vote = "rke2" -}}
{{- else if hasPrefix "cri-o://" $runtime -}}
{{- $vote = "crio" -}}
{{- end -}}
{{- $_ := set $votes $vote (add1 (get $votes $vote)) -}}
{{- end -}}
{{- $dist = "containerd" -}}
{{- range $dists -}}
{{- if gt (get $votes .) (get $votes $dist) -}}
{{- $dist = . -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $families := list "dpkg" "rpm" "apk" -}}
{{- $pdb := $a.packageDatabases -}}
{{- $dbs := list -}}
{{- $imageBased := false -}}
{{- if kindIs "slice" $pdb -}}
{{- range $pdb -}}
{{- $e := toString . | trim -}}
{{- if and $e (not (has $e $families)) -}}
{{- fail "nodeAgent.packageDatabases must be auto or a list of dpkg, rpm and apk" -}}
{{- end -}}
{{- /* --set nodeAgent.packageDatabases={} gives [""]: an empty entry is no entry. */ -}}
{{- if $e -}}
{{- $dbs = append $dbs $e -}}
{{- end -}}
{{- end -}}
{{- $imageBased = empty $dbs -}}
{{- else if ne (toString $pdb) "auto" -}}
{{- fail "nodeAgent.packageDatabases must be auto or a list of dpkg, rpm and apk" -}}
{{- else if not $nodes -}}
{{- $dbs = list "dpkg" "rpm" -}}
{{- else -}}
{{- $found := dict -}}
{{- $imageBased = true -}}
{{- range $nodes -}}
{{- $os := dig "status" "nodeInfo" "osImage" "" . | toString | lower -}}
{{- if regexMatch "debian|ubuntu" $os -}}
{{- $_ := set $found "dpkg" true -}}
{{- $imageBased = false -}}
{{- else if regexMatch "red hat|rhel|centos|rocky|alma|oracle linux|fedora|suse|sles|amazon linux|azure linux|mariner" $os -}}
{{- $_ := set $found "rpm" true -}}
{{- $imageBased = false -}}
{{- else if regexMatch "alpine" $os -}}
{{- $_ := set $found "apk" true -}}
{{- $imageBased = false -}}
{{- else if not (regexMatch "talos|flatcar|container-optimized os|bottlerocket" $os) -}}
{{- $_ := set $found "dpkg" true -}}
{{- $_ = set $found "rpm" true -}}
{{- $imageBased = false -}}
{{- end -}}
{{- end -}}
{{- range $families -}}
{{- if hasKey $found . -}}
{{- $dbs = append $dbs . -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- toJson (dict "distribution" $dist "packageDatabases" $dbs "imageBased" $imageBased) -}}
{{- end -}}

{{- /*
ffs.agentHost is ffs.agentHostFrom over the cluster's Nodes. Without lookup data (helm template, a
dry run) it resolves as if there were no nodes.
*/ -}}
{{- define "ffs.agentHost" -}}
{{- $nodes := dig "items" (list) (lookup "v1" "Node" "" "") -}}
{{- include "ffs.agentHostFrom" (dict "nodes" $nodes "agent" .Values.nodeAgent) -}}
{{- end -}}

{{- /*
ffs.agentContentStore is the host path of the containerd content store, "" for crio, from (dict "dist"
<distribution> "root" <nodeAgent.hostPaths.containerdRoot>). An empty root uses the distribution's path from
the agent's host-path table; a set root (k0s, MicroK8s or a custom containerd root) replaces it and must be an
absolute path outside the directories the agent never mounts.
*/ -}}
{{- define "ffs.agentContentStore" -}}
{{- $root := toString (.root | default "") | trim -}}
{{- if $root -}}
{{- if or (not (regexMatch "^(/[A-Za-z0-9._+-]+)+$" $root)) (regexMatch "(^|/)\\.\\.?(/|$)" $root) -}}
{{- fail (printf "nodeAgent.hostPaths.containerdRoot must be an absolute path to containerd's root directory, such as /var/lib/k0s/containerd, not %q" $root) -}}
{{- end -}}
{{- if regexMatch "^/(proc|sys|dev|run|var/run|var/lib/kubelet|etc/kubernetes|etc/rancher)(/|$)" $root -}}
{{- fail (printf "nodeAgent.hostPaths.containerdRoot: %s is not allowed; the agent never mounts it" $root) -}}
{{- end -}}
{{- if eq .dist "crio" -}}
{{- fail "nodeAgent.hostPaths.containerdRoot does not apply to crio, which has no containerd content store" -}}
{{- end -}}
{{- printf "%s/io.containerd.content.v1.content" $root -}}
{{- else -}}
{{- get (dict "containerd" "/var/lib/containerd/io.containerd.content.v1.content"
  "k3s" "/var/lib/rancher/k3s/agent/containerd/io.containerd.content.v1.content"
  "rke2" "/var/lib/rancher/rke2/agent/containerd/io.containerd.content.v1.content") .dist -}}
{{- end -}}
{{- end -}}

{{- /*
ffs.agentExtraBinDirs is nodeAgent.hostPaths.extraBinDirs as JSON, from (dict "root" $ "imageBased" <bool>).
Each must be a directory under /usr or /opt with no . or .. component, listed once, and not one the chart
mounts already (/usr/bin, /usr/sbin, and /usr/local/bin except on image-based OSes): two mounts at one path
make the DaemonSet invalid.
*/ -}}
{{- define "ffs.agentExtraBinDirs" -}}
{{- $builtIn := list "/usr/bin" "/usr/sbin" -}}
{{- if not .imageBased -}}
{{- $builtIn = append $builtIn "/usr/local/bin" -}}
{{- end -}}
{{- $dirs := list -}}
{{- range .root.Values.nodeAgent.hostPaths.extraBinDirs -}}
{{- $d := toString . -}}
{{- if or (not (regexMatch "^/(usr|opt)(/[A-Za-z0-9._+-]+)+$" $d)) (regexMatch "(^|/)\\.\\.?(/|$)" $d) -}}
{{- fail (printf "nodeAgent.hostPaths.extraBinDirs: %s is not allowed; use a directory under /usr or /opt" $d) -}}
{{- end -}}
{{- if has $d $builtIn -}}
{{- fail (printf "nodeAgent.hostPaths.extraBinDirs: %s is searched already; list only other directories" $d) -}}
{{- end -}}
{{- if has $d $dirs -}}
{{- fail (printf "nodeAgent.hostPaths.extraBinDirs: %s is listed twice" $d) -}}
{{- end -}}
{{- $dirs = append $dirs $d -}}
{{- end -}}
{{- toJson $dirs -}}
{{- end -}}

{{- /*
ffs.agentArchitectures is nodeAgent.architectures as JSON, without empty entries (--set x={} gives [""]); it
must name at least one architecture, or the DaemonSet's node affinity is invalid.
*/ -}}
{{- define "ffs.agentArchitectures" -}}
{{- $archs := list -}}
{{- range .Values.nodeAgent.architectures -}}
{{- $a := toString . | trim -}}
{{- if $a -}}
{{- $archs = append $archs $a -}}
{{- end -}}
{{- end -}}
{{- if not $archs -}}
{{- fail "nodeAgent.architectures must list at least one node architecture, such as amd64" -}}
{{- end -}}
{{- toJson $archs -}}
{{- end -}}

{{- /*
ffs.agentScratch sizes the agent's scratch volumes from nodeAgent.scratchSizeLimit, their total, as JSON
{"stage", "catalog", "limit"} in bytes:
- stage: the collector's staging volume, which the cataloguer mounts read-only. It holds the host inputs (up to
  512Mi) or one image (up to nodeAgent.maxImageBytes), plus 256Mi for spooled SBOMs (up to 65Mi each: a job's
  and a kept host inventory's) and file-system overhead.
- catalog: the cataloguer's own volume, where it unpacks images: the rest, at least 512Mi.
- limit: the cataloguer's --scratch-limit, its volume less 256Mi, so a job is stopped before the kubelet
  evicts the pod.
*/ -}}
{{- define "ffs.agentScratch" -}}
{{- $size := include "ffs.bytes" (list "nodeAgent.scratchSizeLimit" .Values.nodeAgent.scratchSizeLimit) | int64 -}}
{{- $image := include "ffs.bytes" (list "nodeAgent.maxImageBytes" .Values.nodeAgent.maxImageBytes) | int64 -}}
{{- $stage := add (max $image 536870912) 268435456 -}}
{{- $need := add $stage 536870912 -}}
{{- if lt $size $need -}}
{{- fail (printf "nodeAgent.scratchSizeLimit (%d bytes) must be at least %d bytes: the staging volume takes nodeAgent.maxImageBytes or 512Mi, whichever is larger, plus 256Mi, and the cataloguer needs 512Mi to unpack images" $size $need) -}}
{{- end -}}
{{- $catalog := sub $size $stage -}}
{{- toJson (dict "stage" $stage "catalog" $catalog "limit" (sub $catalog 268435456)) -}}
{{- end -}}

{{- /*
ffs.agentTLSSecret is the name of the Secret holding the agent API's certificate. The Secret cert-manager writes
has a name of its own, so switching nodeAgent.tls.certManager.enabled either way never asks Helm to take over
cert-manager's Secret, or cert-manager to write into the chart's.
*/ -}}
{{- define "ffs.agentTLSSecret" -}}
{{- include "ffs.fullname" . -}}-agent{{ if .Values.nodeAgent.tls.certManager.enabled }}-cert-manager{{ end }}-tls
{{- end -}}

{{- /*
ffs.agentTLSPair decides the agent API's certificate from (dict "secret" <looked-up Secret> "configMap"
<looked-up ConfigMap> "root" $). While both exist and the Secret's ffs.theitdept.au/not-after
annotation (unix seconds) is more than 30 days ahead, their data is returned unchanged, so renders do
not drift; otherwise a new CA and certificate are generated for 3650 days. It returns JSON
{"tlsCrt", "tlsKey" (base64, as Secret data), "caCrt" (PEM), "notAfter" (unix seconds)}.
*/ -}}
{{- define "ffs.agentTLSPair" -}}
{{- $secret := .secret | default dict -}}
{{- $cm := .configMap | default dict -}}
{{- $root := .root -}}
{{- $crt := dig "data" "tls.crt" "" $secret | toString -}}
{{- $key := dig "data" "tls.key" "" $secret | toString -}}
{{- $ca := dig "data" "ca.crt" "" $cm | toString -}}
{{- $notAfter := dig "metadata" "annotations" "ffs.theitdept.au/not-after" "" $secret | toString -}}
{{- $nowSecs := now | unixEpoch | int64 -}}
{{- $reuse := and $crt $key $ca (regexMatch "^[0-9]+$" $notAfter) -}}
{{- if $reuse -}}
{{- $reuse = gt (int64 $notAfter) (add $nowSecs 2592000) -}}
{{- end -}}
{{- if $reuse -}}
{{- toJson (dict "tlsCrt" $crt "tlsKey" $key "caCrt" $ca "notAfter" $notAfter) -}}
{{- else -}}
{{- $fullname := include "ffs.fullname" $root -}}
{{- $svc := printf "%s-agent-api" $fullname -}}
{{- $ns := $root.Release.Namespace -}}
{{- $caPair := genCA (printf "%s-agent-ca" $fullname) 3650 -}}
{{- $cert := genSignedCert $svc nil (list $svc (printf "%s.%s" $svc $ns) (printf "%s.%s.svc" $svc $ns) (printf "%s.%s.svc.cluster.local" $svc $ns)) 3650 $caPair -}}
{{- toJson (dict "tlsCrt" ($cert.Cert | b64enc) "tlsKey" ($cert.Key | b64enc) "caCrt" $caPair.Cert "notAfter" (toString (add $nowSecs 315360000))) -}}
{{- end -}}
{{- end -}}
