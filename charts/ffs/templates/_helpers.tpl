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
{{- $_ = set $c "nodeAgent" (dict "enabled" $na.enabled "listen" (printf ":%d" (int $na.port)) "certDir" "/etc/ffs/agent-tls"
  "namespace" (include "ffs.agentNamespace" .) "serviceAccount" (include "ffs.agentServiceAccount" .)
  "maxReportBytes" (include "ffs.bytes" (list "nodeAgent.maxReportBytes" $na.maxReportBytes) | int64)
  "reportInterval" $na.reportInterval "imageListInterval" $na.imageListInterval "staleAfter" $na.staleAfter
  "runtimeGrace" $na.runtimeGrace "workPerReport" (int $na.workPerReport) "workTimeout" $na.workTimeout
  "exposedNodes" $na.exposedNodes) -}}
{{- toYaml $c -}}
{{- end -}}

{{- define "ffs.agentNamespace" -}}
{{- default (printf "%s-agent" .Release.Namespace) .Values.nodeAgent.namespace | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ffs.agentServiceAccount" -}}
{{- printf "%s-agent" (include "ffs.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- /*
ffs.bytes renders a byte count from a number or a Kubernetes quantity with no fraction ("18Gi",
"15G"). It is called with (list "<value path>" <value>) and fails the render on anything else.
*/ -}}
{{- define "ffs.bytes" -}}
{{- $name := index . 0 -}}
{{- $v := index . 1 -}}
{{- if or (kindIs "float64" $v) (kindIs "int64" $v) (kindIs "int" $v) -}}
{{- int64 $v -}}
{{- else -}}
{{- $s := toString $v | trim -}}
{{- if not (regexMatch "^(0|[1-9][0-9]*)(k|M|G|T|Ki|Mi|Gi|Ti)?$" $s) -}}
{{- fail (printf "%s must be a byte count or a quantity such as 18Gi, not %q" $name $s) -}}
{{- end -}}
{{- $units := dict "" 1 "k" 1000 "M" 1000000 "G" 1000000000 "T" 1000000000000 "Ki" 1024 "Mi" 1048576 "Gi" 1073741824 "Ti" 1099511627776 -}}
{{- mul (regexFind "^[0-9]+" $s | int64) (get $units (regexReplaceAll "^[0-9]+" $s "")) -}}
{{- end -}}
{{- end -}}

{{- /*
ffs.goMemLimit is the controller's GOMEMLIMIT in bytes: 90% of its memory limit. The rest is for
what the Go runtime does not count: SQLite's page caches and sort buffers, which live outside the Go
heap, and the kernel's own accounting. At 100% the container can be OOM-killed before the garbage
collector has tried to stay under the limit.
*/ -}}
{{- define "ffs.goMemLimit" -}}
{{- include "ffs.goMemLimitOf" (list "controller.resources.limits.memory" .) -}}
{{- end -}}

{{- /*
ffs.goMemLimitOf is a GOMEMLIMIT of 90% of a memory limit, in bytes, from (list "<value path>" <limit>), for
the same reason as ffs.goMemLimit: at 100% a container can be OOM-killed before the garbage collector has
tried to stay under its limit.
*/ -}}
{{- define "ffs.goMemLimitOf" -}}
{{- $limit := include "ffs.bytes" . | int64 -}}
{{- div (mul $limit 9) 10 -}}
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
ffs.agentPort is nodeAgent.port, which must differ from the controller's other ports.
*/ -}}
{{- define "ffs.agentPort" -}}
{{- $port := int .Values.nodeAgent.port -}}
{{- if has $port (list 8080 8081 8443) -}}
{{- fail "nodeAgent.port must not be one of the controller's other ports (8080, 8081, 8443)" -}}
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
ffs.agentContentStore is the host path of the containerd content store of a distribution, "" for crio.
The paths follow the agent's host-path table.
*/ -}}
{{- define "ffs.agentContentStore" -}}
{{- get (dict "containerd" "/var/lib/containerd/io.containerd.content.v1.content"
  "k3s" "/var/lib/rancher/k3s/agent/containerd/io.containerd.content.v1.content"
  "rke2" "/var/lib/rancher/rke2/agent/containerd/io.containerd.content.v1.content") . -}}
{{- end -}}

{{- /*
ffs.agentExtraBinDirs is nodeAgent.hostPaths.extraBinDirs as JSON, each checked to be a directory under
/usr or /opt.
*/ -}}
{{- define "ffs.agentExtraBinDirs" -}}
{{- $dirs := list -}}
{{- range .Values.nodeAgent.hostPaths.extraBinDirs -}}
{{- $d := toString . -}}
{{- if or (not (regexMatch "^/(usr|opt)(/[A-Za-z0-9._+-]+)+$" $d)) (contains ".." $d) -}}
{{- fail (printf "nodeAgent.hostPaths.extraBinDirs: %s is not allowed; use a directory under /usr or /opt" $d) -}}
{{- end -}}
{{- $dirs = append $dirs $d -}}
{{- end -}}
{{- toJson $dirs -}}
{{- end -}}

{{- /*
ffs.agentScratchLimit is the agent cataloguer's --scratch-limit: nodeAgent.scratchSizeLimit less
nodeAgent.maxImageBytes (the staged image) and 256Mi of headroom, in bytes.
*/ -}}
{{- define "ffs.agentScratchLimit" -}}
{{- $size := include "ffs.bytes" (list "nodeAgent.scratchSizeLimit" .Values.nodeAgent.scratchSizeLimit) | int64 -}}
{{- $image := include "ffs.bytes" (list "nodeAgent.maxImageBytes" .Values.nodeAgent.maxImageBytes) | int64 -}}
{{- if lt $size 1073741824 -}}
{{- fail "nodeAgent.scratchSizeLimit must be at least 1Gi: host inputs are staged up to 512Mi" -}}
{{- end -}}
{{- $limit := sub (sub $size $image) 268435456 -}}
{{- if le $limit 0 -}}
{{- fail (printf "nodeAgent.scratchSizeLimit (%d bytes) must exceed nodeAgent.maxImageBytes (%d bytes) by more than 256Mi: the agent stages an image and unpacks it in the same scratch volume" $size $image) -}}
{{- end -}}
{{- $limit -}}
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
