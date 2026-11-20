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
{{- toYaml $c -}}
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
{{- $limit := include "ffs.bytes" (list "controller.resources.limits.memory" .) | int64 -}}
{{- div (mul $limit 9) 10 -}}
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
