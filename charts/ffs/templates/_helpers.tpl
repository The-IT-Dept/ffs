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
{{- toYaml $c -}}
{{- end -}}
