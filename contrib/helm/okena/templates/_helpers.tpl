{{- define "okena.name" -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "okena.labels" -}}
app.kubernetes.io/name: okena
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "okena.selector" -}}
app.kubernetes.io/name: okena
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
