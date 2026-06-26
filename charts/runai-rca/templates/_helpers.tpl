{{- define "runai-rca.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "runai-rca.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "runai-rca.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "runai-rca.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "runai-rca.selectorLabels" -}}
app.kubernetes.io/name: {{ include "runai-rca.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "runai-rca.backend.fullname" -}}
{{ include "runai-rca.fullname" . }}-backend
{{- end -}}

{{- define "runai-rca.agent.fullname" -}}
{{ include "runai-rca.fullname" . }}-agent
{{- end -}}

{{- define "runai-rca.frontend.fullname" -}}
{{ include "runai-rca.fullname" . }}-frontend
{{- end -}}

{{- define "runai-rca.postgresql.fullname" -}}
{{ include "runai-rca.fullname" . }}-postgresql
{{- end -}}

{{- define "runai-rca.postgresql.secretName" -}}
{{ include "runai-rca.postgresql.fullname" . }}
{{- end -}}

{{- define "runai-rca.secretName" -}}
{{- default (printf "%s-secrets" (include "runai-rca.fullname" .)) .Values.secrets.existingSecret -}}
{{- end -}}

{{- define "runai-rca.databaseUrl" -}}
{{- if .Values.secrets.databaseUrl -}}
{{- .Values.secrets.databaseUrl -}}
{{- else if .Values.postgresql.enabled -}}
{{- printf "postgres://%s:%s@%s:%v/%s?sslmode=disable" .Values.postgresql.auth.username .Values.postgresql.auth.password (include "runai-rca.postgresql.fullname" .) .Values.postgresql.service.port .Values.postgresql.auth.database -}}
{{- else -}}
{{- "" -}}
{{- end -}}
{{- end -}}

{{- define "runai-rca.postgresDsn" -}}
{{- if .Values.secrets.postgresDsn -}}
{{- .Values.secrets.postgresDsn -}}
{{- else -}}
{{- include "runai-rca.databaseUrl" . -}}
{{- end -}}
{{- end -}}

{{- define "runai-rca.agent.serviceAccountName" -}}
{{- if .Values.agent.serviceAccount.create -}}
{{- default (include "runai-rca.agent.fullname" .) .Values.agent.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.agent.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "runai-rca.image" -}}
{{- $root := .root -}}
{{- $image := .image -}}
{{- $tag := default $root.Chart.AppVersion $image.tag -}}
{{- if $root.Values.global.imageRegistry -}}
{{- printf "%s/%s:%s" $root.Values.global.imageRegistry $image.repository $tag -}}
{{- else -}}
{{- printf "%s:%s" $image.repository $tag -}}
{{- end -}}
{{- end -}}
