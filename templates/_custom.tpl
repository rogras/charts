{{- define "custom.config" -}}
<?xml version='1.0' encoding='UTF-8'?>
      <hudson>
        <disabledAdministrativeMonitors/>
        <version>{{ .Values.master.imageTag }}</version>
        <numExecutors>{{ .Values.master.numExecutors }}</numExecutors>
        <mode>NORMAL</mode>
        <useSecurity>{{ .Values.master.useSecurity }}</useSecurity>
  {{ .Values.master.authorizationStrategy | indent 6 }}
  {{ .Values.master.securityRealm | indent 6 }}
        <disableRememberMe>false</disableRememberMe>
        <projectNamingStrategy class="jenkins.model.ProjectNamingStrategy$DefaultProjectNamingStrategy"/>
        <workspaceDir>${JENKINS_HOME}/workspace/${ITEM_FULLNAME}</workspaceDir>
        <buildsDir>${ITEM_ROOTDIR}/builds</buildsDir>
  {{- if .Values.master.enableRawHtmlMarkupFormatter }}
        <markupFormatter class="hudson.markup.RawHtmlMarkupFormatter" plugin="antisamy-markup-formatter">
          <disableSyntaxHighlighting>true</disableSyntaxHighlighting>
        </markupFormatter>
  {{- else }}
        <markupFormatter class="hudson.markup.EscapedMarkupFormatter"/>
  {{- end }}
        <jdks/>
        <viewsTabBar class="hudson.views.DefaultViewsTabBar"/>
        <myViewsTabBar class="hudson.views.DefaultMyViewsTabBar"/>
        <clouds>
          <org.csanchez.jenkins.plugins.kubernetes.KubernetesCloud plugin="kubernetes@{{ template "jenkins.kubernetes-version" . }}">
            <name>kubernetes</name>
            <templates>
  {{- if .Values.agent.enabled }}
              <org.csanchez.jenkins.plugins.kubernetes.PodTemplate>
                <inheritFrom></inheritFrom>
                <name>{{ .Values.agent.podName }}</name>
                <instanceCap>2147483647</instanceCap>
                <idleMinutes>{{ .Values.agent.idleMinutes }}</idleMinutes>
                <label>{{ .Release.Name }}-{{ .Values.agent.componentName }} {{ .Values.agent.customJenkinsLabels  | join " " }}</label>
                <serviceAccount>{{ include "jenkins.serviceAccountAgentName" . }}</serviceAccount>
                <nodeSelector>
                  {{- $local := dict "first" true }}
                  {{- range $key, $value := .Values.agent.nodeSelector }}
                    {{- if not $local.first }},{{- end }}
                    {{- $key }}={{ $value }}
                    {{- $_ := set $local "first" false }}
                  {{- end }}</nodeSelector>
                  <nodeUsageMode>NORMAL</nodeUsageMode>
                <volumes>
  {{- range $index, $volume := .Values.agent.volumes }}
                  <org.csanchez.jenkins.plugins.kubernetes.volumes.{{ $volume.type }}Volume>
  {{- range $key, $value := $volume }}{{- if not (eq $key "type") }}
                    <{{ $key }}>{{ $value }}</{{ $key }}>
  {{- end }}{{- end }}
                  </org.csanchez.jenkins.plugins.kubernetes.volumes.{{ $volume.type }}Volume>
  {{- end }}
  {{ if .Values.buildImages.enabled }}
                  <org.csanchez.jenkins.plugins.kubernetes.volumes.EmptyDirVolume>
                    <mountPath>"/var/lib/containers"</mountPath>
                    <memory>true</memory>
                  </org.csanchez.jenkins.plugins.kubernetes.volumes.EmptyDirVolume>
  {{- end }}
  {{ if .Values.permanentagent.sspmutualtls.enabled }}
                  <org.csanchez.jenkins.plugins.kubernetes.volumes.SecretVolume>
                    <mountPath>{{ .Values.permanentagent.sspmutualtls.ssldir }}/tmp</mountPath>
                    <secretName>{{ template "jenkins.fullname" . }}-permanentagent-sspmutualtls-secret</secretName>
                  </org.csanchez.jenkins.plugins.kubernetes.volumes.SecretVolume>
  {{- end }}
                </volumes>
                <containers>
                  <org.csanchez.jenkins.plugins.kubernetes.ContainerTemplate>
                    <name>{{ .Values.agent.sideContainerName }}</name>
                    <image>{{ .Values.agent.image }}:{{ .Values.agent.imageTag }}</image>
  {{- if or (.Values.agent.privileged) (.Values.buildImages.enabled) }}
                    <privileged>true</privileged>
  {{- else }}
                    <privileged>false</privileged>
  {{- end }}
  {{- if and (.Values.agent.runAsUser) (not .Values.buildImages.enabled) }}
                     <runAsUser>{{ .Values.agent.runAsUser }}</runAsUser>  
  {{- end }}
                    <alwaysPullImage>{{ .Values.agent.alwaysPullImage }}</alwaysPullImage>
                    <workingDir>/home/jenkins</workingDir>
    {{- if .Values.agent.command }}
                    <command>{{ .Values.agent.command }}</command>
    {{- else if .Values.permanentagent.sspmutualtls.enabled }}
                    <command>sh</command>
    {{- else }}
                    <command></command>
    {{- end }}
  {{- if .Values.agent.args }}
                    <args>{{ .Values.agent.args }}</args>
  {{- else if .Values.permanentagent.sspmutualtls.enabled }}
                    <args>/opt/init/init_slave.sh ${computer.jnlpmac} ${computer.name}</args>
  {{- else }}
                    <args>${computer.jnlpmac} ${computer.name}</args>
  {{- end }}
                    <ttyEnabled>{{ .Values.agent.TTYEnabled }}</ttyEnabled>
                    # Resources configuration is a little hacky. This was to prevent breaking
                    # changes, and should be cleanned up in the future once everybody had
                    # enough time to migrate.
                    <resourceRequestCpu>{{.Values.agent.resources.requests.cpu}}</resourceRequestCpu>
                    <resourceRequestMemory>{{.Values.agent.resources.requests.memory}}</resourceRequestMemory>
                    <resourceLimitCpu>{{.Values.agent.resources.limits.cpu}}</resourceLimitCpu>
                    <resourceLimitMemory>{{.Values.agent.resources.limits.memory}}</resourceLimitMemory>
                  </org.csanchez.jenkins.plugins.kubernetes.ContainerTemplate>
                </containers>
                <envVars>
  {{- range $index, $var := .Values.agent.envVars }}
                  <org.csanchez.jenkins.plugins.kubernetes.PodEnvVar>
                    <key>{{ $var.name }}</key>
                    <value>{{ $var.value }}</value>
                  </org.csanchez.jenkins.plugins.kubernetes.PodEnvVar>
  {{- end }}
  {{- if .Values.proxy.enabled }}
                  <org.csanchez.jenkins.plugins.kubernetes.PodEnvVar>
                    <key>http_proxy</key>
                    <value>{{ .Values.proxy.server }}:{{ default "80" .Values.proxy.port }}</value>
                  </org.csanchez.jenkins.plugins.kubernetes.PodEnvVar>
                  <org.csanchez.jenkins.plugins.kubernetes.PodEnvVar>
                    <key>https_proxy</key>
                    <value>{{ .Values.proxy.server }}:{{ default "443" .Values.proxy.port }}</value>
                  </org.csanchez.jenkins.plugins.kubernetes.PodEnvVar>
  {{- end }}
  {{- if .Values.permanentagent.sspmutualtls.enabled }}
                  <org.csanchez.jenkins.plugins.kubernetes.PodEnvVar>
                    <key>SSL_DIR</key>
                    <value>{{ .Values.permanentagent.sspmutualtls.ssldir }}</value>
                  </org.csanchez.jenkins.plugins.kubernetes.PodEnvVar>
  {{- end }}
  {{- if .Values.buildImages.format }}
                  <org.csanchez.jenkins.plugins.kubernetes.PodEnvVar>
                    <key>BUILDAH_FORMAT</key>
                    <value>{{ .Values.buildImages.format }}</value>
                  </org.csanchez.jenkins.plugins.kubernetes.PodEnvVar>
  {{- end }}
                </envVars>
                <annotations/>
  {{- if .Values.agent.imagePullSecretName }}
                <imagePullSecrets>
                  <org.csanchez.jenkins.plugins.kubernetes.PodImagePullSecret>
                    <name>{{ .Values.agent.imagePullSecretName }}</name>
                  </org.csanchez.jenkins.plugins.kubernetes.PodImagePullSecret>
                </imagePullSecrets>
  {{- else }}
                <imagePullSecrets/>
  {{- end }}
                <nodeProperties/>
  {{- if .Values.agent.yamlTemplate }}
                <yaml>{{ tpl .Values.agent.yamlTemplate . | html | trim }}</yaml>
  {{- end }}
                <podRetention class="org.csanchez.jenkins.plugins.kubernetes.pod.retention.Default"/>
              </org.csanchez.jenkins.plugins.kubernetes.PodTemplate>
  {{- end -}}
            </templates>
            <serverUrl>https://kubernetes.default</serverUrl>
            <skipTlsVerify>false</skipTlsVerify>
            <namespace>{{ default .Release.Namespace .Values.master.slaveKubernetesNamespace }}</namespace>
  {{- if .Values.master.slaveKubernetesNamespace }}
            <jenkinsUrl>http://{{ template "jenkins.fullname" . }}.{{.Release.Namespace}}:{{.Values.master.servicePort}}{{ default "" .Values.master.jenkinsUriPrefix }}</jenkinsUrl>
            <jenkinsTunnel>{{ template "jenkins.fullname" . }}-agent.{{.Release.Namespace}}:{{ .Values.master.slaveListenerPort }}</jenkinsTunnel>
  {{- else }}
            <jenkinsUrl>http://{{ template "jenkins.fullname" . }}:{{.Values.master.servicePort}}{{ default "" .Values.master.jenkinsUriPrefix }}</jenkinsUrl>
            <jenkinsTunnel>{{ template "jenkins.fullname" . }}-agent:{{ .Values.master.slaveListenerPort }}</jenkinsTunnel>
  {{- end }}
            <containerCap>{{ .Values.agent.containerCap }}</containerCap>
            <retentionTimeout>5</retentionTimeout>
            <connectTimeout>0</connectTimeout>
            <readTimeout>0</readTimeout>
            <podRetention class="org.csanchez.jenkins.plugins.kubernetes.pod.retention.{{ .Values.agent.podRetention }}"/>
          </org.csanchez.jenkins.plugins.kubernetes.KubernetesCloud>
        </clouds>
        <quietPeriod>5</quietPeriod>
        <scmCheckoutRetryCount>0</scmCheckoutRetryCount>
        <views>
          <hudson.model.AllView>
            <owner class="hudson" reference="../../.."/>
            <name>All</name>
            <filterExecutors>false</filterExecutors>
            <filterQueue>false</filterQueue>
            <properties class="hudson.model.View$PropertyList"/>
          </hudson.model.AllView>
        </views>
        <primaryView>All</primaryView>
        <slaveAgentPort>{{ .Values.master.slaveListenerPort }}</slaveAgentPort>
        <disabledAgentProtocols>
  {{- range .Values.master.disabledAgentProtocols }}
          <string>{{ . }}</string>
  {{- end }}
        </disabledAgentProtocols>
        <label></label>
  {{- if .Values.master.csrf.defaultCrumbIssuer.enabled }}
        <crumbIssuer class="hudson.security.csrf.DefaultCrumbIssuer">
  {{- if .Values.master.csrf.defaultCrumbIssuer.proxyCompatability }}
          <excludeClientIPFromCrumb>true</excludeClientIPFromCrumb>
  {{- end }}
        </crumbIssuer>
  {{- end }}
        <nodeProperties/>
        <globalNodeProperties/>
        <noUsageStatistics>true</noUsageStatistics>
      </hudson>
  
{{- end}}
  
###
  
{{- define "custom.scriptapproval" -}}
<?xml version='1.0' encoding='UTF-8'?>
      <scriptApproval plugin="script-security@1.27">
        <approvedScriptHashes/>
        <approvedSignatures>
  {{- range $key, $val := .Values.master.scriptApproval }}
          <string>{{ $val }}</string>
  {{- end }}
        </approvedSignatures>
        <aclApprovedSignatures/>
        <approvedClasspathEntries/>
        <pendingScripts/>
        <pendingSignatures/>
        <pendingClasspathEntries/>
      </scriptApproval>
{{- end}}

###

{{- define "custom.JenkinsLocationConfiguration" -}}
<?xml version='1.1' encoding='UTF-8'?>
      <jenkins.model.JenkinsLocationConfiguration>
        <adminAddress>{{ default "" .Values.master.jenkinsAdminEmail }}</adminAddress>
  {{- if .Values.master.jenkinsUrl }}
        <jenkinsUrl>{{ .Values.master.jenkinsUrl }}</jenkinsUrl>
  {{- else }}
    {{- if .Values.master.ingress.hostName }}
      {{- if .Values.master.ingress.tls }}
        <jenkinsUrl>{{ default "https" .Values.master.jenkinsUrlProtocol }}://{{ .Values.master.ingress.hostName }}{{ default "" .Values.master.jenkinsUriPrefix }}</jenkinsUrl>
      {{- else }}
        <jenkinsUrl>{{ default "http" .Values.master.jenkinsUrlProtocol }}://{{ .Values.master.ingress.hostName }}{{ default "" .Values.master.jenkinsUriPrefix }}</jenkinsUrl>
      {{- end }}
    {{- else }}
        <jenkinsUrl>{{ default "http" .Values.master.jenkinsUrlProtocol }}://{{ template "jenkins.fullname" . }}:{{.Values.master.servicePort}}{{ default "" .Values.master.jenkinsUriPrefix }}</jenkinsUrl>
    {{- end}}
  {{- end}}
      </jenkins.model.JenkinsLocationConfiguration>
{{- end}}

###

{{- define "custom.CLI" -}}    
<?xml version='1.1' encoding='UTF-8'?>
      <jenkins.CLI>
  {{- if .Values.master.cli }}
        <enabled>true</enabled>
  {{- else }}
        <enabled>false</enabled>
  {{- end }}
      </jenkins.CLI>}}}
{{- end}}

{{- define "custom.plugins" -}}
  {{- if .Values.master.installPlugins }}
  {{- range $index, $val := .Values.master.installPlugins }}
  {{ $val | indent 4 }}
  {{- end }}
  {{- if .Values.master.JCasC.enabled }}
    {{- if not (contains "configuration-as-code" (quote .Values.master.installPlugins)) }}
      configuration-as-code:{{ .Values.master.JCasC.pluginVersion }}
    {{- end }}
    {{- if not (contains "configuration-as-code-support" (quote .Values.master.installPlugins)) }}
      configuration-as-code-support:{{ .Values.master.JCasC.supportPluginVersion }}
    {{- end }}
  {{- end }}
  {{ else }}
  
  {{- end -}}
{{- end }}

{{- define "custom.apply_config" -}}
       mkdir -p /usr/share/jenkins/ref/secrets/;
    echo "false" > /usr/share/jenkins/ref/secrets/slave-to-master-security-kill-switch;
{{- if .Values.master.overwriteConfig }}
    cp /var/jenkins_config/config.xml /var/jenkins_home;
    cp /var/jenkins_config/jenkins.CLI.xml /var/jenkins_home;
    cp /var/jenkins_config/jenkins.model.JenkinsLocationConfiguration.xml /var/jenkins_home;
    cp /var/jenkins_config/org.jenkinsci.plugins.workflow.libs.GlobalLibraries.xml /var/jenkins_home;
  {{- else }}
    yes n | cp -i /var/jenkins_config/config.xml /var/jenkins_home;
    yes n | cp -i /var/jenkins_config/jenkins.CLI.xml /var/jenkins_home;
    yes n | cp -i /var/jenkins_config/jenkins.model.JenkinsLocationConfiguration.xml /var/jenkins_home;
    yes n | cp -i /var/jenkins_config/org.jenkinsci.plugins.workflow.libs.GlobalLibraries.xml /var/jenkins_home;
  {{- end }}
  {{- if .Values.master.additionalConfig }}
{{- range $key, $val := .Values.master.additionalConfig }}
    cp /var/jenkins_config/{{- $key }} /var/jenkins_home;
  {{- end }}
{{- end }}
{{- if .Values.master.overwritePlugins -}}
    # remove all plugins from shared volume
    rm -rf /var/jenkins_home/plugins/*
{{- end }}
{{- if .Values.master.installPlugins }}
    # Install missing plugins
    cp /var/jenkins_config/plugins.txt /var/jenkins_home;
    rm -rf /usr/share/jenkins/ref/plugins/*.lock
    /usr/local/bin/install-plugins.sh `echo $(cat /var/jenkins_home/plugins.txt)`;
    # Copy plugins to shared volume
    yes n | cp -i /usr/share/jenkins/ref/plugins/* /var/jenkins_plugins/;
{{- end }}
{{- if .Values.master.scriptApproval }}
    yes n | cp -i /var/jenkins_config/scriptapproval.xml /var/jenkins_home/scriptApproval.xml;
{{- end }}
{{- if and (.Values.master.JCasC.enabled) (.Values.master.sidecars.configAutoReload.enabled) }}
  {{- if not .Values.master.initScripts }}
    mkdir -p /var/jenkins_home/init.groovy.d/;
    yes n | cp -i /var/jenkins_config/*.groovy /var/jenkins_home/init.groovy.d/;
  {{- end }}
{{- end }}
{{- if .Values.master.initScripts -}}
    mkdir -p /var/jenkins_home/init.groovy.d/;
    {{- if .Values.master.overwriteConfig }}
    rm -f /var/jenkins_home/init.groovy.d/*.groovy
    {{- end }}
    yes n | cp -i /var/jenkins_config/*.groovy /var/jenkins_home/init.groovy.d/;
{{- end }}
{{- if .Values.master.JCasC.enabled }}
  {{- if .Values.master.sidecars.configAutoReload.enabled }}
    bash -c 'ssh-keygen -y -f <(echo "${ADMIN_PRIVATE_KEY}") > /var/jenkins_home/key.pub'
  {{- else }}
    mkdir -p /var/jenkins_home/casc_configs;
    rm -rf /var/jenkins_home/casc_configs/*
    cp -v /var/jenkins_config/*.yaml /var/jenkins_home/casc_configs
  {{- end }}
{{- end }}
{{- if .Values.master.credentialsXmlSecret }}
    yes n | cp -i /var/jenkins_credentials/credentials.xml /var/jenkins_home;
{{- end }}
{{- if .Values.master.secretsFilesSecret }}
    yes n | cp -i /var/jenkins_secrets/* /usr/share/jenkins/ref/secrets/;
{{- end }}
{{- if .Values.master.jobs }}
    for job in $(ls /var/jenkins_jobs); do
      mkdir -p /var/jenkins_home/jobs/$job
      yes {{ if not .Values.master.overwriteJobs }}n{{ end }} | cp -i /var/jenkins_jobs/$job /var/jenkins_home/jobs/$job/config.xml
    done
{{- end }}

{{- end }}

{{- define "custom.init-add-ssh-key-to-admin" -}}
    import jenkins.security.*
    import hudson.model.User
    import jenkins.security.ApiTokenProperty
    import jenkins.model.Jenkins
    User u = User.get("{{ .Values.master.adminUser | default "admin" }}")
    ApiTokenProperty t = u.getProperty(ApiTokenProperty.class)
    String sshKeyString = new File('/var/jenkins_home/key.pub').text
    keys_param = new org.jenkinsci.main.modules.cli.auth.ssh.UserPropertyImpl(sshKeyString)
    u.addProperty(keys_param)
    def inst = Jenkins.getInstance()
    def sshDesc = inst.getDescriptor("org.jenkinsci.main.modules.sshd.SSHD")
    sshDesc.setPort({{ .Values.master.sidecars.configAutoReload.sshTcpPort | default 1044 }})
    sshDesc.getActualPort()
    sshDesc.save()
{{- end }}

{{- define "custom.GlobalLibraries" -}}
        <?xml version='1.1' encoding='UTF-8'?>
        <org.jenkinsci.plugins.workflow.libs.GlobalLibraries plugin="workflow-cps-global-lib@2.9">
          <libraries>
            <org.jenkinsci.plugins.workflow.libs.LibraryConfiguration>
              <name>caas-pipeline</name>
              <retriever class="org.jenkinsci.plugins.workflow.libs.SCMSourceRetriever">
                <scm class="jenkins.plugins.git.GitSCMSource" plugin="git@3.9.1">
                  <id>b4c73de4-8f52-4eab-910e-72bdf97ac8ba</id>
                  <remote>{{ .Values.master.GlobalLibraries.gitlabHost }}/cbk/arquitectura/containers/pipelines/caas-pipeline.git</remote>
                  <credentialsId>git_user</credentialsId>
                  <traits>
                    <jenkins.plugins.git.traits.BranchDiscoveryTrait/>
                  </traits>
                </scm>
              </retriever>
              <defaultVersion>{{ .Values.master.GlobalLibraries.sharedLibrary }}</defaultVersion>
              <implicit>true</implicit>
              <allowVersionOverride>true</allowVersionOverride>
              <includeInChangesets>true</includeInChangesets>
            </org.jenkinsci.plugins.workflow.libs.LibraryConfiguration>
          </libraries>
        </org.jenkinsci.plugins.workflow.libs.GlobalLibraries>
{{- end }}

{{- define "custom.init_slave.sh" }}
     #!/bin/sh
     {{- if .Values.permanentagent.sspmutualtls.enabled }}
       certutil -N -d ${SSL_DIR} -f ${SSL_DIR}/tmp/nsspasswd
       pk12util -i ${SSL_DIR}/tmp/sspcrt -d ${SSL_DIR} -w ${SSL_DIR}/tmp/p12passwd -k ${SSL_DIR}/tmp/nsspasswd
     {{- end }}
       if [[ ${PERMANENT_AGENT} ]]; then
         java -jar {{ .Values.permanentagent.swarmBin }} -master http://{{template "jenkins.fullname" . }}:{{ .Values.master.servicePort }} -tunnel {{template "jenkins.fullname" . }}-agent:{{ .Values.master.slaveListenerPort }} -executors {{ .Values.permanentagent.executors }} -username {{ .Values.permanentagent.user }} -password {{ .Values.permanentagent.password }}
       else
         jenkins-slave $@
       fi
{{- end }}

