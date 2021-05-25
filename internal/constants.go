package publiccerts

import "github.ibm.com/security-services/secrets-manager-common-utils/logging/logdna"

//todo move to common
const (
	PluginMountPath          = "/v1/ibmcloud/public_cert/"
	FieldRegistrationUrl     = "registration_uri"
	FieldName                = "name"
	FieldDirectoryUrl        = "directory_url"
	FieldCaCert              = "ca-cert"
	FieldEmail               = "email"
	FieldPrivateKey          = "private_key"
	FieldConfig              = "config"
	SecretTypePublicCert     = "public_cert"
	CA                       = "certificate_authorities"
	DNS                      = "dns_providers"
	Root                     = "root"
	ConfigCAPath             = "config/" + CA
	ConfigDNSPath            = "config/" + DNS
	ConfigRootPath           = "config/" + Root
	DeleteEngineConfigAction = "secrets-manager.secret-engine-config.delete"
)
const (
	Error07001 = logdna.ServiceNamePrefix + ".Error07001" //public_certs common/root
	Error07002 = logdna.ServiceNamePrefix + ".Error07002" //public_certs common/root
	Error07003 = logdna.ServiceNamePrefix + ".Error07003" //public_certs common/root
	Error07004 = logdna.ServiceNamePrefix + ".Error07004" //public_certs common/root
	Error07005 = logdna.ServiceNamePrefix + ".Error07005" //public_certs
	Error07006 = logdna.ServiceNamePrefix + ".Error07006" //public_certs
	Error07007 = logdna.ServiceNamePrefix + ".Error07007" //public_certs
	Error07008 = logdna.ServiceNamePrefix + ".Error07008" //public_certs
	Error07009 = logdna.ServiceNamePrefix + ".Error07009" //public_certs
	Error07010 = logdna.ServiceNamePrefix + ".Error07010" //public_certs ca config
	Error07011 = logdna.ServiceNamePrefix + ".Error07011" //public_certs ca config
	Error07012 = logdna.ServiceNamePrefix + ".Error07012" //public_certs ca config
	Error07013 = logdna.ServiceNamePrefix + ".Error07013" //public_certs ca config
	Error07014 = logdna.ServiceNamePrefix + ".Error07014" //public_certs ca config
	Error07015 = logdna.ServiceNamePrefix + ".Error07015" //public_certs ca config
	Error07016 = logdna.ServiceNamePrefix + ".Error07016" //public_certs ca config
	Error07017 = logdna.ServiceNamePrefix + ".Error07017" //public_certs ca config
	Error07018 = logdna.ServiceNamePrefix + ".Error07018" //public_certs ca config
	Error07019 = logdna.ServiceNamePrefix + ".Error07019" //public_certs ca config
	Error07020 = logdna.ServiceNamePrefix + ".Error07020" //public_certs ca config
	Error07021 = logdna.ServiceNamePrefix + ".Error07021" //public_certs ca config
	Error07022 = logdna.ServiceNamePrefix + ".Error07022" //public_certs ca config
	Error07023 = logdna.ServiceNamePrefix + ".Error07023" //public_certs ca config
	Error07024 = logdna.ServiceNamePrefix + ".Error07024" //public_certs ca config
	Error07025 = logdna.ServiceNamePrefix + ".Error07025" //public_certs ca config
	Error07026 = logdna.ServiceNamePrefix + ".Error07026" //public_certs ca config
	Error07027 = logdna.ServiceNamePrefix + ".Error07027" //public_certs ca config
	Error07028 = logdna.ServiceNamePrefix + ".Error07028" //public_certs ca config
	Error07029 = logdna.ServiceNamePrefix + ".Error07029" //public_certs ca config
	Error07030 = logdna.ServiceNamePrefix + ".Error07030" //public_certs ca config
	Error07031 = logdna.ServiceNamePrefix + ".Error07031" //public_certs ca config
	Error07032 = logdna.ServiceNamePrefix + ".Error07032" //public_certs ca config
	Error07033 = logdna.ServiceNamePrefix + ".Error07033" //public_certs ca config
	Error07034 = logdna.ServiceNamePrefix + ".Error07034" //public_certs
	Error07035 = logdna.ServiceNamePrefix + ".Error07035" //public_certs
	Error07036 = logdna.ServiceNamePrefix + ".Error07036" //public_certs
	Error07037 = logdna.ServiceNamePrefix + ".Error07037" //public_certs
	Error07038 = logdna.ServiceNamePrefix + ".Error07038" //public_certs
	Error07039 = logdna.ServiceNamePrefix + ".Error07039" //public_certs
	Error07040 = logdna.ServiceNamePrefix + ".Error07040" //public_certs dns config
	Error07041 = logdna.ServiceNamePrefix + ".Error07041" //public_certs dns config
	Error07042 = logdna.ServiceNamePrefix + ".Error07042" //public_certs dns config
	Error07043 = logdna.ServiceNamePrefix + ".Error07043" //public_certs dns config
	Error07044 = logdna.ServiceNamePrefix + ".Error07044" //public_certs dns config
	Error07045 = logdna.ServiceNamePrefix + ".Error07045" //public_certs dns config
	Error07046 = logdna.ServiceNamePrefix + ".Error07046" //public_certs dns config
	Error07047 = logdna.ServiceNamePrefix + ".Error07047" //public_certs dns config
	Error07048 = logdna.ServiceNamePrefix + ".Error07048" //public_certs dns config
	Error07049 = logdna.ServiceNamePrefix + ".Error07049" //public_certs dns config
	Error07050 = logdna.ServiceNamePrefix + ".Error07050" //public_certs dns config
	Error07051 = logdna.ServiceNamePrefix + ".Error07051" //public_certs dns config
	Error07052 = logdna.ServiceNamePrefix + ".Error07052" //public_certs dns config
	Error07053 = logdna.ServiceNamePrefix + ".Error07053" //public_certs dns config
	Error07054 = logdna.ServiceNamePrefix + ".Error07054" //public_certs dns config
	Error07055 = logdna.ServiceNamePrefix + ".Error07055" //public_certs dns config
	Error07056 = logdna.ServiceNamePrefix + ".Error07056" //public_certs dns config
	Error07057 = logdna.ServiceNamePrefix + ".Error07057" //public_certs dns config
	Error07058 = logdna.ServiceNamePrefix + ".Error07058" //public_certs dns config
	Error07059 = logdna.ServiceNamePrefix + ".Error07059" //public_certs dns config
	Error07060 = logdna.ServiceNamePrefix + ".Error07060" //public_certs dns config
	Error07061 = logdna.ServiceNamePrefix + ".Error07061" //public_certs dns config
	Error07062 = logdna.ServiceNamePrefix + ".Error07062" //public_certs dns config
	Error07063 = logdna.ServiceNamePrefix + ".Error07063" //public_certs
	Error07064 = logdna.ServiceNamePrefix + ".Error07064" //public_certs
	Error07065 = logdna.ServiceNamePrefix + ".Error07065" //public_certs
	Error07066 = logdna.ServiceNamePrefix + ".Error07066" //public_certs
	Error07067 = logdna.ServiceNamePrefix + ".Error07067" //public_certs
	Error07068 = logdna.ServiceNamePrefix + ".Error07068" //public_certs
	Error07069 = logdna.ServiceNamePrefix + ".Error07069" //public_certs
	Error07070 = logdna.ServiceNamePrefix + ".Error07070" //public_certs

)
