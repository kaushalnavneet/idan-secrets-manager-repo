package publiccerts

import (
	"fmt"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client_impl"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"time"
)

func GetDNSTypesAllowedValues() []interface{} {
	return []interface{}{dnsConfigTypeCIS, dnsConfigTypeSoftLayer}
}

//this function is used for dns config only
func prepareDNSConfigToStore(p *ProviderConfig, smInstanceCrn string, auth common.AuthUtils) error {
	//create resty client
	cf := &rest_client_impl.RestClientFactory{}
	//init resty client with not default options
	cf.InitClientWithOptions(rest_client.RestClientOptions{
		Timeout:    10 * time.Second,
		Retries:    2,
		RetryDelay: 1 * time.Second,
	})
	switch p.Type {
	case dnsConfigTypeCIS:
		if err := validateCISConfigStructure(p.Config, smInstanceCrn); err != nil {
			return err
		}
		return NewCISDNSProvider(p.Config, cf, auth).validateConfig()
	case dnsConfigTypeSoftLayer:
		if err := validateSoftLayerConfigStructure(p.Config); err != nil {
			return err
		}
		return NewSoftlayerDNSProvider(p.Config, cf).validateConfig()
	default:
		//TODO we won't support ALL providers, it should be locked list
		_, err := dns.NewDNSChallengeProviderByName(p.Type)
		if err != nil {
			return err
		}
	}
	return nil
}

func getDNSConfigForResponse(p *ProviderConfig) map[string]string {
	result := make(map[string]string)
	switch p.Type {
	case dnsConfigTypeCIS:
		result[dnsConfigCisCrn] = p.Config[dnsConfigCisCrn]
		if apikey, ok := p.Config[dnsConfigCisApikey]; ok {
			result[dnsConfigCisApikey] = apikey
		}
	case dnsConfigTypeSoftLayer:
		result[dnsConfigSLUser] = p.Config[dnsConfigSLUser]
		result[dnsConfigSLPassword] = p.Config[dnsConfigSLPassword]
	}
	return result
}

func buildOrderError(code, message string) error {
	return fmt.Errorf(errorPattern, code, message)
}
