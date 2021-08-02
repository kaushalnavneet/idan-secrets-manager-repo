package publiccerts

import (
	"fmt"
	"github.com/go-acme/lego/v4/providers/dns"
)

func GetDNSTypesAllowedValues() []interface{} {
	return []interface{}{dnsConfigTypeCIS, dnsConfigTypeSoftLayer}
}

//this function is used for dns config only
func prepareDNSConfigToStore(p *ProviderConfig, smInstanceCrn string) error {
	switch p.Type {
	case dnsConfigTypeCIS:
		if err := validateCISConfigStructure(p.Config, smInstanceCrn); err != nil {
			return err
		}
		return NewCISDNSProvider(p.Config).validateConfig()
	case dnsConfigTypeSoftLayer:
		if err := validateSoftLayerStructure(p.Config); err != nil {
			return err
		}
		return NewSoftlayerDNSProvider(p.Config).validateConfig()
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
