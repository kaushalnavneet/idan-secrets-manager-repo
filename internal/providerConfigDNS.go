package publiccerts

import "github.com/go-acme/lego/v4/providers/dns"

func GetDNSTypesAllowedValues() []interface{} {
	return []interface{}{dnsConfigTypeCIS}
}

//this function is used for dns config only
func prepareDNSConfigToStore(p *ProviderConfig) error {
	switch p.Type {
	case dnsConfigTypeCIS:
		err := validateCISConfigStructure(p.Config)
		if err != nil {
			return err
		}
		return NewCISDNSProvider(p.Config, p.smInstanceCrn).validateConfig()
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
	result[dnsConfigCisCrn] = p.Config[dnsConfigCisCrn]
	result[dnsConfigCisApikey] = p.Config[dnsConfigCisApikey]
	return result
}
