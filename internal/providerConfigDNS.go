package publiccerts

import (
	"fmt"
)

func GetDNSTypesAllowedValues() []interface{} {
	return []interface{}{dnsConfigTypeCIS, dnsConfigTypeSoftLayer}
}

//this function is used for dns config only
func (ob *OrdersBackend) prepareDNSConfigToStore(p *ProviderConfig) error {
	smInstanceCrn := ob.ordersHandler.pluginConfig.Service.Instance.CRN
	auth := ob.secretBackend.GetValidator().GetAuth()
	rc := ob.RestClient
	switch p.Type {
	case dnsConfigTypeCIS:
		if err := validateCISConfigStructure(p.Config, smInstanceCrn); err != nil {
			return err
		}
		return NewCISDNSProvider(p.Config, rc, auth).validateConfig()
	case dnsConfigTypeSoftLayer:
		if err := validateSoftLayerConfigStructure(p.Config); err != nil {
			return err
		}
		return NewSoftlayerDNSProvider(p.Config, rc).validateConfig()
		//default:
		//	//we won't support ALL providers, it should be locked list
		//	_, err := dns.NewDNSChallengeProviderByName(p.Type)
		//	if err != nil {
		//		return err
		//	}
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
