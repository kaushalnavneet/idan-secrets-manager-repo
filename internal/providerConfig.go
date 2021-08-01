package publiccerts

type ProviderConfig struct {
	Name          string            `json:"name"`
	Type          string            `json:"type"`
	Config        map[string]string `json:"config"`
	smInstanceCrn string
}

func NewProviderConfig(name, configType string, config map[string]string, smInstanceCrn string) *ProviderConfig {
	providerConfig := &ProviderConfig{
		Name:          name,
		Type:          configType,
		Config:        config,
		smInstanceCrn: smInstanceCrn,
	}
	return providerConfig
}

func (p *ProviderConfig) getProviderConfigMetadata() map[string]interface{} {
	result := make(map[string]interface{})
	result[FieldName] = p.Name
	result[FieldType] = p.Type
	return result
}

//Define fields to be returned in "get config" api
func (p *ProviderConfig) getConfigForResponse(providerType string) map[string]string {
	if providerType == providerTypeCA {
		return getCAConfigForResponse(p)
	} else {
		return getDNSConfigForResponse(p)
	}
}
