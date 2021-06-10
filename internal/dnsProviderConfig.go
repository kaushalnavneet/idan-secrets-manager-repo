package publiccerts

type DnsProviderConfig struct {
	Name   string            `json:"name"`
	Type   string            `json:"type"`
	Config map[string]string `json:"config"`
}

func (p *DnsProviderConfig) GetConfig() map[string]string {
	return p.Config
}

func NewDnsProviderConfig(name, providerType string, config map[string]string) *DnsProviderConfig {
	providerConfig := &DnsProviderConfig{
		Name:   name,
		Type:   providerType,
		Config: config,
	}

	return providerConfig
}
