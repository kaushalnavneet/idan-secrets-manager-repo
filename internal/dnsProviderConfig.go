package publiccerts

type DnsProviderConfig struct {
	Name   string            `json:"name"`
	Config map[string]string `json:"config"`
}

func (p *DnsProviderConfig) GetConfig() map[string]string {
	return p.Config
}

func NewDnsProviderConfig(name string, config map[string]string) *DnsProviderConfig {
	providerConfig := &DnsProviderConfig{
		Name:   name,
		Config: config,
	}

	return providerConfig
}
