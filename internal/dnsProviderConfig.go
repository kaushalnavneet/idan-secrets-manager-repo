package publiccerts

import (
	"github.com/go-acme/lego/v4/providers/dns"
)

type DnsProviderConfig struct {
	Name          string            `json:"name"`
	Type          string            `json:"type"`
	Config        map[string]string `json:"config"`
	smInstanceCrn string
}

func (p *DnsProviderConfig) GetConfig() map[string]string {
	return p.Config
}

func NewDnsProviderConfig(name, providerType string, config map[string]string, smInstanceCrn string) *DnsProviderConfig {
	providerConfig := &DnsProviderConfig{
		Name:          name,
		Type:          providerType,
		Config:        config,
		smInstanceCrn: smInstanceCrn,
	}

	return providerConfig
}

func (p *DnsProviderConfig) validateConfig() error {
	switch p.Type {
	case "cis":
		return NewCISDNSProvider(p.Config, p.smInstanceCrn).validateConfig()
	default:
		//TODO we won't want to support ALL providers, it should be locked list
		_, err := dns.NewDNSChallengeProviderByName(p.Type)
		if err != nil {
			return err
		}
	}
	return nil
}
