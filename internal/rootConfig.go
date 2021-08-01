package publiccerts

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
)

type RootConfig struct {
	CaConfigs  []*ProviderConfig `json:"certificate_authorities"`
	DnsConfigs []*ProviderConfig `json:"dns_providers"`
}

func getRootConfig(ctx context.Context, req *logical.Request) (*RootConfig, error) {
	entry, err := req.Storage.Get(ctx, ConfigRootPath)
	if err != nil {
		return nil, err
	}
	config := &RootConfig{}
	if entry == nil {
		return &RootConfig{CaConfigs: make([]*ProviderConfig, 0), DnsConfigs: make([]*ProviderConfig, 0)}, nil
	}
	if err = entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}

func (rc *RootConfig) getConfigsByProviderType(providerType string) []*ProviderConfig {
	if providerType == providerTypeCA {
		return rc.CaConfigs
	} else if providerType == providerTypeDNS {
		return rc.DnsConfigs
	}
	return nil
}

func (rc *RootConfig) setConfigsByProviderType(providerType string, configs []*ProviderConfig) {
	if providerType == providerTypeCA {
		rc.CaConfigs = configs
	} else if providerType == providerTypeDNS {
		rc.DnsConfigs = configs
	}
}

func (rc *RootConfig) getConfigsAsMap(providerType string) []map[string]interface{} {
	confArray := rc.getConfigsByProviderType(providerType)
	result := make([]map[string]interface{}, len(confArray))
	for i, conf := range confArray {
		result[i] = conf.getProviderConfigMetadata()
	}
	return result
}

func (rc *RootConfig) save(ctx context.Context, req *logical.Request) error {
	// Store the configuration to the backend storage
	// Generate a new storage entry
	entry, err := logical.StorageEntryJSON(ConfigRootPath, rc)
	if err != nil {
		return err
	}
	// Save the storage entry
	if err = req.Storage.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}
