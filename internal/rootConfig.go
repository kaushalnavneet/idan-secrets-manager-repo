package publiccerts

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
)

type RootConfig struct {
	CaConfigs       []*CAUserConfigToStore `json "certificate_authorities"`
	ProviderConfigs []*DnsProviderConfig   `json "dns_providers"`
}

func getRootConfig(ctx context.Context, req *logical.Request) (*RootConfig, error) {
	entry, err := req.Storage.Get(ctx, ConfigRootPath)
	if err != nil {
		return nil, err
	}
	config := &RootConfig{}
	if entry == nil {
		return config, nil
	}
	if err = entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}

func putRootConfig(ctx context.Context, req *logical.Request, config *RootConfig) error {
	// Store the configuration to the backend storage
	// Generate a new storage entry
	entry, err := logical.StorageEntryJSON(ConfigRootPath, config)
	if err != nil {
		return err
	}
	// Save the storage entry
	if err = req.Storage.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}

func getCAConfigsAsMap(config *RootConfig) []map[string]string {
	confArray := make([]map[string]string, len(config.CaConfigs))
	for i, caConfig := range config.CaConfigs {
		confArray[i] = make(map[string]string)
		confArray[i][FieldName] = caConfig.Name
		confArray[i][FieldDirectoryUrl] = caConfig.DirectoryURL
	}
	return confArray
}

func getDNSConfigsAsMap(config *RootConfig) []map[string]string {
	confArray := make([]map[string]string, len(config.ProviderConfigs))
	for i, dnsConfig := range config.ProviderConfigs {
		confArray[i] = make(map[string]string)
		confArray[i][FieldName] = dnsConfig.Name
		confArray[i][FieldType] = dnsConfig.Type
	}
	return confArray
}
