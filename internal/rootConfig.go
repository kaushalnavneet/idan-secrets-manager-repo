package publiccerts

import (
	"context"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
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
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}

func putRootConfig(ctx context.Context, req *logical.Request, config *RootConfig) error {
	// Store the configuration to the backend storage
	// Generate a new storage entry
	entry, err := logical.StorageEntryJSON(ConfigRootPath, config)
	if err != nil {
		common.Logger().Error("Failed to create storage entry for root configuration.", "error", err)
		common.ErrorLogForCustomer("Internal server error", Error07009, logdna.InternalErrorMessage)
		return errwrap.Wrapf("failed to generate JSON configuration: {{err}}", err)
	}
	// Save the storage entry
	if err := req.Storage.Put(ctx, entry); err != nil {
		common.Logger().Error("Failed to save root configuration to storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", Error07010, logdna.InternalErrorMessage)
		return errwrap.Wrapf("failed to persist configuration to storage: {{err}}", err)
	}
	return nil
}
