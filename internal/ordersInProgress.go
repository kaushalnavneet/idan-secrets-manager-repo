package publiccerts

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
)

type OrdersInProgress struct {
	SecretIds []SecretId `json:"secret_ids"`
}
type SecretId struct {
	GroupId string `json:"group_id"`
	Id      string `json:"id"`
}

func getOrdersInProgress(storage logical.Storage) *OrdersInProgress {
	//it's empty by default
	orders := &OrdersInProgress{SecretIds: make([]SecretId, 0)}
	//get from storage
	entry, err := storage.Get(context.Background(), PathOrdersInProgress)
	if err != nil { //will use the default
		common.Logger().Error("Failed to get Orders in progress from the storage: " + err.Error())
	} else if entry == nil { //will use the default
		common.Logger().Info("Orders in progress doesn't exist in the storage.")
	} else if err = entry.DecodeJSON(orders); err != nil { //try to unmarshal it, if not, use the default
		common.Logger().Error("Orders in progress data was corrupted: " + err.Error() + "Data: " + string(entry.Value))
	}
	return orders
}

func (o *OrdersInProgress) save(storage logical.Storage) {
	// Store the item to the backend storage
	// Generate a new storage entry
	entry, err := logical.StorageEntryJSON(PathOrdersInProgress, o)
	if err != nil {
		common.Logger().Error("Failed to parse Orders in progress: " + err.Error())
		return
	}
	// Save the storage entry
	if err = storage.Put(context.Background(), entry); err != nil {
		common.Logger().Error("Failed to save Orders in progress: " + err.Error())
	}
}
