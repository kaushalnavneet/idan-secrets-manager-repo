package publiccerts

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
)

type OrdersInProgress struct {
	Ids []string
}

func getOrdersInProgress(storage logical.Storage) (*OrdersInProgress, error) {
	entry, err := storage.Get(context.Background(), PathOrdersInProgress)
	if err != nil {
		return nil, err
	}
	orders := &OrdersInProgress{}
	if entry == nil {
		return &OrdersInProgress{Ids: make([]string, 0)}, nil
	}
	if err = entry.DecodeJSON(orders); err != nil {
		return nil, err
	}
	return orders, nil
}

func (o *OrdersInProgress) save(storage logical.Storage) error {
	// Store the item to the backend storage
	// Generate a new storage entry
	entry, err := logical.StorageEntryJSON(PathOrdersInProgress, o)
	if err != nil {
		return err
	}
	// Save the storage entry
	if err = storage.Put(context.Background(), entry); err != nil {
		return err
	}
	return nil
}
