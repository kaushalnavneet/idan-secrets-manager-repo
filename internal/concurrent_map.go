package publiccerts

// shared nothing map that is safe for concurrent access
// TODO - test performance overhead

type KeyValue struct {
	Key   string
	Value string
	Reply chan FetchResult
}

type FetchResult struct {
	KeyValue KeyValue
	IsFound  bool
}

type Cache struct {
	db                     map[string]string
	storeChannel           chan KeyValue
	restrictedStoreChannel chan KeyValue
	fetchChannel           chan KeyValue
	deleteChannel          chan KeyValue
}

func NewCache() *Cache {
	c := &Cache{}

	c.db = make(map[string]string)

	c.storeChannel = make(chan KeyValue)
	c.restrictedStoreChannel = make(chan KeyValue)
	c.fetchChannel = make(chan KeyValue)
	c.deleteChannel = make(chan KeyValue)

	go func() {

		for {
			select {
			case storeValue := <-c.storeChannel:
				c.internalStore(storeValue)

			case storeValue := <-c.restrictedStoreChannel:
				result := c.internalStoreIfNotExists(storeValue)
				storeValue.Reply <- result

			case fetchKey := <-c.fetchChannel:
				fetchKey.Reply <- c.internalFetch(fetchKey)

			case deleteKey := <-c.deleteChannel:
				c.internalDelete(deleteKey)
			}
		}
	}()

	return c
}

func (c *Cache) internalFetch(kv KeyValue) FetchResult {
	v, ok := c.db[kv.Key]
	if ok {
		return FetchResult{KeyValue{Key: kv.Key, Value: v}, true}
	}
	return FetchResult{KeyValue{Key: kv.Key}, false}
}

func (c *Cache) internalStore(kv KeyValue) {
	c.db[kv.Key] = kv.Value
}

func (c *Cache) internalStoreIfNotExists(kv KeyValue) FetchResult {
	result := c.internalFetch(kv)
	if result.IsFound {
		return FetchResult{result.KeyValue, true}
	}
	c.db[kv.Key] = kv.Value
	return FetchResult{kv, false}
}

func (c *Cache) internalDelete(kv KeyValue) {
	delete(c.db, kv.Key)
}

func (c *Cache) Fetch(key string) (KeyValue, bool) {
	ch := make(chan FetchResult)
	c.fetchChannel <- KeyValue{Key: key, Reply: ch}

	result := <-ch
	return result.KeyValue, result.IsFound
}

func (c *Cache) Store(key string, value string) {
	c.storeChannel <- KeyValue{Key: key, Value: value}
}

func (c *Cache) StoreIfNotExists(key string, value string) (KeyValue, bool) {
	ch := make(chan FetchResult)
	c.restrictedStoreChannel <- KeyValue{Key: key, Value: value, Reply: ch}
	result := <-ch
	return result.KeyValue, !result.IsFound
}

func (c *Cache) Delete(key string) {
	c.deleteChannel <- KeyValue{Key: key}
}
