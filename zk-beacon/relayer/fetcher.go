package relayer

import (
	"github.com/kysee/zkp/zk-beacon/types"
)

// LCUpdateFetcher defines the interface for fetching light client update data
type LCUpdateFetcher interface {
	// FetchUpdate retrieves a light client update
	FetchUpdate() (*types.LightClientUpdate, error)
}
