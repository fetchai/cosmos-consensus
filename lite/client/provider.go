/*
Package client defines a provider that uses a rpchttp
to get information, which is used to get new headers
and validators directly from a Tendermint client.
*/
package client

import (
	"fmt"
	"math/rand"
	"net/url"
	"time"

	log "github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/lite"
	rpcclient "github.com/tendermint/tendermint/rpc/client"
	rpchttp "github.com/tendermint/tendermint/rpc/client/http"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	rpctypes "github.com/tendermint/tendermint/rpc/jsonrpc/types"
	"github.com/tendermint/tendermint/types"
)

// SignStatusClient combines a SignClient and StatusClient.
type SignStatusClient interface {
	rpcclient.SignClient
	rpcclient.StatusClient
}

type provider struct {
	logger  log.Logger
	chainID string
	client  SignStatusClient
}

// NewProvider implements Provider (but not PersistentProvider).
func NewProvider(chainID string, client SignStatusClient) lite.Provider {
	return &provider{
		logger:  log.NewNopLogger(),
		chainID: chainID,
		client:  client,
	}
}

// NewHTTPProvider can connect to a tendermint json-rpc endpoint
// at the given url, and uses that as a read-only provider.
func NewHTTPProvider(chainID, remote string) (lite.Provider, error) {
	httpClient, err := rpchttp.New(remote, "/websocket")
	if err != nil {
		return nil, err
	}
	return NewProvider(chainID, httpClient), nil
}

// Implements Provider.
func (p *provider) SetLogger(logger log.Logger) {
	logger = logger.With("module", "lite/client")
	p.logger = logger
}

// StatusClient returns the internal client as a StatusClient
func (p *provider) StatusClient() rpcclient.StatusClient {
	return p.client
}

// LatestFullCommit implements Provider.
func (p *provider) LatestFullCommit(chainID string, minHeight, maxHeight int64) (fc lite.FullCommit, err error) {
	if chainID != p.chainID {
		err = fmt.Errorf("expected chainID %s, got %s", p.chainID, chainID)
		return
	}
	if maxHeight != 0 && maxHeight < minHeight {
		err = fmt.Errorf("need maxHeight == 0 or minHeight <= maxHeight, got min %v and max %v",
			minHeight, maxHeight)
		return
	}
	commit, err := p.fetchLatestCommit(minHeight, maxHeight)
	if err != nil {
		return
	}
	fc, err = p.fillFullCommit(commit.SignedHeader)
	return
}

// fetchLatestCommit fetches the latest commit from the client.
func (p *provider) fetchLatestCommit(minHeight int64, maxHeight int64) (*ctypes.ResultCommit, error) {
	status, err := p.client.Status()
	if err != nil {
		return nil, err
	}
	if status.SyncInfo.LatestBlockHeight < minHeight {
		err = fmt.Errorf("provider is at %v but require minHeight=%v",
			status.SyncInfo.LatestBlockHeight, minHeight)
		return nil, err
	}
	if maxHeight == 0 {
		maxHeight = status.SyncInfo.LatestBlockHeight
	} else if status.SyncInfo.LatestBlockHeight < maxHeight {
		maxHeight = status.SyncInfo.LatestBlockHeight
	}
	return p.client.Commit(&maxHeight)
}

// Implements Provider.
func (p *provider) ValidatorSet(chainID string, height int64) (valset *types.ValidatorSet, err error) {
	return p.getValidatorSet(chainID, height)
}

func (p *provider) getValidatorSet(chainID string, height int64) (*types.ValidatorSet, error) {
	if chainID != p.chainID {
		return nil, fmt.Errorf("expected chainID %s, got %s", p.chainID, chainID)
	}
	if height < 1 {
		return nil, fmt.Errorf("expected height >= 1, got height %v", height)
	}

	// iterate through all validator pages up to 10000 validators.
	// ported from v0.40.x fix at https://github.com/tendermint/tendermint/blob/20610be98cef42c663169e3aae7f3a65ac5336bc/light/provider/http/http.go#L162
	const maxPages = 100
	const maxRetryAttempts = 5
	var (
		perPage = 100
		vals    = []*types.Validator{}
		page    = 1
		total   = -1
	)

	for len(vals) != total && page <= maxPages {
		attempt := uint16(0)
		for {
			res, err := p.client.Validators(&height, page, perPage)
			if err != nil {
				switch e := err.(type) {
				case *url.Error:
					if e.Timeout() {
						// if we have exceeded retry attempts then return a no response error
						if attempt == maxRetryAttempts {
							return nil, fmt.Errorf("client failed to respond after %d attempts", attempt)
						}
						attempt++
						// request timed out: we wait and try again with exponential backoff
						time.Sleep(backoffTimeout(attempt))
						continue
					}
					return nil, fmt.Errorf("client provided bad signed header: %v", e)
				case *rpctypes.RPCError:
					// process the rpc error and return the corresponding error to the light client
					return nil, fmt.Errorf("rpc error: %v", e)
				default:
					// If we don't know the error then by default we return an unreliable provider error and
					// terminate the connection with the peer.
					return nil, fmt.Errorf("client deemed unreliable: %v", e)
				}
			}

			if len(res.Validators) == 0 {
				return nil, fmt.Errorf(
					"validator set is empty (height: %d, page: %d, per_page: %d)",
					height,
					page,
					perPage,
				)
			}
			if res.Total <= 0 {
				return nil, fmt.Errorf(
					"total number of vals is <= 0: %d (height: %d, page: %d, per_page: %d)",
					res.Total,
					height,
					page,
					perPage,
				)
			}

			total = res.Total
			vals = append(vals, res.Validators...)
			page++
			break
		}
	}

	return types.NewValidatorSet(vals), nil
}

// This does no validation.
func (p *provider) fillFullCommit(signedHeader types.SignedHeader) (fc lite.FullCommit, err error) {

	// Get the validators.
	valset, err := p.getValidatorSet(signedHeader.ChainID, signedHeader.Height)
	if err != nil {
		return lite.FullCommit{}, err
	}

	// Get the next validators.
	nextValset, err := p.getValidatorSet(signedHeader.ChainID, signedHeader.Height+1)
	if err != nil {
		return lite.FullCommit{}, err
	}

	return lite.NewFullCommit(signedHeader, valset, nextValset), nil
}

// exponential backoff (with jitter)
// 0.5s -> 2s -> 4.5s -> 8s -> 12.5 with 1s variation
func backoffTimeout(attempt uint16) time.Duration {
	// nolint:gosec // G404: Use of weak random number generator
	return time.Duration(500*attempt*attempt)*time.Millisecond + time.Duration(rand.Intn(1000))*time.Millisecond
}
