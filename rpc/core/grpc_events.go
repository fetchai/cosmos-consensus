package core

import (
	"context"
	"fmt"

	"github.com/pkg/errors"

	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmquery "github.com/tendermint/tendermint/libs/pubsub/query"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
)

// Subscribe for events via GRPC.
func GRPCSubscribe(ctx *context.Context, addr, query string) (chan *ctypes.ResultEvent, chan error, error) {
	if eventBus.NumClients() >= config.MaxSubscriptionClients {
		return nil, nil, fmt.Errorf("max_subscription_clients %d reached", config.MaxSubscriptionClients)
	} else if eventBus.NumClientSubscriptions(addr) >= config.MaxSubscriptionsPerClient {
		return nil, nil, fmt.Errorf("max_subscriptions_per_client %d reached", config.MaxSubscriptionsPerClient)
	}

	logger.Info("Subscribe to query", "remote", addr, "query", query)

	q, err := tmquery.New(query)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to parse query")
	}

	subCtx, cancel := context.WithTimeout(*ctx, SubscribeTimeout)
	defer cancel()

	sub, err := eventBus.Subscribe(subCtx, addr, q, subBufferSize)
	if err != nil {
		return nil, nil, err
	}

	resultChan := make(chan *ctypes.ResultEvent)
	errorChan := make(chan error)

	go func() {
		for {
			select {
			case msg := <-sub.Out():
				resultEvent := &ctypes.ResultEvent{Query: query, Data: msg.Data(), Events: msg.Events()}
				resultChan <- resultEvent
			case <-sub.Cancelled():
				if sub.Err() != tmpubsub.ErrUnsubscribed {
					var reason string
					if sub.Err() == nil {
						reason = "Tendermint exited"
					} else {
						reason = sub.Err().Error()
					}
					errorChan <- fmt.Errorf("subscription was cancelled (reason: %s)", reason)
				}
				return
			}
		}
	}()

	return resultChan, errorChan, nil
}


// Unsubscribe from events via GRPC.
func GRPCUnsubscribe(ctx *context.Context, addr, query string) (*ctypes.ResultUnsubscribe, error) {
	logger.Info("Unsubscribe from query", "remote", addr, "query", query)
	q, err := tmquery.New(query)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse query")
	}
	err = eventBus.Unsubscribe(context.Background(), addr, q)
	if err != nil {
		return nil, err
	}
	return &ctypes.ResultUnsubscribe{}, nil
}

// UnsubscribeAll from all events via GRPC.
func GRPCUnsubscribeAll(addr string) (*ctypes.ResultUnsubscribe, error) {
	logger.Info("Unsubscribe from all", "remote", addr)
	err := eventBus.UnsubscribeAll(context.Background(), addr)
	if err != nil {
		return nil, err
	}
	return &ctypes.ResultUnsubscribe{}, nil
}
