package application

import (
	"context"
	"errors"

	"github.com/JustIkra/umir-auth/internal/domain"
)

type RegistryEntry struct {
	Restaurant domain.Restaurant      `json:"restaurant"`
	Settings   domain.Settings        `json:"settings"`
	Services   []domain.PeerReadiness `json:"services"`
}
type RegistryTombstone struct {
	RestaurantID     domain.EntityID `json:"restaurantID"`
	OrgID            domain.EntityID `json:"orgID"`
	LifecycleVersion domain.Version  `json:"lifecycleVersion"`
}
type RegistryResult struct {
	RegistryRevision domain.Version      `json:"registryRevision"`
	Complete         bool                `json:"complete"`
	Entries          []RegistryEntry     `json:"entries"`
	Tombstones       []RegistryTombstone `json:"tombstones"`
}

func (s *Accounts) Registry(ctx context.Context) (RegistryResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var observed map[string]RuntimeStatus
	for {
		a, err := s.load(ctx)
		if err != nil {
			return RegistryResult{}, err
		}
		if len(a.Restaurants) > 10000 {
			return RegistryResult{}, ErrAuthUnavailable
		}
		statuses, err := s.observeRuntimeStatuses(ctx, a.AggregateRevision, &observed)
		if errors.Is(err, ErrRevisionConflict) {
			continue
		}
		if err != nil {
			return RegistryResult{}, err
		}
		result := RegistryResult{RegistryRevision: a.AggregateRevision, Complete: true, Entries: []RegistryEntry{}, Tombstones: []RegistryTombstone{}}
		for _, r := range a.Restaurants {
			if r.Lifecycle == "deleted" {
				continue
			}
			entry := RegistryEntry{Restaurant: r, Services: []domain.PeerReadiness{}}
			for _, o := range a.Organizations {
				if o.OrgID == r.OrgID {
					entry.Settings = o.Settings
					break
				}
			}
			index := latestIntent(a, r)
			allReady := true
			for _, service := range runtimeServices {
				st, known := statuses[service]
				if !known {
					allReady = false
					continue
				}
				peer := domain.PeerReadiness{RestaurantID: r.RestaurantID, Service: service, Epoch: st.Epoch, State: "pending", LifecycleVersion: r.LifecycleVersion}
				if index >= 0 {
					for _, saved := range a.LifecycleIntents[index].Services {
						if saved.RestaurantID == r.RestaurantID && saved.Service == service && saved.Epoch == st.Epoch {
							peer = saved
							break
						}
					}
				}
				if peer.State == "ready" && !st.Ready {
					peer.State = "pending"
				}
				allReady = allReady && peer.State == "ready"
				entry.Services = append(entry.Services, peer)
			}
			if entry.Restaurant.Lifecycle == "ready" && !allReady {
				entry.Restaurant.Lifecycle = "registering"
			}
			result.Entries = append(result.Entries, entry)
		}
		for _, t := range a.Tombstones {
			if t.Kind == "restaurant" {
				result.Tombstones = append(result.Tombstones, RegistryTombstone{RestaurantID: t.EntityID, OrgID: t.OrgID, LifecycleVersion: t.LifecycleVersion})
			}
		}
		if len(result.Tombstones) > 10000 {
			return RegistryResult{}, ErrAuthUnavailable
		}
		return result, nil
	}
}
