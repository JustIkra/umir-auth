package application

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/JustIkra/umir-auth/internal/domain"
)

var (
	ErrUnknownTimeZone         = errors.New("unknown time zone")
	ErrTimeZoneDataUnavailable = errors.New("time zone data unavailable")
	ErrSettingsChanged         = errors.New("organization settings changed")
)

type ZoneData struct {
	Version string
	SHA256  string
}
type TimeZoneCatalog interface {
	Validate(string) error
	Ready() (ZoneData, error)
}
type UpdateSettingsInput struct {
	CommandID               string         `json:"commandID"`
	ExpectedSettingsVersion domain.Version `json:"expectedSettingsVersion"`
	TimeZone                string         `json:"timeZone"`
}

func (s *Accounts) validateZone(zone string) error {
	if s.opts.TimeZones == nil {
		return ErrTimeZoneDataUnavailable
	}
	if _, err := s.opts.TimeZones.Ready(); err != nil {
		return errors.Join(ErrTimeZoneDataUnavailable, err)
	}
	return s.opts.TimeZones.Validate(zone)
}
func (s *Accounts) UpdateSettings(ctx context.Context, token, csrf string, orgID domain.EntityID, in UpdateSettingsInput) (domain.Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, err := json.Marshal(in)
	if err != nil {
		return domain.Settings{}, ErrAuthUnavailable
	}
	for {
		if err := ctx.Err(); err != nil {
			return domain.Settings{}, err
		}
		a, err := s.load(ctx)
		if err != nil {
			return domain.Settings{}, err
		}
		u, err := s.membershipActor(a, token, csrf)
		if err != nil {
			return domain.Settings{}, err
		}
		if !domain.IsOrgAdmin(a, u.UserID, orgID) {
			return domain.Settings{}, ErrForbidden
		}
		if _, ok := domain.VersionNumber(in.ExpectedSettingsVersion); !ok {
			return domain.Settings{}, &FieldError{Field: "expectedSettingsVersion", Code: "InvalidFormat"}
		}
		fp, record, err := s.membershipCommand(a, u.UserID, "updateSettings", orgID, "", "", in.CommandID, payload)
		if err != nil {
			return domain.Settings{}, err
		}
		if record != nil {
			var result domain.Settings
			err = openMembershipResult(s, *record, "Settings", &result)
			return result, err
		}
		if err := s.validateZone(in.TimeZone); err != nil {
			return domain.Settings{}, err
		}
		for i, o := range a.Organizations {
			if o.OrgID != orgID {
				continue
			}
			if o.Settings.SettingsVersion != in.ExpectedSettingsVersion {
				return domain.Settings{}, ErrSettingsChanged
			}
			v, err := nextVersion(o.Settings.SettingsVersion)
			if err != nil {
				return domain.Settings{}, err
			}
			result := domain.Settings{TimeZone: in.TimeZone, SettingsVersion: v}
			a.Organizations[i].Settings = result
			if err := saveMembershipResult(s, &a, u.UserID, "updateSettings", orgID, in.CommandID, fp, "Settings", result); err != nil {
				return domain.Settings{}, err
			}
			if err := s.commit(ctx, a); err != nil {
				if errors.Is(err, ErrRevisionConflict) {
					break
				}
				return domain.Settings{}, err
			}
			return result, nil
		}
	}
}
