package application

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/JustIkra/umir-auth/internal/domain"
	"golang.org/x/text/unicode/norm"
)

func registrationDefaults(o *RegistrationOptions) error {
	values := []struct {
		value             *int
		fallback, maximum int
	}{
		{&o.MailLimitPer10Minutes, 30, 60},
		{&o.OrganizationsPerUser, 3, 100},
		{&o.OrganizationCreationsPerHour, 2, 100},
		{&o.WrongCodesPerAddressPerHour, 10, 100},
	}
	for _, v := range values {
		if *v.value == 0 {
			*v.value = v.fallback
		}
		if *v.value < 1 || *v.value > v.maximum {
			return ErrAuthUnavailable
		}
	}
	return nil
}
func sameEmail(a, b string) bool {
	return a != "" && b != "" && strings.EqualFold(domain.ComparisonEmail(a), domain.ComparisonEmail(b))
}
func challengeTarget(a domain.Aggregate, c domain.Challenge) (string, error) {
	if c.RegistrationEmail != "" {
		return c.RegistrationEmail, nil
	}
	if c.SuppressedEmail != "" {
		return c.SuppressedEmail, nil
	}
	if c.InvitationID != "" {
		i, err := invitationIndex(a, c.InvitationID)
		if err != nil {
			return "", err
		}
		return a.Invitations[i].Email, nil
	}
	u, ok := findUser(a, c.UserID)
	if !ok {
		return "", ErrAuthUnavailable
	}
	return u.Email, nil
}
func (s *Accounts) wrongCodeLimit(a domain.Aggregate, email string, now time.Time) error {
	var failures []time.Time
	for _, c := range a.Challenges {
		if len(c.WrongAttemptTimes) == 0 {
			continue
		}
		target, err := challengeTarget(a, c)
		if err != nil {
			return err
		}
		if !sameEmail(target, email) {
			continue
		}
		for _, raw := range c.WrongAttemptTimes {
			at, err := time.Parse(time.RFC3339Nano, string(raw))
			if err != nil {
				return ErrAuthUnavailable
			}
			if now.Sub(at) < time.Hour {
				failures = append(failures, at)
			}
		}
	}
	if wait := rollingIssueDelay(failures, s.opts.Registration.WrongCodesPerAddressPerHour, time.Hour, now); wait > 0 {
		return &InvitationRateLimitError{RetryAfter: wait}
	}
	return nil
}
func (s *Accounts) organizationCreationLimit(a domain.Aggregate, user domain.EntityID) error {
	created := map[domain.EntityID]bool{}
	var attempts []time.Time
	now := s.opts.Clock.Now()
	for _, r := range a.Idempotency {
		if r.ActorID != user || r.OperationID != "createOrganization" {
			continue
		}
		plain, err := s.opts.Results.Open(r.EncryptedResponse)
		if err != nil {
			return ErrAuthUnavailable
		}
		var result LifecycleResult
		err = json.Unmarshal(plain, &result)
		clear(plain)
		if err != nil || r.ResponseSchema != "LifecycleResult" || result.OrgID == "" {
			return ErrAuthUnavailable
		}
		created[result.OrgID] = true
		if r.RecordedAt != "" {
			at, err := time.Parse(time.RFC3339Nano, string(r.RecordedAt))
			if err != nil {
				return ErrAuthUnavailable
			}
			if now.Sub(at) < time.Hour {
				attempts = append(attempts, at)
			}
		}
	}
	count := 0
	for _, o := range a.Organizations {
		if created[o.OrgID] && o.Lifecycle != "deleted" {
			count++
		}
	}
	if count >= s.opts.Registration.OrganizationsPerUser {
		return &InvitationRateLimitError{RetryAfter: time.Hour}
	}
	if wait := rollingIssueDelay(attempts, s.opts.Registration.OrganizationCreationsPerHour, time.Hour, now); wait > 0 {
		return &InvitationRateLimitError{RetryAfter: wait}
	}
	return nil
}

func loginMatches(stored, input string) bool {
	return normalizedEmailLogin(stored) == normalizedEmailLogin(input)
}
func normalizedEmailLogin(input string) string {
	const whitespace = "\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
	value := norm.NFC.String(strings.Trim(input, whitespace))
	local, host, ok := strings.Cut(value, "@")
	if !ok || local == "" || len(host) < 3 || strings.Contains(host, "@") || strings.ContainsAny(value, whitespace) || !strings.Contains(host[1:len(host)-1], ".") {
		return input
	}
	return local + "@" + strings.ToLower(host)
}
