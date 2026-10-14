package invitationurl

import (
	"net"
	"net/url"
	"strings"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type Policy struct{}

func (Policy) Origin(o application.InvitationMailOptions) (string, error) {
	u, err := url.Parse(o.FrontendOrigin)
	if err != nil || o.FrontendOrigin == "" || len(o.FrontendOrigin) > 2048 || strings.ContainsRune(o.FrontendOrigin, '#') || strings.TrimSpace(o.FrontendOrigin) != o.FrontendOrigin || u.Opaque != "" || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || u.Path != "" && u.Path != "/" {
		return "", application.ErrDeliveryUnavailable
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if !o.AllowLoopbackHTTP || u.Scheme != "http" || u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", application.ErrDeliveryUnavailable
		}
	}
	return u.Scheme + "://" + u.Host, nil
}

func (p Policy) Link(o application.InvitationMailOptions, id domain.EntityID) (string, error) {
	origin, err := p.Origin(o)
	if err != nil {
		return "", err
	}
	if !domain.ValidEntityID(id) {
		return "", application.ErrDeliveryUnavailable
	}
	return origin + "/invite/" + url.PathEscape(string(id)), nil
}

func (p Policy) Validate(link string, id domain.EntityID) error {
	u, err := url.Parse(link)
	if err != nil || strings.ContainsRune(link, '#') || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "/invite/"+string(id) {
		return application.ErrAuthUnavailable
	}
	_, err = p.Origin(application.InvitationMailOptions{FrontendOrigin: u.Scheme + "://" + u.Host, AllowLoopbackHTTP: true})
	return err
}
