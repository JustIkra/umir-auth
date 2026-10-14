package mailadapter

import (
	"bytes"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func (t *RegistrationTemplate) RenderInvitationLink(mail application.InvitationLinkMail) (RegistrationMessage, error) {
	u, err := url.Parse(mail.URL)
	if t == nil || t.link == nil || err != nil || !validRegistrationTarget(mail.Email) || !domain.ValidEntityID(mail.InvitationID) || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "/invite/"+string(mail.InvitationID) || (u.Scheme != "https" && (u.Scheme != "http" || !validInvitationLoopback(u.Hostname()))) || mail.CreatedAt.IsZero() || !mail.ExpiresAt.After(mail.CreatedAt) {
		return RegistrationMessage{}, errors.New("invalid invitation link mail")
	}
	data := struct {
		Subject, Preheader, URL, ExpiresAt, OperatorName, OperatorAddress, PrivacyURL, LogoContentID string
	}{"Приглашение в «Ровный ход»", "Откройте приглашение и подтвердите вашу электронную почту.", mail.URL, formatRegistrationDeadline(mail.ExpiresAt), t.config.OperatorName, t.config.OperatorAddress, t.config.PrivacyURL, registrationLogoContentID}
	var body bytes.Buffer
	if err := t.link.Execute(&body, data); err != nil {
		return RegistrationMessage{}, err
	}
	text := strings.Join([]string{data.Subject, "Откройте приглашение:", mail.URL, "Подтвердите вашу электронную почту на странице приглашения.", "Срок действия приглашения: " + data.ExpiresAt + " МСК.", "Открытие ссылки не предоставляет доступ без подтверждения почты.", "Если письмо пришло по ошибке, проигнорируйте его.", t.config.OperatorName + " · " + t.config.OperatorAddress}, "\n\n")
	return RegistrationMessage{Subject: data.Subject, Preheader: data.Preheader, Text: text, HTML: body.String(), LogoContentID: registrationLogoContentID, LogoContentType: "image/png", LogoPNG: bytes.Clone(t.logo)}, nil
}

func validInvitationLoopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

func (s *RegistrationSMTP) linkMessage(delivery application.MailDelivery) ([]byte, error) {
	if delivery.Link == nil || delivery.Mail != (application.CodeMail{}) || !domain.ValidEntityID(delivery.JobID) {
		return nil, errors.New("invalid invitation delivery identity")
	}
	rendered, err := s.template.RenderInvitationLink(*delivery.Link)
	if err != nil {
		return nil, err
	}
	return s.renderedMessage(delivery.Link.Email, "<invitation."+string(delivery.JobID)+"@"+s.smtp.domain+">", rendered)
}
