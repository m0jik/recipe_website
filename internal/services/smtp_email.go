package services

import (
	"fmt"
	"net/smtp"
)

type SMTPEmail struct {
	Host     string
	Port     int
	From     string
	Password string
}

func NewSMTPEmail(host string, port int, from, password string) *SMTPEmail {
	return &SMTPEmail{
		Host:     host,
		Port:     port,
		From:     from,
		Password: password,
	}
}

func (e *SMTPEmail) Send(to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", e.Host, e.Port)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		e.From,
		to,
		subject,
		body,
	)

	auth := smtp.PlainAuth("", e.From, e.Password, e.Host)

	return smtp.SendMail(addr, auth, e.From, []string{to}, []byte(msg))
}
