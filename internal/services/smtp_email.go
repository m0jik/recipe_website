package services

import (
	"fmt"
	"net/smtp"
)

type SMTPEmail struct {
	Host     string
	Port     string
	From     string
	Password string
}

func NewSMTPEmail(host, port, from, password string) *SMTPEmail {
	return &SMTPEmail{
		Host:     host,
		Port:     port,
		From:     from,
		Password: password,
	}
}

func (e *SMTPEmail) Send(to, subject, body string) error {
	addr := fmt.Sprintf("%s:%s", e.Host, e.Port)

	msg := "From: " + e.From + "\r\n" + "To: " + to + "\r\n" + "Subject: " + subject + "\r\n" + "MIME-version: 1.0;\r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n" + body

	auth := smtp.PlainAuth("", e.From, e.Password, e.Host)

	return smtp.SendMail(addr, auth, e.From, []string{to}, []byte(msg))
}
