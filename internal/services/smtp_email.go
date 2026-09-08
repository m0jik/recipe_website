package services

import (
	"fmt"
	"net/smtp"
	"regexp"
	"strings"
	"time"
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

func (e *SMTPEmail) Send(to, subject, htmlBody string) error {
	addr := fmt.Sprintf("%s:%d", e.Host, e.Port)
	boundary := fmt.Sprintf("recipe-website-%d", time.Now().UnixNano())
	plainBody := toPlainText(htmlBody)

	msg := strings.Builder{}
	msg.WriteString(fmt.Sprintf("From: %s\r\n", e.From))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=%q\r\n", boundary))
	msg.WriteString("Date: ")
	msg.WriteString(time.Now().Format(time.RFC1123Z))
	msg.WriteString("\r\n")
	msg.WriteString("\r\n")
	msg.WriteString("--")
	msg.WriteString(boundary)
	msg.WriteString("\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	msg.WriteString(plainBody)
	msg.WriteString("\r\n")
	msg.WriteString("--")
	msg.WriteString(boundary)
	msg.WriteString("\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	msg.WriteString(htmlBody)
	msg.WriteString("\r\n")
	msg.WriteString("--")
	msg.WriteString(boundary)
	msg.WriteString("--\r\n")

	auth := smtp.PlainAuth("", e.From, e.Password, e.Host)

	return smtp.SendMail(addr, auth, e.From, []string{to}, []byte(msg.String()))
}

func toPlainText(htmlBody string) string {
	stripped := regexp.MustCompile(`<[^>]+>`).ReplaceAllString(htmlBody, "\n")
	stripped = strings.ReplaceAll(stripped, "&nbsp;", " ")
	stripped = strings.ReplaceAll(stripped, "&amp;", "&")
	stripped = strings.ReplaceAll(stripped, "&lt;", "<")
	stripped = strings.ReplaceAll(stripped, "&gt;", ">")
	stripped = strings.TrimSpace(stripped)
	lines := strings.Split(stripped, "\n")
	cleaned := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	return strings.Join(cleaned, "\n")
}
