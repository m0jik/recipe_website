package services

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sestypes "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

type SESEmail struct {
	client               *sesv2.Client
	from                 string
	configurationSetName string
}

func NewSESEmail(ctx context.Context, region, from, configurationSetName string) (*SESEmail, error) {
	if region == "" {
		return nil, errors.New("aws region is required for ses email")
	}
	if from == "" {
		return nil, errors.New("from email is required for ses email")
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}

	return &SESEmail{
		client:               sesv2.NewFromConfig(cfg),
		from:                 from,
		configurationSetName: configurationSetName,
	}, nil
}

func (e *SESEmail) Send(to, subject, body string) error {
	input := &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(e.from),
		Destination: &sestypes.Destination{
			ToAddresses: []string{to},
		},
		Content: &sestypes.EmailContent{
			Simple: &sestypes.Message{
				Subject: &sestypes.Content{
					Data: aws.String(subject),
				},
				Body: &sestypes.Body{
					Text: &sestypes.Content{
						Data: aws.String(body),
					},
				},
			},
		},
	}

	if e.configurationSetName != "" {
		input.ConfigurationSetName = aws.String(e.configurationSetName)
	}

	_, err := e.client.SendEmail(context.Background(), input)
	return err
}
