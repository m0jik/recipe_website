# Jacob's Grub

A no-frills recipe website for the people.

## How to Launch

Use ```go run main.go```, open a web browser, and load ```localhost:8080```. This should take you to the login page. The test username is ```admin``` and the test password is ```admin```.

## Email Configuration

The app now supports both SMTP and AWS SES for account verification and password reset emails.

Set ```email.provider``` in ```config.json``` to:

- ```smtp``` to use the existing SMTP flow
- ```ses``` to use AWS SES with the AWS SDK for Go v2

For AWS deployment, prefer environment variables instead of storing secrets in ```config.json```:

- ```EMAIL_PROVIDER=ses```
- ```EMAIL_FROM=<your verified SES sender>```
- ```AWS_REGION=<your SES region>```
- ```AWS_SES_CONFIGURATION_SET=<optional configuration set name>```

When deployed on AWS, the SES sender uses the default AWS credential chain, so it can work with an EC2/ECS/Elastic Beanstalk role instead of an app password.
