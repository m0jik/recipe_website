# Jacob's Grub

A no-frills recipe website for the people.

## How to Launch Locally

Use `go run main.go`, open a web browser, and load `localhost:8080`. This
should take you to the login page. The test username is `admin` and the test
password is `admin`.

## Email Configuration

The app uses SMTP for account verification and password reset emails.

Configure the SMTP provider in `config.json`, or override it with
`EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_FROM`, and `EMAIL_PASSWORD` environment
variables.
