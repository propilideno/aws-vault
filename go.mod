module github.com/byteness/aws-vault/v7

go 1.24

require (
	github.com/alecthomas/kingpin/v2 v2.3.2
	github.com/aws/aws-sdk-go-v2 v1.17.7
	github.com/aws/aws-sdk-go-v2/config v1.18.19
	github.com/aws/aws-sdk-go-v2/credentials v1.13.18
	github.com/aws/aws-sdk-go-v2/service/iam v1.19.8
	github.com/aws/aws-sdk-go-v2/service/sso v1.12.6
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.14.6
	github.com/aws/aws-sdk-go-v2/service/sts v1.18.7
	github.com/google/go-cmp v0.5.9
	github.com/mattn/go-isatty v0.0.18
	github.com/mattn/go-tty v0.0.4
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966
	golang.org/x/term v0.6.0
	gopkg.in/ini.v1 v1.67.0
)
