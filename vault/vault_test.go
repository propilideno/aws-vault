package vault_test

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

func TestUsageWebIdentityExample(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile role2]
role_arn = arn:aws:iam::33333333333:role/role2
web_identity_token_process = oidccli raw
`))
	defer os.Remove(f)
	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "role2"}
	config, err := configLoader.GetProfileConfig("role2")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
	p, err := vault.NewTempCredentialsProvider(config, ckr, true, true)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := p.(*vault.AssumeRoleWithWebIdentityProvider)
	if !ok {
		t.Fatalf("Expected AssumeRoleWithWebIdentityProvider, got %T", p)
	}
}

func TestIssue1176(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile my-shared-base-profile]
credential_process=aws-vault exec my-shared-base-profile -j
mfa_serial=arn:aws:iam::1234567890:mfa/danielholz
region=eu-west-1

[profile profile-with-role]
source_profile=my-shared-base-profile
include_profile=my-shared-base-profile
region=eu-west-1
role_arn=arn:aws:iam::12345678901:role/allow-view-only-access-from-other-accounts
`))
	defer os.Remove(f)
	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "my-shared-base-profile"}
	config, err := configLoader.GetProfileConfig("my-shared-base-profile")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
	p, err := vault.NewTempCredentialsProvider(config, ckr, true, true)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := p.(*vault.CredentialProcessProvider)
	if !ok {
		t.Fatalf("Expected CredentialProcessProvider, got %T", p)
	}
}

func TestIssue1195(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile test]
source_profile=dev
region=ap-northeast-2

[profile dev]
sso_session=common
sso_account_id=2160xxxx
sso_role_name=AdministratorAccess
region=ap-northeast-2
output=json

[default]
sso_session=common
sso_account_id=3701xxxx
sso_role_name=AdministratorAccess
region=ap-northeast-2
output=json

[sso-session common]
sso_start_url=https://xxxx.awsapps.com/start
sso_region=ap-northeast-2
sso_registration_scopes=sso:account:access
`))
	defer os.Remove(f)
	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "test"}
	config, err := configLoader.GetProfileConfig("test")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
	p, err := vault.NewTempCredentialsProvider(config, ckr, true, true)
	if err != nil {
		t.Fatal(err)
	}

	ssoProvider, ok := p.(*vault.SSORoleCredentialsProvider)
	if !ok {
		t.Fatalf("Expected SSORoleCredentialsProvider, got %T", p)
	}
	if ssoProvider.AccountID != "2160xxxx" {
		t.Fatalf("Expected AccountID to be 2160xxxx, got %s", ssoProvider.AccountID)
	}
}

// Ensures direct role login does not force GetSessionToken when the profile is not acting as a role source.
func TestRoleProfileNotUsedAsRoleSourceSkipsGetSessionToken(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile role1]
role_arn=arn:aws:iam::111111111111:role/role1
mfa_serial=arn:aws:iam::111111111111:mfa/user
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "role1"}
	config, err := configLoader.GetProfileConfig("role1")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	config.MfaToken = "123456"

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
	err = ckr.Set("role1", aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	prevPrefix := log.Prefix()
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
	}()

	_, err = vault.NewTempCredentialsProvider(config, ckr, false, true)
	if err != nil {
		t.Fatal(err)
	}

	logs := buf.String()

	if strings.Contains(logs, "profile role1: using GetSessionToken") {
		t.Fatalf("did not expect GetSessionToken for non-chained role profile, logs:\n%s", logs)
	}
	if !strings.Contains(logs, "profile role1: using AssumeRole") {
		t.Fatalf("expected AssumeRole with MFA, logs:\n%s", logs)
	}
}

// Ensures role->role chaining keeps MFA context by priming with GetSessionToken before chained AssumeRole calls.
func TestRoleChainingMfaPrimesSessionThenAssumes(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile source]
role_arn=arn:aws:iam::111111111111:role/source
mfa_serial=arn:aws:iam::111111111111:mfa/user

[profile target]
source_profile=source
role_arn=arn:aws:iam::222222222222:role/target
mfa_serial=arn:aws:iam::111111111111:mfa/user
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "target"}
	config, err := configLoader.GetProfileConfig("target")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	config.MfaToken = "123456"
	config.SourceProfile.MfaToken = "123456"

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
	err = ckr.Set("source", aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	prevPrefix := log.Prefix()
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
	}()

	_, err = vault.NewTempCredentialsProvider(config, ckr, false, true)
	if err != nil {
		t.Fatal(err)
	}

	logs := buf.String()
	idxSession := strings.Index(logs, "profile source: using GetSessionToken")
	idxSourceAssume := strings.Index(logs, "profile source: using AssumeRole")
	idxTargetAssume := strings.Index(logs, "profile target: using AssumeRole")

	if idxSession == -1 || idxSourceAssume == -1 || idxTargetAssume == -1 {
		t.Fatalf("expected source GetSessionToken then source/target AssumeRole, logs:\n%s", logs)
	}
	if !(idxSession < idxSourceAssume && idxSourceAssume < idxTargetAssume) {
		t.Fatalf("unexpected flow order, logs:\n%s", logs)
	}
}

// Ensures a role source chained to a non-role target is not treated as role chaining for GetSessionToken.
func TestSourceChainingNonRoleTargetDoesNotTreatAsRoleChaining(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile role_source]
role_arn=arn:aws:iam::111111111111:role/role-source
mfa_serial=arn:aws:iam::111111111111:mfa/user

[profile leaf]
source_profile=role_source
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "leaf"}
	config, err := configLoader.GetProfileConfig("leaf")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	config.MfaPromptMethod = "terminal"
	config.SourceProfile.MfaToken = "123456"

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
	err = ckr.Set("role_source", aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	prevPrefix := log.Prefix()
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
	}()

	_, err = vault.NewTempCredentialsProvider(config, ckr, false, true)
	if err != nil {
		t.Fatal(err)
	}

	logs := buf.String()

	if strings.Contains(logs, "profile role_source: using GetSessionToken") {
		t.Fatalf("did not expect GetSessionToken for role source chained to non-role target, logs:\n%s", logs)
	}
	if !strings.Contains(logs, "profile role_source: using AssumeRole") {
		t.Fatalf("expected role_source to AssumeRole with MFA, logs:\n%s", logs)
	}
}

// Ensures non-role source profile uses GetSessionToken before target role AssumeRole when MFA chaining is needed.
func TestNonRoleSourceProfileUsesGetSessionTokenWhenAllowed(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile user]
mfa_serial=arn:aws:iam::111111111111:mfa/user

[profile target]
source_profile=user
role_arn=arn:aws:iam::222222222222:role/target
mfa_serial=arn:aws:iam::111111111111:mfa/user
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "target"}
	config, err := configLoader.GetProfileConfig("target")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	config.MfaToken = "123456"
	config.SourceProfile.MfaToken = "123456"

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
	err = ckr.Set("user", aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	prevPrefix := log.Prefix()
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
	}()

	_, err = vault.NewTempCredentialsProvider(config, ckr, false, true)
	if err != nil {
		t.Fatal(err)
	}

	logs := buf.String()
	idxSession := strings.Index(logs, "profile user: using GetSessionToken")
	idxAssume := strings.Index(logs, "profile target: using AssumeRole")

	if idxSession == -1 || idxAssume == -1 {
		t.Fatalf("expected user GetSessionToken and target AssumeRole, logs:\n%s", logs)
	}
	if idxSession > idxAssume {
		t.Fatalf("unexpected flow order, logs:\n%s", logs)
	}
}

// Ensures disabled sessions on non-role profile skip GetSessionToken and return the source credentials provider.
func TestGetSessionTokenSkippedForDisabledSessionsNonRoleReturnsSourceCreds(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile base]
mfa_serial=arn:aws:iam::111111111111:mfa/user
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "base"}
	config, err := configLoader.GetProfileConfig("base")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	config.MfaToken = "123456"

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
	err = ckr.Set("base", aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}

	creator := vault.TempCredentialsCreator{
		Keyring:                   ckr,
		DisableCache:              true,
		DisableSessionsForProfile: "base",
	}

	var provider any
	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	prevPrefix := log.Prefix()
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
	}()

	p, err := creator.GetProviderForProfile(config)
	if err != nil {
		t.Fatal(err)
	}
	provider = p

	logs := buf.String()

	if !strings.Contains(logs, "profile base: skipping GetSessionToken because sessions are disabled for this profile") {
		t.Fatalf("expected disabled session skip log, logs:\n%s", logs)
	}
	if _, ok := provider.(*vault.KeyringProvider); !ok {
		t.Fatalf("expected KeyringProvider when sessions disabled for non-role profile, got %T", provider)
	}
}
