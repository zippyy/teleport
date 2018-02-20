/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package services implements API services exposed by Teleport:
// * presence service that takes care of heartbeats
// * web service that takes care of web logins
// * ca service - certificate authorities
package services

import (
	"encoding/json"

	"github.com/gravitational/trace"

	"golang.org/x/crypto/ssh"
)

type SSHLoginEntry interface {
	// GetUsername returns a logged in user informationn
	GetUser() string
	// GetCert returns a PEM encoded signed certificate
	GetCert() []byte
	// GetTLSCert returns a PEM encoded TLS certificate signed by TLS certificate authority
	GetTLSCert() []byte
	// GetHostSigners returns a list of signing host public keys trusted by proxy
	GetHostSigners() []TrustedCerts
}

// TeleportSSHLoginEntry is a response returned by web proxy, it preserves backwards compatibility
// on the wire, which is the primary reason for non-matching json tags
type TeleportSSHLoginEntry struct {
	// User contains a logged in user informationn
	Username string `json:"username"`
	// Cert is a PEM encoded  signed certificate
	Cert []byte `json:"cert"`
	// TLSCertPEM is a PEM encoded TLS certificate signed by TLS certificate authority
	TLSCert []byte `json:"tls_cert"`
	// HostSigners is a list of signing host public keys trusted by proxy
	HostSigners []TrustedCerts `json:"host_signers"`
}

// GetUsername returns a logged in user informationn
func (t TeleportSSHLoginEntry) GetUser() string {
	return t.Username
}

// GetCert returns a PEM encoded signed certificate
func (t TeleportSSHLoginEntry) GetCert() []byte {
	return t.Cert
}

// GetTLSCert returns a PEM encoded TLS certificate signed by TLS certificate authority
func (t TeleportSSHLoginEntry) GetTLSCert() []byte {
	return t.TLSCert
}

// GetHostSigners returns a list of signing host public keys trusted by proxy
func (t TeleportSSHLoginEntry) GetHostSigners() []TrustedCerts {
	return t.HostSigners
}

// SSHLoginEntryMarshaler implements marshal/unmarshal of SSHLoginEntry implementations
// mostly adds support for extended versions.
type SSHLoginEntryMarshaler interface {
	Marshal(c SSHLoginEntry, opts ...MarshalOption) ([]byte, error)
	Unmarshal(bytes []byte) (SSHLoginEntry, error)
}

var sshLoginEntryMarshaler SSHLoginEntryMarshaler = &TeleportSSHLoginEntryMarshaler{}

func SetSSHLoginEntryMarshaler(m SSHLoginEntryMarshaler) {
	marshalerMutex.Lock()
	defer marshalerMutex.Unlock()
	sshLoginEntryMarshaler = m
}

func GetSSHLoginEntryMarshaler() SSHLoginEntryMarshaler {
	marshalerMutex.Lock()
	defer marshalerMutex.Unlock()
	return sshLoginEntryMarshaler
}

type TeleportSSHLoginEntryMarshaler struct{}

// Unmarshal unmarshals role from JSON or YAML.
func (t *TeleportSSHLoginEntryMarshaler) Unmarshal(bytes []byte) (SSHLoginEntry, error) {
	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing resource data")
	}

	var teleSSHLoginEntry TeleportSSHLoginEntry
	if err := json.Unmarshal(bytes, &teleSSHLoginEntry); err != nil {
		return nil, trace.Wrap(err)
	}

	return teleSSHLoginEntry, nil
}

// Marshal marshals role to JSON or YAML.
func (t *TeleportSSHLoginEntryMarshaler) Marshal(c SSHLoginEntry, opts ...MarshalOption) ([]byte, error) {
	return json.Marshal(c)
}

type SSHLoginEntryRequest struct {
	// User contains a logged in user informationn
	Username string `json:"username"`
	// Cert is a PEM encoded  signed certificate
	Cert []byte `json:"cert"`
	// TLSCertPEM is a PEM encoded TLS certificate signed by TLS certificate authority
	TLSCert []byte `json:"tls_cert"`
	// HostSigners is a list of signing host public keys trusted by proxy
	HostSigners []TrustedCerts `json:"host_signers"`
}

// TrustedCerts contains host certificates, it preserves backwards compatibility
// on the wire, which is the primary reason for non-matching json tags
type TrustedCerts struct {
	// ClusterName identifies teleport cluster name this authority serves,
	// for host authorities that means base hostname of all servers,
	// for user authorities that means organization name
	ClusterName string `json:"domain_name"`
	// HostCertificates is a list of SSH public keys that can be used to check
	// host certificate signatures
	HostCertificates [][]byte `json:"checking_keys"`
	// TLSCertificates  is a list of TLS certificates of the certificate authoritiy
	// of the authentication server
	TLSCertificates [][]byte `json:"tls_certs"`
}

// SSHCertPublicKeys returns a list of trusted host SSH certificate authority public keys
func (c *TrustedCerts) SSHCertPublicKeys() ([]ssh.PublicKey, error) {
	out := make([]ssh.PublicKey, 0, len(c.HostCertificates))
	for _, keyBytes := range c.HostCertificates {
		publicKey, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		out = append(out, publicKey)
	}
	return out, nil
}
