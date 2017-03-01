/*
 *   keepsake - Automatic PKI key/cert management with Vault
 *   Copyright (c) 2017 Shannon Wynter.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"time"

	log "github.com/Sirupsen/logrus"
	vaultAPI "github.com/hashicorp/vault/api"
)

const (
	EnvVaultToken = "VAULT_TOKEN"
)

var (
	version = "Undefined"
	commit  = "Undefined"
)

var environmentVariables = []string{
	EnvVaultToken,
	vaultAPI.EnvVaultAddress,
	vaultAPI.EnvVaultCACert,
	vaultAPI.EnvVaultCAPath,
	vaultAPI.EnvVaultClientCert,
	vaultAPI.EnvVaultClientKey,
	vaultAPI.EnvVaultInsecure,
	vaultAPI.EnvVaultTLSServerName,
	vaultAPI.EnvVaultWrapTTL,
	vaultAPI.EnvVaultMaxRetries,
}

func renewDuration(seconds int) time.Duration {
	return time.Duration(float64(time.Duration(seconds)*time.Second) * 0.9)
}

func main() {
	vaultPKIPath := flag.String("vault-path", "pki", "Path for pki")
	vaultRole := flag.String("vault-role", "server", "Role for pki")
	certCN := flag.String("cn", "", "Certificate common name")
	certAltNames := flag.String("alt-names", "", "Comma seperated list of alt-names")
	certIPSans := flag.String("ip-sans", "127.0.0.1", "Comma seperated list of alternate ips")
	certTTL := flag.Duration("certTTL", time.Duration(0), "TTL of the certificate issued")
	certFile := flag.String("certFile", "", "Output certificate file")
	keyFile := flag.String("keyFile", "", "Output key file")
	caFile := flag.String("caFile", "", "Output ca file")
	command := flag.String("cmd", "", "Command to execute")
	showVersion := flag.Bool("version", false, "Show version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n\n", os.Args[0])

		flag.PrintDefaults()

		fmt.Fprintln(os.Stderr, "\nRequired flags:")
		for _, f := range []string{"cn", "certFile", "keyFile", "caFile"} {
			fmt.Fprintf(os.Stderr, "\t-%s\n", f)
		}

		fmt.Fprintln(os.Stderr, "\nEnvironment variables:")
		for _, e := range environmentVariables {
			fmt.Fprintf(os.Stderr, "\t%s\n", e)
		}
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("keepsake - %s (%s)\n", version, commit)
		fmt.Println("https://github.com/freman/keepsake")
		return
	}

	if *certCN == "" || *certFile == "" || *keyFile == "" || *caFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	vaultPath := fmt.Sprintf("%s/issue/%s", *vaultPKIPath, *vaultRole)
	vaultArgs := map[string]interface{}{
		"common_name": *certCN,
		"ip_sans":     *certIPSans,
	}

	if *certAltNames != "" {
		vaultArgs["alt_names"] = *certAltNames
	}

	if *certTTL != 0 {
		vaultArgs["ttl"] = certTTL.String()
	}

	token := os.Getenv(EnvVaultToken)
	if token == "" {
		log.Fatal("No token found")
	}

	vault, err := vaultAPI.NewClient(nil)
	if err != nil {
		log.WithError(err).Fatal("Unable to launch vault client")
	}
	vault.SetToken(token)

	secret, err := vault.Logical().Unwrap(token)
	if err != nil {
		log.WithError(err).Fatal("Unwrapping secret failed")
	}

	if secret != nil {
		vault.SetToken(secret.Auth.ClientToken)
	} else {
		secret, err = vault.Auth().Token().LookupSelf()
		if err != nil {
			log.WithError(err).Fatal("Unable to look up token details")
		}
	}

	go func() {
		renewalInterval := renewDuration(secret.Auth.LeaseDuration)
		for {
			time.Sleep(renewalInterval)
			newSecret, err := vault.Auth().Token().RenewSelf(0)
			if err != nil {
				log.WithError(err).Fatal("Unable to renew token")
			}
			renewalInterval = renewDuration(newSecret.Auth.LeaseDuration)
		}
	}()

	var certRenewalInterval time.Duration

	renewal := func() {
		pkiSecret, err := vault.Logical().Write(vaultPath, vaultArgs)
		if err != nil {
			log.WithError(err).Fatal("Unable to get keys")
		}
		if err := ioutil.WriteFile(*certFile, []byte(pkiSecret.Data["certificate"].(string)), 0640); err != nil {
			log.WithError(err).WithField("file", *certFile).Fatal("Failed to write certificate")
		}
		if err := ioutil.WriteFile(*caFile, []byte(pkiSecret.Data["issuing_ca"].(string)), 0640); err != nil {
			log.WithError(err).WithField("file", *caFile).Fatal("Failed to write ca")
		}
		if err := ioutil.WriteFile(*keyFile, []byte(pkiSecret.Data["private_key"].(string)), 0640); err != nil {
			log.WithError(err).WithField("file", *keyFile).Fatal("Failed to write key")
		}

		certRenewalInterval = renewDuration(pkiSecret.LeaseDuration)

		if *command != "" {
			cmd := exec.Command("/bin/bash", "-c", *command)
			err := cmd.Run()
			if err != nil {
				log.WithError(err).WithField("cmd", cmd).Fatal("Unable to run cmd")
			}
		}
	}
	renewal()

	for {
		time.Sleep(certRenewalInterval)
		renewal()
	}
}
