# Keepsake

Grab PKI keys and certificates from [HashiCorp's Vault](https://www.vaultproject.io.)

Automatically maintains keys and certificates on disk, runs command at the end of each cycle.

## Example

```
	VAULT_TOKEN=`vault token-create --policy="pki/ops/vault" --wrap-ttl 10s --format=json --ttl=60m | jq -r ".wrap_info.token"`
	keepsake \
		-vault-path=pki/ops \
		-vault-role=vault \
		-cn="vault.service.dc1.consul" \
		-ip-sans="127.0.0.1,10.38.2.1" \
		-certFile /etc/vault/vault.crt \
		-keyFile /etc/vault/vault.key \
		-caFile /etc/vault/ca.crt \
		-certTTL=720h \
		-cmd="kill -HUP `cat /proc/vault/vault.pid`"
```