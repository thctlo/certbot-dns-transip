# certbot-dns-transip

A certbot DNS Authenticator plugin that completes the `dns-01` challenge
via the [TransIP](https://www.transip.nl/) API, using the `transip-rest`
package.

## Platform

Built and packaged for Debian 13 (trixie); not tested on other
distributions or Debian releases.

## Named plugin

`dns-transip` (same name as the now-unmaintained
[hsmade/certbot_dns_transip](https://github.com/hsmade/certbot_dns_transip),
so existing `-a dns-transip` invocations keep working if you switch to
this package).

## Credentials file

An example with full comments is installed at
`/usr/share/doc/python3-certbot-dns-transip/examples/transip.ini.example`.
It is **not** copied into `/etc/letsencrypt/` automatically (it only
has placeholder values) - copy and edit it yourself:

```bash
cp /usr/share/doc/python3-certbot-dns-transip/examples/transip.ini.example \
    /etc/letsencrypt/transip.ini
# edit transip.ini with your real username/key_file
chmod 600 /etc/letsencrypt/transip.ini /etc/letsencrypt/transip.key
```

```ini
dns_transip_username = your-transip-login
dns_transip_key_file = /etc/letsencrypt/transip.key
# optional, default: false (token limited to whitelisted IPs)
dns_transip_global_key = false
```

**Deliberately not supported**: an inline private key in the
credentials file. The original plugin had this option, but its
implementation could never have worked (it wrote the key content to a
string, not a file). Supply a `key_file` path instead.

## Usage

```
certbot certonly -a dns-transip --dns-transip-credentials /etc/letsencrypt/transip.ini -d example.com
```

## Multiple TransIP accounts

If the domains you need certificates for are split across more than
one TransIP account, point `--dns-transip-credentials` at a
**directory** instead of a single file:

```
certbot certonly -a dns-transip \
    --dns-transip-credentials /etc/letsencrypt/transip/ \
    -d example.com -d '*.example.com' -d example.org -d '*.example.org'
```

This package creates that directory on install (empty, with an
example account file), at:

```
/etc/letsencrypt/transip/
├── README.md              (short pointer back to this file)
├── keys/                   (put your private key files here)
├── cache/                  (token caches, one per account - see below)
└── accounts.d/
    └── account1-example.ini-disabled
```

To add an account, copy `accounts.d/account1-example.ini-disabled` to
a new file **ending in `.ini`** (e.g. `accounts.d/account1.ini`) and
fill it in - same keys as the single-file credentials format above,
plus one more, optional one:

```ini
dns_transip_username = your-transip-login
dns_transip_key_file = /etc/letsencrypt/transip/keys/account1.key
#dns_transip_domains = example.com, example.org
```

`dns_transip_domains` is a comma-separated list of the base domains
(zones) this account manages at TransIP. **It only controls which
TransIP account the plugin uses internally to validate a given
domain - it has no effect on what ends up on your certificate.** Which
domains are requested is still entirely controlled by `-d` on the
certbot command line, every time, regardless of this setting.

- If set, the plugin matches against it directly - no TransIP API call
  needed to figure out which account to use for that domain.
- If left unset (the default), the plugin instead asks the TransIP API
  which account manages a domain, automatically, the first time it
  needs to for that run - slightly slower, but just as correct, and
  the normal choice when you only have one or two accounts.
- If more than one account's `dns_transip_domains` claims the same
  domain, certbot fails with a clear error naming the conflicting
  accounts, rather than silently picking one.

Files in `accounts.d/` not ending in `.ini` (like the shipped
`*-example.ini-disabled`) are ignored, which is also how you can
temporarily disable an account without deleting it - rename its `.ini`
to end in anything else.

Single-account setups do not need any of this - a plain file path for
`--dns-transip-credentials`, as in **Usage** above, keeps working
exactly as before.

## Token cache file

The plugin requests a TransIP API access token once per certbot run
and reuses it for every domain handled by the same account in that
run. It also keeps a small cache file per account (mode `600`,
containing the still-valid token - treat it like a secret), so a
`certbot renew` shortly after another run reuses that token instead of
requesting a new one under the same label while the old one is still
active. In single-file mode this lives at `<credentials file>.token-cache.json`,
next to the credentials file; in directory mode it lives at
`<directory>/cache/<account name>.token-cache.json`, one per account.
TransIP tokens expire on their own (the API has no way to list or
revoke one without already holding a valid token for it), so there is
nothing to clean up manually; deleting a cache file is always safe, it
just means the next run for that account requests a fresh token.

## Provenance

Original implementation - see `debian/copyright` and the `transip-rest`
package's README for how the underlying TransIP API usage was
researched and verified.
