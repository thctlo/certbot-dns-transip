"""Certbot DNS Authenticator plugin for TransIP.

Fulfils the dns-01 challenge by creating and removing a TXT record via
the TransIP API, through transip_rest.client.TransipClient.

Supports two credential layouts, auto-detected from the path given to
--dns-transip-credentials:

- A single INI file: one TransIP account, used for every domain. This
  is the original, simplest layout.
- A directory: expects an accounts.d/ subdirectory containing one INI
  file per TransIP account (same key format as the single-file case).
  Each domain being validated is matched to the right account, either
  via that account's optional dns_transip_domains hint or, if that's
  not set, by asking the TransIP API which account manages the zone.
  Token caches are written to a cache/ subdirectory in this mode.

See /etc/letsencrypt/transip/README.md (installed by this package)
for the directory layout in detail.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

from transip_rest.client import TransipClient
from transip_rest.exceptions import TransipApiError

logger = logging.getLogger(__name__)

# Short-lived on purpose: this record only needs to survive long enough
# for the ACME server to query it during validation, then _cleanup
# removes it immediately. A long TTL would only mean it lingers in
# resolver caches for longer after being deleted, with no benefit.
# Fixed as a constant (not the general-purpose client's own default)
# so _perform and _cleanup always agree on the exact value - TransIP's
# API matches a DELETE against the entry's name, type, content AND
# expire, so a mismatch here would make cleanup silently fail to match.
_CHALLENGE_TTL = 60

_REQUIRED_CREDENTIAL_VARS = {
    "username": "TransIP account login",
    "key_file": "Path to the RSA private key (PEM) for this account",
}


@dataclass
class _Account:
    """One TransIP account: its credentials and the zones it's configured for.

    `domains` comes from the optional dns_transip_domains credentials
    key. It is only ever used to pick which account owns a domain being
    validated - it has no effect on what ends up on the certificate
    (that's controlled entirely by certbot's own -d flags).
    """

    name: str
    credentials: CredentialsConfiguration
    domains: list[str] = field(default_factory=list)


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for TransIP."""

    description = "Obtain certificates using a DNS TXT record (if you are using TransIP for DNS)."

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._accounts: list[_Account] = []
        self._cache_dir: Optional[Path] = None
        self._clients_by_account: dict[str, TransipClient] = {}
        # Which account (and base domain) actually handled a given
        # challenge, recorded in _perform and consulted by _cleanup so
        # cleanup never has to re-run the account search (and can never
        # land on a different answer than _perform did).
        self._domain_account: dict[tuple[str, str], tuple[_Account, str]] = {}

    @classmethod
    def add_parser_arguments(cls, add, **kwargs):
        super().add_parser_arguments(add, default_propagation_seconds=240)
        add(
            "credentials",
            help=(
                "Path to a TransIP credentials INI file (one account), or a "
                "directory containing accounts.d/*.ini (one or more TransIP "
                "accounts) - see /etc/letsencrypt/transip/README.md."
            ),
        )

    def more_info(self):
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 "
            "challenge using the TransIP API."
        )

    def _setup_credentials(self):
        raw_path = self.conf("credentials")
        if not raw_path:
            raise errors.PluginError(
                "--dns-transip-credentials is required: either a single "
                "credentials INI file, or a directory containing "
                "accounts.d/*.ini. See /etc/letsencrypt/transip/README.md."
            )
        path = Path(os.path.abspath(os.path.expanduser(raw_path)))

        if path.is_dir():
            self._accounts = self._load_account_directory(path)
            self._cache_dir = path / "cache"
            # Normally already created by the .deb's postinst, but the
            # plugin must not depend on that (e.g. a pip install has no
            # postinst) - caching is a pure optimization, so a failure
            # here just means FileTokenCache's own writes will silently
            # no-op (same best-effort contract as the rest of caching),
            # not a reason to abort credential setup.
            try:
                self._cache_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
        else:
            creds = CredentialsConfiguration(str(path), self.dest)
            creds.require(_REQUIRED_CREDENTIAL_VARS)
            self._accounts = [_Account(path.stem, creds)]
            self._cache_dir = None

        self._clients_by_account = {}
        self._domain_account = {}

    def _load_account_directory(self, path: Path) -> list[_Account]:
        accounts_dir = path / "accounts.d"
        if not accounts_dir.is_dir():
            raise errors.PluginError(
                f"{accounts_dir} does not exist - expected an accounts.d "
                "subdirectory with one .ini file per TransIP account."
            )
        ini_files = sorted(p for p in accounts_dir.glob("*.ini") if p.is_file())
        if not ini_files:
            raise errors.PluginError(
                f"No account .ini files found in {accounts_dir} (files "
                "ending in .ini-disabled, like the shipped example, are "
                "intentionally skipped)."
            )

        accounts = []
        for ini_path in ini_files:
            creds = CredentialsConfiguration(str(ini_path), self.dest)
            creds.require(_REQUIRED_CREDENTIAL_VARS)
            domains_raw = creds.conf("domains")
            domains = [d.strip() for d in domains_raw.split(",") if d.strip()] if domains_raw else []
            accounts.append(_Account(ini_path.stem, creds, domains))
        return accounts

    def _get_client(self, account: _Account) -> TransipClient:
        if account.name not in self._clients_by_account:
            creds = account.credentials
            global_key_raw = creds.conf("global_key")
            global_key = bool(global_key_raw) and global_key_raw.strip().lower() in (
                "true", "yes", "1",
            )
            self._clients_by_account[account.name] = TransipClient(
                username=creds.conf("username"),
                private_key_pem=self._read_key_file(creds),
                global_key=global_key,
                label="certbot-dns-transip",
                token_cache_path=self._token_cache_path(account),
            )
        return self._clients_by_account[account.name]

    def _token_cache_path(self, account: _Account) -> Optional[Path]:
        if self._cache_dir is not None:
            return self._cache_dir / f"{account.name}.token-cache.json"
        # Single-file (legacy) mode: cache lives next to the credentials
        # file, as before - no new config option needed.
        filename = getattr(account.credentials.confobj, "filename", None)
        if not filename:
            return None
        p = Path(filename)
        return p.with_name(p.name + ".token-cache.json")

    @staticmethod
    def _read_key_file(creds: CredentialsConfiguration) -> bytes:
        key_file = creds.conf("key_file")
        if not key_file:
            raise errors.PluginError(
                "dns_transip_key_file is required in the credentials file"
            )
        try:
            with open(key_file, "rb") as fh:
                return fh.read()
        except OSError as exc:
            raise errors.PluginError(
                f"Could not read TransIP key file {key_file}: {exc}"
            ) from exc

    @staticmethod
    def _domain_matches_zone(validation_name: str, zone: str) -> bool:
        return validation_name == zone or validation_name.endswith("." + zone)

    def _find_account_and_base_domain(self, validation_name: str) -> tuple[_Account, str]:
        """Pick which configured account manages validation_name's zone.

        Accounts with an explicit dns_transip_domains list are matched
        directly, with no API call - that list is treated as exhaustive
        for that account, so it's never also tried via the live-probe
        fallback below. Accounts without one are tried in order via a
        live find_domain() call, first success wins.
        """
        explicit_matches = [
            (account, zone)
            for account in self._accounts
            for zone in account.domains
            if self._domain_matches_zone(validation_name, zone)
        ]
        if len(explicit_matches) > 1:
            names = ", ".join(account.name for account, _ in explicit_matches)
            raise errors.PluginError(
                f"Multiple TransIP accounts ({names}) claim {validation_name!r} "
                "via dns_transip_domains - fix the overlapping configuration."
            )
        if explicit_matches:
            return explicit_matches[0]

        probe_errors = []
        for account in self._accounts:
            if account.domains:
                continue
            client = self._get_client(account)
            try:
                base_domain = client.find_domain(validation_name)
                return account, base_domain
            except TransipApiError as exc:
                probe_errors.append(f"{account.name}: {exc}")

        detail = "; ".join(probe_errors) if probe_errors else "no account configured without an explicit domain list"
        raise errors.PluginError(
            f"No configured TransIP account manages {validation_name!r} ({detail})"
        )

    def _perform(self, domain, validation_name, validation):
        account, base_domain = self._find_account_and_base_domain(validation_name)
        client = self._get_client(account)
        name = self._relative_name(base_domain, validation_name)
        try:
            client.create_dns_entry(base_domain, name, "TXT", validation, expire=_CHALLENGE_TTL)
        except TransipApiError as exc:
            raise errors.PluginError(
                f"Error creating TXT record via the TransIP API: {exc}"
            ) from exc
        self._domain_account[(validation_name, validation)] = (account, base_domain)

    def _cleanup(self, domain, validation_name, validation):
        entry = self._domain_account.pop((validation_name, validation), None)
        if entry is None:
            # _perform never got far enough to create a record for this
            # challenge - nothing to clean up, and re-running the account
            # search here could pick a different account than _perform
            # would have, which would be worse than doing nothing.
            return
        account, base_domain = entry
        client = self._get_client(account)
        name = self._relative_name(base_domain, validation_name)
        try:
            client.delete_dns_entry(base_domain, name, "TXT", validation, expire=_CHALLENGE_TTL)
        except TransipApiError as exc:
            # Cleanup failures are logged, not raised: by this point the
            # certificate has already been issued or the attempt has
            # already failed for another reason: a stray leftover TXT
            # record is undesirable but not worth failing the run over.
            logger.warning("Error removing TXT record via the TransIP API: %s", exc)

    @staticmethod
    def _relative_name(base_domain: str, full_name: str) -> str:
        # TransIP's API wants the record name relative to the domain,
        # e.g. "_acme-challenge" for "_acme-challenge.example.com" under
        # "example.com".
        suffix = "." + base_domain
        if full_name.endswith(suffix):
            return full_name[: -len(suffix)]
        return full_name
