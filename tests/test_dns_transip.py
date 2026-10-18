"""Unit tests for the certbot TransIP DNS Authenticator - fully mocked,
no live API calls (credential files are real temp files on disk, since
certbot's own CredentialsConfiguration does real file I/O)."""
from unittest import mock

import pytest

from certbot_dns_transip.dns_transip import Authenticator, _Account, _CHALLENGE_TTL
from transip_rest.exceptions import TransipApiError


def _make_authenticator():
    config = mock.MagicMock()
    # "dns-transip" must match the real certbot.plugins entry point name
    # (see pyproject.toml) - self.dest()/self.mapper() derive the
    # dns_transip_* ini key prefix from this, which _write_ini() below
    # writes literally, so a mismatch here would break every real
    # (non-mocked) credentials-parsing test silently.
    return Authenticator(config, "dns-transip")


def _write_ini(path, username="u", key_file="/dev/null", domains=None, global_key=None):
    lines = [f"dns_transip_username = {username}", f"dns_transip_key_file = {key_file}"]
    if domains is not None:
        lines.append(f"dns_transip_domains = {domains}")
    if global_key is not None:
        lines.append(f"dns_transip_global_key = {global_key}")
    path.write_text("\n".join(lines) + "\n")


def _account_with_mock_client(name, client, domains=None):
    """An _Account whose credentials are never touched, for tests that
    only care about _perform/_cleanup/_find_account behaviour and inject
    the TransipClient directly via a patched _get_client."""
    return _Account(name=name, credentials=mock.MagicMock(), domains=domains or [])


# ---------------------------------------------------------------------------
# _setup_credentials: single-file vs. directory mode
# ---------------------------------------------------------------------------

def test_setup_credentials_single_file_mode(tmp_path):
    ini = tmp_path / "transip.ini"
    _write_ini(ini)
    auth = _make_authenticator()
    auth.conf = mock.MagicMock(return_value=str(ini))

    auth._setup_credentials()

    assert len(auth._accounts) == 1
    assert auth._accounts[0].name == "transip"
    assert auth._cache_dir is None


def test_setup_credentials_missing_path_raises():
    auth = _make_authenticator()
    auth.conf = mock.MagicMock(return_value=None)

    with pytest.raises(Exception, match="required"):
        auth._setup_credentials()


def test_setup_credentials_directory_mode_loads_accounts(tmp_path):
    accounts_dir = tmp_path / "accounts.d"
    accounts_dir.mkdir()
    _write_ini(accounts_dir / "account1.ini", domains="example.com")
    _write_ini(accounts_dir / "account2.ini")

    auth = _make_authenticator()
    auth.conf = mock.MagicMock(return_value=str(tmp_path))

    auth._setup_credentials()

    names = sorted(a.name for a in auth._accounts)
    assert names == ["account1", "account2"]
    assert auth._cache_dir == tmp_path / "cache"
    account1 = next(a for a in auth._accounts if a.name == "account1")
    assert account1.domains == ["example.com"]
    account2 = next(a for a in auth._accounts if a.name == "account2")
    assert account2.domains == []


def test_setup_credentials_directory_mode_ignores_disabled_example(tmp_path):
    accounts_dir = tmp_path / "accounts.d"
    accounts_dir.mkdir()
    _write_ini(accounts_dir / "account1.ini")
    _write_ini(accounts_dir / "account-example.ini-disabled")

    auth = _make_authenticator()
    auth.conf = mock.MagicMock(return_value=str(tmp_path))

    auth._setup_credentials()

    assert [a.name for a in auth._accounts] == ["account1"]


def test_setup_credentials_missing_accounts_dir_raises(tmp_path):
    auth = _make_authenticator()
    auth.conf = mock.MagicMock(return_value=str(tmp_path))

    with pytest.raises(Exception, match="accounts.d"):
        auth._setup_credentials()


def test_setup_credentials_empty_accounts_dir_raises(tmp_path):
    (tmp_path / "accounts.d").mkdir()
    auth = _make_authenticator()
    auth.conf = mock.MagicMock(return_value=str(tmp_path))

    with pytest.raises(Exception, match="No account"):
        auth._setup_credentials()


def test_setup_credentials_resets_state_for_a_new_run(tmp_path):
    ini = tmp_path / "transip.ini"
    _write_ini(ini)
    auth = _make_authenticator()
    auth.conf = mock.MagicMock(return_value=str(ini))
    auth._clients_by_account = {"stale": mock.MagicMock()}
    auth._domain_account = {("x", "y"): ("stale", "stale")}

    auth._setup_credentials()

    assert auth._clients_by_account == {}
    assert auth._domain_account == {}


# ---------------------------------------------------------------------------
# Token cache path derivation
# ---------------------------------------------------------------------------

def test_token_cache_path_directory_mode(tmp_path):
    auth = _make_authenticator()
    auth._cache_dir = tmp_path / "cache"
    account = _Account(name="account1", credentials=mock.MagicMock())

    assert auth._token_cache_path(account) == tmp_path / "cache" / "account1.token-cache.json"


def test_token_cache_path_legacy_single_file_mode():
    auth = _make_authenticator()
    auth._cache_dir = None
    creds = mock.MagicMock()
    creds.confobj.filename = "/etc/letsencrypt/transip.ini"
    account = _Account(name="transip", credentials=creds)

    path = auth._token_cache_path(account)

    assert str(path) == "/etc/letsencrypt/transip.ini.token-cache.json"


# ---------------------------------------------------------------------------
# _read_key_file
# ---------------------------------------------------------------------------

def test_read_key_file_missing_key_file_setting_raises():
    creds = mock.MagicMock()
    creds.conf.return_value = None

    with pytest.raises(Exception, match="dns_transip_key_file"):
        Authenticator._read_key_file(creds)


def test_read_key_file_unreadable_path_raises(tmp_path):
    creds = mock.MagicMock()
    creds.conf.return_value = str(tmp_path / "does-not-exist.key")

    with pytest.raises(Exception, match="Could not read TransIP key file"):
        Authenticator._read_key_file(creds)


def test_read_key_file_reads_bytes(tmp_path):
    key_path = tmp_path / "account.key"
    key_path.write_bytes(b"fake-pem-content")
    creds = mock.MagicMock()
    creds.conf.return_value = str(key_path)

    assert Authenticator._read_key_file(creds) == b"fake-pem-content"


# ---------------------------------------------------------------------------
# Account selection: explicit dns_transip_domains vs. live-probe fallback
# ---------------------------------------------------------------------------

def test_find_account_explicit_domains_match_skips_api_call():
    auth = _make_authenticator()
    auth._accounts = [_account_with_mock_client("account1", None, domains=["example.com"])]

    account, base_domain = auth._find_account_and_base_domain("_acme-challenge.example.com")

    assert account.name == "account1"
    assert base_domain == "example.com"
    assert auth._clients_by_account == {}  # no TransipClient was ever built


def test_find_account_explicit_domains_match_for_apex_itself():
    auth = _make_authenticator()
    auth._accounts = [_account_with_mock_client("account1", None, domains=["example.com"])]

    account, base_domain = auth._find_account_and_base_domain("example.com")

    assert account.name == "account1"
    assert base_domain == "example.com"


def test_find_account_conflicting_explicit_domains_raises():
    auth = _make_authenticator()
    auth._accounts = [
        _account_with_mock_client("account1", None, domains=["example.com"]),
        _account_with_mock_client("account2", None, domains=["example.com"]),
    ]

    with pytest.raises(Exception, match="Multiple TransIP accounts"):
        auth._find_account_and_base_domain("_acme-challenge.example.com")


def test_find_account_falls_back_to_live_probe_when_no_explicit_domains():
    auth = _make_authenticator()
    mock_client = mock.MagicMock()
    mock_client.find_domain.return_value = "example.com"
    account = _account_with_mock_client("account1", mock_client)
    auth._accounts = [account]
    auth._get_client = mock.MagicMock(return_value=mock_client)

    found_account, base_domain = auth._find_account_and_base_domain("_acme-challenge.example.com")

    assert found_account is account
    assert base_domain == "example.com"


def test_find_account_probe_tries_next_account_on_failure():
    auth = _make_authenticator()
    failing_client = mock.MagicMock()
    failing_client.find_domain.side_effect = TransipApiError("not found")
    succeeding_client = mock.MagicMock()
    succeeding_client.find_domain.return_value = "example.com"

    account1 = _account_with_mock_client("account1", failing_client)
    account2 = _account_with_mock_client("account2", succeeding_client)
    auth._accounts = [account1, account2]
    auth._get_client = mock.MagicMock(
        side_effect=lambda acct: {"account1": failing_client, "account2": succeeding_client}[acct.name]
    )

    found_account, base_domain = auth._find_account_and_base_domain("_acme-challenge.example.com")

    assert found_account is account2
    assert base_domain == "example.com"


def test_find_account_explicit_accounts_are_not_tried_via_probe():
    """An account with a dns_transip_domains list that doesn't include
    this domain must not be probed as a fallback - its list is treated
    as exhaustive for that account."""
    auth = _make_authenticator()
    mock_client = mock.MagicMock()
    account_with_list = _account_with_mock_client("account1", mock_client, domains=["other.example"])
    auth._accounts = [account_with_list]
    auth._get_client = mock.MagicMock(return_value=mock_client)

    with pytest.raises(Exception, match="No configured TransIP account"):
        auth._find_account_and_base_domain("_acme-challenge.example.com")

    mock_client.find_domain.assert_not_called()


def test_find_account_no_match_raises_with_detail():
    auth = _make_authenticator()
    failing_client = mock.MagicMock()
    failing_client.find_domain.side_effect = TransipApiError("no domains for this account")
    account = _account_with_mock_client("account1", failing_client)
    auth._accounts = [account]
    auth._get_client = mock.MagicMock(return_value=failing_client)

    with pytest.raises(Exception, match="account1"):
        auth._find_account_and_base_domain("_acme-challenge.example.com")


# ---------------------------------------------------------------------------
# _perform / _cleanup
# ---------------------------------------------------------------------------

def test_perform_creates_txt_record_with_fixed_ttl():
    auth = _make_authenticator()
    mock_client = mock.MagicMock()
    account = _account_with_mock_client("account1", mock_client)
    auth._find_account_and_base_domain = mock.MagicMock(return_value=(account, "example.com"))
    auth._get_client = mock.MagicMock(return_value=mock_client)

    auth._perform("example.com", "_acme-challenge.example.com", "validation-token-value")

    mock_client.create_dns_entry.assert_called_once_with(
        "example.com", "_acme-challenge", "TXT", "validation-token-value", expire=_CHALLENGE_TTL
    )


def test_perform_then_cleanup_reuse_the_same_account():
    auth = _make_authenticator()
    mock_client = mock.MagicMock()
    account = _account_with_mock_client("account1", mock_client)
    auth._find_account_and_base_domain = mock.MagicMock(return_value=(account, "example.com"))
    auth._get_client = mock.MagicMock(return_value=mock_client)

    auth._perform("example.com", "_acme-challenge.example.com", "validation-token-value")
    # cleanup must not need to search for the account again
    auth._find_account_and_base_domain.reset_mock()
    auth._cleanup("example.com", "_acme-challenge.example.com", "validation-token-value")

    auth._find_account_and_base_domain.assert_not_called()
    mock_client.delete_dns_entry.assert_called_once_with(
        "example.com", "_acme-challenge", "TXT", "validation-token-value", expire=_CHALLENGE_TTL
    )
    assert auth._domain_account == {}  # popped after use


def test_cleanup_without_a_prior_perform_is_a_noop():
    auth = _make_authenticator()
    auth._get_client = mock.MagicMock()

    auth._cleanup("example.com", "_acme-challenge.example.com", "validation-token-value")

    auth._get_client.assert_not_called()


def test_cleanup_failure_is_logged_not_raised():
    auth = _make_authenticator()
    mock_client = mock.MagicMock()
    account = _account_with_mock_client("account1", mock_client)
    auth._find_account_and_base_domain = mock.MagicMock(return_value=(account, "example.com"))
    auth._get_client = mock.MagicMock(return_value=mock_client)
    mock_client.delete_dns_entry.side_effect = TransipApiError("boom")

    auth._perform("example.com", "_acme-challenge.example.com", "validation-token-value")
    # Must not raise: a cleanup failure is logged, not fatal.
    auth._cleanup("example.com", "_acme-challenge.example.com", "validation-token-value")


def test_relative_name_strips_base_domain():
    assert (
        Authenticator._relative_name("example.com", "_acme-challenge.example.com")
        == "_acme-challenge"
    )
    assert (
        Authenticator._relative_name("example.com", "_acme-challenge.www.example.com")
        == "_acme-challenge.www"
    )
