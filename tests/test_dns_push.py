"""DNS reconciliation tests: no configured domains, credentials or DNS writes."""

import ast
import base64
import copy
import os
import subprocess
import sys
import urllib.parse
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from moulinette import Moulinette, m18n

from yunohost import dns
from yunohost.utils.error import YunohostError, YunohostValidationError


@pytest.fixture(autouse=True)
def clone_test_app():
    # These tests do not need the session-wide test-app checkout.
    pass


def record(rtype="A", content="192.0.2.1", name="@", ttl=3600, **extra):
    return dict(name=name, type=rtype, content=content, ttl=ttl, **extra)


@pytest.fixture
def push(monkeypatch):
    import lexicon.client
    import yunohost.log

    m18n.set_locales_dir(str(Path(dns.__file__).resolve().parents[1] / "locales"))
    m18n.set_locale("en")
    monkeypatch.setattr(Moulinette, "_interface", SimpleNamespace(type="api"))
    monkeypatch.setattr(dns, "logger", Mock())
    monkeypatch.setattr(yunohost.log, "OperationLogger", Mock(_instances=[]))
    monkeypatch.setattr(dns, "_assert_domain_exists", lambda _: None)
    state = SimpleNamespace(
        domain="example.org",
        zone="example.org",
        wanted=[record()],
        remote=[],
        hashes=[],
        calls=[],
        configs=[],
        failure=None,
        constructor_error=None,
        authentication_error=None,
        entered=0,
        exited=[],
        next_id=0,
        credentials={"auth_token": "dummy-token"},
    )
    monkeypatch.setattr(dns, "_get_dns_zone_for_domain", lambda _: state.zone)
    monkeypatch.setattr(
        dns, "_get_registar_settings", lambda _: ("lebureau", state.credentials)
    )
    monkeypatch.setattr(
        dns, "_build_dns_conf", lambda _: {"basic": copy.deepcopy(state.wanted)}
    )
    monkeypatch.setattr(
        dns, "_get_managed_dns_records_hashes", lambda _: state.hashes[:]
    )
    monkeypatch.setattr(
        dns,
        "_set_managed_dns_records_hashes",
        lambda _, hashes: setattr(state, "hashes", hashes),
    )

    class Client:
        def __init__(self, config):
            state.configs.append(config)
            if state.constructor_error:
                raise state.constructor_error
            self.config = config

        def __enter__(self):
            if state.authentication_error:
                raise state.authentication_error
            state.entered += 1
            return self

        def __exit__(self, error_type, error, traceback):
            state.exited.append(error_type)

        def list_records(self, rtype):
            if state.failure == "list":
                raise RuntimeError("AXFR refused")
            return copy.deepcopy([r for r in state.remote if r["type"] == rtype])

        def create_record(self, rtype, name, content):
            return self.write("create", rtype, name, content)

        def update_record(self, identifier=None, rtype=None, name=None, content=None):
            return self.write("update", rtype, name, content, identifier)

        def delete_record(self, identifier=None, rtype=None, name=None, content=None):
            return self.write("delete", rtype, name, content, identifier)

        def write(self, action, rtype, name, content, identifier=None):
            state.calls.append((action, rtype, identifier))
            if state.failure == action:
                raise RuntimeError("UPDATE refused")
            if state.failure == "false":
                return False
            if action in ("update", "delete"):
                assert identifier is not None
                old = next(r for r in state.remote if r["id"] == identifier)
                state.remote.remove(old)
            if action != "delete":
                state.next_id += 1
                new = record(
                    rtype,
                    content,
                    name,
                    ttl=self.config.resolve("lexicon:ttl"),
                    id=str(state.next_id),
                )
                if rtype == "MX":
                    priority, exchange = new["content"].split()
                    new["content"] = exchange
                    new["options"] = {"mx": {"priority": int(priority)}}
                state.remote.append(new)
            return True

    monkeypatch.setattr(lexicon.client, "Client", Client)
    state.run = lambda **kwargs: dns.domain_dns_push(state.domain, **kwargs)
    return state


@pytest.mark.parametrize(
    "rtype,content",
    [
        ("A", "192.0.2.1"),
        ("AAAA", "2001:db8::1"),
        ("MX", "10 mail.example.org."),
        ("MX", "0 mail.example.org."),
        ("TXT", '"v=spf1 -all"'),
        ("CNAME", "target.example.org."),
        ("SRV", "0 5 443 target.example.org."),
        ("CAA", '0 issue "letsencrypt.org"'),
    ],
)
def test_create_then_noop(push, rtype, content):
    push.wanted = [record(rtype, content)]
    assert push.run() == {}
    assert push.calls == [("create", rtype, None)]
    assert len(push.hashes) == 1
    assert push.hashes[0].startswith("sha256:")
    preview = push.run(dry_run=True)
    assert len(preview["unchanged"]) == 1
    assert not any(preview[action] for action in ("create", "update", "delete"))
    assert push.run() == {}
    assert len(push.calls) == 1


def test_mx_priority_update_and_delete_use_listed_ids(push):
    push.wanted = [record("MX", "10 mail.example.org.")]
    push.run()
    identifier = push.remote[0]["id"]
    push.wanted[0]["content"] = "0 mail.example.org."
    assert push.run() == {}
    assert push.calls[-1] == ("update", "MX", identifier)
    assert push.remote[0]["options"]["mx"]["priority"] == 0
    assert not push.run(dry_run=True)["update"]
    identifier = push.remote[0]["id"]
    push.wanted = []
    assert push.run() == {}
    assert push.calls[-1] == ("delete", "MX", identifier)
    assert push.hashes == []


def test_explicit_ttls_survive_context_api_writes(push):
    push.wanted = [
        record("A", "192.0.2.1", ttl=120),
        record("TXT", '"custom TTL"', "custom", ttl=600),
    ]
    assert push.run() == {}
    assert {r["type"]: r["ttl"] for r in push.remote} == {"A": 120, "TXT": 600}
    push.wanted[0]["content"] = "192.0.2.2"
    assert push.run() == {}
    assert {r["type"]: r["ttl"] for r in push.remote} == {"A": 120, "TXT": 600}
    assert push.entered == len(push.exited)
    assert all(error is None for error in push.exited)


def test_long_dkim_and_literal_at_sign_converge(push):
    value = "v=DKIM1; p=" + base64.b64encode(b"public-fixture" * 50).decode()
    push.wanted = [record("TXT", f'"{value}"', "mail._domainkey")]
    push.run()
    push.remote[0]["content"] = " ".join(
        f'"{value[i : i + 255]}"' for i in range(0, len(value), 255)
    )
    assert not push.run(dry_run=True)["update"]
    push.wanted.append(record("TXT", '"contact=postmaster@example.org"'))
    push.run()
    assert not push.run(dry_run=True)["update"]


def test_unchanged_sibling_retains_ownership_when_rrset_changes(push):
    push.wanted = [record("TXT", '"one"'), record("TXT", '"two"')]
    push.run()
    push.wanted.pop()
    preview = push.run(dry_run=True)
    assert [r["content"] for r in preview["unchanged"]] == ['"one"']
    assert push.run() == {}
    assert len(push.hashes) == 1
    push.wanted = []
    assert push.run() == {}
    assert not push.remote
    assert not push.hashes


@pytest.mark.parametrize("failure", ["update", "false"])
def test_failed_update_retains_old_ownership(push, failure):
    push.run()
    previous = push.hashes[:]
    push.wanted[0]["content"] = "192.0.2.2"
    push.failure = failure
    assert push.run()["errors"]
    assert push.hashes == previous
    assert push.entered == len(push.exited)
    assert push.exited[-1] is (RuntimeError if failure == "update" else None)
    push.failure = None
    assert push.run() == {}
    assert push.remote[0]["content"] == "192.0.2.2"


def test_failed_delete_retains_ownership(push):
    push.run()
    previous = push.hashes[:]
    push.wanted = []
    push.failure = "delete"
    assert push.run()["errors"]
    assert push.hashes == previous
    push.failure = None
    assert push.run() == {}
    assert not push.hashes


def test_matching_external_record_is_not_adopted_by_ordinary_push(push):
    external = record(name=push.domain, id="external")
    push.remote.append(external)
    push.wanted.append(record("TXT", '"added by YunoHost"', "managed"))
    push.run()
    assert dns._hash_dns_record(external) not in push.hashes
    push.wanted = []
    push.run()
    assert push.remote == [external]


def test_force_explicitly_adopts_matching_records(push):
    push.remote.append(record(name=push.domain, id="external"))
    push.hashes = [123456789]  # A legacy integer from an unknown process seed.
    original_hashes = push.hashes[:]
    push.run(dry_run=True, force=True)
    assert push.hashes == original_hashes
    push.run(force=True)
    assert not push.calls
    assert len(push.hashes) == 1 and isinstance(push.hashes[0], str)
    push.wanted = []
    push.run()
    assert not push.remote


def test_matching_legacy_ownership_migrates_without_dns_write(push):
    existing = record(name=push.domain, id="old")
    push.remote.append(existing)
    push.hashes = [dns._legacy_hash_dns_record(existing)]
    push.run()
    assert push.hashes == [dns._hash_dns_record(existing)]
    assert not push.calls


def test_external_edit_is_not_overwritten(push):
    push.run()
    push.remote[0]["content"] = "192.0.2.9"
    push.run()
    assert push.remote[0]["content"] == "192.0.2.9"
    assert len(push.calls) == 1


def test_unmanaged_conflicts_are_previewed_but_skipped_until_forced(push):
    conflict = record("TXT", '"lebureau-force-old"', push.domain, id="conflict")
    sibling = record("TXT", '"lebureau-force-keep"', push.domain, id="sibling")
    orphan = record("TXT", '"orphan"', "orphan." + push.domain, id="orphan")
    push.remote = [conflict, sibling, orphan]
    push.wanted = [
        record("TXT", '"lebureau-force-new"'),
        record("TXT", '"lebureau-force-keep"'),
        record("A", "192.0.2.1", "fresh"),
    ]
    for force in (False, True):
        plan = push.run(dry_run=True, force=force)
        assert len(plan["update"]) == len(plan["delete"]) == len(plan["create"]) == 1
        assert all(
            not r["managed_by_yunohost"]
            for k in ("update", "delete", "unchanged")
            for r in plan[k]
        )
        assert not push.calls and not push.hashes
    push.run()
    assert push.calls == [("create", "A", None)]
    assert all(r in push.remote for r in (conflict, sibling, orphan))
    push.calls.clear()
    push.run(force=True)
    assert push.calls == [("delete", "TXT", "orphan"), ("update", "TXT", "conflict")]
    assert sibling in push.remote
    assert len(push.hashes) == 3
    plan = push.run(dry_run=True)
    assert not any(plan[k] for k in ("create", "update", "delete"))
    assert all(r["managed_by_yunohost"] for r in plan["unchanged"])
    push.wanted[0]["content"] = '"lebureau-force-next"'
    push.calls.clear()
    push.run()
    assert len(push.calls) == 1 and push.calls[0][0] == "update"


def test_subdomain_scope_and_delegated_configuration(push):
    push.domain = push.zone = "child.example.org"
    external = [
        record(name="example.org", id="parent"),
        record(name="other.example.org", id="sibling"),
        record(name="notchild.example.org", id="suffix"),
    ]
    push.remote.extend(external)
    push.run(force=True)
    assert push.calls == [("create", "A", None)]
    assert all(r in push.remote for r in external)
    for config in push.configs:
        assert config.resolve("lexicon:domain") == push.zone
        assert config.resolve("lexicon:delegated") == push.zone


@pytest.mark.parametrize("failure", ["constructor", "authentication", "list"])
def test_listing_errors_are_wrapped_before_writes(push, failure):
    if failure == "constructor":
        push.constructor_error = ValueError("invalid configuration")
    elif failure == "authentication":
        push.authentication_error = ValueError("invalid credentials")
    else:
        push.failure = "list"
    with pytest.raises(YunohostError) as exc:
        push.run()
    assert exc.value.key == "domain_dns_push_failed_to_list"
    assert not push.calls
    assert not push.hashes
    assert push.entered == len(push.exited)
    if failure == "list":
        assert push.exited == [RuntimeError]


def test_empty_credentials_stop_before_client_construction(push):
    push.credentials = {"auth_token": ""}
    with pytest.raises(YunohostValidationError):
        push.run()
    assert not push.configs


@pytest.mark.parametrize("priority", [0, 10, "20"])
def test_mx_normalization_keeps_full_values(priority):
    options = {"mx": {"priority": priority}}
    assert (
        dns._normalize_mx_content("mail.example.org.", options)
        == f"{priority} mail.example.org."
    )
    assert (
        dns._normalize_mx_content("30 mail.example.org.", options)
        == "30 mail.example.org."
    )
    assert (
        dns._normalize_mx_content("10 mail.example.org.", {}) == "10 mail.example.org."
    )


def test_ownership_identity_survives_python_hash_seeds():
    # Run the actual helper in isolated processes without initializing a server.
    module = ast.parse(Path(dns.__file__).read_text())
    function = next(
        n
        for n in module.body
        if isinstance(n, ast.FunctionDef) and n.name == "_hash_dns_record"
    )
    code = "import hashlib, json\nDNSRecord = dict\n" + ast.unparse(function)
    code += "\nprint(_hash_dns_record({'name': 'example.org', 'type': 'A', 'content': '192.0.2.1'}))"
    results = [
        subprocess.check_output(
            [sys.executable, "-c", code],
            env={**os.environ, "PYTHONHASHSEED": seed},
            text=True,
        )
        for seed in ("1", "2")
    ]
    assert results[0] == results[1]
    assert results[0].startswith("sha256:")


@pytest.mark.parametrize("secret_size", [32, 128])
def test_lebureau_password_form_accepts_token_and_redacts_it(
    push, monkeypatch, secret_size
):
    pytest.importorskip("pydantic")
    from yunohost.utils.configpanel import ConfigPanelModel
    from yunohost.utils.form import OperationLogger, build_form
    from yunohost.utils.file_utils import read_toml

    metadata = read_toml(
        str(Path(dns.__file__).resolve().parents[1] / "share/registrar_list.toml")
    )["lebureau"]
    metadata["auth_token"]["default"] = ""  # Added by registrar discovery.
    config = ConfigPanelModel(version=1.0, dns={"registrar": metadata})
    option = config.get_option("auth_token")
    assert option.type == "password"
    assert option.redact is True
    logger = SimpleNamespace(data_to_redact=[])
    monkeypatch.setattr(OperationLogger, "_instances", [logger])
    token = "hmac-sha512:test-key:" + base64.b64encode(b"\xff" * secret_size).decode()
    form_type = build_form(config.options)
    form = form_type(auth_token=token)
    assert form.auth_token == token
    assert token in logger.data_to_redact
    encoded = urllib.parse.urlencode({"auth_token": token})
    for secret in logger.data_to_redact:
        encoded = encoded.replace(secret, "[REDACTED]")
    assert encoded == "auth_token=[REDACTED]"
    # Pydantic leaves an omitted optional default as None; submitted empty
    # values pass through the form validators and normalize to an empty string.
    assert form_type().auth_token is None
    assert form_type(auth_token="").auth_token == ""


def test_lebureau_form_preserves_saved_token(push):
    pytest.importorskip("pydantic")
    from yunohost.utils.form import (
        build_form,
        parse_raw_options,
        prompt_or_validate_form,
    )
    from yunohost.utils.file_utils import read_toml

    metadata = read_toml(
        str(Path(dns.__file__).resolve().parents[1] / "share/registrar_list.toml")
    )["lebureau"]
    token = "hmac-sha512:test-key:" + base64.b64encode(b"public-test-secret").decode()
    options = parse_raw_options(metadata, serialize=False)
    form = build_form(options).model_construct(auth_token=token)
    form = prompt_or_validate_form(options, form, prefilled_answers={})
    assert form.auth_token == token
