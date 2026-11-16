"""Keep the existing highest-installed-parent model for automatic DNS."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from moulinette import Moulinette, m18n

from yunohost import dns, domain
from yunohost.utils.error import YunohostValidationError


@pytest.fixture(autouse=True)
def clone_test_app():
    pass


@pytest.fixture
def hierarchy(monkeypatch):
    m18n.set_locales_dir(str(Path(dns.__file__).resolve().parents[1] / "locales"))
    m18n.set_locale("en")
    monkeypatch.setattr(Moulinette, "_interface", SimpleNamespace(type="api"))
    names = ["example.org", "child.example.org", "grandchild.child.example.org"]

    def installed(exclude_subdomains=False):
        return [names[0]] if exclude_subdomains else names

    monkeypatch.setattr(domain, "_get_domains", installed)
    monkeypatch.setattr(domain, "_assert_domain_exists", lambda _: None)
    monkeypatch.setattr(dns, "_assert_domain_exists", lambda _: None)
    monkeypatch.setattr(dns, "logger", Mock())
    return names


@pytest.mark.parametrize("name", ["child.example.org", "grandchild.child.example.org"])
def test_descendants_use_highest_installed_parent(hierarchy, monkeypatch, name):
    monkeypatch.setattr(dns, "_get_dns_zone_for_domain", lambda _: "example.org")
    config = dns._get_registrar_config_section(name)
    assert config["registrar"]["default"] == "parent_domain"
    assert "(#/domains/example.org/dns)" in config["infos"]["ask"]
    assert "auth_token" not in config


def test_child_reuses_existing_parent_zone_cache(hierarchy, monkeypatch):
    parent_cache = "/var/cache/yunohost/dns_zones/child.example.org"
    exists = dns.os.path.exists
    ctime = dns.os.path.getctime
    read = dns.read_file
    monkeypatch.setattr(
        dns.os.path,
        "exists",
        lambda path: True if path == parent_cache else exists(path),
    )
    monkeypatch.setattr(
        dns.os.path,
        "getctime",
        lambda path: dns.time.time() if path == parent_cache else ctime(path),
    )
    monkeypatch.setattr(
        dns,
        "read_file",
        lambda path: "example.org" if path == parent_cache else read(path),
    )
    query = Mock(side_effect=AssertionError("The parent cache should be reused"))
    monkeypatch.setattr(dns, "dig", query)
    assert dns._get_dns_zone_for_domain("grandchild.child.example.org") == "example.org"
    query.assert_not_called()


def test_parent_suggestions_include_installed_descendants(hierarchy, monkeypatch):
    from yunohost import settings

    monkeypatch.setattr(dns, "_get_dns_zone_for_domain", lambda _: "example.org")
    monkeypatch.setattr(
        dns, "get_public_ip", lambda version=4: "192.0.2.1" if version == 4 else None
    )
    monkeypatch.setattr(settings, "settings_get", lambda _: "ipv4")
    monkeypatch.setattr(
        dns, "domain_config_get", lambda *a, **kw: {"mail_in": False, "mail_out": False}
    )
    monkeypatch.setattr(dns, "hook_callback", lambda *a, **kw: {})
    result = dns._build_dns_conf("example.org")
    assert {r["name"] for r in result["basic"]} == {"@", "child", "grandchild.child"}


def test_child_push_directs_to_highest_installed_parent(hierarchy, monkeypatch):
    import yunohost.log

    monkeypatch.setattr(yunohost.log, "OperationLogger", Mock(_instances=[]))
    monkeypatch.setattr(
        dns,
        "_get_registar_settings",
        lambda name: (
            ("lebureau", {"auth_token": "dummy"})
            if name == "example.org"
            else ("parent_domain", {})
        ),
    )
    with pytest.raises(YunohostValidationError) as failure:
        dns.domain_dns_push("grandchild.child.example.org")
    assert failure.value.key == "domain_dns_push_managed_in_parent_domain"
    assert failure.value.kwargs["parent_domain"] == "example.org"
