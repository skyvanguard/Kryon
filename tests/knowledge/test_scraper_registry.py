"""Tests for SCRAPER_REGISTRY and auto-updater refactoring."""

import importlib

import pytest

try:
    _scrapers = importlib.import_module("kryon.knowledge.scrapers")
    SCRAPER_REGISTRY = _scrapers.SCRAPER_REGISTRY
    BaseScraper = _scrapers.BaseScraper
except (ImportError, ModuleNotFoundError):
    pytest.skip("RAG dependencies not installed", allow_module_level=True)


def test_registry_has_expected_keys():
    expected_keys = {
        "intelligence",
        "nvd",
        "github",
        "exploit-db",
        "writeups",
        "research-writeups",
        "owasp",
        "cwe",
        "vendor-advisories",
        "static-seed",
    }
    assert expected_keys == set(SCRAPER_REGISTRY.keys())


def test_registry_values_are_scraper_subclasses():
    for name, cls in SCRAPER_REGISTRY.items():
        assert issubclass(cls, BaseScraper), f"{name} -> {cls} is not a BaseScraper subclass"


def test_registry_scrapers_instantiate():
    for name, cls in SCRAPER_REGISTRY.items():
        instance = cls()
        assert instance.get_source_name(), f"{name} has empty source name"


def test_registry_scrapers_have_scrape_method():
    for name, cls in SCRAPER_REGISTRY.items():
        instance = cls()
        assert callable(getattr(instance, "scrape", None)), f"{name} missing scrape()"
