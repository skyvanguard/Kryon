"""Tests for IoC extraction."""

from kryon.intelligence.ioc import IoCExtractor


def test_extract_ipv4():
    extractor = IoCExtractor(include_private_ips=True)
    text = "Found open port on 192.168.1.100 and 10.0.0.1"
    iocs = extractor.extract_from_text(text, source="nmap")
    ips = [i for i in iocs if i.type == "ip"]
    assert len(ips) == 2
    assert ips[0].value == "192.168.1.100"


def test_extract_ipv4_excludes_private():
    extractor = IoCExtractor(include_private_ips=False)
    text = "Malicious traffic from 8.8.8.8 and 192.168.1.1"
    iocs = extractor.extract_from_text(text)
    ips = [i for i in iocs if i.type == "ip"]
    assert len(ips) == 1
    assert ips[0].value == "8.8.8.8"


def test_extract_domains():
    extractor = IoCExtractor()
    text = "Resolved to evil.hack and c2.malware.com"
    iocs = extractor.extract_from_text(text)
    domains = [i for i in iocs if i.type == "domain"]
    values = [d.value for d in domains]
    assert "evil.hack" in values
    assert "c2.malware.com" in values


def test_extract_urls():
    extractor = IoCExtractor()
    text = "Callback to https://malware.com/payload.exe and http://evil.dev/c2"
    iocs = extractor.extract_from_text(text)
    urls = [i for i in iocs if i.type == "url"]
    assert len(urls) == 2


def test_extract_emails():
    extractor = IoCExtractor()
    text = "Contact admin@example.com for phishing report"
    iocs = extractor.extract_from_text(text)
    emails = [i for i in iocs if i.type == "email"]
    assert len(emails) == 1
    assert emails[0].value == "admin@example.com"


def test_extract_md5():
    extractor = IoCExtractor()
    text = "File hash: d41d8cd98f00b204e9800998ecf8427e"
    iocs = extractor.extract_from_text(text)
    hashes = [i for i in iocs if i.type == "hash_md5"]
    assert len(hashes) == 1
    assert hashes[0].value == "d41d8cd98f00b204e9800998ecf8427e"


def test_extract_sha256():
    extractor = IoCExtractor()
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    text = f"SHA256: {h}"
    iocs = extractor.extract_from_text(text)
    hashes = [i for i in iocs if i.type == "hash_sha256"]
    assert len(hashes) == 1
    assert hashes[0].value == h


def test_extract_deduplicates():
    extractor = IoCExtractor()
    text = "IP 8.8.8.8 was seen again at 8.8.8.8"
    iocs = extractor.extract_from_text(text)
    ips = [i for i in iocs if i.type == "ip"]
    assert len(ips) == 1


def test_extract_source_preserved():
    extractor = IoCExtractor()
    iocs = extractor.extract_from_text("8.8.8.8", source="nmap_scan")
    assert iocs[0].source == "nmap_scan"


def test_extract_empty_text():
    extractor = IoCExtractor()
    iocs = extractor.extract_from_text("")
    assert iocs == []
