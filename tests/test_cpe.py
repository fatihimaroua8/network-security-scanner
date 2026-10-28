from netscanner.cpe import to_cpe23, usable_cpe


def test_uri_to_23():
    assert to_cpe23("cpe:/a:apache:http_server:2.2.8") == "cpe:2.3:a:apache:http_server:2.2.8:*:*:*:*:*:*:*"


def test_23_passthrough():
    c = "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"
    assert to_cpe23(c) == c


def test_garbage():
    assert to_cpe23("garbage") is None
    assert to_cpe23("") is None
    assert to_cpe23("cpe:/x:foo:bar:1") is None


def test_usable_application_with_version():
    assert usable_cpe("cpe:/a:apache:http_server:2.2.8") == "cpe:2.3:a:apache:http_server:2.2.8:*:*:*:*:*:*:*"


def test_distro_suffix_is_stripped():
    assert usable_cpe("cpe:/a:mysql:mysql:5.0.51a-3ubuntu5") == "cpe:2.3:a:mysql:mysql:5.0.51a:*:*:*:*:*:*:*"


def test_unversioned_or_os_cpe_is_rejected():
    assert usable_cpe("cpe:/a:apache:http_server") is None      # would match every CVE
    assert usable_cpe("cpe:/o:microsoft:windows") is None       # OS, no version
    assert usable_cpe("cpe:/o:linux:linux_kernel:2.6") is None  # not an application
    assert usable_cpe("garbage") is None
