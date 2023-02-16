import pytest
import boltlib


def test_build_url_template_append():
    url = "lnurlw://card.yourdomain.com/ln"
    obj = boltlib.build_url_template(url)
    assert (
        obj.url
        == "lnurlw://card.yourdomain.com/ln?p=00000000000000000000000000000000&c=0000000000000000"
    )
    assert obj.picc_offset == 41
    assert obj.cmac_offset == 76


def test_build_url_template_substitute():
    url = "lnurlw://card.yourdomain.com/ln?p={picc}&c={cmac}"
    obj = boltlib.build_url_template(url)
    assert (
        obj.url
        == "lnurlw://card.yourdomain.com/ln?p=pppppppppppppppppppppppppppppppp&c=cccccccccccccccc"
    )
    assert obj.picc_offset == 41
    assert obj.cmac_offset == 76


def test_build_url_template_query_string_ok_if_url_template():
    obj = boltlib.build_url_template(
        "lnurlw://test.com/ln?key=value&cmac={cmac}&picc={picc}"
    )
    assert obj.url == (
        "lnurlw://test.com/ln"
        "?key=value&cmac=cccccccccccccccc&picc=pppppppppppppppppppppppppppppppp"
    )


def test_build_url_template_is_lnurlw():
    with pytest.raises(ValueError):
        boltlib.build_url_template("https://card.yourdomain.com/ln")


def test_build_url_template_no_query_string_if_base_url():
    with pytest.raises(ValueError):
        boltlib.build_url_template("lnurlw://card.yourdomain.com/ln?key=value")


def test_build_url_template_url_too_long():
    url = f"lnurlw://card.yourdomain.com/ln/{'x' * 250}"
    with pytest.raises(ValueError):
        boltlib.build_url_template(url)


def test_pad_padding():
    unpadded = b"\x12\x12\x12\x12"
    assert boltlib.pad(unpadded, 8) == b"\x12\x12\x12\x12\x80\x00\x00\x00"
