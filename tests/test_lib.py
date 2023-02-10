import pytest
import boltlib


def test_build_url_template_ok():
    url = "lnurlw://card.yourdomain.com/ln"
    obj = boltlib.build_url_template(url)
    assert (
        obj.url
        == "lnurlw://card.yourdomain.com/ln?p=00000000000000000000000000000000&c=0000000000000000"
    )
    assert obj.picc_offset == 41
    assert obj.cmac_offset == 76


def test_build_url_template_is_lnurlw():
    with pytest.raises(ValueError):
        boltlib.build_url_template("https://card.yourdomain.com/ln")


def test_build_url_template_now_query_string():
    with pytest.raises(ValueError):
        boltlib.build_url_template("lnurlw://card.yourdomain.com/ln?key=value")
