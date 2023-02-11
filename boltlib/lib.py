# -*- coding: utf-8 -*-
import boltlib as bl

__all__ = ["build_url_template"]


def build_url_template(url):
    # type: (str) -> bl.UrlTemplate
    """
    Takes a base URL or URL template and builds the UrlTemplate to be written to the BoltCard.

    Examples:
        url=lnurlw://boltserver.com/withdraw  # Will append p and c query sting
        url=lnurlw://boltserver.com/withdraw=?p={picc}&c={cmac}  # Will substitute {picc} & {cmac}

    :param str url: Withdraw endpoint URL or URL template
    """

    if not url.startswith("lnurlw://"):
        raise ValueError("url must start with scheme lnurlw://")

    if "{picc}" in url and "{cmac}" in url:
        p_value = "p" * 32
        c_value = "c" * 16
        url = url.format(picc=p_value, cmac=c_value)
        picc_offset = url.index(p_value) + 7
        cmac_offset = url.index(c_value) + 7
    else:
        if "?" in url:
            raise ValueError("base url must not include any query strings")
        suffix = "?p=00000000000000000000000000000000&c=0000000000000000"
        base_len = len(url)
        picc_offset = base_len + 10
        cmac_offset = base_len + 45
        url += suffix

    if len(url) >= 250:
        raise ValueError("expanded url must be shorter than 250 characters")

    return bl.UrlTemplate(url, picc_offset, cmac_offset)
