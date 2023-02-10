# -*- coding: utf-8 -*-


__all__ = ["build_url_template"]


class UrlTemplate:
    """URL tamplate to be written to BoltCard"""

    def __init__(self, url, picc_offset, cmac_offset):
        # type: (str, int, int) -> None
        self.url = url
        self.picc_offset = picc_offset
        self.cmac_offset = cmac_offset


def build_url_template(url):
    # type: (str) -> UrlTemplate
    """
    Takes a base URL and builds the UrlTemplate to be written to the BoltCard.

    :param str url: Withdraw endpoint url (example: lnurlw://boltserver.com/withdraw)
    """

    # Sanity check
    if not url.startswith("lnurlw://"):
        raise ValueError("url must start with scheme lnurlw://")
    if "?" in url:
        raise ValueError("url must not include any query strings")

    suffix = "?p=00000000000000000000000000000000&c=0000000000000000"
    base_len = len(url)
    pic_offset = base_len + 10
    cmac_offset = base_len + 45
    url += suffix
    return UrlTemplate(url, pic_offset, cmac_offset)
