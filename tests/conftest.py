# -*- coding: utf-8 -*-
import boltlib as bl
import pytest


@pytest.fixture(scope="module")
def session():
    return bl.AuthSession()


@pytest.fixture(scope="module")
def wsession():
    return bl.AuthSession(key="0d2e69d49ba54a3e3ecc1e8c5fbbb6a8")
