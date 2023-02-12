# -*- coding: utf-8 -*-
import boltlib as bl
import pytest


@pytest.fixture(scope="module")
def session():
    return bl.AuthSession()
