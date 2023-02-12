# -*- coding: utf-8 -*-
import pytest
import boltlib as bl


url = "lnurlw://legend.lnbits.com/boltcards/api/v1/scan/q3cksam5j5d6guxuhearty"
keys = [
    "0d2e69d49ba54a3e3ecc1e8c5fbbb6a8",
    "2b0c4da7541352808f1ef8d94991963e",
    "9d4b638be2f1200bbe7fe73fd611cf14",
    "2b0c4da7541352808f1ef8d94991963e",
    "9d4b638be2f1200bbe7fe73fd611cf14",
]


def test_burn_01_write_url():
    apdus = bl.burn_01_write_url(url)
    assert apdus == [
        "00A4040007D276000085010100",
        "00A4000002E10400",
        "00D68400840082D1017E55006C6E75726C773A2F2F6C6567656E642E6C6E626974732E636F6D2F626F6C7463617264732F6170692F76312F7363616E2F7133636B73616D356A356436677578756865617274793F703D303030303030303030303030303030303030303030303030303030303030303026633D30303030303030303030303030303030",
    ]


@pytest.mark.skip(reason="Todo")
def test_burn_02_auth_challenge(session):
    apdus = bl.burn_02_auth_challenge(session)
    assert apdus == ["00A4040007D276000085010100", "9071000005000300000000"]
    assert session.cmd_counter == 0
    assert session.authenticated == False


@pytest.mark.skip(reason="Todo")
def test_burn_03_auth_response(session):
    response = "FE1DCEA6D6AF8721040C914674ECC1B191AF"
    apdus = bl.burn_03_auth_response(session, response)
    assert apdus == [
        "90AF000020738008B0506A2BD29A129B4F2FA94A3C72632AD7F3288C1590B3C2BB28C8948700"
    ]
    assert session.cmd_counter == 0
    assert session.authenticated is False


@pytest.mark.skip(reason="Todo")
def test_burn_04_auth_finalize(session):
    response = "3D24888F864B60E14CD26E88C060989946EFD72497EB4D3ABC5D3E48FD9DFCEB9100"
    bl.burn_04_auth_finalize(session, response)
    assert session.authenticated
    assert session.rnd_a == "5A10C44FCF6132B6ADD93B9DBBEA05EA"
    assert session.rnd_b == "9BB1FF456458597F96520DC7E56ECA22"
    assert session.ti == "AB3C4643"
    assert session.key_mac == "3D851559D90F4BC2A7B2577ED02BC2AC"
    assert session.key_enc == "0773EC0F4A6584E4C8C2010F759196A3"
    assert session.cmd_counter == 0


@pytest.mark.skip(reason="Todo")
def test_burn_05_configure_picc(session):
    assert session.cmd_counter == 0
    apdus = bl.burn_05_configure_picc(session, url)
    assert apdus == ["905F00001902A20C420788C44DAEEEBD74112286FFDE6B900201EFA2F0EE00"]
    assert session.cmd_counter == 1


@pytest.mark.skip(reason="Todo")
def test_burn_06_change_keys(session):
    assert session.cmd_counter == 1
    apdus = bl.burn_06_change_keys(session, keys)
    assert apdus == [
        "90C40000290462091CAA28FC9977C25B5C98FFFA710EA82C534F370197B72B0FCFA86468413BF91D57F1A428063100",
        "90C4000029037DC30C130622677882A3447537BE3E5D4BF56FC9E987B870ADFEA3E412575398F27A1D3B7163473000",
        "90C4000029022680EF1BEB50581FBEA2604EA7D3F5CECB74A6A6E9763DBCEBA050006F97DA3798E91381A16A11D300",
        "90C400002901C1F6723DEC5E6C447411B0E85025A87A74DBA553BE1057ACBF71C4E75303805F24CEC783560388D900",
    ]
    assert session.cmd_counter == 5
