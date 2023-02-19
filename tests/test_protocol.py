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
        "00D60000840082D1017E55006C6E75726C773A2F2F6C6567656E642E6C6E626974732E636F6D2F626F6C7463617264732F6170692F76312F7363616E2F7133636B73616D356A356436677578756865617274793F703D303030303030303030303030303030303030303030303030303030303030303026633D30303030303030303030303030303030",
    ]


def test_burn_02_auth_challenge():
    apdus = bl.burn_02_auth_challenge()
    assert apdus == ["00A4040007D276000085010100", "9071000005000300000000"]


def test_burn_03_auth_response(session):
    session.rnd_a = bytes.fromhex("5A10C44FCF6132B6ADD93B9DBBEA05EA")
    response = "FE1DCEA6D6AF8721040C914674ECC1B191AF"
    apdus = bl.burn_03_auth_response(session, response)
    assert apdus == [
        "90AF000020738008B0506A2BD29A129B4F2FA94A3C72632AD7F3288C1590B3C2BB28C8948700"
    ]
    assert session.rnd_b == bytes.fromhex("9BB1FF456458597F96520DC7E56ECA22")
    assert session.cmd_counter == 0
    assert session.authenticated is False


def test_burn_04_auth_finalize(session):
    response = "3D24888F864B60E14CD26E88C060989946EFD72497EB4D3ABC5D3E48FD9DFCEB9100"
    bl.burn_04_auth_finalize(session, response)
    assert session.rnd_a.hex().upper() == "5A10C44FCF6132B6ADD93B9DBBEA05EA"
    assert session.rnd_b.hex().upper() == "9BB1FF456458597F96520DC7E56ECA22"
    assert session.ti.hex().upper() == "AB3C4643"
    assert session.key_mac.hex().upper() == "3D851559D90F4BC2A7B2577ED02BC2AC"
    assert session.key_enc.hex().upper() == "0773EC0F4A6584E4C8C2010F759196A3"
    assert session.authenticated
    assert session.cmd_counter == 0


def test_burn_05_configure_picc(session):
    assert session.cmd_counter == 0
    apdus = bl.burn_05_configure_picc(session, url)
    assert apdus == ["905F00001902A20C420788C44DAEEEBD74112286FFDE6B900201EFA2F0EE00"]
    assert session.cmd_counter == 1


def test_burn_06_change_keys(session):
    assert session.cmd_counter == 1
    apdus = bl.burn_06_change_keys(session, keys)
    expected = [
        "90C40000290462091CAA28FC9977C25B5C98FFFA710EA82C534F370197B72B0FCFA86468413BF91D57F1A428063100",
        "90C4000029037DC30C130622677882A3447537BE3E5D4BF56FC9E987B870ADFEA3E412575398F27A1D3B7163473000",
        "90C4000029022680EF1BEB50581FBEA2604EA7D3F5CECB74A6A6E9763DBCEBA050006F97DA3798E91381A16A11D300",
        "90C400002901C1F6723DEC5E6C447411B0E85025A87A74DBA553BE1057ACBF71C4E75303805F24CEC783560388D900",
        "90C40000290002E9375E2D0D1F450E414218081E89548DC46FEF97959E5DA18282E103CAD72A15B0909DF008831B00",
    ]
    for e, a in zip(expected, apdus):
        assert a == e
    assert session.cmd_counter == 6


def test_wipe_01_auth_challenge():
    apdus = bl.wipe_01_auth_challenge()
    assert apdus == ["00A4040007D276000085010100", "9071000005000300000000"]


def test_wipe_02_auth_response(wsession):
    wsession.rnd_a = bytes.fromhex("7FA9B3E2113552CFF1F44B8BB2B6775A")
    response = "876FA92BBBBC15F470F28FF3851F373491AF"
    apdus = bl.wipe_02_auth_response(wsession, response)
    assert apdus == [
        "90AF000020047C98FFD117092937C798A603417B09324FDB66FF0B60356A65D8BF34B4152000"
    ]
    assert wsession.rnd_b == bytes.fromhex("95BA5DA5716557DBE86ED0A51C8EAD96")
    assert wsession.cmd_counter == 0
    assert wsession.authenticated is False


def test_wipe_03_auth_finalize(wsession):
    response = "EF58F86DA9CD541F3C280DC0C64385B77D4A064FCF8C77AB9A7C98144745E4509100"
    bl.wipe_03_auth_finalize(wsession, response)
    assert wsession.rnd_a.hex().upper() == "7FA9B3E2113552CFF1F44B8BB2B6775A"
    assert wsession.rnd_b.hex().upper() == "95BA5DA5716557DBE86ED0A51C8EAD96"
    assert wsession.ti.hex().upper() == "C521C846"
    assert wsession.key_mac.hex().upper() == "56DF52877E4B0FFD1159090811C279BE"
    assert wsession.key_enc.hex().upper() == "7739D803B4304C69B60AC69A9ECB78C3"
    assert wsession.cmd_counter == 0


def test_wipe_04_reset_picc(wsession):
    assert wsession.cmd_counter == 0
    apdus = bl.wipe_04_reset_picc(wsession)
    assert apdus == ["905F00001902DCEDE38C556531EEFACE37109948FD16B0656D366997A9C100"]
    assert wsession.cmd_counter == 1


def test_wipe_05_changekeys(wsession):
    assert wsession.cmd_counter == 1
    apdus = bl.wipe_05_changekeys(wsession, keys)
    expected = [
        "90C400002904125B7201D5FBC4D3550E751E66953B06BABB543F4CB8E270F5CFD208EEDAC2528A3485001F9F8BFD00",
        "90C400002903D49BC9F646CE0E6CFB906127372B395DC59BD575660D015277CA78D54022CD5B1AFE77E104A8312900",
        "90C400002902A64DC1429C5C9FB81E832A493B8153C73C1D3464468B34D360A600728F10C41F3A3377B54AF4C38100",
        "90C400002901A11AD8CAA19332A82050D07B6DA8578C03905E6F61143F2DBF32FB34B60C3027A20DFE79F1CB3BF300",
        "90C400002900731818AD6CCB4F6392AB4B6DBC15C306785E5920A53BB44BB9843C5F0C2BE059AC043FF5951BD2FF00",
    ]
    for e, a in zip(expected, apdus):
        assert a == e
    assert wsession.cmd_counter == 6


def wipe_06_clear_ndef():
    pass
