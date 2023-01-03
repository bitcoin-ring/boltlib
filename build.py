# -*- coding: utf-8 -*-
import PyInstaller.__main__
import platform

# fmt: off
cmd = [
        "boltlib/cli.py",
        "--clean",
        "--console",
        "--name", "boltcard",
]
# fmt: on

if platform.system() != "Darwin":
    cmd.append("--onefile")

PyInstaller.__main__.run(cmd)
