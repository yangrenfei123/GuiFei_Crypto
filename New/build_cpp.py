# -*- coding: utf-8 -*-
"""用当前机器上的 MSVC 编译 C++ 源码（不需要 vcvarsall，直接拼参数）。"""
import os
import subprocess
import sys

MSVC = r"C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Tools\MSVC\14.50.35717"
SDK = r"C:\Program Files (x86)\Windows Kits\10"
SDK_VER = "10.0.26100.0"

ROOT = os.path.dirname(os.path.abspath(__file__))
OBJ_DIR = os.path.join(ROOT, "obj")
BIN_DIR = os.path.join(ROOT, "bin")


def env():
    e = dict(os.environ)
    inc = [
        os.path.join(MSVC, "include"),
        os.path.join(SDK, "Include", SDK_VER, "ucrt"),
        os.path.join(SDK, "Include", SDK_VER, "um"),
        os.path.join(SDK, "Include", SDK_VER, "shared"),
        os.path.join(SDK, "Include", SDK_VER, "winrt"),
        os.path.join(ROOT, "lib", "webview2"),
        os.path.join(ROOT, "src"),
    ]
    lib = [
        os.path.join(MSVC, "lib", "x64"),
        os.path.join(MSVC, "lib", "x64", "store"),
        os.path.join(SDK, "Lib", SDK_VER, "ucrt", "x64"),
        os.path.join(SDK, "Lib", SDK_VER, "um", "x64"),
        os.path.join(ROOT, "lib", "webview2"),
    ]
    e["INCLUDE"] = ";".join(inc)
    e["LIB"] = ";".join(lib)
    # cl.exe 需要这些 DLL 才能启动
    e["PATH"] = os.pathsep.join([
        os.path.join(MSVC, "bin", "Hostx64", "x64"),
        os.path.join(ROOT, "bin"),
        e.get("PATH", ""),
    ])
    return e


CL = os.path.join(MSVC, "bin", "Hostx64", "x64", "cl.exe")
RC = os.path.join(SDK, "bin", SDK_VER, "x64", "rc.exe")


def run(cmd):
    print(">", " ".join(cmd))
    proc = subprocess.run(cmd, env=env(), capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    out = (proc.stdout or "") + (proc.stderr or "")
    if out.strip():
        print(out.strip())
    return proc.returncode


def compile_exe(name, sources, extra_link=(), defines=(), console=True):
    os.makedirs(OBJ_DIR, exist_ok=True)
    os.makedirs(BIN_DIR, exist_ok=True)
    objs = []
    for src in sources:
        obj = os.path.join(OBJ_DIR, os.path.splitext(os.path.basename(src))[0] + ".obj")
        cmd = [CL, "/nologo", "/c", "/O2", "/EHsc", "/std:c++20", "/utf-8",
               "/W3", "/permissive-", "/MD", "/D_CRT_SECURE_NO_WARNINGS"]
        cmd += [f"/D{d}" for d in defines]
        cmd += ["/Fo" + obj, os.path.join(ROOT, src)]
        code = run(cmd)
        if code != 0:
            return code
        objs.append(obj)
    exe = os.path.join(BIN_DIR, name + ".exe")
    cmd = [CL, "/nologo", "/Fe" + exe] + objs + ["/link",
           "/SUBSYSTEM:CONSOLE" if console else "/SUBSYSTEM:WINDOWS"] + list(extra_link)
    return run(cmd)


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "crypto"
    if which == "crypto":
        rc = compile_exe("crypto_test",
                         ["src/tests/crypto_test.cpp", "src/core/crypto.cpp", "src/core/util.cpp"],
                         extra_link=["bcrypt.lib", "user32.lib"])
        print("build crypto_test exit:", rc)
