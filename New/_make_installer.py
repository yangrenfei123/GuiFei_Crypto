"""把载荷 zip 追加到安装器 exe 末尾，生成最终安装包。

文件尾部格式：
    [payload zip][json 头][b"GFSTUP01"][int32 json 长度]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import zipfile

MAGIC = b"GFSTUP01"


def zip_dir(src: str, out_zip: str) -> None:
    total = 0
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, _dirs, files in os.walk(src):
            for name in files:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, src).replace("\\", "/")
                zf.write(full, rel)
                total += os.path.getsize(full)
    print(f"[zip] {out_zip} -> {os.path.getsize(out_zip)/1048576:.1f} MB (raw {total/1048576:.1f} MB)")


def zip_single(src_file: str, out_zip: str) -> None:
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.write(src_file, os.path.basename(src_file))
    print(f"[zip] {out_zip} -> {os.path.getsize(out_zip)/1048576:.1f} MB")


def build(base_exe: str, payload_zip: str, out_exe: str, info: dict) -> None:
    payload_size = os.path.getsize(payload_zip)
    info = dict(info)
    info["Length"] = payload_size
    json_bytes = json.dumps(info, ensure_ascii=False).encode("utf-8")
    with open(out_exe, "wb") as out, open(base_exe, "rb") as base:
        shutil.copyfileobj(base, out)
        offset = out.tell()
        with open(payload_zip, "rb") as payload:
            shutil.copyfileobj(payload, out)
        out.write(json_bytes)
        out.write(MAGIC)
        out.write(struct.pack("<i", len(json_bytes)))
    print(f"[setup] {out_exe} -> {os.path.getsize(out_exe)/1048576:.1f} MB (payload at {offset})")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--dir", help="目录载荷（onedir）")
    parser.add_argument("--file", help="单文件载荷")
    parser.add_argument("--mode", required=True)
    parser.add_argument("--exe-name", required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument("--shortcut-name", required=True)
    parser.add_argument("--version", default="18.0.0")
    parser.add_argument("--note", default="")
    parser.add_argument("--payload-zip", help="复用已生成的载荷 zip")
    args = parser.parse_args()

    work_zip = args.payload_zip or (os.path.splitext(args.out)[0] + ".payload.zip")
    if args.payload_zip:
        print(f"[zip] reuse {work_zip} -> {os.path.getsize(work_zip)/1048576:.1f} MB")
    elif args.dir:
        zip_dir(args.dir, work_zip)
    elif args.file:
        zip_single(args.file, work_zip)
    else:
        raise SystemExit("必须指定 --dir 或 --file")

    build(args.base, work_zip, args.out, {
        "Mode": args.mode,
        "ExeName": args.exe_name,
        "DisplayName": args.display_name,
        "ShortcutName": args.shortcut_name,
        "Version": args.version,
        "Note": args.note,
    })


if __name__ == "__main__":
    main()
