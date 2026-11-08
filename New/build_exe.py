# -*- coding: utf-8 -*-
"""
GuìFē! :) 超级加密工具 —— PyInstaller 打包脚本
================================================================
用法（在项目目录下执行）：

    python build_exe.py                 # 目录版（推荐），含人脸模型，不含声纹
    python build_exe.py --onefile       # 单文件版（EXE 体积大、启动慢，模型也在 EXE 内）
    python build_exe.py --with-voice    # 连声纹模块（torch / librosa）一起打包，体积很大
    python build_exe.py --no-models     # 不打包模型，首次使用人脸时让用户下载
    python build_exe.py --name MyApp    # 自定义 EXE 名称

说明：
    * 人脸模型放在 models/buffalo_l/ 下（det_10g.onnx + w600k_r50.onnx），
      运行一次 v18.0.0.py 时如果缺失会自动提示下载，也可以用 build_exe.py 的说明手动放置。
    * 目录版：模型会被放进 dist/<name>/_internal/models/buffalo_l，
      程序运行时从 sys._MEIPASS 找到它；也可以把模型放到 EXE 同级的 models/buffalo_l。
    * 单文件版：模型会被压进 EXE，启动时解压到临时目录，因此启动会慢几秒。
    * 声纹依赖 torch，打包后通常 1.5 GB 以上；不需要声纹就别加 --with-voice。
"""

import argparse
import base64
import os
import re
import shutil
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_FILE = os.path.join(BASE_DIR, "v18.0.0.py")
MODEL_DIR = os.path.join(BASE_DIR, "models", "buffalo_l")
MODEL_FILES = ("det_10g.onnx", "w600k_r50.onnx")


def extract_icon(destination: str):
    try:
        source = open(APP_FILE, "r", encoding="utf-8").read()
        match = re.search(r'APP_ICON_B64 = "([^"]+)"', source)
        if not match:
            return None
        data = base64.b64decode(match.group(1))
        with open(destination, "wb") as f:
            f.write(data)
        return destination
    except Exception as exc:
        print(f"[warn] 图标提取失败：{exc}")
        return None


def check_models():
    missing = [
        name
        for name in MODEL_FILES
        if not os.path.isfile(os.path.join(MODEL_DIR, name))
    ]
    return missing


def pywin32_dlls():
    """pywin32 的运行时 DLL。

    某些 sitecustomize（例如 IDE / 调试器安装的）会在解释器启动时预先加载
    pywintypes，导致 PyInstaller 认为它是“已加载的系统库”，不再把它复制到
    _internal 里；用户换一台机器运行时就会报“找不到指定的 DLL”。
    这里把它们显式补进包里，彻底避免这个问题。
    """
    try:
        import sysconfig

        platlib = sysconfig.get_paths()["platlib"]
    except Exception:
        return []

    candidates = [
        os.path.join(platlib, "pywin32_system32", "pywintypes313.dll"),
        os.path.join(platlib, "pywin32_system32", "pythoncom313.dll"),
    ]
    return [path for path in candidates if os.path.isfile(path)]


def verify_build(name: str, onefile: bool) -> bool:
    """检查打包结果里关键 DLL 是否齐全，缺了就补进去。"""
    if onefile:
        # 单文件版内容在 EXE 内部，运行时自动处理
        return True

    target = os.path.join(BASE_DIR, "dist", name, "_internal")
    if not os.path.isdir(target):
        print(f"[warn] 没有找到 {target}，跳过 DLL 检查")
        return True

    required = ["python313.dll", "vcruntime140.dll", "pywintypes313.dll", "pythoncom313.dll"]
    missing = [dll for dll in required if not os.path.isfile(os.path.join(target, dll))]
    if not missing:
        print("[ok] 关键 DLL 检查通过：" + ", ".join(required))
        return True

    print("[warn] 打包结果缺少 DLL：" + ", ".join(missing) + "，正在自动补齐…")
    for dll in missing:
        source = next(
            (p for p in pywin32_dlls() if os.path.basename(p) == dll), None
        )
        if source:
            shutil.copy2(source, target)
            print(f"       已补齐 {dll}")

    still = [dll for dll in required if not os.path.isfile(os.path.join(target, dll))]
    if still:
        print(
            "[warn] 仍然缺少："
            + ", ".join(still)
            + "（python313.dll 应由 PyInstaller 自带，若缺失请删除 build/ 目录后重新打包）"
        )
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description="打包 GuìFē! :) 超级加密工具")
    parser.add_argument("--onefile", action="store_true", help="打包成单个 EXE")
    parser.add_argument("--with-voice", action="store_true", help="包含声纹模块（torch）")
    parser.add_argument("--no-models", action="store_true", help="不打包人脸模型")
    parser.add_argument("--name", default="GuifeiCrypto", help="EXE 名称")
    args = parser.parse_args()

    if not os.path.isfile(APP_FILE):
        print(f"[error] 找不到 {APP_FILE}")
        return 1

    if not args.no_models:
        missing = check_models()
        if missing:
            print("[error] 缺少人脸模型文件：")
            for name in missing:
                print(f"        {os.path.join(MODEL_DIR, name)}")
            print("\n解决办法（任选其一）：")
            print("  1. 先运行一次 python v18.0.0.py，勾选人脸因子，按提示自动下载；")
            print("  2. 手动下载 buffalo_l 的 det_10g.onnx / w600k_r50.onnx 放进 models/buffalo_l/；")
            print("  3. 确认不需要人脸功能，加 --no-models 跳过。")
            return 1

    separator = ";" if os.name == "nt" else ":"
    icon_path = extract_icon(os.path.join(BASE_DIR, "build_app.ico"))

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--name",
        args.name,
        "--onedir" if not args.onefile else "--onefile",
        # 懒加载的模块需要显式声明
        "--hidden-import",
        "insightface",
        "--hidden-import",
        "insightface.app",
        "--hidden-import",
        "onnxruntime",
        "--hidden-import",
        "cv2",
        "--hidden-import",
        "sounddevice",
        "--hidden-import",
        "requests",
        "--hidden-import",
        "galois",
        "--hidden-import",
        "numba",
        "--hidden-import",
        "llvmlite",
        "--collect-data",
        "galois",
        "--collect-all",
        "insightface",
        "--collect-all",
        "sounddevice",
        # 这些小依赖用不到，排除掉能减小体积
        "--exclude-module",
        "tkinter",
        "--exclude-module",
        "matplotlib",
        "--exclude-module",
        "PyQt5",
        "--exclude-module",
        "PyQt6",
        "--exclude-module",
        "IPython",
        "--exclude-module",
        "notebook",
    ]

    if args.with_voice:
        command += [
            "--hidden-import",
            "resemblyzer",
            "--hidden-import",
            "webrtcvad",
            "--hidden-import",
            "torch",
            "--collect-all",
            "resemblyzer",
            "--collect-all",
            "librosa",
        ]
    else:
        # 明确排除声纹依赖，避免被间接拖进来
        command += [
            "--exclude-module",
            "resemblyzer",
            "--exclude-module",
            "librosa",
            "--exclude-module",
            "torch",
            "--exclude-module",
            "torchaudio",
            "--exclude-module",
            "webrtcvad",
        ]

    if icon_path:
        command += ["--icon", icon_path]

    if not args.no_models:
        command += ["--add-data", f"{MODEL_DIR}{separator}models/buffalo_l"]

    # pywin32 运行时 DLL 必须显式带上（否则可能因 sitecustomize 预加载而被漏掉）
    for dll in pywin32_dlls():
        command += ["--add-binary", f"{dll}{separator}."]

    command.append(APP_FILE)

    print("=" * 64)
    print("PyInstaller 命令：")
    print(" ".join(f'"{c}"' if " " in c else c for c in command))
    print("=" * 64)

    result = subprocess.run(command, cwd=BASE_DIR)
    if result.returncode != 0:
        print("\n[error] 打包失败，请查看上面的日志。")
        return result.returncode

    dist_dir = os.path.join(BASE_DIR, "dist", args.name)
    if args.onefile:
        exe_path = os.path.join(BASE_DIR, "dist", args.name + ".exe")
    else:
        exe_path = os.path.join(dist_dir, args.name + ".exe")

    dll_ok = verify_build(args.name, args.onefile)

    print("\n" + "=" * 64)
    print("[ok] 打包完成")
    print(f"     {exe_path}")
    if not args.no_models:
        print("     模型已包含在 EXE/目录中，换电脑也能直接使用。")
    if args.onefile:
        print("     单文件版首次启动会解压模型，可能需要 10 秒左右。")
    if not dll_ok:
        print("     [!] DLL 检查未完全通过，请先本机运行 GuifeiCrypto.exe --selftest")
    print("     自检：GuifeiCrypto.exe --selftest（结果写到当前目录 guifei_selftest.txt）")
    print("=" * 64)
    return 0 if dll_ok else 1


if __name__ == "__main__":
    sys.exit(main())
