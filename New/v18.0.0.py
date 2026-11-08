# -*- coding: utf-8 -*-
"""
GuìFē! :) 超级加密工具  v18.2.1
================================================================
GUI 全面重写：PySide6 + PySide6-Fluent-Widgets[full]

与 v17.6.3 的加密格式 100% 兼容：
    文件 = MAGIC(12B) + VERSION(1B) + factor_mask(1B) + salt(16B)
           + [face_helper_len(2B) + face_helper_json]
           + [voice_helper_len(2B) + voice_helper_json]
           + AES-256-GCM(nonce(12B) + tag(16B) + ciphertext)
    明文 = JSON{content(b64), type(b64), original_filename,
               original_basename, timestamp}

2026-11 重写要点：
    * Tkinter -> PySide6 / qfluentwidgets 全量重绘
    * 原生拖拽（不再依赖 tkinterdnd2）
    * QThread + Signal 替代 root.after 轮询
    * 人脸/声纹模型全部延迟导入，冷启动更快
    * 新增主页 / 关于页 / 深浅色切换 / InfoBar 通知 / 依赖自检
    * 人脸模型自动查找（EXE 内置 / 同级目录 / 用户目录），缺失时
      可断点续传下载，不再卡死在“正在加载模型”
    * 附带 build_exe.py，可把模型一起打包进 EXE（--onefile / --with-voice）

安装依赖：
    pip install "PySide6-Fluent-Widgets[full]"

运行：
    python v18.0.0.py

打包：
    python build_exe.py                # 目录版，含人脸模型
    python build_exe.py --onefile      # 单文件 EXE
"""

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import logging
import os
import re
import struct
import sys
import tempfile
import threading
import time
import traceback
import warnings
import zipfile

try:
    import winreg
except ImportError:  # 非 Windows 平台
    winreg = None

warnings.filterwarnings("ignore", category=FutureWarning, module="insightface")
warnings.filterwarnings("ignore", category=FutureWarning, module="skimage")

import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from PySide6.QtCore import (
    QPointF,
    QRectF,
    QSize,
    Qt,
    QThread,
    QTimer,
    QUrl,
    Signal,
)
from PySide6.QtGui import (
    QAction,
    QColor,
    QDesktopServices,
    QFont,
    QIcon,
    QImage,
    QPainter,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMenu,
    QScrollArea,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

# qfluentwidgets 在 import 时会往 stdout 打印一条 Pro 版广告，这里静默掉
with contextlib.redirect_stdout(io.StringIO()):
    from qfluentwidgets import (
        BodyLabel,
        CaptionLabel,
        CardWidget,
        CheckBox,
        FluentIcon,
        FluentStyleSheet,
        FluentWindow,
        IconWidget,
        IndeterminateProgressBar,
        InfoBar,
        InfoBarPosition,
        LineEdit,
        MaskDialogBase,
        MessageBox,
        MessageBoxBase,
        NavigationItemPosition,
        PasswordLineEdit,
        PlainTextEdit,
        PrimaryPushButton,
        ProgressBar,
        PushButton,
        SimpleCardWidget,
        SplashScreen,
        StrongBodyLabel,
        SubtitleLabel,
        SwitchButton,
        TextEdit,
        Theme,
        TitleLabel,
        ToolButton,
        drawIcon,
        isDarkTheme,
        setTheme,
        themeColor,
    )

# ====================== 应用信息 ======================
APP_NAME = "GuìFē! :) 超级加密工具"
APP_VERSION = "v18.2.1"

# ====================== 全局日志 ======================
def _resolve_log_file() -> str:
    """优先写用户主目录；目录不可写时退回到临时目录。"""
    candidates = [
        os.path.join(os.path.expanduser("~"), "guifei_crypto_error.log"),
        os.path.join(tempfile.gettempdir(), "guifei_crypto_error.log"),
    ]
    for candidate in candidates:
        try:
            with open(candidate, "a", encoding="utf-8"):
                return candidate
        except OSError:
            continue
    return candidates[-1]


LOG_FILE = _resolve_log_file()
try:
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        encoding="utf-8",
    )
except OSError:
    logging.basicConfig(level=logging.INFO)

# ====================== 核心常量 ======================
ENCRYPTION_MAGIC = b"guifeiCRYPT3"
VERSION = b"\x03"
AES_KEY_LENGTH = 32
GCM_NONCE_LENGTH = 12
SALT_LENGTH = 16

# N=2^14 (16384) 内存需求约 16MB，避免 OpenSSL 内存限制错误
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

FILE_TYPE_TEXT = b"msc"
FILE_TYPE_FILE = b"guifei"
FILE_TYPE_FOLDER = b"guifeinext"

GRID_SIZE = 5
GRID_POINT_SIZE = 24
GRID_SPACING = 8

FACE_SIMILARITY_THRESHOLD = 0.75
FACE_MODEL_NAME = "buffalo_l"
FACE_PREVIEW_SIZE = (480, 360)

# 人脸因子实际只需要 buffalo_l 里的检测 + 识别两个模型（约 191 MB），
# 其余性别年龄 / 关键点模型不加载，既省内存也明显加快首次加载。
FACE_MODEL_FILES = ("det_10g.onnx", "w600k_r50.onnx")
FACE_MODEL_SIZES = {
    "det_10g.onnx": 16923827,
    "w600k_r50.onnx": 174383860,
}
FACE_MODEL_MIN_BYTES = 1_000_000
FACE_MODEL_URLS = {
    "det_10g.onnx": [
        "https://hf-mirror.com/DavidHoa/buffalo_l/resolve/main/det_10g.onnx",
        "https://hf-mirror.com/public-data/insightface/resolve/main/models/buffalo_l/det_10g.onnx",
    ],
    "w600k_r50.onnx": [
        "https://hf-mirror.com/DavidHoa/buffalo_l/resolve/main/w600k_r50.onnx",
        "https://hf-mirror.com/public-data/insightface/resolve/main/models/buffalo_l/w600k_r50.onnx",
    ],
}

VOICE_SAMPLE_RATE = 16000
VOICE_DURATION = 3
VOICE_EMBEDDING_THRESHOLD = 0.75

# BCH 参数 (galois 库自动计算纠错能力)
BCH_N = 127
BCH_K = 64
BCH_K_BYTES = BCH_K // 8
BCH_N_BITS = BCH_N

FACTOR_PASSWORD = 0b0001
FACTOR_GRID = 0b0010
FACTOR_FACE = 0b0100
FACTOR_VOICE = 0b1000

FACTOR_LABELS = [
    (FACTOR_PASSWORD, "主密码"),
    (FACTOR_GRID, "宫格密码"),
    (FACTOR_FACE, "人脸"),
    (FACTOR_VOICE, "声纹"),
]


# ====================== 生物模糊密钥（BCH 承诺） ======================
# galois 首次 import 会触发 numba 编译，可能较慢；延迟到真正需要时再加载，
# 并在窗口启动后由后台线程预热，避免拖慢冷启动。
_galois_module = None
_galois_lock = threading.Lock()


def get_galois():
    global _galois_module
    if _galois_module is None:
        with _galois_lock:
            if _galois_module is None:
                import galois

                _galois_module = galois
    return _galois_module


def stable_feature_bits(features_avg, num_bits, selected_indices=None):
    vec = features_avg
    if selected_indices is not None:
        selected_vals = vec[selected_indices]
    else:
        selected_vals = vec[:num_bits]
    bits = (selected_vals >= 0).astype(np.uint8)
    bit_bytes = np.packbits(bits, bitorder="little")
    expected_len = (num_bits + 7) // 8
    if len(bit_bytes) < expected_len:
        bit_bytes = np.pad(bit_bytes, (0, expected_len - len(bit_bytes)))
    full_bytes = bit_bytes[:expected_len]
    full_bytes = bytes(full_bytes)
    if num_bits % 8 != 0:
        mask = (1 << (num_bits % 8)) - 1
        full_bytes = full_bytes[:-1] + bytes([full_bytes[-1] & mask])
    return full_bytes


def select_stable_indices(features_list, num_bits=BCH_N_BITS):
    avg = np.mean(features_list, axis=0)
    if len(avg) < num_bits:
        raise ValueError(
            f"特征维度({len(avg)})小于所需位数({num_bits})，无法提取稳定位"
        )
    abs_avg = np.abs(avg)
    indices = np.argsort(-abs_avg)[:num_bits]
    return indices.tolist()


def generate_bio_key_and_helper(avg_feature, features_list=None):
    if features_list:
        indices = select_stable_indices(features_list, BCH_N_BITS)
    else:
        if len(avg_feature) < BCH_N_BITS:
            raise ValueError(
                f"特征维度({len(avg_feature)})小于BCH所需位数({BCH_N_BITS})"
            )
        indices = list(range(BCH_N_BITS))

    galois = get_galois()
    bch = galois.BCH(n=BCH_N, k=BCH_K)
    key = get_random_bytes(BCH_K_BYTES)
    key_bits = np.unpackbits(
        np.frombuffer(key, dtype=np.uint8), bitorder="little"
    )[:BCH_K]
    key_gf = galois.GF(2)(key_bits.tolist())
    codeword_gf = bch.encode(key_gf)
    codeword_bits = np.array(codeword_gf.tolist(), dtype=np.uint8)
    codeword_bytes = np.packbits(codeword_bits, bitorder="little")
    expected_len = (BCH_N + 7) // 8
    codeword_bytes = codeword_bytes[:expected_len]
    codeword_bytes = bytes(codeword_bytes)
    if BCH_N % 8 != 0:
        mask = (1 << (BCH_N % 8)) - 1
        codeword_bytes = codeword_bytes[:-1] + bytes([codeword_bytes[-1] & mask])

    bio_bits_raw = stable_feature_bits(avg_feature, BCH_N_BITS, indices)
    if len(codeword_bytes) != len(bio_bits_raw):
        raise RuntimeError(
            f"码字长度({len(codeword_bytes)})与生物比特长度({len(bio_bits_raw)})不匹配"
        )
    helper_bytes = bytes(a ^ b for a, b in zip(codeword_bytes, bio_bits_raw))
    helper_data = {
        "helper": base64.b64encode(helper_bytes).decode(),
        "indices": indices,
    }
    return key, helper_data


def recover_bio_key(helper_data, avg_feature):
    galois = get_galois()
    bch = galois.BCH(n=BCH_N, k=BCH_K)
    helper_bytes = base64.b64decode(helper_data["helper"])
    indices = helper_data["indices"]

    if len(avg_feature) < BCH_N_BITS:
        raise ValueError(f"特征维度({len(avg_feature)})小于BCH所需位数({BCH_N_BITS})")
    bio_bits_raw = stable_feature_bits(avg_feature, BCH_N_BITS, indices)

    if len(helper_bytes) != len(bio_bits_raw):
        raise RuntimeError("辅助数据长度与生物比特长度不匹配")

    noisy_codeword_bytes = bytes(a ^ b for a, b in zip(helper_bytes, bio_bits_raw))
    noisy_bits = np.unpackbits(
        np.frombuffer(noisy_codeword_bytes, dtype=np.uint8), bitorder="little"
    )[:BCH_N]
    noisy_gf = galois.GF(2)(noisy_bits.tolist())
    decoded_gf = bch.decode(noisy_gf)
    decoded_bits = np.array(decoded_gf.tolist(), dtype=np.uint8)

    if len(decoded_bits) < BCH_K:
        decoded_bits = np.pad(decoded_bits, (0, BCH_K - len(decoded_bits)), "constant")
    else:
        decoded_bits = decoded_bits[:BCH_K]

    key_bytes = np.packbits(decoded_bits, bitorder="little")
    return key_bytes[:BCH_K_BYTES].tobytes()


# ====================== 加解密核心（与旧版字节级兼容） ======================
def derive_key_scrypt(total_factor: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(
        total_factor,
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=AES_KEY_LENGTH,
    )


def encrypt_data(plaindata: bytes, total_factor: bytes, salt: bytes, aad: bytes) -> bytes:
    key = derive_key_scrypt(total_factor, salt)
    nonce = get_random_bytes(GCM_NONCE_LENGTH)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaindata)
    return nonce + tag + ciphertext


def decrypt_data(payload: bytes, total_factor: bytes, salt: bytes, aad: bytes) -> bytes:
    key = derive_key_scrypt(total_factor, salt)
    nonce = payload[:GCM_NONCE_LENGTH]
    tag = payload[GCM_NONCE_LENGTH : GCM_NONCE_LENGTH + 16]
    ciphertext = payload[GCM_NONCE_LENGTH + 16 :]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)


def build_file_header(factor_mask: int, salt: bytes, helpers: dict) -> bytes:
    header = ENCRYPTION_MAGIC + VERSION + bytes([factor_mask]) + salt
    for factor, key_name in [(FACTOR_FACE, "face"), (FACTOR_VOICE, "voice")]:
        if factor_mask & factor:
            helper_json = json.dumps(helpers[key_name], sort_keys=True).encode("utf-8")
            header += struct.pack("<H", len(helper_json)) + helper_json
    return header


def parse_file_header(data: bytes):
    pos = 0
    if data[pos : pos + len(ENCRYPTION_MAGIC)] != ENCRYPTION_MAGIC:
        raise ValueError("无效的加密文件")
    pos += len(ENCRYPTION_MAGIC)
    if data[pos : pos + 1] != VERSION:
        raise ValueError("文件版本不匹配")
    pos += 1
    factor_mask = data[pos]
    pos += 1
    salt = data[pos : pos + SALT_LENGTH]
    pos += SALT_LENGTH
    helpers = {}
    if factor_mask & FACTOR_FACE:
        length = struct.unpack("<H", data[pos : pos + 2])[0]
        pos += 2
        helpers["face"] = json.loads(data[pos : pos + length].decode("utf-8"))
        pos += length
    if factor_mask & FACTOR_VOICE:
        length = struct.unpack("<H", data[pos : pos + 2])[0]
        pos += 2
        helpers["voice"] = json.loads(data[pos : pos + length].decode("utf-8"))
        pos += length
    return factor_mask, salt, helpers, data[pos:]


def is_encrypted_file(filepath: str) -> bool:
    try:
        with open(filepath, "rb") as f:
            return f.read(len(ENCRYPTION_MAGIC)) == ENCRYPTION_MAGIC
    except OSError:
        return False


def make_packet(data: bytes, file_type: bytes, original_filename: str) -> bytes:
    return json.dumps(
        {
            "content": base64.b64encode(data).decode("ascii"),
            "type": base64.b64encode(file_type).decode("ascii"),
            "original_filename": original_filename,
            "original_basename": os.path.basename(original_filename),
            "timestamp": time.time(),
        }
    ).encode("utf-8")


def read_packet(plain_packet: bytes) -> dict:
    data = json.loads(plain_packet.decode("utf-8"))
    return {
        "content": base64.b64decode(data["content"]),
        "file_type": base64.b64decode(data["type"]),
        "original_filename": data.get("original_filename", ""),
        "original_basename": data.get("original_basename", ""),
    }


def describe_factors(factor_mask: int) -> str:
    names = [label for bit, label in FACTOR_LABELS if factor_mask & bit]
    return " + ".join(names) if names else "未知"


# ====================== 应用图标（内嵌 ICO / PNG） ======================
APP_ICON_B64 = "AAABAAEAICAAAAEAIACoEAAAFgAAACgAAAAgAAAAQAAAAAEAIAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHtoZgBlUlEEgXBuH4t9e1VyaW15Wl50GV1hdgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJB7dQCLdm8EiHVwI2paXSdLWY0BbW6LAHhoZQCejIcel4eDY6GTkKWuo6Lcvra2+re2vfSWorc8maS4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAK+dkgCplYoGs6KYQLeooZ25rKjioJujyY2YtxiZobkA++jcAsm+uqDHv77/1tDS/+Dc4P/k4ub/zM/Z+HV9l45CQlkiAAAAACkqPgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALGcjwDb0cgAxLSpJcq8s5vTyMLv3tjV/+bi4v/Y2N/4srnOT7rB0wD///8A5uLihuXj5//m4+j+5uLn/uXh5v7a2uH+sbPB/n6BlNhYYHpiOEhrCEVScgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADMua0A////ANXFu0Pbz8jR5N3Z/+rm5f/q5+f+6ebn/+Pi5P/Kzdl/6+vrAOjk5QDp5OQc5uTmx+Xi5//m4uf+5eLn/+Ph5v7k4ub+1NTc/5+nufZrfZyNR2KMDlNskgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzrqtAOvh2wDez8VF5drT4Ovl4v/s6Ob+6ufm/unn5//o5+fq5eTlrtvc4Dvt6+kA5dvZAOjm6QDp5eZG5uPn7OPh5vzj4ebe5OLm9+Pi5f/j4+X+39/l/7O9z/x7krWOTXGjCGGAqwAAAAAAAAAAAAAAAAAAAAAAAAAAAKeHbwDl184A49TKJ+re2NPv5uP/7+fk/uzn5f/q5+Xz6efmnOfk5TTf4OMF4t/gAAAAAAAAAAAA7vH2AP7//wHo5+t34uLrstzd4ynk4+Ve5OTm0+Pj5f/j4+f+4ODm/7fD1/eCn8JlydPkAGKFsAAAAAAAAAAAAAAAAAAAAAAA5tXKAODLuwXt4dqa8Ofi//Dn4/7u5uP/6+Xj6Onk42Hm4uIG/zIAACaYXy7NkVdiyYxRacmNUGjKjFFmyY5UY8uUY2bHm3hOonFVBdXFvQDl5OYn4+TmuOLi5//h4ef+293n/6/B19Z9oMYlhabJAAAAAAAAAAAAAAAAAAAAAADw49sA7+HYOPLo4uvx6OT/8Ofj/+zl4vHo4d9ciGR7AOq5ggDrt30k4Klo1duhXv/Ynlv/0JNV/9CTUv/Mklj/zJNY/sqUXO2/kWpKw5BiAOPi5gDj4uUj3+Dmyt/f6P/f3+n+z9fk/qS913HM2eYAcJO8AAAAAAAAAAAA5dHEAPz6/ADz5+GC8unl//Ho5P7u5uL/5+DfldjM1QTg19gA7rx/AO68gEjjrWr436Vd/sCLgv6HVY/+ll91/oZcl/66glf+zpZa/8SWbHrPlVUA1tPYANja4wDZ2eBS2dvk9dzd5//a3ef/v8/guXyozwmTs9MAAAAAAAAAAADy49kA9eTZCfXq5bvy6eX/8ejk/+vj4ene2Noz4NrcAAAAAADvvYAA776CTeSva/rfpl7+zJZ5/n1Yxv5eQM/+f1id/sOKWP/Ol1r/xZdsgdOUTAA4KjAAzszSAM3L0A/U1t/D2Nvl/9vc5v/O1+Tgq8beIa3G3gAAAAAAAAAAAPnt5gD67ucZ9ezn2PLo5P/w5+P/5t/evsjBzArOxs8AAAAAAPC/ggDxwIRN5LBs+t+nYP7Dj4H+elbJ/m9Pz/51T6D+u4NX/s+YW//GmW6B1JRLAEEvMQC6sbQA9P//ANDQ2JLU2OP/2Nvl/9Pa5fG8z+I4vtHjAAAAAAAAAAAA+e/qAPrv6iX17Ojm8unl//Do5P/h292iAAA7AaugswAAAAAA88SJAPPEik3ms3D636li/sqXgP6vgJf+wI2C/qV5mf7KlGH+0Zte/8iddIHUlkwASzc4AJSAeQDk8f8A0MzQiNTY4v/X3OX+1Nzm98PU5ETH1+UAAAAAAAAAAAD57+kA+e/pJvXs5+by6eX/8Ojk/9zV261qZZoEoZu0AAAAAAD1y5oA9sybQ+3AhfbjsG3/4a5w/+CtcP/eq2//3alt/9qlaP7VqHv/za+ec9SvkQBFMTQAwK+mAJFLCwHW0NGi2Nrk/9rc5v/V3Ob1xNXkP8bW5QAAAAAAAAAAAPjt5wD57ucZ9evn2fLp5f/x6OT/2tTa1KWhuxirpr0AAAAAAPXOpAD20KkT88ufqOa0e/3iv6zk5tDL1+bRytrozb3h4LF//de8rcrUyNMq1cbMAAAAAADQwroA0cC1GNzW19Lc3ef/3N7o/9Xc5ujB0+MqwtTkAAAAAAAAAAAA9ejfAPjp4Aj16+a38unl//Lp5f7h2t34sq3CWczI2ABrZIIA6MCzAPLEhgD0x4o336pv7s+XfGLn6v8U4Nv3F+zJpzzZqXHqw56AaMCQYwDY1/AAuqidAOjf2wDazsde4N3g+d7f6f7d3uj/09vmxrTM3w+3zd8AAAAAAAAAAADs288A9vDuAPXq5Xnz6ub/8unl/uzk4v/CvczEjoilGZuVrwAAAAAA9MeLAPjMkCbisHXmyYdad+LCcwDmsnIA6LFuP9ancO7DoohUxKCDAGJIOQDXycEA0sO5IODY1Mzj4eb/4eHo/t3f5//O2OSD////AJ230AAAAAAAAAAAAAAAAADz5+EA8ubgLfPp5ePy6eX/8enl/tzW2/6uqLyYfnGKDpCGngD7z48A/96fBvDEiqHaomnnz41We9aWW2XcpmrK0qqD0sWupR7HrqEA1ci/AMm5sBbd0syo5eHh/+Tk5v7i4ef/2d7m48PR4C/J1eIAAAAAAAAAAAAAAAAAAAAAAOja0ADRt6AB8ebhhfLp5f/x6OT+7+fk/tLM0/upnK2ihm11Ir2qmguwoKBmuqOYTe7AhJ/ks3nn4LB97Nyyi8HTtaQ+2KRxAIVpWgHIt60y2s7HtOXf3v3l5Of+5OPl/t/g5v3Q2ON/AFGhAa3B1wAAAAAAAAAAAAAAAAAAAAAAAAAAAO3g2QDr3dUY8ObhvPDo4P/w5+P+7ebj/tXN0v60oabUu6afoNjOzfa0scOyoJagFO/MpSTlyLQs38rMDqiUigq+q6E5zb+2jNvQyuPl39//5uPo/uTj5v7h4uX/1tvjs7zK2xTDz90AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyrOjAO3k3wDo3dYs7OTgyO7n5P/v5+T+6+bk/uLc2//f1dL/6uTj/9TS2vqnqL9r////AK2enQC+qJwF0cO8ldfMxvLh2dj/5uLl/+fj6P7l4+f+4uLl/9nc473Fz90k09njAGB9pAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyrSmAPHr5wDm29Qn6+Ler+zl4vvr5uT/6+bk/uvm5f7p5OX/5uLk/8PE0t2Sl7EtoaO3AMCpmgXi29mw5eLl/+fk5P7n4+j/5eLn/+Hg5fnY2uGkxMzZH9ja4QB1kbUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoX9rAOfd1wDg0ssQ597abenj4Nfq5eP+6uXj/unk5P7o5OT/3Nrf/7S4yXHQ0t4A7OvtAN/Z2Grk4uT+5ePm/+Pg5vvd3OLO09XeY7vE0wzJztoADCBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM28sQD37ukA5NfQYOrk4P3o5OL/5+Pi/eTh4+re3OC+xsnVPtvb4QDa0tAA2NDOId7c3rrb2+Cw1NXeX8TI1Bj///8Akp+4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOje2QDk2dJF5N/ezuDd4Kfb2d5n1NLaL8HD0QsAABAAfomqALGoqAC2q6kBwL/HDrK2xgfa2N4ANEBoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAx727AMa9ugTIwscTt7TFBMfDzQAREVoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA///////////////////B///DAf//AgD//gMAP/wDAB/4A4AP8AeAD+AQBAfgYAYH4GAHA8DgBwPA4AeDwOAHg8DgBwPA4AcDwPAPA+BxjgfgMAwH4AAQB/AAAA/4AYAf/ACAP/4AwH//gMH//4HH//+P//////////////////8="


def load_app_icon() -> QIcon:
    try:
        raw = base64.b64decode(APP_ICON_B64)
        if not raw:
            return QIcon()
        pixmap = QPixmap()
        if pixmap.loadFromData(raw):
            return QIcon(pixmap)
    except Exception:
        logging.error("图标加载失败: %s", traceback.format_exc())
    return QIcon()


# ====================== 人脸模型定位 / 配置 ======================
def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


# 打包成精简 EXE 时，可以按需裁剪人脸 / 声纹模块，界面会自动禁用对应因子
FACE_SUPPORT = _module_available("insightface") and _module_available("onnxruntime") and _module_available("cv2")
VOICE_SUPPORT = _module_available("resemblyzer") and _module_available("sounddevice")


def _config_path() -> str:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "GuifeiCrypto", "config.json")


def load_config() -> dict:
    try:
        with open(_config_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_config(updates: dict):
    path = _config_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = load_config()
        data.update(updates)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        logging.error("配置保存失败: %s", traceback.format_exc())


# ====================== 系统集成（右键菜单 / 开机启动） ======================
DECRYPT_EXTENSIONS = (".guifei", ".guifeinext", ".guifeitext", ".msc")
DEFAULT_ENCRYPT_EXTENSIONS = [
    ".txt",
    ".md",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".pdf",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".zip",
    ".7z",
    ".rar",
]


def normalize_extension(text: str) -> str:
    ext = (text or "").strip().lower()
    if not ext:
        return ""
    if not ext.startswith("."):
        ext = "." + ext
    if not re.fullmatch(r"\.[a-z0-9][a-z0-9._-]{0,15}", ext):
        return ""
    return ext


def configured_encrypt_extensions() -> list:
    data = load_config()
    values = data.get("encrypt_extensions")
    if not isinstance(values, list):
        values = DEFAULT_ENCRYPT_EXTENSIONS
    result = []
    for item in values:
        ext = normalize_extension(str(item))
        if ext and ext not in result:
            result.append(ext)
    return result


def _app_base_command() -> str:
    if getattr(sys, "frozen", False):
        return f'"{os.path.abspath(sys.executable)}"'
    return f'"{sys.executable}" "{os.path.abspath(__file__)}"'


def _icon_file() -> str:
    """把内置图标写到配置目录，供右键菜单 / 快捷方式使用。"""
    path = os.path.join(os.path.dirname(_config_path()), "guifei.ico")
    try:
        if not os.path.exists(path) or os.path.getsize(path) < 100:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(base64.b64decode(APP_ICON_B64))
    except Exception:
        return ""
    return path


def _set_shell_verb(ext: str, key_name: str, label: str, args: str) -> bool:
    if winreg is None:
        return False
    base = rf"Software\Classes\SystemFileAssociations\{ext}\shell\{key_name}"
    icon = _icon_file() or sys.executable
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base) as item:
            winreg.SetValueEx(item, "", 0, winreg.REG_SZ, label)
            winreg.SetValueEx(item, "Icon", 0, winreg.REG_SZ, icon)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r"\command") as item:
            winreg.SetValueEx(item, "", 0, winreg.REG_SZ, f'{_app_base_command()} {args} "%1"')
        return True
    except OSError:
        logging.error("写入右键菜单失败 %s: %s", ext, traceback.format_exc())
        return False


def _delete_shell_verb(ext: str, key_name: str) -> None:
    if winreg is None:
        return
    base = rf"Software\Classes\SystemFileAssociations\{ext}\shell\{key_name}"
    for path in (base + r"\command", base):
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        except OSError:
            pass


def register_shell_menus() -> bool:
    """按配置注册“加密 / 解密”右键菜单；先记录旧后缀，删除不再需要的项。"""
    if winreg is None:
        return False
    old = load_config().get("_registered_encrypt_extensions") or []
    wanted = configured_encrypt_extensions()
    ok = True
    for ext in old:
        if ext not in wanted:
            _delete_shell_verb(ext, "GuifeiEncrypt")
    for ext in DECRYPT_EXTENSIONS:
        _delete_shell_verb(ext, "GuifeiDecrypt")
        ok = _set_shell_verb(ext, "GuifeiDecrypt", "用 GuifeiCrypto 解密", "--decrypt") and ok
    for ext in wanted:
        ok = _set_shell_verb(ext, "GuifeiEncrypt", "用 GuifeiCrypto 加密", "--encrypt") and ok
    if ok:
        save_config({"_registered_encrypt_extensions": wanted})
    logging.info("右键菜单注册结果: %s", ok)
    return ok


def unregister_shell_menus() -> None:
    if winreg is None:
        return
    for ext in set(DECRYPT_EXTENSIONS) | set(configured_encrypt_extensions()):
        _delete_shell_verb(ext, "GuifeiDecrypt")
        _delete_shell_verb(ext, "GuifeiEncrypt")
    save_config({"_registered_encrypt_extensions": []})

def register_uninstall_entry() -> None:
    """写入“设置 → 应用”里的卸载项（由 --register-shell 调用）。"""
    if winreg is None or not getattr(sys, "frozen", False):
        return
    exe = os.path.abspath(sys.executable)
    exe_dir = os.path.dirname(exe)
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\GuifeiCrypto"
    uninst = os.path.join(exe_dir, "uninst.exe")
    if os.path.isfile(uninst):
        uninstall = f'"{uninst}"'
    else:
        uninstall = (
            f'cmd.exe /c ""{exe}" --unregister-shell & ping -n 2 127.0.0.1 >nul '
            f'& rmdir /s /q "{exe_dir}" & '
            f'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\GuifeiCrypto" /f"'
        )
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, APP_NAME)
            winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, APP_VERSION)
            winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, exe_dir)
            winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ, exe)
            winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, "GuifeiCrypto")
            winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, uninstall)
            winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
        total = 0
        for root, _dirs, files in os.walk(exe_dir):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(root, name))
                except OSError:
                    continue
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, "EstimatedSize", 0, winreg.REG_DWORD,
                              min(total // 1024, 2**31 - 1))
    except OSError:
        logging.error("写入卸载项失败: %s", traceback.format_exc())


def remove_uninstall_entry() -> None:
    if winreg is None:
        return
    try:
        winreg.DeleteKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall\GuifeiCrypto",
        )
    except OSError:
        pass



def apply_autostart(enabled: bool) -> bool:
    if winreg is None:
        return False
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE
        ) as key:
            if enabled:
                winreg.SetValueEx(
                    key, "GuifeiCrypto", 0, winreg.REG_SZ,
                    f"{_app_base_command()} --tray",
                )
            else:
                try:
                    winreg.DeleteValue(key, "GuifeiCrypto")
                except OSError:
                    pass
        save_config({"auto_start": bool(enabled)})
        return True
    except OSError:
        logging.error("设置开机启动失败: %s", traceback.format_exc())
        return False


def autostart_enabled() -> bool:
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"
        ) as key:
            winreg.QueryValueEx(key, "GuifeiCrypto")
            return True
    except OSError:
        return False


def _search_bases():
    """返回需要查找 models/buffalo_l 的根目录（脚本目录 / EXE 目录 / 打包资源目录）。"""
    bases = []
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        bases.append(exe_dir)
        bases.append(os.path.join(exe_dir, "_internal"))
        bundle_dir = getattr(sys, "_MEIPASS", None)
        if bundle_dir:
            bases.append(bundle_dir)
    else:
        bases.append(os.path.dirname(os.path.abspath(__file__)))
    bases.append(os.path.expanduser("~/.insightface"))
    return bases


def _model_dir_candidates():
    dirs = []
    env_dir = os.environ.get("GUIFEI_FACE_MODEL_DIR")
    if env_dir:
        dirs.append(env_dir)
    saved = load_config().get("face_model_dir")
    if saved:
        dirs.append(saved)
    for base in _search_bases():
        dirs.append(os.path.join(base, "models", FACE_MODEL_NAME))
        dirs.append(os.path.join(base, FACE_MODEL_NAME))
    return dirs


def face_model_dir_ready(path) -> bool:
    if not path or not os.path.isdir(path):
        return False
    for name in FACE_MODEL_FILES:
        try:
            if os.path.getsize(os.path.join(path, name)) < FACE_MODEL_MIN_BYTES:
                return False
        except OSError:
            return False
    return True


def resolve_face_model_dir():
    """按优先级查找可用的人脸模型目录，找不到返回 None。"""
    seen = set()
    for path in _model_dir_candidates():
        if not path:
            continue
        full = os.path.abspath(os.path.expanduser(path))
        if full in seen:
            continue
        seen.add(full)
        if face_model_dir_ready(full):
            return full
    return None


def face_model_install_dir() -> str:
    """默认安装位置：优先 ~/.insightface（与 insightface 原生布局一致）。"""
    local = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    candidates = [
        os.path.join(os.path.expanduser("~"), ".insightface", "models", FACE_MODEL_NAME),
        os.path.join(local, "GuifeiCrypto", "models", FACE_MODEL_NAME),
    ]
    for path in candidates:
        try:
            os.makedirs(path, exist_ok=True)
            return path
        except OSError:
            continue
    return candidates[-1]


def face_model_root(model_dir: str):
    """如果目录形如 <root>/models/buffalo_l，返回 <root>，便于 FaceAnalysis(root=...)。"""
    parent = os.path.dirname(os.path.abspath(model_dir))
    if os.path.basename(parent).lower() == "models":
        return os.path.dirname(parent)
    return None


# ====================== 线程工具 ======================
_ACTIVE_WORKERS = set()


class Worker(QThread):
    """在后台线程执行一个可调用对象，并把结果/异常投递回主线程。"""

    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, fn):
        super().__init__()
        self._fn = fn

    def run(self):
        try:
            result = self._fn()
        except Exception:
            self.failed.emit(traceback.format_exc())
        else:
            self.succeeded.emit(result)


def run_async(fn, on_success=None, on_error=None):
    worker = Worker(fn)
    _ACTIVE_WORKERS.add(worker)
    if on_success is not None:
        worker.succeeded.connect(on_success)
    if on_error is not None:
        worker.failed.connect(on_error)
    worker.finished.connect(lambda w=worker: _ACTIVE_WORKERS.discard(w))
    worker.start()
    return worker


_galois_warm_started = False


def warm_galois_async():
    """勾选人脸 / 声纹时后台预热 galois（只启动一次）。"""
    global _galois_warm_started
    if _galois_warm_started or _galois_module is not None:
        return
    _galois_warm_started = True
    run_async(get_galois, None, None)


# ====================== 通用 UI 组件 ======================
def _warn(parent, title: str, content: str):
    """统一的信息提示（非阻塞）。"""
    InfoBar.warning(
        title,
        content,
        parent=parent,
        position=InfoBarPosition.TOP_RIGHT,
        duration=2600,
    )


def _info(parent, title: str, content: str):
    InfoBar.info(
        title,
        content,
        parent=parent,
        position=InfoBarPosition.TOP_RIGHT,
        duration=2200,
    )


def _success(parent, title: str, content: str):
    InfoBar.success(
        title,
        content,
        parent=parent,
        position=InfoBarPosition.TOP_RIGHT,
        duration=2600,
    )


def _error_toast(parent, title: str, content: str):
    InfoBar.error(
        title,
        content,
        parent=parent,
        position=InfoBarPosition.TOP_RIGHT,
        duration=3200,
    )


class IconBadge(QWidget):
    """圆角底色 + Fluent 图标的小徽章。"""

    def __init__(self, icon, size: int = 40, radius: int = 10, parent=None):
        super().__init__(parent)
        self._icon = icon
        self._radius = radius
        self.setFixedSize(size, size)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        bg = QColor(themeColor())
        bg.setAlpha(52 if isDarkTheme() else 26)
        painter.setPen(Qt.NoPen)
        painter.setBrush(bg)
        painter.drawRoundedRect(QRectF(self.rect()), self._radius, self._radius)
        inset = max(6, self.width() // 5)
        drawIcon(self._icon, painter, self.rect().adjusted(inset, inset, -inset, -inset))


class StatusFooter(QWidget):
    """页面底部的状态栏。"""

    def __init__(self, text: str = "就绪", parent=None):
        super().__init__(parent)
        self.setFixedHeight(26)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(2, 0, 2, 0)
        layout.setSpacing(6)
        self.label = CaptionLabel(self)
        self.label.setText(text)
        layout.addWidget(self.label, 1)

    def setText(self, text: str):
        self.label.setText(text)


class BasePage(QWidget):
    """所有功能页的基类：统一页脚、拖拽与忙碌状态。"""

    def __init__(self, object_name: str, parent=None, status: str = "就绪"):
        super().__init__(parent)
        self.setObjectName(object_name)
        self.setAcceptDrops(True)
        self.vBoxLayout = QVBoxLayout(self)
        self.vBoxLayout.setContentsMargins(36, 22, 36, 12)
        self.vBoxLayout.setSpacing(14)
        self.footer = StatusFooter(status, self)
        self.progress = None

    # ---------- 布局 ----------
    def create_progress(self) -> IndeterminateProgressBar:
        self.progress = IndeterminateProgressBar(self, start=False)
        self.progress.setVisible(False)
        self.progress.setFixedHeight(4)
        return self.progress

    def finish_layout(self):
        if self.progress is not None:
            self.vBoxLayout.addWidget(self.progress)
        self.vBoxLayout.addWidget(self.footer)

    # ---------- 状态 ----------
    def setStatus(self, text: str):
        self.footer.setText(text)

    def setBusy(self, busy: bool):
        if self.progress is None:
            return
        self.progress.setVisible(busy)
        if busy:
            self.progress.start()
        else:
            self.progress.stop()

    # ---------- 拖拽 ----------
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def first_local_path(self, event):
        for url in event.mimeData().urls():
            if url.isLocalFile():
                return url.toLocalFile()
        return None


class DropZone(QFrame):
    """虚线拖拽区，点击可选择文件。"""

    clicked = Signal()
    dropped = Signal(str)

    NORMAL_QSS = """
        QFrame#dropZone {
            border: 2px dashed rgba(140, 140, 140, 150);
            border-radius: 12px;
            background: transparent;
        }
    """
    ACTIVE_QSS = """
        QFrame#dropZone {
            border: 2px dashed rgba(0, 120, 212, 220);
            border-radius: 12px;
            background: rgba(0, 120, 212, 18);
        }
    """

    def __init__(self, title: str, hint: str, parent=None):
        super().__init__(parent)
        self.setObjectName("dropZone")
        self.setAcceptDrops(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(140)
        self.setStyleSheet(self.NORMAL_QSS)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(6)
        layout.setAlignment(Qt.AlignCenter)

        icon = IconWidget(FluentIcon.CLOUD_DOWNLOAD, self)
        icon.setFixedSize(40, 40)
        layout.addWidget(icon, 0, Qt.AlignHCenter)

        self.titleLabel = StrongBodyLabel(self)
        self.titleLabel.setText(title)
        layout.addWidget(self.titleLabel, 0, Qt.AlignHCenter)

        self.hintLabel = CaptionLabel(self)
        self.hintLabel.setText(hint)
        layout.addWidget(self.hintLabel, 0, Qt.AlignHCenter)

    # ---------- 事件 ----------
    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mouseReleaseEvent(event)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            self.setStyleSheet(self.ACTIVE_QSS)
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragLeaveEvent(self, event):
        self.setStyleSheet(self.NORMAL_QSS)
        super().dragLeaveEvent(event)

    def dropEvent(self, event):
        self.setStyleSheet(self.NORMAL_QSS)
        for url in event.mimeData().urls():
            if url.isLocalFile():
                self.dropped.emit(url.toLocalFile())
                break
        event.acceptProposedAction()


class ActionCard(CardWidget):
    """主页上的功能入口卡片。"""

    clicked = Signal()

    def __init__(self, icon, title: str, desc: str, parent=None):
        super().__init__(parent)
        self.setFixedHeight(132)
        self.setCursor(Qt.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 14)
        layout.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(8)
        top.addWidget(IconBadge(icon, 40), 0, Qt.AlignLeft)
        top.addStretch(1)
        arrow = IconWidget(FluentIcon.CHEVRON_RIGHT_MED, self)
        arrow.setFixedSize(14, 14)
        top.addWidget(arrow, 0, Qt.AlignVCenter)
        layout.addLayout(top)

        self.titleLabel = StrongBodyLabel(self)
        self.titleLabel.setText(title)
        layout.addWidget(self.titleLabel)

        self.descLabel = CaptionLabel(self)
        self.descLabel.setText(desc)
        self.descLabel.setWordWrap(True)
        layout.addWidget(self.descLabel)
        layout.addStretch(1)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton and self.rect().contains(
            event.position().toPoint()
        ):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class SectionCard(CardWidget):
    """带标题的内容卡片。"""

    def __init__(self, title: str, subtitle: str = "", parent=None):
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(20, 16, 20, 18)
        self._layout.setSpacing(10)

        self.titleLabel = StrongBodyLabel(self)
        self.titleLabel.setText(title)
        self._layout.addWidget(self.titleLabel)

        if subtitle:
            self.subtitleLabel = CaptionLabel(self)
            self.subtitleLabel.setText(subtitle)
            self.subtitleLabel.setWordWrap(True)
            self._layout.addWidget(self.subtitleLabel)

    def addWidget(self, widget, stretch: int = 0):
        self._layout.addWidget(widget, stretch)
        return widget

    def addLayout(self, layout):
        self._layout.addLayout(layout)
        return layout


class FactorSelector(QWidget):
    """附加因子多选，状态写入共享 dict。"""

    def __init__(self, factors: dict, parent=None):
        super().__init__(parent)
        self.factors = factors
        self._boxes = {}

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(22)

        specs = [
            ("grid", "宫格密码", "5×5 宫格手势，至少连接 4 个点"),
            ("face", "人脸因子", "现场采集 3 张人脸，BCH 模糊提取"),
            ("voice", "声纹因子", "现场录制 3 段 3 秒语音"),
        ]
        for key, text, tip in specs:
            box = CheckBox(self)
            box.setText(text)
            box.setToolTip(tip)
            if key == "face" and not FACE_SUPPORT:
                box.setEnabled(False)
                box.setToolTip("当前构建未包含人脸模块（insightface / onnxruntime / opencv）")
                self.factors[key] = False
            elif key == "voice" and not VOICE_SUPPORT:
                box.setEnabled(False)
                box.setToolTip("当前构建未包含声纹模块（resemblyzer / sounddevice）")
                self.factors[key] = False
            box.toggled.connect(lambda checked, k=key: self._on_toggled(k, checked))
            layout.addWidget(box)
            self._boxes[key] = box

        layout.addStretch(1)
        self.sync()

    def _on_toggled(self, key: str, checked: bool):
        self.factors[key] = checked
        if checked and key in ("face", "voice"):
            warm_galois_async()

    def sync(self):
        for key, box in self._boxes.items():
            box.blockSignals(True)
            box.setChecked(bool(self.factors.get(key, False)))
            box.blockSignals(False)


class StrengthBar(QWidget):
    """密码强度条。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._score = 0
        self.setFixedHeight(6)

    def setScore(self, score: int):
        self._score = max(0, min(100, int(score)))
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)

        bg = QColor(140, 140, 140, 60)
        painter.setBrush(bg)
        painter.drawRoundedRect(QRectF(self.rect()), 3, 3)

        if self._score <= 0:
            return
        color = strength_color(self._score)
        painter.setBrush(color)
        width = self.width() * self._score / 100
        painter.drawRoundedRect(QRectF(0, 0, width, self.height()), 3, 3)


def calculate_strength(password: str) -> int:
    score = 0
    length = len(password)
    if length >= 8:
        score += 20
    if length >= 12:
        score += 10
    if length >= 16:
        score += 10
    if length >= 20:
        score += 10
    if re.search(r"[A-Z]", password):
        score += 15
    if re.search(r"[a-z]", password):
        score += 15
    if re.search(r"[0-9]", password):
        score += 15
    if re.search(r"[^A-Za-z0-9]", password):
        score += 15
    common_passwords = {
        "12345678",
        "password",
        "01234567",
        "1234567890",
        "abcd1234",
        "11111111",
    }
    if password.lower() in common_passwords:
        score = max(0, score - 30)
    return min(score, 100)


def strength_color(score: int) -> QColor:
    if score < 30:
        return QColor("#e74c3c")
    if score < 60:
        return QColor("#f39c12")
    if score < 80:
        return QColor("#aacc00")
    return QColor("#2ecc71")


def strength_text(score: int) -> str:
    if score < 30:
        return "弱"
    if score < 60:
        return "中"
    if score < 80:
        return "强"
    return "极强"


# ====================== 对话框基类 ======================
class FluentDialog(MaskDialogBase):
    """MaskDialogBase 的居中修正版：固定宽度、内容垂直布局、标准按钮。"""

    def __init__(self, parent, width: int = 460):
        super().__init__(parent)
        self._hBoxLayout.removeWidget(self.widget)
        self._hBoxLayout.addWidget(self.widget, 1, Qt.AlignCenter)
        self.widget.setFixedWidth(width)

        self.vBoxLayout = QVBoxLayout(self.widget)
        self.vBoxLayout.setContentsMargins(24, 22, 24, 20)
        self.vBoxLayout.setSpacing(14)

        self.setClosableOnMaskClicked(False)
        self.setModal(True)

        # 与 MessageBoxBase 一致的卡片背景、圆角与投影
        FluentStyleSheet.DIALOG.apply(self)
        self.setShadowEffect(60, (0, 10), QColor(0, 0, 0, 50))
        self.setMaskColor(QColor(0, 0, 0, 76))

    def add_title(self, title: str, subtitle: str = ""):
        self.titleLabel = SubtitleLabel(self.widget)
        self.titleLabel.setText(title)
        self.vBoxLayout.addWidget(self.titleLabel)

        if subtitle:
            self.subtitleLabel = BodyLabel(self.widget)
            self.subtitleLabel.setText(subtitle)
            self.subtitleLabel.setWordWrap(True)
            self.vBoxLayout.addWidget(self.subtitleLabel)

    def add_buttons(self, ok_text: str = "确定", cancel_text: str = "取消"):
        row = QHBoxLayout()
        row.setSpacing(10)
        row.addStretch(1)

        self.cancelButton = PushButton(self.widget)
        self.cancelButton.setText(cancel_text)
        self.cancelButton.clicked.connect(self.reject)

        self.okButton = PrimaryPushButton(self.widget)
        self.okButton.setText(ok_text)
        self.okButton.clicked.connect(self._on_accept_clicked)

        row.addWidget(self.cancelButton)
        row.addWidget(self.okButton)
        self.vBoxLayout.addLayout(row)

    def add_error_label(self):
        self.errorLabel = CaptionLabel(self.widget)
        self.errorLabel.setText("")
        self.errorLabel.setStyleSheet("color: #e74c3c;")
        self.errorLabel.setVisible(False)
        self.vBoxLayout.addWidget(self.errorLabel)

    def show_inline_error(self, text: str):
        if hasattr(self, "errorLabel"):
            self.errorLabel.setText(text)
            self.errorLabel.setVisible(bool(text))

    def _on_accept_clicked(self):
        if self.validate():
            self.accept()

    def validate(self) -> bool:
        return True


# ====================== 密码对话框 ======================
class PasswordDialog(FluentDialog):
    def __init__(self, parent, title: str, prompt: str, show_strength: bool = True):
        super().__init__(parent, 460)
        self.add_title(title, prompt)

        self.passwordEdit = PasswordLineEdit(self.widget)
        self.passwordEdit.setPlaceholderText("请输入密码")
        self.passwordEdit.setClearButtonEnabled(True)
        self.passwordEdit.returnPressed.connect(self._on_accept_clicked)
        self.vBoxLayout.addWidget(self.passwordEdit)

        self.show_strength = show_strength
        if show_strength:
            self.strengthBar = StrengthBar(self.widget)
            self.vBoxLayout.addWidget(self.strengthBar)

            self.strengthLabel = CaptionLabel(self.widget)
            self.strengthLabel.setText("密码强度：无")
            self.vBoxLayout.addWidget(self.strengthLabel)
            self.passwordEdit.textChanged.connect(self._update_strength)

        self.add_error_label()
        self.add_buttons("确定", "取消")
        self.passwordEdit.setFocus()

    def _update_strength(self, text: str):
        score = calculate_strength(text)
        self.strengthBar.setScore(score)
        self.strengthLabel.setText(
            f"密码强度：{strength_text(score)}（{score}%）"
            if text
            else "密码强度：无"
        )

    def validate(self) -> bool:
        if not self.passwordEdit.text():
            self.show_inline_error("密码不能为空")
            return False
        self.show_inline_error("")
        return True

    def password(self) -> str:
        return self.passwordEdit.text()

    @classmethod
    def ask(cls, parent, title: str, prompt: str, show_strength: bool = True):
        dialog = cls(parent, title, prompt, show_strength)
        if dialog.exec() == QDialog.Accepted:
            return dialog.password()
        return None


# ====================== 5×5 宫格签名 ======================
class GridPadWidget(QWidget):
    """5×5 宫格手势画板（QPainter 重绘版）。"""

    changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scale = 1.62
        self.cell = (GRID_POINT_SIZE + GRID_SPACING) * self.scale
        side = int(GRID_SIZE * self.cell + GRID_SPACING * self.scale)
        self.setFixedSize(side, side)
        self.setCursor(Qt.CrossCursor)

        self.points = {}
        start = GRID_SPACING * self.scale + self.cell / 2
        for row in range(GRID_SIZE):
            for col in range(GRID_SIZE):
                self.points[(row, col)] = QPointF(
                    start + col * self.cell, start + row * self.cell
                )

        self.selected = []

    # ---------- 绘制 ----------
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        bg = QColor(38, 38, 38) if isDarkTheme() else QColor(255, 255, 255)
        painter.setPen(Qt.NoPen)
        painter.setBrush(bg)
        painter.drawRoundedRect(QRectF(self.rect()), 10, 10)

        radius = GRID_POINT_SIZE * 0.52 * self.scale
        idle_fill = QColor(90, 90, 90) if isDarkTheme() else QColor(206, 206, 206)
        idle_line = QColor(120, 120, 120) if isDarkTheme() else QColor(130, 130, 130)
        text_color = QColor(220, 220, 220) if isDarkTheme() else QColor(90, 90, 90)

        # 底图：所有点位 + 坐标
        font = QFont(self.font())
        font.setPointSizeF(6.2)
        font.setBold(False)
        for (row, col), pos in self.points.items():
            painter.setPen(QPen(idle_line, 1.4))
            painter.setBrush(idle_fill)
            painter.drawEllipse(pos, radius, radius)
            painter.setPen(text_color)
            painter.setFont(font)
            painter.drawText(
                QRectF(
                    pos.x() - radius,
                    pos.y() - radius,
                    radius * 2,
                    radius * 2,
                ),
                Qt.AlignCenter,
                f"{row + 1},{col + 1}",
            )

        if not self.selected:
            return

        # 连线
        painter.setPen(QPen(QColor("#44dd00"), 3.4, Qt.SolidLine, Qt.RoundCap))
        painter.setBrush(Qt.NoBrush)
        for i in range(1, len(self.selected)):
            painter.drawLine(
                self.points[self.selected[i - 1]], self.points[self.selected[i]]
            )

        # 选中点与序号
        number_font = QFont(self.font())
        number_font.setPointSizeF(8.5)
        number_font.setBold(True)
        for index, key in enumerate(self.selected):
            pos = self.points[key]
            painter.setPen(QPen(QColor("#22bb00"), 2))
            painter.setBrush(QColor("#44dd00"))
            painter.drawEllipse(pos, radius, radius)
            painter.setPen(QColor("white"))
            painter.setFont(number_font)
            painter.drawText(
                QRectF(pos.x() - radius, pos.y() - radius, radius * 2, radius * 2),
                Qt.AlignCenter,
                str(index + 1),
            )

    # ---------- 交互 ----------
    def mousePressEvent(self, event):
        if event.button() != Qt.LeftButton:
            return
        pos = event.position()
        radius = GRID_POINT_SIZE * 0.55 * self.scale
        for key, point in self.points.items():
            if (pos - point).manhattanLength() <= radius * 1.6:
                if (pos.x() - point.x()) ** 2 + (pos.y() - point.y()) ** 2 <= radius**2:
                    if not self.selected or self.selected[-1] != key:
                        self.selected.append(key)
                        self.changed.emit()
                        self.update()
                    return

    # ---------- 数据 ----------
    def clear(self):
        self.selected.clear()
        self.changed.emit()
        self.update()

    def signature_string(self) -> str:
        return "+".join(f"({row + 1},{col + 1})" for row, col in self.selected)

    def signature_data(self) -> dict:
        signature_str = self.signature_string()
        return {
            "version": "1.0",
            "grid_size": GRID_SIZE,
            "signature_string": signature_str,
            "point_sequence": self.selected,
            "sequence_length": len(self.selected),
            "created_at": time.time(),
            "hash": hashlib.sha256(signature_str.encode()).hexdigest(),
        }


def parse_signature_string(signature_str: str):
    if not signature_str:
        return []
    points = []
    for row_str, col_str in re.findall(r"\((\d+),(\d+)\)", signature_str):
        row, col = int(row_str) - 1, int(col_str) - 1
        if 0 <= row < GRID_SIZE and 0 <= col < GRID_SIZE:
            points.append((row, col))
    return points


class GridPadDialog(FluentDialog):
    def __init__(self, parent, title: str = "宫格密码", existing_signature=None):
        super().__init__(parent, 360)
        self.existing_signature = existing_signature
        self.is_verified = False
        self.result = None

        prompt = (
            "请按之前设置的顺序点击宫格点完成验证"
            if existing_signature
            else "请按顺序点击宫格点完成连接（至少选择 4 格）"
        )
        self.add_title(title, prompt)

        self.pad = GridPadWidget(self.widget)
        self.vBoxLayout.addWidget(self.pad, 0, Qt.AlignHCenter)
        self.pad.changed.connect(self._update_label)

        self.pointLabel = CaptionLabel(self.widget)
        self.pointLabel.setText("已选点：无")
        self.vBoxLayout.addWidget(self.pointLabel)

        self.add_error_label()

        row = QHBoxLayout()
        row.setSpacing(10)
        clearButton = PushButton(self.widget)
        clearButton.setText("清除")
        clearButton.clicked.connect(self.pad.clear)
        row.addWidget(clearButton)
        row.addStretch(1)

        self.cancelButton = PushButton(self.widget)
        self.cancelButton.setText("取消")
        self.cancelButton.clicked.connect(self.reject)
        row.addWidget(self.cancelButton)

        self.okButton = PrimaryPushButton(self.widget)
        self.okButton.setText("确定")
        self.okButton.clicked.connect(self._on_accept_clicked)
        row.addWidget(self.okButton)
        self.vBoxLayout.addLayout(row)

        self._update_label()

    def _update_label(self):
        if not self.pad.selected:
            self.pointLabel.setText("已选点：无")
            return
        text = "+".join(f"({r + 1},{c + 1})" for r, c in self.pad.selected)
        self.pointLabel.setText("已选点：" + text)

    def validate(self) -> bool:
        if len(self.pad.selected) < 4:
            self.show_inline_error("至少需要选择 4 个点完成连接")
            return False

        if self.existing_signature:
            reference = self.existing_signature.get("signature_string", "")
            if self.pad.selected != parse_signature_string(reference):
                self.show_inline_error("宫格连接顺序不匹配，验证失败")
                self.pad.clear()
                return False
            self.is_verified = True

        self.result = self.pad.signature_data()
        return True

    @classmethod
    def ask(cls, parent, title: str, existing_signature=None):
        dialog = cls(parent, title, existing_signature)
        if dialog.exec() == QDialog.Accepted:
            return dialog.result
        return None


# ====================== 错误 / 关于 ======================
class ErrorDialog(MessageBoxBase):
    """可滚动的详细错误窗口（替代 Tk 版 ScrolledText 窗口）。"""

    def __init__(self, parent, title: str, detail: str):
        super().__init__(parent)

        self.titleLabel = SubtitleLabel(self)
        self.titleLabel.setText(title)
        self.viewLayout.addWidget(self.titleLabel)

        self.detailEdit = PlainTextEdit(self)
        self.detailEdit.setReadOnly(True)
        self.detailEdit.setPlainText(detail)
        self.detailEdit.setFixedHeight(360)
        self.detailEdit.setStyleSheet(
            "font-family: Consolas, 'Cascadia Mono', 'Courier New', monospace;"
        )
        self.viewLayout.addWidget(self.detailEdit)

        self.widget.setMinimumWidth(780)
        self.yesButton.setText("关闭")
        self.cancelButton.hide()
        self.buttonLayout.insertStretch(0, 1)
        self.buttonLayout.addStretch(1)
        self.yesButton.setFixedWidth(160)


def show_error_detail(parent, title: str, detail: str):
    logging.error("%s: %s", title, detail)
    dialog = ErrorDialog(parent, title, detail)
    dialog.exec()


def ask_confirm(parent, title: str, content: str) -> bool:
    box = MessageBox(title, content, parent)
    return box.exec() == QDialog.Accepted


# ====================== 人脸模型下载 ======================
class _ModelDownloadCancelled(Exception):
    pass


class FaceModelDownloadWorker(QThread):
    """带进度、断点续传和超时的模型下载线程。"""

    progress = Signal(int, str)
    succeeded = Signal(str)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, target_dir: str):
        super().__init__()
        self.target_dir = target_dir
        self._cancel = threading.Event()

    def cancel(self):
        self._cancel.set()

    def _check_cancel(self):
        if self._cancel.is_set():
            raise _ModelDownloadCancelled()

    def run(self):
        try:
            import requests  # 延迟导入，避免拖慢冷启动

            os.makedirs(self.target_dir, exist_ok=True)
            total = len(FACE_MODEL_FILES)
            for index, name in enumerate(FACE_MODEL_FILES):
                self._check_cancel()
                destination = os.path.join(self.target_dir, name)
                if self._is_valid(name, destination):
                    continue
                self._download_one(name, destination, index, total, requests)

            if not face_model_dir_ready(self.target_dir):
                raise RuntimeError("模型文件不完整，请重试")
            self.succeeded.emit(self.target_dir)
        except _ModelDownloadCancelled:
            self.cancelled.emit()
        except Exception:
            logging.error("人脸模型下载失败: %s", traceback.format_exc())
            self.failed.emit(traceback.format_exc())

    @staticmethod
    def _is_valid(name: str, path: str) -> bool:
        try:
            size = os.path.getsize(path)
        except OSError:
            return False
        expected = FACE_MODEL_SIZES.get(name)
        if expected:
            return size == expected
        return size >= FACE_MODEL_MIN_BYTES

    def _download_one(self, name, destination, index, total, requests):
        part = destination + ".part"
        expected = FACE_MODEL_SIZES.get(name)
        if expected and os.path.exists(part) and os.path.getsize(part) == expected:
            os.replace(part, destination)
            return

        last_error = None
        for url in FACE_MODEL_URLS[name]:
            self._check_cancel()
            try:
                self._download_url(url, part, name, index, total, requests)
                os.replace(part, destination)
                return
            except _ModelDownloadCancelled:
                raise
            except Exception as exc:
                last_error = exc
                logging.warning("模型下载源失败 %s: %s", url, exc)
        raise RuntimeError(f"{name} 下载失败：{last_error}")

    def _download_url(self, url, part, name, index, total, requests):
        existing = os.path.getsize(part) if os.path.exists(part) else 0
        headers = {"Range": f"bytes={existing}-"} if existing else {}

        with requests.get(
            url, stream=True, timeout=(15, 45), headers=headers
        ) as response:
            response.raise_for_status()

            if existing and response.status_code == 206:
                mode = "ab"
                total_bytes = existing + int(response.headers.get("Content-Length") or 0)
            else:
                existing = 0
                mode = "wb"
                total_bytes = int(response.headers.get("Content-Length") or 0)

            done = existing
            started = time.time()
            with open(part, mode) as f:
                for chunk in response.iter_content(chunk_size=262144):
                    self._check_cancel()
                    if not chunk:
                        continue
                    f.write(chunk)
                    done += len(chunk)
                    percent = int(done * 100 / total_bytes) if total_bytes else 0
                    elapsed = max(time.time() - started, 0.001)
                    speed = (done - existing) / elapsed / (1024 * 1024)
                    self.progress.emit(
                        percent,
                        f"正在下载 {name}（{index + 1}/{total}）  "
                        f"{done / 1048576:.1f} / {total_bytes / 1048576:.1f} MB  "
                        f"{speed:.2f} MB/s",
                    )

            if total_bytes and done < total_bytes:
                raise IOError(f"下载不完整（{done}/{total_bytes} 字节）")


class FaceModelDialog(FluentDialog):
    """模型缺失时的引导窗口：自动下载 / 选择本地文件夹。"""

    def __init__(self, parent, current_dir=None):
        super().__init__(parent, 620)
        self.model_dir = current_dir
        self._worker = None
        self._downloading = False
        self._target_dir = face_model_install_dir()

        self.add_title(
            "人脸模型已就绪" if current_dir else "人脸模型未就绪",
            "人脸因子需要 buffalo_l 中的检测与识别模型（约 191 MB）。"
            "可以从镜像自动下载，也可以选择本地已经下载好的模型文件夹。",
        )

        pathLabel = CaptionLabel(self.widget)
        if current_dir:
            pathLabel.setText(f"当前模型目录：{current_dir}")
        else:
            pathLabel.setText(f"默认安装位置：{self._target_dir}")
        pathLabel.setWordWrap(True)
        pathLabel.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.vBoxLayout.addWidget(pathLabel)

        self.progressBar = ProgressBar(self.widget)
        self.progressBar.setValue(0)
        self.progressBar.setVisible(False)
        self.vBoxLayout.addWidget(self.progressBar)

        self.statusLabel = CaptionLabel(self.widget)
        self.statusLabel.setText(
            "提示：自动下载会依次尝试多个镜像，支持断点续传，可随时停止。"
        )
        self.statusLabel.setWordWrap(True)
        self.vBoxLayout.addWidget(self.statusLabel)

        self.add_error_label()

        row = QHBoxLayout()
        row.setSpacing(10)
        row.addStretch(1)

        self.cancelButton = PushButton(self.widget)
        self.cancelButton.setText("取消")
        self.cancelButton.clicked.connect(self._on_cancel_clicked)
        row.addWidget(self.cancelButton)

        self.chooseButton = PushButton(self.widget)
        self.chooseButton.setText("选择本地文件夹…")
        self.chooseButton.clicked.connect(self._choose_folder)
        row.addWidget(self.chooseButton)

        self.downloadButton = PrimaryPushButton(self.widget)
        self.downloadButton.setText("自动下载")
        self.downloadButton.clicked.connect(self._start_download)
        row.addWidget(self.downloadButton)
        self.vBoxLayout.addLayout(row)

    # ---------- 下载 ----------
    def _start_download(self):
        if self._downloading:
            return
        self._downloading = True
        self.show_inline_error("")
        self.downloadButton.setEnabled(False)
        self.chooseButton.setEnabled(False)
        self.cancelButton.setText("停止下载")
        self.progressBar.setValue(0)
        self.progressBar.setVisible(True)
        self.statusLabel.setText("正在连接镜像…")

        self._worker = FaceModelDownloadWorker(self._target_dir)
        self._worker.progress.connect(self._on_progress)
        self._worker.succeeded.connect(self._on_success)
        self._worker.failed.connect(self._on_failed)
        self._worker.cancelled.connect(self._on_cancelled)
        self._worker.start()

    def _on_progress(self, percent: int, text: str):
        self.progressBar.setValue(percent)
        self.statusLabel.setText(text)

    def _on_success(self, path: str):
        self._downloading = False
        self._worker = None
        self.model_dir = path
        save_config({"face_model_dir": path})
        self.progressBar.setValue(100)
        self.statusLabel.setText(f"下载完成：{path}")
        self.accept()

    def _on_failed(self, detail: str):
        self._downloading = False
        self._worker = None
        self._reset_buttons()
        self.progressBar.setVisible(False)
        self.statusLabel.setText("下载失败，可以重试，或选择本地模型文件夹。")
        first_line = detail.strip().splitlines()[-1] if detail.strip() else "未知错误"
        self.show_inline_error(f"下载失败：{first_line}")

    def _on_cancelled(self):
        self._downloading = False
        self._worker = None
        self._reset_buttons()
        self.progressBar.setVisible(False)
        self.statusLabel.setText("已停止下载，可以稍后重试。")

    def _reset_buttons(self):
        self.downloadButton.setEnabled(True)
        self.chooseButton.setEnabled(True)
        self.cancelButton.setText("取消")

    def _stop_worker(self):
        if self._worker is not None:
            self._worker.cancel()
            self._worker.wait(4000)
            self._worker = None
        self._downloading = False

    def _on_cancel_clicked(self):
        if self._downloading:
            self._stop_worker()
            self._reset_buttons()
            self.progressBar.setVisible(False)
            self.statusLabel.setText("已停止下载，可以稍后重试。")
        else:
            self.reject()

    # ---------- 手动选择 ----------
    def _choose_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self, "选择包含 det_10g.onnx 与 w600k_r50.onnx 的文件夹"
        )
        if not folder:
            return
        if not face_model_dir_ready(folder):
            self.show_inline_error(
                "该文件夹缺少 det_10g.onnx 或 w600k_r50.onnx，或文件不完整。"
            )
            return
        folder = os.path.abspath(folder)
        save_config({"face_model_dir": folder})
        self.model_dir = folder
        self.accept()

    def done(self, code):
        self._stop_worker()
        super().done(code)


def ensure_face_model(parent):
    """确保本地有人脸模型；缺失时弹出下载/选择窗口。"""
    if not FACE_SUPPORT:
        _warn(
            parent,
            "人脸模块不可用",
            "当前安装缺少 insightface / onnxruntime / opencv，"
            "请安装完整依赖，或使用包含人脸模块的 EXE。",
        )
        return None

    model_dir = resolve_face_model_dir()
    if model_dir:
        return model_dir

    dialog = FaceModelDialog(parent)
    if dialog.exec() == QDialog.Accepted:
        return dialog.model_dir
    return None


# ====================== 人脸识别 ======================
class FaceAuthManager:
    """InsightFace 单例封装（模型延迟加载，失败可降级到 CPU）。"""

    _instance = None
    _face_app = None

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def load_model(self, model_dir=None):
        if self._face_app is not None:
            return True, "模型已加载"

        try:
            from insightface.app import FaceAnalysis
        except Exception as exc:
            return False, f"未安装 insightface 或依赖缺失：{exc}"

        model_dir = model_dir or resolve_face_model_dir()
        if not model_dir:
            return False, "未找到人脸模型，请先下载或选择模型文件夹"

        model_dir = os.path.abspath(model_dir)
        root = face_model_root(model_dir)
        common = {
            "allowed_modules": ["detection", "recognition"],
        }

        def build(providers):
            if root:
                return FaceAnalysis(
                    name=FACE_MODEL_NAME,
                    root=root,
                    providers=providers,
                    **common,
                )
            # insightface >= 0.7.3 支持直接把模型目录传进去，避免触发下载
            return FaceAnalysis(name=model_dir, providers=providers, **common)

        try:
            import onnxruntime as ort

            dml_available = "DmlExecutionProvider" in ort.get_available_providers()
        except Exception:
            dml_available = False

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            try:
                if dml_available:
                    face_app = build(["DmlExecutionProvider"])
                    face_app.prepare(ctx_id=0, det_size=(640, 640))
                    actual = self._session_providers(face_app)
                    if "DmlExecutionProvider" in actual:
                        self._face_app = face_app
                        return True, "人脸识别已启用 GPU（DirectML）加速"
                    # 驱动不可用时 onnxruntime 会静默退回 CPU，继续走 CPU 分支
                    face_app = build(["CPUExecutionProvider"])
                    face_app.prepare(ctx_id=-1, det_size=(640, 640))
                else:
                    face_app = build(["CPUExecutionProvider"])
                    face_app.prepare(ctx_id=-1, det_size=(640, 640))

                self._face_app = face_app
                return True, "未检测到 GPU 加速，将使用 CPU 进行人脸识别，速度可能较慢"
            except Exception as exc:
                logging.error("人脸模型加载失败: %s", traceback.format_exc())
                return False, f"人脸模型加载失败：{exc}"

    @staticmethod
    def _session_providers(face_app):
        try:
            session = face_app.det_model.session
            return list(session.get_providers())
        except Exception:
            return []

    def extract_feature(self, frame):
        if self._face_app is None:
            return None
        faces = self._face_app.get(frame)
        if not faces:
            return None
        best_face = max(faces, key=lambda f: f.det_score)
        return best_face.embedding.copy()

    @staticmethod
    def calc_similarity(feat1, feat2):
        return np.dot(feat1, feat2) / (
            np.linalg.norm(feat1) * np.linalg.norm(feat2)
        )


class FaceAuthDialog(FluentDialog):
    """摄像头预览 + 采集 / 比对。"""

    def __init__(
        self,
        parent,
        mode="collect",
        reference_features=None,
        title="人脸验证",
        model_dir=None,
    ):
        super().__init__(parent, 560)
        self.mode = mode
        self.reference_features = reference_features or []
        self.model_dir = model_dir
        self.result = None
        self.is_verified = False
        self.collected_features = []
        self.capture_count = 0
        self.current_frame = None
        self._cap = None
        self._closed = False
        self._confirm_stage = False

        self._timer = QTimer(self)
        self._timer.setInterval(33)
        self._timer.timeout.connect(self._update_preview)

        prompt = (
            "请正对摄像头，点击按钮采集第 1 张人脸（共 3 张）"
            if mode == "collect"
            else "请正对摄像头，点击按钮完成人脸验证"
        )
        self.add_title(title, prompt)

        self.previewLabel = QLabel(self.widget)
        self.previewLabel.setFixedSize(*FACE_PREVIEW_SIZE)
        self.previewLabel.setAlignment(Qt.AlignCenter)
        self.previewLabel.setStyleSheet(
            "background: #101010; border-radius: 8px; color: #888;"
        )
        self.previewLabel.setText("正在加载人脸模型…")
        self.vBoxLayout.addWidget(self.previewLabel, 0, Qt.AlignHCenter)

        self.statusLabel = CaptionLabel(self.widget)
        self.statusLabel.setText("正在初始化，请稍候…")
        self.vBoxLayout.addWidget(self.statusLabel)

        self.resultLabel = CaptionLabel(self.widget)
        self.resultLabel.setText("")
        self.vBoxLayout.addWidget(self.resultLabel)

        row = QHBoxLayout()
        row.setSpacing(10)
        row.addStretch(1)

        self.cancelButton = PushButton(self.widget)
        self.cancelButton.setText("取消")
        self.cancelButton.clicked.connect(self.reject)
        row.addWidget(self.cancelButton)

        self.captureButton = PrimaryPushButton(self.widget)
        self.captureButton.setText("拍照采集")
        self.captureButton.setEnabled(False)
        self.captureButton.clicked.connect(self._on_capture)
        row.addWidget(self.captureButton)
        self.vBoxLayout.addLayout(row)

        run_async(
            lambda: FaceAuthManager.instance().load_model(self.model_dir),
            self._on_model_loaded,
            self._on_load_failed,
        )

    # ---------- 初始化 ----------
    def _on_model_loaded(self, result):
        if self._closed:
            return
        ok, message = result
        if not ok:
            self._fail(message)
            return

        try:
            import cv2

            backend = cv2.CAP_DSHOW if sys.platform == "win32" else 0
            cap = cv2.VideoCapture(0, backend)
            if not cap.isOpened():
                cap.release()
                cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                cap.release()
                self._fail("无法打开摄像头设备，请检查摄像头是否被占用")
                return
            self._cap = cap
        except Exception as exc:
            self._fail(f"摄像头初始化失败：{exc}")
            return

        self.previewLabel.setText("")
        self.statusLabel.setText(message)
        self.captureButton.setEnabled(True)
        self._timer.start()

    def _on_load_failed(self, detail: str):
        if self._closed:
            return
        logging.error("人脸初始化失败: %s", detail)
        self._fail("人脸模块初始化失败，详情见错误日志")

    def _fail(self, message: str):
        self.statusLabel.setText(message)
        self.statusLabel.setStyleSheet("color: #e74c3c;")
        self.captureButton.setEnabled(False)

    # ---------- 预览 ----------
    def _update_preview(self):
        if self._cap is None:
            return
        try:
            import cv2

            ret, frame = self._cap.read()
            if not ret or frame is None:
                return
            self.current_frame = frame
            small = cv2.resize(frame, FACE_PREVIEW_SIZE)
            rgb = cv2.cvtColor(small, cv2.COLOR_BGR2RGB)
            height, width = rgb.shape[:2]
            image = QImage(
                rgb.data, width, height, 3 * width, QImage.Format_RGB888
            ).copy()
            self.previewLabel.setPixmap(QPixmap.fromImage(image))
        except Exception:
            logging.error("预览更新异常: %s", traceback.format_exc())
            self._timer.stop()

    # ---------- 采集 / 比对 ----------
    def _on_capture(self):
        if self._confirm_stage:
            self._confirm_collect()
            return

        if self.current_frame is None:
            self.statusLabel.setText("尚未获取到画面，请稍候再试")
            return

        manager = FaceAuthManager.instance()
        try:
            feature = manager.extract_feature(self.current_frame)
        except Exception:
            logging.error("人脸特征提取失败: %s", traceback.format_exc())
            self.statusLabel.setText("人脸特征提取失败，请重试")
            return

        if feature is None:
            self.statusLabel.setText("未检测到人脸，请正对摄像头")
            return

        if self.mode == "collect":
            self.collected_features.append(feature)
            self.capture_count += 1
            self.resultLabel.setText(f"✅ 第 {self.capture_count} 张采集成功")
            if self.capture_count < 3:
                remaining = 3 - self.capture_count
                self.statusLabel.setText(
                    f"继续采集第 {self.capture_count + 1} 张人脸（共 3 张，还差 {remaining} 张）"
                )
            else:
                self.statusLabel.setText("3 张人脸采集完成，可以确认使用")
                self.captureButton.setText("确认使用")
                self._confirm_stage = True
        else:
            similarities = [
                manager.calc_similarity(feature, ref)
                for ref in self.reference_features
            ]
            avg_similarity = float(np.mean(similarities)) if similarities else 0.0
            self.is_verified = avg_similarity >= FACE_SIMILARITY_THRESHOLD
            self.result = self.is_verified
            if self.is_verified:
                self.resultLabel.setText(f"✅ 验证通过  相似度：{avg_similarity:.4f}")
                self.resultLabel.setStyleSheet("color: #2e7d32;")
                self.captureButton.setEnabled(False)
                self.statusLabel.setText("验证成功")
                QTimer.singleShot(700, self.accept)
            else:
                self.resultLabel.setText(f"❌ 验证失败  相似度：{avg_similarity:.4f}")
                self.resultLabel.setStyleSheet("color: #c62828;")
                self.statusLabel.setText("请调整光线与角度后重试")

    def _confirm_collect(self):
        avg_feature = np.mean(self.collected_features, axis=0)
        self.result = {
            "features": self.collected_features,
            "avg": avg_feature,
            "count": self.capture_count,
        }
        self.accept()

    # ---------- 资源释放 ----------
    def _shutdown(self):
        self._closed = True
        self._timer.stop()
        if self._cap is not None:
            try:
                self._cap.release()
            except Exception:
                logging.error("摄像头释放异常: %s", traceback.format_exc())
            self._cap = None

    def done(self, code):
        self._shutdown()
        super().done(code)

    def closeEvent(self, event):
        self._shutdown()
        super().closeEvent(event)

    @classmethod
    def ask(cls, parent, mode="collect", reference_features=None, title="人脸验证"):
        model_dir = ensure_face_model(parent)
        if not model_dir:
            return None, False
        dialog = cls(
            parent, mode, reference_features, title, model_dir=model_dir
        )
        accepted = dialog.exec() == QDialog.Accepted
        return dialog.result, (accepted and bool(dialog.result))


# ====================== 声纹识别 ======================
def _patch_numba_cache_for_frozen():
    """frozen 环境中 librosa 的 numba cache=True 找不到源文件，去掉缓存参数。"""
    try:
        import numba
    except Exception:
        return
    for name in ("jit", "njit", "vectorize", "guvectorize"):
        original = getattr(numba, name, None)
        if original is None or getattr(original, "_guifei_patched", False):
            continue

        def wrapper(*args, __orig=original, **kwargs):
            kwargs.pop("cache", None)
            return __orig(*args, **kwargs)

        wrapper._guifei_patched = True
        setattr(numba, name, wrapper)


class VoiceAuthManager:
    _encoder = None

    @classmethod
    def get_encoder(cls):
        if cls._encoder is None:
            _patch_numba_cache_for_frozen()
            from resemblyzer import VoiceEncoder

            cls._encoder = VoiceEncoder()
        return cls._encoder

    @staticmethod
    def record_audio(duration=VOICE_DURATION, sample_rate=VOICE_SAMPLE_RATE):
        import sounddevice as sd

        recording = sd.rec(
            int(duration * sample_rate),
            samplerate=sample_rate,
            channels=1,
            dtype="float32",
        )
        sd.wait()
        return recording.flatten()

    @staticmethod
    def extract_embedding(audio, sample_rate=VOICE_SAMPLE_RATE):
        from resemblyzer import preprocess_wav

        wav = preprocess_wav(audio, source_sr=sample_rate)
        return VoiceAuthManager.get_encoder().embed_utterance(wav)

    @staticmethod
    def calc_similarity(embed1, embed2):
        embed1 = embed1 / np.linalg.norm(embed1)
        embed2 = embed2 / np.linalg.norm(embed2)
        return float(np.dot(embed1, embed2))


class VoiceAuthDialog(FluentDialog):
    """录音采集 + 声纹比对。"""

    def __init__(self, parent, mode="collect", reference_embeddings=None, title="声纹验证"):
        super().__init__(parent, 480)
        self.mode = mode
        self.reference_embeddings = reference_embeddings or []
        self.result = None
        self.is_verified = False
        self.collected_embeddings = []
        self.capture_count = 0
        self._closed = False
        self._confirm_stage = False
        self._recording = False

        prompt = (
            "请点击按钮录制声音（每次 3 秒，共 3 次）"
            if mode == "collect"
            else "请点击按钮录制声音以验证身份"
        )
        self.add_title(title, prompt)

        iconRow = QHBoxLayout()
        iconRow.addStretch(1)
        iconRow.addWidget(IconBadge(FluentIcon.MICROPHONE, 64, 16, self.widget))
        iconRow.addStretch(1)
        self.vBoxLayout.addLayout(iconRow)
        self.vBoxLayout.addSpacing(4)

        self.statusLabel = BodyLabel(self.widget)
        self.statusLabel.setAlignment(Qt.AlignCenter)
        self.statusLabel.setText("准备就绪")
        self.vBoxLayout.addWidget(self.statusLabel)

        self.progressLabel = CaptionLabel(self.widget)
        self.progressLabel.setAlignment(Qt.AlignCenter)
        self.progressLabel.setText("")
        self.vBoxLayout.addWidget(self.progressLabel)

        row = QHBoxLayout()
        row.setSpacing(10)
        row.addStretch(1)

        self.cancelButton = PushButton(self.widget)
        self.cancelButton.setText("取消")
        self.cancelButton.clicked.connect(self.reject)
        row.addWidget(self.cancelButton)

        self.recordButton = PrimaryPushButton(self.widget)
        self.recordButton.setText("开始录音")
        self.recordButton.clicked.connect(self._on_record)
        row.addWidget(self.recordButton)
        self.vBoxLayout.addLayout(row)

    # ---------- 录音 ----------
    def _on_record(self):
        if self._confirm_stage:
            self._confirm_collect()
            return
        if self._recording:
            return

        self._recording = True
        self.recordButton.setEnabled(False)
        self.recordButton.setText("录音中…")
        self.statusLabel.setText("正在录音，请说话…")
        self.progressLabel.setText("")

        run_async(self._record_job, self._on_recorded, self._on_record_failed)

    @staticmethod
    def _record_job():
        audio = VoiceAuthManager.record_audio()
        return VoiceAuthManager.extract_embedding(audio)

    def _on_record_failed(self, detail: str):
        logging.error("录音失败: %s", detail)
        if self._closed:
            return
        self._recording = False
        self.recordButton.setEnabled(True)
        self.recordButton.setText("开始录音")
        self.statusLabel.setText("录音失败，请检查麦克风设备")
        self.progressLabel.setText("详情已写入日志")
        self.progressLabel.setStyleSheet("color: #e74c3c;")

    def _on_recorded(self, embedding):
        if self._closed:
            return
        self._recording = False
        self.recordButton.setEnabled(True)
        self.recordButton.setText("开始录音")
        self.progressLabel.setStyleSheet("")

        if self.mode == "collect":
            self.collected_embeddings.append(embedding)
            self.capture_count += 1
            self.progressLabel.setText(f"✅ 第 {self.capture_count} 次录音成功")
            if self.capture_count < 3:
                self.statusLabel.setText(
                    f"继续录制第 {self.capture_count + 1} 次声音（共 3 次）"
                )
            else:
                self.statusLabel.setText("3 次声音录制完成，可以确认使用")
                self.recordButton.setText("确认使用")
                self._confirm_stage = True
        else:
            similarities = [
                VoiceAuthManager.calc_similarity(embedding, ref)
                for ref in self.reference_embeddings
            ]
            avg_similarity = float(np.mean(similarities)) if similarities else 0.0
            self.is_verified = avg_similarity >= VOICE_EMBEDDING_THRESHOLD
            self.result = self.is_verified
            if self.is_verified:
                self.progressLabel.setText(f"✅ 验证通过  相似度：{avg_similarity:.4f}")
                self.progressLabel.setStyleSheet("color: #2e7d32;")
                self.statusLabel.setText("验证成功")
                self.recordButton.setEnabled(False)
                QTimer.singleShot(700, self.accept)
            else:
                self.progressLabel.setText(f"❌ 验证失败  相似度：{avg_similarity:.4f}")
                self.progressLabel.setStyleSheet("color: #c62828;")
                self.statusLabel.setText("请保持环境安静后重试")

    def _confirm_collect(self):
        avg_embedding = np.mean(self.collected_embeddings, axis=0)
        self.result = {
            "embeddings": self.collected_embeddings,
            "avg": avg_embedding,
            "count": self.capture_count,
        }
        self.accept()

    def done(self, code):
        self._closed = True
        super().done(code)

    @classmethod
    def ask(cls, parent, mode="collect", reference_embeddings=None, title="声纹验证"):
        dialog = cls(parent, mode, reference_embeddings, title)
        accepted = dialog.exec() == QDialog.Accepted
        return dialog.result, (accepted and bool(dialog.result))


# ====================== 页面辅助 ======================
def build_page_header(page: QWidget, title: str, desc: str = ""):
    box = QVBoxLayout()
    box.setSpacing(4)
    titleLabel = SubtitleLabel(page)
    titleLabel.setText(title)
    box.addWidget(titleLabel)
    if desc:
        descLabel = CaptionLabel(page)
        descLabel.setText(desc)
        descLabel.setWordWrap(True)
        box.addWidget(descLabel)
    page.vBoxLayout.addLayout(box)
    return box


def make_feature_card(icon, title: str, desc: str, parent) -> SimpleCardWidget:
    card = SimpleCardWidget(parent)
    card.setFixedHeight(104)
    layout = QVBoxLayout(card)
    layout.setContentsMargins(16, 12, 16, 12)
    layout.setSpacing(6)

    top = QHBoxLayout()
    top.addWidget(IconBadge(icon, 26, 8, card), 0, Qt.AlignLeft)
    top.addStretch(1)
    layout.addLayout(top)

    titleLabel = StrongBodyLabel(card)
    titleLabel.setText(title)
    layout.addWidget(titleLabel)

    descLabel = CaptionLabel(card)
    descLabel.setText(desc)
    descLabel.setWordWrap(True)
    layout.addWidget(descLabel)
    layout.addStretch(1)
    return card


# ====================== 主页 ======================
class HomePage(BasePage):
    def __init__(self, parent):
        super().__init__(
            "homePage",
            parent,
            status="就绪  |  支持拖拽文件 / 文件夹，拖入加密文件会自动进入解密",
        )

        header = QHBoxLayout()
        left = QVBoxLayout()
        left.setSpacing(4)
        title = TitleLabel(self)
        title.setText("GuìFē! :)")
        left.addWidget(title)
        subtitle = BodyLabel(self)
        subtitle.setText(
            f"超级加密工具 {APP_VERSION}   ·   AES-256-GCM   ·   多因子生物密钥"
        )
        left.addWidget(subtitle)
        header.addLayout(left, 1)

        themeButton = ToolButton(self)
        themeButton.setIcon(FluentIcon.BRIGHTNESS)
        themeButton.setToolTip("切换浅色 / 深色主题")
        themeButton.clicked.connect(self._toggle_theme)
        header.addWidget(themeButton, 0, Qt.AlignTop)
        self.vBoxLayout.addLayout(header)

        self.dropZone = DropZone(
            "把文件或文件夹拖到这里",
            "也可以点击此处选择文件；拖入 .guifei / .guifeinext / .guifeitext 将直接进入解密",
            self,
        )
        self.dropZone.dropped.connect(self._on_dropped)
        self.dropZone.clicked.connect(self._on_drop_clicked)
        self.dropZone.setMinimumHeight(160)
        self.vBoxLayout.addWidget(self.dropZone, 1)

        section = StrongBodyLabel(self)
        section.setText("快速开始")
        self.vBoxLayout.addWidget(section)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)
        entries = [
            ("文件加密", "任意文件 → .guifei", FluentIcon.DOCUMENT, "filePage"),
            ("文件夹加密", "整目录打包 → .guifeinext", FluentIcon.FOLDER, "folderPage"),
            ("文档加密", "直接编辑并加密文本 → .guifeitext", FluentIcon.EDIT, "docPage"),
            ("一键解密", "自动识别因子并还原", FluentIcon.DOWNLOAD, "decryptPage"),
        ]
        for column, (text, desc, icon, route) in enumerate(entries):
            card = ActionCard(icon, text, desc, self)
            card.clicked.connect(lambda r=route: self._goto(r))
            grid.addWidget(card, 0, column)
            grid.setColumnStretch(column, 1)
        self.vBoxLayout.addLayout(grid)

        features = QHBoxLayout()
        features.setSpacing(12)
        features.addWidget(
            make_feature_card(
                FluentIcon.CERTIFICATE, "AES-256-GCM", "认证加密，任何篡改都会导致解密失败", self
            ),
            1,
        )
        features.addWidget(
            make_feature_card(
                FluentIcon.FINGERPRINT, "scrypt + BCH", "密码派生密钥，生物特征模糊提取", self
            ),
            1,
        )
        features.addWidget(
            make_feature_card(
                FluentIcon.GLOBE, "纯本地运行", "不联网、不上传，数据始终留在本机", self
            ),
            1,
        )
        self.vBoxLayout.addLayout(features)
        self.finish_layout()

    # ---------- 交互 ----------
    def _goto(self, route: str):
        window = self.window()
        page = getattr(window, route, None)
        if page is not None:
            window.switchTo(page)

    def _toggle_theme(self):
        setTheme(Theme.LIGHT if isDarkTheme() else Theme.DARK)

    def _on_drop_clicked(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if path:
            self.window().handle_drop(path)

    def _on_dropped(self, path: str):
        self.window().handle_drop(path)

    def dragEnterEvent(self, event):
        super().dragEnterEvent(event)
        if event.mimeData().hasUrls():
            self.dropZone.setStyleSheet(DropZone.ACTIVE_QSS)

    def dragLeaveEvent(self, event):
        self.dropZone.setStyleSheet(DropZone.NORMAL_QSS)
        super().dragLeaveEvent(event)

    def dropEvent(self, event):
        self.dropZone.setStyleSheet(DropZone.NORMAL_QSS)
        path = self.first_local_path(event)
        if path:
            self.window().handle_drop(path)
            event.acceptProposedAction()
        else:
            event.ignore()


# ====================== 文件 / 文件夹加密页 ======================
class PathEncryptPage(BasePage):
    def __init__(self, parent, factors: dict, kind: str = "file"):
        is_dir = kind == "folder"
        object_name = "folderPage" if is_dir else "filePage"
        status = (
            "文件夹加密页  |  可将文件夹直接拖入窗口"
            if is_dir
            else "文件加密页  |  可将文件直接拖入窗口"
        )
        super().__init__(object_name, parent, status)
        self.kind = kind
        self.is_dir = is_dir
        self.factors = factors
        self.source_path = ""
        self.save_path = ""
        self._save_path_custom = False

        if self.is_dir:
            build_page_header(
                self,
                "文件夹加密",
                "把整个文件夹压缩后加密为单个 .guifeinext 文件，解密时原目录结构会完整还原。",
            )
        else:
            build_page_header(
                self,
                "文件加密",
                "使用 AES-256-GCM 加密任意文件，输出为 .guifei。可叠加宫格、人脸、声纹因子。",
            )

        content = QHBoxLayout()
        content.setSpacing(14)

        # ----- 左列：源 / 目标 -----
        left = QVBoxLayout()
        left.setSpacing(14)

        sourceCard = SectionCard(
            "选择文件夹" if self.is_dir else "选择文件",
            "支持直接把文件夹拖进窗口"
            if self.is_dir
            else "支持直接把文件拖进窗口",
        )
        self.sourceEdit = LineEdit(sourceCard)
        self.sourceEdit.setReadOnly(True)
        self.sourceEdit.setPlaceholderText("尚未选择")
        browseSource = PushButton(sourceCard)
        browseSource.setText("浏览…")
        browseSource.clicked.connect(self._browse_source)
        sourceRow = QHBoxLayout()
        sourceRow.setSpacing(10)
        sourceRow.addWidget(self.sourceEdit, 1)
        sourceRow.addWidget(browseSource)
        sourceCard.addLayout(sourceRow)
        left.addWidget(sourceCard)

        saveCard = SectionCard(
            "保存位置", "默认保存在源文件旁边，也可以另存到其他位置"
        )
        self.saveEdit = LineEdit(saveCard)
        self.saveEdit.setPlaceholderText("尚未设置保存路径")
        browseSave = PushButton(saveCard)
        browseSave.setText("另存为…")
        browseSave.clicked.connect(self._browse_save)
        self.saveEdit.editingFinished.connect(self._sync_save_path_from_edit)
        saveRow = QHBoxLayout()
        saveRow.setSpacing(10)
        saveRow.addWidget(self.saveEdit, 1)
        saveRow.addWidget(browseSave)
        saveCard.addLayout(saveRow)
        left.addWidget(saveCard)
        left.addStretch(1)

        # ----- 右列：因子 / 执行 -----
        right = QVBoxLayout()
        right.setSpacing(14)

        factorCard = SectionCard(
            "附加验证因子", "主密码始终启用，下面三项可以任意组合叠加"
        )
        self.factorSelector = FactorSelector(self.factors, factorCard)
        factorCard.addWidget(self.factorSelector)
        hint = CaptionLabel(factorCard)
        hint.setText("因子缺失或错误时，AES-GCM 校验不会通过，文件无法被还原。")
        hint.setWordWrap(True)
        factorCard.addWidget(hint)
        right.addWidget(factorCard)

        actionCard = SectionCard("执行加密")
        self.startButton = PrimaryPushButton(actionCard)
        self.startButton.setText("开始加密")
        self.startButton.setFixedHeight(40)
        self.startButton.clicked.connect(self._on_start)
        actionCard.addWidget(self.startButton)

        actionHint = CaptionLabel(actionCard)
        actionHint.setText("加密不会修改或删除原始数据。")
        actionHint.setWordWrap(True)
        actionCard.addWidget(actionHint)
        right.addWidget(actionCard)
        right.addStretch(1)

        content.addLayout(left, 3)
        content.addLayout(right, 2)
        self.vBoxLayout.addLayout(content)

        tipsCard = SectionCard("使用提示")
        if self.is_dir:
            tips = [
                "把文件夹拖进窗口即可自动填入源路径，并生成同名的 .guifeinext 保存路径。",
                "主密码是必选项，宫格 / 人脸 / 声纹可以任意叠加，解密时需要完全相同的组合。",
                "整个目录会先打包成 ZIP 再整体加密，解密时原目录结构会完整还原。",
            ]
        else:
            tips = [
                "把文件拖进窗口即可自动填入源路径，并生成同名的 .guifei 保存路径。",
                "主密码是必选项，宫格 / 人脸 / 声纹可以任意叠加，解密时需要完全相同的组合。",
                "加密只读取源数据，不会修改或删除原始文件。",
            ]
        for line in tips:
            label = CaptionLabel(tipsCard)
            label.setText(line)
            label.setWordWrap(True)
            tipsCard.addWidget(label)
        self.vBoxLayout.addWidget(tipsCard)
        self.vBoxLayout.addStretch(1)

        self.create_progress()
        self.finish_layout()

    # ---------- 数据 ----------
    def set_source(self, path: str):
        if not path:
            return
        self.source_path = os.path.abspath(path)
        self.sourceEdit.setText(self.source_path)
        self.sourceEdit.setToolTip(self.source_path)
        self.sourceEdit.setCursorPosition(0)
        if not self._save_path_custom:
            self._suggest_save_path()
        self.setStatus(f"已选择：{self.source_path}")

    def _suggest_save_path(self):
        if not self.source_path:
            return
        extension = ".guifeinext" if self.is_dir else ".guifei"
        directory = os.path.dirname(self.source_path)
        basename = os.path.basename(self.source_path.rstrip("\\/"))
        self.save_path = os.path.join(directory, basename + extension)
        self.saveEdit.setText(self.save_path)
        self.saveEdit.setToolTip(self.save_path)
        self.saveEdit.setCursorPosition(0)

    def _sync_save_path_from_edit(self):
        text = self.saveEdit.text().strip()
        if text and text != self.save_path:
            self.save_path = text
            self._save_path_custom = True

    # ---------- 浏览 ----------
    def _browse_source(self):
        if self.is_dir:
            path = QFileDialog.getExistingDirectory(self, "选择要加密的文件夹")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "选择要加密的文件")
        if path:
            self.set_source(path)

    def _browse_save(self):
        extension = ".guifeinext" if self.is_dir else ".guifei"
        initial = self.save_path or ""
        path, _ = QFileDialog.getSaveFileName(
            self,
            "选择保存位置",
            initial,
            f"加密文件 (*{extension});;所有文件 (*.*)",
        )
        if not path:
            return
        if not os.path.splitext(path)[1]:
            path += extension
        self.save_path = path
        self.saveEdit.setText(path)
        self.saveEdit.setToolTip(path)
        self.saveEdit.setCursorPosition(0)
        self._save_path_custom = True

    # ---------- 拖拽 ----------
    def dropEvent(self, event):
        path = self.first_local_path(event)
        if not path:
            event.ignore()
            return
        if os.path.isdir(path) != self.is_dir:
            self.window().handle_drop(path)
        else:
            self.set_source(path)
        event.acceptProposedAction()

    # ---------- 执行 ----------
    def _on_start(self):
        self._sync_save_path_from_edit()
        self.window().start_path_encryption(self)

    def setBusy(self, busy: bool):
        super().setBusy(busy)
        self.startButton.setEnabled(not busy)

    def showEvent(self, event):
        self.factorSelector.sync()
        super().showEvent(event)


# ====================== 文档加密页 ======================
class DocEncryptPage(BasePage):
    def __init__(self, parent, factors: dict):
        super().__init__("docPage", parent, "文档加密页  |  直接编辑文本内容")
        self.factors = factors

        header = QHBoxLayout()
        left = QVBoxLayout()
        left.setSpacing(4)
        title = SubtitleLabel(self)
        title.setText("文档加密")
        left.addWidget(title)
        desc = CaptionLabel(self)
        desc.setText("在下方输入文本，保存为 .guifeitext 加密文档；解密后会回到此页面显示。")
        desc.setWordWrap(True)
        left.addWidget(desc)
        header.addLayout(left, 1)

        clearButton = PushButton(self)
        clearButton.setText("清空")
        clearButton.clicked.connect(self._clear)
        header.addWidget(clearButton, 0, Qt.AlignTop)
        self.vBoxLayout.addLayout(header)

        textCard = SectionCard("文档内容")
        self.textEdit = TextEdit(textCard)
        self.textEdit.setPlaceholderText("在此输入或粘贴要加密的文本…")
        self.textEdit.setAcceptRichText(False)
        docFont = QFont("Consolas")
        docFont.setStyleHint(QFont.Monospace)
        docFont.setPointSize(10)
        self.textEdit.setFont(docFont)
        textCard.addWidget(self.textEdit, 1)
        self.vBoxLayout.addWidget(textCard, 1)

        factorCard = SectionCard("附加验证因子", "主密码始终启用，下面三项可以任意组合叠加")
        self.factorSelector = FactorSelector(self.factors, factorCard)
        factorCard.addWidget(self.factorSelector)
        self.vBoxLayout.addWidget(factorCard)

        buttonRow = QHBoxLayout()
        buttonRow.setSpacing(10)
        buttonRow.addStretch(1)
        self.openButton = PushButton(self)
        self.openButton.setText("打开加密文档")
        self.openButton.clicked.connect(self._open)
        buttonRow.addWidget(self.openButton)
        self.saveButton = PrimaryPushButton(self)
        self.saveButton.setText("保存加密文档")
        self.saveButton.clicked.connect(self._save)
        buttonRow.addWidget(self.saveButton)
        self.vBoxLayout.addLayout(buttonRow)

        self.create_progress()
        self.finish_layout()

    def text(self) -> str:
        return self.textEdit.toPlainText()

    def setText(self, text: str):
        self.textEdit.setPlainText(text)

    def _clear(self):
        self.textEdit.clear()
        self.setStatus("已清空编辑区")

    def _save(self):
        self.window().start_doc_encryption(self)

    def _open(self):
        self.window().open_encrypted_doc(self)

    def setBusy(self, busy: bool):
        super().setBusy(busy)
        self.saveButton.setEnabled(not busy)
        self.openButton.setEnabled(not busy)

    def showEvent(self, event):
        self.factorSelector.sync()
        super().showEvent(event)


# ====================== 一键解密页 ======================
class DecryptPage(BasePage):
    def __init__(self, parent):
        super().__init__(
            "decryptPage",
            parent,
            "解密页  |  支持 .guifei / .guifeinext / .guifeitext",
        )
        self.source_path = ""

        build_page_header(
            self,
            "一键解密",
            "读取文件头自动识别所需因子，按提示依次验证后还原内容。",
        )

        fileCard = SectionCard("选择加密文件", "也可以直接把加密文件拖进窗口")
        self.pathEdit = LineEdit(fileCard)
        self.pathEdit.setReadOnly(True)
        self.pathEdit.setPlaceholderText("尚未选择加密文件")
        browseButton = PushButton(fileCard)
        browseButton.setText("浏览…")
        browseButton.clicked.connect(self._browse)
        row = QHBoxLayout()
        row.setSpacing(10)
        row.addWidget(self.pathEdit, 1)
        row.addWidget(browseButton)
        fileCard.addLayout(row)
        self.vBoxLayout.addWidget(fileCard)

        infoCard = SectionCard("解密流程")
        steps = [
            "1. 读取文件头，识别加密时使用的因子（主密码 / 宫格 / 人脸 / 声纹）。",
            "2. 按需弹出对应窗口采集因子，生物因子会现场重新采集。",
            "3. 使用 scrypt 派生密钥，AES-256-GCM 校验通过后还原原始内容。",
            "4. 文本直接载入文档页；文件或文件夹会让你选择保存位置。",
        ]
        for step in steps:
            label = CaptionLabel(infoCard)
            label.setText(step)
            label.setWordWrap(True)
            infoCard.addWidget(label)
        self.vBoxLayout.addWidget(infoCard)

        noteCard = SectionCard("安全说明")
        notes = [
            "文件头只记录因子类型和随机盐值，不包含密码、人脸或声纹的原始数据。",
            "解密失败不会修改或删除原文件，可以放心重试。",
            "生物因子需要现场重新采集，请尽量保持与加密时相近的光线与环境。",
        ]
        for line in notes:
            label = CaptionLabel(noteCard)
            label.setText(line)
            label.setWordWrap(True)
            noteCard.addWidget(label)
        self.vBoxLayout.addWidget(noteCard)

        buttonRow = QHBoxLayout()
        self.startButton = PrimaryPushButton(self)
        self.startButton.setText("开始解密")
        self.startButton.setFixedHeight(40)
        self.startButton.setMinimumWidth(200)
        self.startButton.clicked.connect(self._start)
        buttonRow.addWidget(self.startButton)
        buttonRow.addStretch(1)
        self.vBoxLayout.addLayout(buttonRow)
        self.vBoxLayout.addStretch(1)

        self.create_progress()
        self.finish_layout()

    def set_source(self, path: str):
        if not path:
            return
        self.source_path = os.path.abspath(path)
        self.pathEdit.setText(self.source_path)
        self.pathEdit.setToolTip(self.source_path)
        self.pathEdit.setCursorPosition(0)
        self.setStatus(f"已选择：{self.source_path}")

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "选择要解密的文件",
            "",
            "所有支持的加密文件 (*.guifei *.guifeinext *.guifeitext *.msc);;"
            "加密文件 (*.guifei);;加密文件夹 (*.guifeinext);;"
            "加密文本 (*.guifeitext *.msc);;所有文件 (*.*)",
        )
        if path:
            self.set_source(path)

    def dropEvent(self, event):
        path = self.first_local_path(event)
        if not path:
            event.ignore()
            return
        if os.path.isdir(path):
            self.window().handle_drop(path)
        else:
            self.set_source(path)
        event.acceptProposedAction()

    def _start(self):
        self.window().start_auto_decryption(self)

    def setBusy(self, busy: bool):
        super().setBusy(busy)
        self.startButton.setEnabled(not busy)


class SettingsPage(BasePage):
    """右键菜单后缀、开机启动、关闭到托盘等系统级设置。"""

    def __init__(self, parent):
        super().__init__("settingsPage", parent, "设置  |  右键菜单 / 开机启动 / 关闭行为")
        build_page_header(
            self,
            "设置",
            "修改后立即生效。右键菜单写入当前用户注册表，不需要管理员权限。",
        )

        menuCard = SectionCard(
            "右键加密菜单",
            "只有下面列表里的后缀，右键时才会出现“用 GuifeiCrypto 加密”。"
            "“.guifei / .guifeinext / .guifeitext”的解密菜单始终可用。",
        )

        self.extContainer = QWidget(menuCard)
        self.extLayout = QVBoxLayout(self.extContainer)
        self.extLayout.setContentsMargins(0, 0, 0, 0)
        self.extLayout.setSpacing(2)
        menuCard.addWidget(self.extContainer)

        addRow = QHBoxLayout()
        addRow.setSpacing(10)
        self.extEdit = LineEdit(menuCard)
        self.extEdit.setPlaceholderText("输入后缀，例如 .txt 或 docx")
        self.extEdit.setClearButtonEnabled(True)
        self.extEdit.returnPressed.connect(self._add_extension)
        addButton = PushButton(menuCard)
        addButton.setText("添加")
        addButton.clicked.connect(self._add_extension)
        resetButton = PushButton(menuCard)
        resetButton.setText("恢复默认")
        resetButton.clicked.connect(self._reset_extensions)
        addRow.addWidget(self.extEdit, 1)
        addRow.addWidget(addButton)
        addRow.addWidget(resetButton)
        menuCard.addLayout(addRow)

        tip = CaptionLabel(menuCard)
        tip.setText("提示：修改后如果资源管理器没有立刻刷新，注销或重启一次即可。")
        tip.setWordWrap(True)
        menuCard.addWidget(tip)
        content = QWidget(self)
        self._content_layout = QVBoxLayout(content)
        self._content_layout.setContentsMargins(0, 0, 0, 0)
        self._content_layout.setSpacing(14)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet(
            "QScrollArea{background:transparent;border:none;}"
            "QScrollArea>QWidget>QWidget{background:transparent;}"
        )
        scroll.setWidget(content)
        self.vBoxLayout.addWidget(scroll, 1)

        self._content_layout.addWidget(menuCard)

        startupCard = SectionCard("启动与退出", "开机启动会以最小化到托盘的方式运行")
        self.autoStartSwitch = SwitchButton(startupCard)
        self.autoStartSwitch.setOnText("开")
        self.autoStartSwitch.setOffText("关")
        self.autoStartSwitch.checkedChanged.connect(self._toggle_autostart)
        self.autoStartSwitch.setChecked(autostart_enabled())
        startupCard.addWidget(self._switch_row("开机自动启动", self.autoStartSwitch))

        self.traySwitch = SwitchButton(startupCard)
        self.traySwitch.setOnText("开")
        self.traySwitch.setOffText("关")
        self.traySwitch.checkedChanged.connect(self._toggle_tray)
        self.traySwitch.setChecked(bool(load_config().get("close_to_tray")))
        startupCard.addWidget(
            self._switch_row("点击关闭按钮时最小化到托盘（不退出）", self.traySwitch)
        )
        self._content_layout.addWidget(startupCard)

        actionCard = SectionCard("维护", "可用于修复被杀毒软件或系统优化工具改掉的右键菜单")
        repairButton = PushButton(actionCard)
        repairButton.setText("重新写入右键菜单")
        repairButton.clicked.connect(self._repair_shell)
        actionCard.addWidget(repairButton)
        self._content_layout.addWidget(actionCard)
        self._content_layout.addStretch(1)

        self.create_progress()
        self.finish_layout()
        self._refresh_extensions()

    @staticmethod
    def _switch_row(text: str, switch: SwitchButton) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 2, 0, 2)
        label = BodyLabel(row)
        label.setText(text)
        layout.addWidget(label, 1)
        layout.addWidget(switch)
        return row

    def _refresh_extensions(self):
        while self.extLayout.count():
            item = self.extLayout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        for ext in configured_encrypt_extensions():
            row = QWidget(self.extContainer)
            row.setFixedHeight(30)
            layout = QHBoxLayout(row)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(6)
            label = BodyLabel(row)
            label.setText(ext)
            label.setFixedHeight(30)
            removeButton = ToolButton(FluentIcon.DELETE, row)
            removeButton.setFixedSize(26, 26)
            removeButton.setToolTip("从右键菜单中移除")
            removeButton.clicked.connect(lambda _=False, e=ext: self._remove_extension(e))
            layout.addWidget(label, 1)
            layout.addWidget(removeButton)
            self.extLayout.addWidget(row)

    def _add_extension(self):
        ext = normalize_extension(self.extEdit.text())
        if not ext:
            _warn(self, "后缀无效", "请输入类似 .txt / .docx 的后缀。")
            return
        values = configured_encrypt_extensions()
        if ext in values:
            _info(self, "已存在", f"{ext} 已经在列表里了。")
            return
        values.append(ext)
        save_config({"encrypt_extensions": values})
        register_shell_menus()
        self.extEdit.clear()
        self._refresh_extensions()
        self.setStatus(f"已添加右键加密后缀：{ext}")

    def _remove_extension(self, ext: str):
        values = [item for item in configured_encrypt_extensions() if item != ext]
        save_config({"encrypt_extensions": values})
        register_shell_menus()
        self._refresh_extensions()
        self.setStatus(f"已移除右键加密后缀：{ext}")

    def _reset_extensions(self):
        save_config({"encrypt_extensions": list(DEFAULT_ENCRYPT_EXTENSIONS)})
        register_shell_menus()
        self._refresh_extensions()
        self.setStatus("已恢复默认后缀列表")

    def _repair_shell(self):
        if register_shell_menus():
            _success(self, "已写入", "右键菜单已重新注册。")
        else:
            _warn(self, "注册失败", "系统拒绝了注册表写入，请检查权限或安全软件。")

    def _toggle_autostart(self, checked: bool):
        if apply_autostart(bool(checked)):
            self.setStatus("已开启开机自动启动" if checked else "已关闭开机自动启动")

    def _toggle_tray(self, checked: bool):
        save_config({"close_to_tray": bool(checked)})
        window = self.window()
        if hasattr(window, "close_to_tray"):
            window.close_to_tray = bool(checked)
            if checked:
                window.ensure_tray()
        self.setStatus("关闭按钮将隐藏到托盘" if checked else "关闭按钮将退出程序")


# ====================== 关于页 ======================
class AboutPage(BasePage):
    DEPENDENCIES = [
        ("numpy", "numpy", "数值计算"),
        ("pycryptodome", "Crypto", "AES-256-GCM"),
        ("galois", "galois", "BCH 纠错码"),
        ("opencv-python", "cv2", "摄像头"),
        ("insightface", "insightface", "人脸识别"),
        ("onnxruntime", "onnxruntime", "模型推理"),
        ("sounddevice", "sounddevice", "麦克风"),
        ("resemblyzer", "resemblyzer", "声纹识别"),
        ("scipy", "scipy", "重采样"),
    ]

    def __init__(self, parent):
        super().__init__("aboutPage", parent, "关于")

        header = QHBoxLayout()
        header.setSpacing(16)
        iconLabel = QLabel(self)
        icon = load_app_icon()
        if not icon.isNull():
            iconLabel.setPixmap(icon.pixmap(64, 64))
        else:
            iconLabel.setFixedSize(64, 64)
            iconLabel.setStyleSheet(
                "background: rgba(128,128,128,60); border-radius: 12px;"
            )
        iconLabel.setFixedSize(64, 64)
        header.addWidget(iconLabel, 0, Qt.AlignTop)

        titleBox = QVBoxLayout()
        titleBox.setSpacing(4)
        title = SubtitleLabel(self)
        title.setText(APP_NAME)
        titleBox.addWidget(title)
        version = BodyLabel(self)
        version.setText(f"{APP_VERSION}   ·   PySide6 + PySide6-Fluent-Widgets")
        titleBox.addWidget(version)
        header.addLayout(titleBox, 1)
        self.vBoxLayout.addLayout(header)

        aboutCard = SectionCard("关于本工具")
        paragraph = BodyLabel(aboutCard)
        paragraph.setWordWrap(True)
        paragraph.setText(
            "多因子加密工具：AES-256-GCM 认证加密 + scrypt 密钥派生 + "
            "宫格 / 人脸 / 声纹因子，生物特征通过 BCH 码做模糊密钥提取，"
            "原始生物数据不会写入加密文件。全部运算在本机完成，不联网、不上传。"
        )
        aboutCard.addWidget(paragraph)
        self.vBoxLayout.addWidget(aboutCard)

        specCard = SectionCard("技术规格")
        specs = [
            ("加密算法", "AES-256-GCM（认证加密）"),
            ("密钥派生", f"scrypt N=2^14, r=8, p=1, dklen=32"),
            ("生物密钥", "BCH(127, 64) 承诺 + 稳定位选择"),
            ("文件格式", "guifeiCRYPT3 / v3，与 v17.x 完全兼容"),
        ]
        for name, value in specs:
            row = QHBoxLayout()
            keyLabel = CaptionLabel(specCard)
            keyLabel.setText(name)
            keyLabel.setFixedWidth(90)
            row.addWidget(keyLabel)
            valueLabel = BodyLabel(specCard)
            valueLabel.setText(value)
            row.addWidget(valueLabel, 1)
            specCard.addLayout(row)
        self.vBoxLayout.addWidget(specCard)

        envCard = SectionCard("运行环境", "缺失的依赖只会影响对应因子，不影响主密码加密")
        envGrid = QGridLayout()
        envGrid.setHorizontalSpacing(18)
        envGrid.setVerticalSpacing(6)
        for index, (package, module, purpose) in enumerate(self.DEPENDENCIES):
            try:
                available = importlib.util.find_spec(module) is not None
            except Exception:
                available = False
            mark = CaptionLabel(envCard)
            mark.setText("✓" if available else "✗")
            mark.setStyleSheet(
                "color: #2ecc71;" if available else "color: #e74c3c;"
            )
            mark.setFixedWidth(16)
            nameLabel = CaptionLabel(envCard)
            nameLabel.setText(f"{package}  ·  {purpose}")
            envGrid.addWidget(mark, index // 3, (index % 3) * 2)
            envGrid.addWidget(nameLabel, index // 3, (index % 3) * 2 + 1)
        envCard.addLayout(envGrid)

        pythonLabel = CaptionLabel(envCard)
        pythonLabel.setText(
            f"Python {sys.version.split()[0]}   ·   PySide6 {self._pyside_version()}   "
            f"·   qfluentwidgets {self._qfw_version()}"
        )
        envCard.addWidget(pythonLabel)

        self.modelLabel = CaptionLabel(envCard)
        self.modelLabel.setWordWrap(True)
        self.modelLabel.setTextInteractionFlags(Qt.TextSelectableByMouse)
        envCard.addWidget(self.modelLabel)
        self._refresh_model_label()

        voiceLabel = CaptionLabel(envCard)
        voiceLabel.setText(
            "声纹模块：已包含"
            if VOICE_SUPPORT
            else "声纹模块：当前构建未包含（声纹因子已禁用）"
        )
        envCard.addWidget(voiceLabel)
        self.vBoxLayout.addWidget(envCard)

        buttonRow = QHBoxLayout()
        buttonRow.setSpacing(10)
        logButton = PushButton(self)
        logButton.setText("打开错误日志")
        logButton.clicked.connect(self._open_log)
        buttonRow.addWidget(logButton)

        modelButton = PushButton(self)
        modelButton.setText("人脸模型…")
        modelButton.clicked.connect(self._manage_face_model)
        buttonRow.addWidget(modelButton)
        buttonRow.addStretch(1)
        self.vBoxLayout.addLayout(buttonRow)
        self.vBoxLayout.addStretch(1)
        self.finish_layout()

    def _refresh_model_label(self):
        model_dir = resolve_face_model_dir()
        if model_dir:
            self.modelLabel.setText(f"人脸模型：已就绪  ·  {model_dir}")
        else:
            self.modelLabel.setText(
                "人脸模型：未安装（首次使用人脸因子时会提示下载，约 191 MB）"
            )

    def _manage_face_model(self):
        dialog = FaceModelDialog(self, current_dir=resolve_face_model_dir())
        dialog.exec()
        self._refresh_model_label()

    def showEvent(self, event):
        self._refresh_model_label()
        super().showEvent(event)

    @staticmethod
    def _pyside_version() -> str:
        try:
            import PySide6

            return PySide6.__version__
        except Exception:
            return "未知"

    @staticmethod
    def _qfw_version() -> str:
        try:
            import qfluentwidgets

            return getattr(qfluentwidgets, "__version__", "未知")
        except Exception:
            return "未知"

    def _open_log(self):
        if os.path.exists(LOG_FILE):
            QDesktopServices.openUrl(QUrl.fromLocalFile(LOG_FILE))
        else:
            _info(self, "日志为空", "目前还没有记录任何错误。")


# ====================== 解密辅助 ======================
def read_header_info(path: str):
    with open(path, "rb") as f:
        head = f.read(65536)
    factor_mask, salt, helpers, _payload = parse_file_header(head)
    return factor_mask, salt, helpers


# ====================== 主窗口 ======================
class GuifeiCryptoWindow(FluentWindow):
    def __init__(self):
        super().__init__()
        # 使用不透明的 Fluent 背景，避免 Mica 在远程桌面 / 虚拟机 / 旧显卡驱动下
        # 变成透明导致文字不可读，也保证深色模式在任意环境下表现一致。
        try:
            self.setMicaEffectEnabled(False)
        except Exception:
            pass
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")

        # 根据可用屏幕自适应初始尺寸（高 DPI 缩放下 840 可能会超出屏幕）
        screen = QApplication.primaryScreen()
        if screen is not None:
            available = screen.availableGeometry()
            width = min(1280, max(900, available.width() - 120))
            height = min(840, max(560, available.height() - 80))
            self.setMinimumSize(
                min(960, max(720, available.width() - 40)),
                min(620, max(520, available.height() - 60)),
            )
        else:
            width, height = 1280, 840
            self.setMinimumSize(960, 620)
        self.resize(width, height)
        if screen is not None:
            frame = self.frameGeometry()
            frame.moveCenter(available.center())
            self.move(frame.topLeft())

        icon = load_app_icon()
        if not icon.isNull():
            self.setWindowIcon(icon)

        self.factors = {"grid": False, "face": False, "voice": False}

        self.homePage = HomePage(self)
        self.filePage = PathEncryptPage(self, self.factors, "file")
        self.folderPage = PathEncryptPage(self, self.factors, "folder")
        self.docPage = DocEncryptPage(self, self.factors)
        self.decryptPage = DecryptPage(self)
        self.settingsPage = SettingsPage(self)
        self.aboutPage = AboutPage(self)

        self.close_to_tray = bool(load_config().get("close_to_tray"))
        self._force_quit = False
        self._tray = None
        self._tray_hint_shown = False

        self._build_navigation()
        self.stackedWidget.setCurrentWidget(self.homePage)

    # ---------- 导航 ----------
    def _build_navigation(self):
        self.addSubInterface(self.homePage, FluentIcon.HOME, "主页")
        self.addSubInterface(self.filePage, FluentIcon.DOCUMENT, "文件加密")
        self.addSubInterface(self.folderPage, FluentIcon.FOLDER, "文件夹加密")
        self.addSubInterface(self.docPage, FluentIcon.EDIT, "文档加密")
        self.addSubInterface(self.decryptPage, FluentIcon.DOWNLOAD, "一键解密")
        self.addSubInterface(
            self.settingsPage, FluentIcon.SETTING, "设置", NavigationItemPosition.BOTTOM
        )
        self.addSubInterface(
            self.aboutPage, FluentIcon.INFO, "关于", NavigationItemPosition.BOTTOM
        )
        try:
            self.navigationInterface.setExpandWidth(240)
        except Exception:
            pass

    def showEvent(self, event):
        super().showEvent(event)
        # 必须等窗口真正显示后再展开，否则会被 FluentWindow 的初始布局压回紧凑模式
        if not getattr(self, "_nav_expanded", False):
            self._nav_expanded = True
            QTimer.singleShot(200, self._expand_navigation)

    def _expand_navigation(self):
        try:
            self.navigationInterface.expand(False)
        except Exception:
            pass

    def _factor_parent(self):
        """主界面里的因子对话框直接以主窗口为父窗口。"""
        return self

    def current_page(self) -> BasePage:
        page = self.stackedWidget.currentWidget()
        return page if isinstance(page, BasePage) else self.homePage

    # ---------- 拖拽路由 ----------
    def handle_drop(self, path: str):
        if not path:
            return
        if not os.path.exists(path):
            _warn(self, "无法识别", f"路径不存在：{path}")
            return

        if os.path.isfile(path) and is_encrypted_file(path):
            self.decryptPage.set_source(path)
            self.switchTo(self.decryptPage)
            _info(self, "已载入加密文件", os.path.basename(path))
        elif os.path.isdir(path):
            self.folderPage.set_source(path)
            self.switchTo(self.folderPage)
        elif os.path.isfile(path):
            self.filePage.set_source(path)
            self.switchTo(self.filePage)
        else:
            _warn(self, "无法识别", "请拖入文件或文件夹。")

    # ---------- 托盘 ----------
    def ensure_tray(self):
        if self._tray is not None:
            return self._tray
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return None
        icon = self.windowIcon()
        if icon.isNull():
            icon = load_app_icon()
        tray = QSystemTrayIcon(icon, self)
        tray.setToolTip(f"{APP_NAME} {APP_VERSION}")
        menu = QMenu()
        showAction = QAction("显示主界面", menu)
        showAction.triggered.connect(self._restore_window)
        quitAction = QAction("退出", menu)
        quitAction.triggered.connect(self.quit_app)
        menu.addAction(showAction)
        menu.addSeparator()
        menu.addAction(quitAction)
        tray.setContextMenu(menu)
        tray.activated.connect(self._on_tray_activated)
        tray.show()
        self._tray = tray
        return tray

    def _on_tray_activated(self, reason):
        if reason in (QSystemTrayIcon.DoubleClick, QSystemTrayIcon.Trigger):
            self._restore_window()

    def _restore_window(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def begin_encryption(self, path: str):
        """右键“加密”/ 命令行 --encrypt：直接进入对应页并开始流程。"""
        if not path or not os.path.exists(path):
            _warn(self, "路径不存在", path or "未指定文件")
            return
        page = self.folderPage if os.path.isdir(path) else self.filePage
        page.set_source(path)
        self.switchTo(page)
        QTimer.singleShot(350, lambda: self.start_path_encryption(page))

    def quit_app(self):
        self._force_quit = True
        self.close()

    # ---------- 因子采集 ----------
    def _collect_factors_for_encrypt(self):
        factor_mask = FACTOR_PASSWORD
        factor_parts = []
        helpers = {}

        password = PasswordDialog.ask(self, "加密密码", "请输入主密码：")
        if not password:
            return None
        pwd_bytes = password.encode("utf-8")
        factor_parts.append(len(pwd_bytes).to_bytes(2, "little") + pwd_bytes)

        if self.factors.get("grid"):
            signature = GridPadDialog.ask(self._factor_parent(), "设置 5×5 宫格密码")
            if not signature:
                return None
            grid_bytes = signature["signature_string"].encode("utf-8")
            factor_parts.append(len(grid_bytes).to_bytes(2, "little") + grid_bytes)
            factor_mask |= FACTOR_GRID

        if self.factors.get("face"):
            if not FACE_SUPPORT:
                _warn(self, "人脸模块不可用", "当前构建未包含人脸模块。")
                return None
            result, _ok = FaceAuthDialog.ask(
                self._factor_parent(), "collect", None, "采集人脸因子"
            )
            if not result:
                return None
            key, helper = generate_bio_key_and_helper(
                result["avg"], result["features"]
            )
            factor_parts.append(key)
            helpers["face"] = helper
            factor_mask |= FACTOR_FACE

        if self.factors.get("voice"):
            if not VOICE_SUPPORT:
                _warn(self, "声纹模块不可用", "当前构建未包含声纹模块。")
                return None
            result, _ok = VoiceAuthDialog.ask(
                self._factor_parent(), "collect", None, "采集声纹因子"
            )
            if not result:
                return None
            key, helper = generate_bio_key_and_helper(
                result["avg"], result["embeddings"]
            )
            factor_parts.append(key)
            helpers["voice"] = helper
            factor_mask |= FACTOR_VOICE

        return factor_mask, b"".join(factor_parts), helpers

    def _collect_factors_for_decrypt(self, factor_mask: int, helpers: dict):
        if factor_mask & FACTOR_FACE and not FACE_SUPPORT:
            raise ValueError("该文件需要人脸因子，但当前版本未包含人脸模块。")
        if factor_mask & FACTOR_VOICE and not VOICE_SUPPORT:
            raise ValueError("该文件需要声纹因子，但当前版本未包含声纹模块。")

        factor_parts = []

        password = PasswordDialog.ask(
            self, "解密密码", "请输入主密码：", show_strength=False
        )
        if not password:
            return None
        pwd_bytes = password.encode("utf-8")
        factor_parts.append(len(pwd_bytes).to_bytes(2, "little") + pwd_bytes)

        if factor_mask & FACTOR_GRID:
            signature = GridPadDialog.ask(self._factor_parent(), "请输入加密时的宫格密码")
            if not signature:
                return None
            grid_bytes = signature["signature_string"].encode("utf-8")
            factor_parts.append(len(grid_bytes).to_bytes(2, "little") + grid_bytes)

        if factor_mask & FACTOR_FACE:
            result, _ok = FaceAuthDialog.ask(
                self._factor_parent(), "collect", None, "采集人脸因子以恢复密钥"
            )
            if not result:
                return None
            try:
                key = recover_bio_key(helpers["face"], result["avg"])
            except Exception as exc:
                raise ValueError(f"人脸因子验证失败，无法恢复密钥：{exc}") from exc
            factor_parts.append(key)

        if factor_mask & FACTOR_VOICE:
            result, _ok = VoiceAuthDialog.ask(
                self._factor_parent(), "collect", None, "采集声纹因子以恢复密钥"
            )
            if not result:
                return None
            try:
                key = recover_bio_key(helpers["voice"], result["avg"])
            except Exception as exc:
                raise ValueError(f"声纹因子验证失败，无法恢复密钥：{exc}") from exc
            factor_parts.append(key)

        return b"".join(factor_parts)

    # ---------- 文件 / 文件夹加密 ----------
    def start_path_encryption(self, page: PathEncryptPage):
        source = page.source_path
        if not source or not os.path.exists(source):
            _warn(
                self,
                "尚未选择",
                "请先选择要加密的文件夹。" if page.is_dir else "请先选择要加密的文件。",
            )
            return

        destination = (page.save_path or "").strip()
        if not destination:
            self._ask_encrypt_destination(page)
            destination = (page.save_path or "").strip()
            if not destination:
                return

        if os.path.abspath(destination) == os.path.abspath(source):
            _warn(self, "路径冲突", "保存路径不能与源路径相同。")
            return

        if os.path.exists(destination):
            if not ask_confirm(
                self,
                "覆盖确认",
                f"目标文件已存在：\n{destination}\n\n是否覆盖？",
            ):
                return

        try:
            size = self._folder_size(source) if page.is_dir else os.path.getsize(source)
        except OSError:
            show_error_detail(self, "读取失败", traceback.format_exc())
            return

        if size > 200 * 1024 * 1024:
            target_name = "文件夹" if page.is_dir else "文件"
            if not ask_confirm(
                self,
                "大文件确认",
                f"{target_name}大小约 {size // (1024 * 1024)} MB，"
                "加密会占用较多内存，是否继续？",
            ):
                return

        factors = self._collect_factors_for_encrypt()
        if factors is None:
            _info(self, "已取消", "已取消加密操作。")
            return
        factor_mask, total_factor, helpers = factors

        file_type = FILE_TYPE_FOLDER if page.is_dir else FILE_TYPE_FILE
        page.setBusy(True)
        page.setStatus("正在加密，请稍候…")

        run_async(
            lambda: self._encrypt_path_job(
                source,
                destination,
                file_type,
                page.is_dir,
                factor_mask,
                total_factor,
                helpers,
            ),
            lambda result, p=page: self._on_encrypt_finished(p, result),
            lambda detail, p=page: self._on_encrypt_failed(p, detail),
        )

    def _ask_encrypt_destination(self, page: PathEncryptPage):
        extension = ".guifeinext" if page.is_dir else ".guifei"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "选择保存位置",
            page.save_path or "",
            f"加密文件 (*{extension});;所有文件 (*.*)",
        )
        if not path:
            return
        if not os.path.splitext(path)[1]:
            path += extension
        page.save_path = path
        page.saveEdit.setText(path)
        page.saveEdit.setToolTip(path)
        page.saveEdit.setCursorPosition(0)

    @staticmethod
    def _folder_size(folder: str) -> int:
        total = 0
        for root, _dirs, files in os.walk(folder):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(root, name))
                except OSError:
                    continue
                if total > 200 * 1024 * 1024:
                    return total
        return total

    @staticmethod
    def _zip_folder(folder: str) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for root, _dirs, files in os.walk(folder):
                for name in files:
                    full = os.path.join(root, name)
                    archive.write(full, os.path.relpath(full, folder))
        return buffer.getvalue()

    def _encrypt_path_job(
        self,
        source,
        destination,
        file_type,
        is_dir,
        factor_mask,
        total_factor,
        helpers,
    ):
        if is_dir:
            data = self._zip_folder(source)
        else:
            with open(source, "rb") as f:
                data = f.read()
        return self._write_encrypted(
            data, destination, file_type, source, factor_mask, total_factor, helpers
        )

    @staticmethod
    def _write_encrypted(
        data,
        destination,
        file_type,
        original_filename,
        factor_mask,
        total_factor,
        helpers,
    ):
        salt = get_random_bytes(SALT_LENGTH)
        header = build_file_header(factor_mask, salt, helpers)
        packet = make_packet(data, file_type, original_filename)
        payload = encrypt_data(packet, total_factor, salt, header)

        parent_dir = os.path.dirname(os.path.abspath(destination))
        if parent_dir and not os.path.isdir(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
        with open(destination, "wb") as f:
            f.write(header + payload)
        return destination

    def _on_encrypt_finished(self, page: BasePage, destination: str):
        page.setBusy(False)
        page.setStatus(f"加密完成：{os.path.basename(destination)}")
        _success(self, "加密完成", os.path.basename(destination))

    def _on_encrypt_failed(self, page: BasePage, detail: str):
        page.setBusy(False)
        page.setStatus("加密失败")
        show_error_detail(self, "加密失败", detail)

    # ---------- 文档加密 ----------
    def start_doc_encryption(self, page: DocEncryptPage):
        content = page.text().encode("utf-8")
        if not content.strip():
            _warn(self, "内容为空", "文档内容不能为空。")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "保存加密文档",
            "document.guifeitext",
            "加密文档 (*.guifeitext *.msc);;所有文件 (*.*)",
        )
        if not path:
            return
        if not os.path.splitext(path)[1]:
            path += ".guifeitext"

        factors = self._collect_factors_for_encrypt()
        if factors is None:
            _info(self, "已取消", "已取消加密操作。")
            return
        factor_mask, total_factor, helpers = factors

        page.setBusy(True)
        page.setStatus("正在加密文档…")
        run_async(
            lambda: self._write_encrypted(
                content,
                path,
                FILE_TYPE_TEXT,
                "document.guifeitext",
                factor_mask,
                total_factor,
                helpers,
            ),
            lambda result, p=page: self._on_encrypt_finished(p, result),
            lambda detail, p=page: self._on_encrypt_failed(p, detail),
        )

    # ---------- 解密 ----------
    def start_auto_decryption(self, page: DecryptPage):
        path = page.source_path
        if not path or not os.path.isfile(path):
            _warn(self, "尚未选择", "请先选择要解密的文件。")
            return
        self._start_decryption(path, page)

    def open_encrypted_doc(self, page: DocEncryptPage):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "打开加密文档",
            "",
            "加密文档 (*.guifeitext *.msc);;所有支持的加密文件 (*.guifei *.guifeinext *.guifeitext *.msc);;"
            "所有文件 (*.*)",
        )
        if path:
            self._start_decryption(path, page)

    def _start_decryption(self, path: str, page: BasePage):
        try:
            factor_mask, _salt, helpers = read_header_info(path)
        except Exception:
            show_error_detail(
                self,
                "无法解析文件",
                "该文件不是有效的加密文件，或文件头已损坏。\n\n"
                + traceback.format_exc(),
            )
            return

        page.setStatus(f"需要因子：{describe_factors(factor_mask)}，正在验证…")
        try:
            total_factor = self._collect_factors_for_decrypt(factor_mask, helpers)
        except Exception as exc:
            logging.error("因子验证失败: %s", traceback.format_exc())
            show_error_detail(self, "因子验证失败", str(exc))
            return

        if total_factor is None:
            _info(self, "已取消", "已取消解密操作。")
            return

        page.setBusy(True)
        page.setStatus("正在解密，请稍候…")
        run_async(
            lambda: self._decrypt_job(path, total_factor),
            lambda packet, p=page: self._handle_decryption_result(p, packet),
            lambda detail, p=page: self._on_decrypt_failed(p, detail),
        )

    @staticmethod
    def _decrypt_job(path: str, total_factor: bytes):
        with open(path, "rb") as f:
            raw = f.read()
        factor_mask, salt, helpers, payload = parse_file_header(raw)
        header = build_file_header(factor_mask, salt, helpers)
        plain_packet = decrypt_data(payload, total_factor, salt, header)
        return read_packet(plain_packet)

    def _on_decrypt_failed(self, page: BasePage, detail: str):
        page.setBusy(False)
        page.setStatus("解密失败")
        show_error_detail(
            self,
            "解密失败",
            "密码或验证因子不正确，或文件已被篡改。\n\n" + detail,
        )

    def _handle_decryption_result(self, page: BasePage, packet: dict):
        page.setBusy(False)
        file_type = packet["file_type"]
        content = packet["content"]
        basename = packet["original_basename"] or "未命名"

        if file_type == FILE_TYPE_TEXT:
            self.docPage.setText(content.decode("utf-8", errors="replace"))
            self.docPage.setStatus(f"文本解密完成：原文件名 {basename}")
            self.switchTo(self.docPage)
            _success(self, "解密完成", f"文本已载入文档页：{basename}")
            return

        if file_type == FILE_TYPE_FILE:
            path, _ = QFileDialog.getSaveFileName(
                self, "保存解密文件", basename, "所有文件 (*.*)"
            )
            if not path:
                page.setStatus("已取消保存（内容已解密）")
                _info(self, "已取消", "未保存解密文件。")
                return
            try:
                with open(path, "wb") as f:
                    f.write(content)
            except Exception:
                show_error_detail(self, "保存失败", traceback.format_exc())
                return
            page.setStatus(f"解密完成：{os.path.basename(path)}")
            _success(self, "解密完成", f"已保存：{path}")
            return

        if file_type == FILE_TYPE_FOLDER:
            parent_dir = QFileDialog.getExistingDirectory(self, "选择文件夹保存位置")
            if not parent_dir:
                page.setStatus("已取消保存（内容已解密）")
                _info(self, "已取消", "未解压文件夹。")
                return
            target_dir = self._unique_dir(parent_dir, basename)
            try:
                os.makedirs(target_dir, exist_ok=True)
                with zipfile.ZipFile(io.BytesIO(content)) as archive:
                    archive.extractall(target_dir)
            except Exception:
                show_error_detail(self, "解压失败", traceback.format_exc())
                return
            page.setStatus(f"文件夹解密完成：{target_dir}")
            _success(self, "解密完成", f"已解压到：{target_dir}")
            return

        _warn(self, "未知类型", "文件头中的类型标识无法识别。")

    @staticmethod
    def _unique_dir(parent_dir: str, base: str) -> str:
        base = base or "decrypted"
        target = os.path.join(parent_dir, base)
        counter = 1
        while os.path.exists(target):
            target = os.path.join(parent_dir, f"{base}_{counter}")
            counter += 1
        return target

    # ---------- 退出 ----------
    def closeEvent(self, event):
        if self._force_quit:
            if self._tray is not None:
                self._tray.hide()
            event.accept()
            return

        if self.close_to_tray:
            tray = self.ensure_tray()
            if tray is not None:
                self.hide()
                event.ignore()
                if not self._tray_hint_shown:
                    self._tray_hint_shown = True
                    try:
                        tray.showMessage(
                            APP_NAME,
                            "程序已最小化到托盘，双击图标可以重新打开。",
                            QSystemTrayIcon.MessageIcon.Information,
                            3000,
                        )
                    except Exception:
                        pass
                return

        if ask_confirm(self, "退出", f"确定要退出 {APP_NAME} 吗？"):
            if self._tray is not None:
                self._tray.hide()
            event.accept()
        else:
            event.ignore()


# -*- coding: utf-8 -*-
"""紧凑加解密窗口（单窗口内切换宫格/人脸/声纹，窗口尺寸固定）。"""

import time
import traceback

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)


class _FactorWidget(QWidget):
    completed = Signal(object)
    cancelled = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._done = False

    def _finish(self, value):
        if self._done:
            return
        self._done = True
        self.completed.emit(value)

    def _cancel(self):
        if self._done:
            return
        self._done = True
        self.cancelled.emit()


class GridFactorWidget(_FactorWidget):
    def __init__(self, parent, title: str, prompt: str):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(6)

        self.titleLabel = SubtitleLabel(self)
        self.titleLabel.setText(title)
        layout.addWidget(self.titleLabel)

        self.promptLabel = CaptionLabel(self)
        self.promptLabel.setText(prompt)
        self.promptLabel.setWordWrap(True)
        layout.addWidget(self.promptLabel)

        self.pad = GridPadWidget(self)
        layout.addWidget(self.pad, 0, Qt.AlignHCenter)

        self.pointLabel = CaptionLabel(self)
        self.pointLabel.setText("已选点：无")
        layout.addWidget(self.pointLabel)

        row = QHBoxLayout()
        row.setSpacing(8)
        clearButton = PushButton(self)
        clearButton.setText("清除")
        clearButton.clicked.connect(self._clear)
        row.addWidget(clearButton)
        row.addStretch(1)
        cancelButton = PushButton(self)
        cancelButton.setText("取消")
        cancelButton.clicked.connect(self._cancel)
        row.addWidget(cancelButton)
        okButton = PrimaryPushButton(self)
        okButton.setText("确定")
        okButton.clicked.connect(self._confirm)
        row.addWidget(okButton)
        layout.addLayout(row)
        layout.addStretch(1)

        self.pad.changed.connect(self._update_label)

    def _clear(self):
        self.pad.clear()

    def _update_label(self):
        if not self.pad.selected:
            self.pointLabel.setText("已选点：无")
            return
        text = "+".join(f"({r + 1},{c + 1})" for r, c in self.pad.selected)
        self.pointLabel.setText("已选点：" + text)

    def _confirm(self):
        if len(self.pad.selected) < 4:
            self.promptLabel.setText("至少选择 4 个点")
            return
        self._finish(self.pad.signature_string())


class FaceFactorWidget(_FactorWidget):
    def __init__(self, parent, title: str):
        super().__init__(parent)
        self._cap = None
        self.current_frame = None
        self.collected = []
        self.capture_count = 0
        self._confirm_stage = False
        self._closed = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(6)

        self.titleLabel = SubtitleLabel(self)
        self.titleLabel.setText(title)
        layout.addWidget(self.titleLabel)

        self.previewLabel = QLabel(self)
        self.previewLabel.setMinimumSize(320, 200)
        self.previewLabel.setAlignment(Qt.AlignCenter)
        self.previewLabel.setStyleSheet(
            "background: #101010; border-radius: 8px; color: #888;"
        )
        self.previewLabel.setText("正在加载人脸模型…")
        layout.addWidget(self.previewLabel, 1)

        self.statusLabel = CaptionLabel(self)
        self.statusLabel.setText("正在初始化，请稍候…")
        layout.addWidget(self.statusLabel)

        self.resultLabel = CaptionLabel(self)
        self.resultLabel.setText("")
        layout.addWidget(self.resultLabel)

        row = QHBoxLayout()
        row.setSpacing(8)
        row.addStretch(1)
        cancelButton = PushButton(self)
        cancelButton.setText("取消")
        cancelButton.clicked.connect(self._cancel)
        row.addWidget(cancelButton)
        self.captureButton = PrimaryPushButton(self)
        self.captureButton.setText("拍照采集")
        self.captureButton.setEnabled(False)
        self.captureButton.clicked.connect(self._on_capture)
        row.addWidget(self.captureButton)
        layout.addLayout(row)

        self._timer = QTimer(self)
        self._timer.setInterval(40)
        self._timer.timeout.connect(self._update_preview)

        run_async(
            lambda: FaceAuthManager.instance().load_model(None),
            self._on_model_loaded,
            self._on_load_failed,
        )

    def _on_model_loaded(self, result):
        if self._closed:
            return
        ok, message = result
        if not ok:
            self.statusLabel.setText(message)
            return
        try:
            import cv2

            backend = cv2.CAP_DSHOW if sys.platform == "win32" else 0
            cap = cv2.VideoCapture(0, backend)
            if not cap.isOpened():
                cap.release()
                cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                cap.release()
                self.statusLabel.setText("无法打开摄像头，请检查是否被占用")
                return
            self._cap = cap
        except Exception:
            logging.error("摄像头初始化失败: %s", traceback.format_exc())
            self.statusLabel.setText("摄像头初始化失败")
            return
        self.previewLabel.setText("")
        self.statusLabel.setText(message)
        self.captureButton.setEnabled(True)
        self._timer.start()

    def _on_load_failed(self, detail: str):
        if self._closed:
            return
        logging.error("人脸初始化失败: %s", detail)
        self.statusLabel.setText("人脸模块初始化失败，详情见日志")

    def _update_preview(self):
        if self._cap is None:
            return
        try:
            import cv2

            ret, frame = self._cap.read()
            if not ret or frame is None:
                return
            self.current_frame = frame
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            height, width = rgb.shape[:2]
            image = QImage(
                rgb.data, width, height, 3 * width, QImage.Format_RGB888
            ).copy()
            pixmap = QPixmap.fromImage(image)
            self.previewLabel.setPixmap(
                pixmap.scaled(
                    self.previewLabel.size(),
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation,
                )
            )
        except Exception:
            logging.error("预览更新异常: %s", traceback.format_exc())
            self._timer.stop()

    def _on_capture(self):
        if self._confirm_stage:
            avg = np.mean(self.collected, axis=0)
            self.stop()
            self._finish({"features": self.collected, "avg": avg, "count": self.capture_count})
            return

        if self.current_frame is None:
            self.statusLabel.setText("尚未获取到画面，请稍候")
            return
        manager = FaceAuthManager.instance()
        try:
            feature = manager.extract_feature(self.current_frame)
        except Exception:
            logging.error("人脸特征提取失败: %s", traceback.format_exc())
            self.statusLabel.setText("人脸特征提取失败，请重试")
            return
        if feature is None:
            self.statusLabel.setText("未检测到人脸，请正对摄像头")
            return

        self.collected.append(feature)
        self.capture_count += 1
        self.resultLabel.setText(f"✅ 第 {self.capture_count} 张采集成功")
        if self.capture_count < 3:
            self.statusLabel.setText(
                f"继续采集第 {self.capture_count + 1} 张（共 3 张）"
            )
        else:
            self.statusLabel.setText("3 张采集完成，可以确认使用")
            self.captureButton.setText("确认使用")
            self._confirm_stage = True

    def stop(self):
        self._closed = True
        self._timer.stop()
        if self._cap is not None:
            try:
                self._cap.release()
            except Exception:
                logging.error("摄像头释放异常: %s", traceback.format_exc())
            self._cap = None

    def _cancel(self):
        self.stop()
        super()._cancel()


class VoiceFactorWidget(_FactorWidget):
    def __init__(self, parent, title: str):
        super().__init__(parent)
        self.collected = []
        self.capture_count = 0
        self._confirm_stage = False
        self._recording = False
        self._closed = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(8)

        self.titleLabel = SubtitleLabel(self)
        self.titleLabel.setText(title)
        layout.addWidget(self.titleLabel)

        iconRow = QHBoxLayout()
        iconRow.addStretch(1)
        iconRow.addWidget(IconBadge(FluentIcon.MICROPHONE, 64, 16, self))
        iconRow.addStretch(1)
        layout.addLayout(iconRow)

        self.statusLabel = BodyLabel(self)
        self.statusLabel.setAlignment(Qt.AlignCenter)
        self.statusLabel.setText("请点击按钮录制声音（每次 3 秒，共 3 次）")
        self.statusLabel.setWordWrap(True)
        layout.addWidget(self.statusLabel)

        self.progressLabel = CaptionLabel(self)
        self.progressLabel.setAlignment(Qt.AlignCenter)
        self.progressLabel.setText("")
        layout.addWidget(self.progressLabel)

        row = QHBoxLayout()
        row.setSpacing(8)
        row.addStretch(1)
        cancelButton = PushButton(self)
        cancelButton.setText("取消")
        cancelButton.clicked.connect(self._cancel)
        row.addWidget(cancelButton)
        self.recordButton = PrimaryPushButton(self)
        self.recordButton.setText("开始录音")
        self.recordButton.clicked.connect(self._on_record)
        row.addWidget(self.recordButton)
        layout.addLayout(row)
        layout.addStretch(1)

    def _on_record(self):
        if self._confirm_stage:
            avg = np.mean(self.collected, axis=0)
            self._finish({"embeddings": self.collected, "avg": avg, "count": self.capture_count})
            return
        if self._recording:
            return
        self._recording = True
        self.recordButton.setEnabled(False)
        self.recordButton.setText("录音中…")
        self.statusLabel.setText("正在录音，请说话…")
        self.progressLabel.setText("")
        run_async(self._record_job, self._on_recorded, self._on_record_failed)

    @staticmethod
    def _record_job():
        audio = VoiceAuthManager.record_audio()
        return VoiceAuthManager.extract_embedding(audio)

    def _on_record_failed(self, detail: str):
        if self._closed:
            return
        logging.error("录音失败: %s", detail)
        self._recording = False
        self.recordButton.setEnabled(True)
        self.recordButton.setText("开始录音")
        self.statusLabel.setText("录音失败，请检查麦克风")
        self.progressLabel.setText("详情已写入日志")

    def _on_recorded(self, embedding):
        if self._closed:
            return
        self._recording = False
        self.recordButton.setEnabled(True)
        self.recordButton.setText("开始录音")
        self.collected.append(embedding)
        self.capture_count += 1
        self.progressLabel.setText(f"✅ 第 {self.capture_count} 次录音成功")
        if self.capture_count < 3:
            self.statusLabel.setText(
                f"继续录制第 {self.capture_count + 1} 次（共 3 次）"
            )
        else:
            self.statusLabel.setText("3 次录制完成，可以确认使用")
            self.recordButton.setText("确认使用")
            self._confirm_stage = True

    def _cancel(self):
        self._closed = True
        super()._cancel()


class CompactCryptoDialog(QDialog):
    """单窗口内完成：保存位置 → 密码 → 宫格/人脸/声纹 → 执行。"""

    def __init__(self, parent, mode: str, source_path: str):
        super().__init__(parent)
        self.mode = mode
        self.source = os.path.abspath(source_path)
        self.is_dir = os.path.isdir(self.source)
        self.busy = False
        self._finished = False
        self._closed = False
        self.result_path = ""
        self.factor_mask = 0
        self.salt = b""
        self.helpers = {}
        self._encrypt_helpers = {}
        self._parts = []
        self._factor_widgets = []

        if self.mode == "decrypt":
            self.factor_mask, self.salt, self.helpers = read_header_info(self.source)
            self._required_mask = self.factor_mask
            self._folder_mode = self.source.lower().endswith(".guifeinext")
        else:
            self._required_mask = 0
            self._folder_mode = self.is_dir

        title = "加密" if mode == "encrypt" else "解密"
        self.setWindowTitle(f"{title} - {os.path.basename(self.source)}")
        self.setModal(True)
        self.setMinimumSize(700, 500)
        self.resize(720, 520)
        icon = load_app_icon()
        if not icon.isNull():
            self.setWindowIcon(icon)
        try:
            FluentStyleSheet.DIALOG.apply(self)
        except Exception:
            pass

        self.vBoxLayout = QVBoxLayout(self)
        self.vBoxLayout.setContentsMargins(24, 20, 24, 18)
        self.vBoxLayout.setSpacing(10)

        self.stack = QStackedWidget(self)
        self.pathPage = self._build_path_page()
        self.optionPage = self._build_factor_page()
        self.runPage = self._build_run_page()
        self.stack.addWidget(self.pathPage)
        self.stack.addWidget(self.optionPage)
        self.stack.addWidget(self.runPage)
        self.vBoxLayout.addWidget(self.stack, 1)

        buttons = QHBoxLayout()
        buttons.setSpacing(10)
        buttons.addStretch(1)
        self.backButton = PushButton(self)
        self.backButton.setText("上一步")
        self.backButton.clicked.connect(self._back)
        self.cancelButton = PushButton(self)
        self.cancelButton.setText("取消")
        self.cancelButton.clicked.connect(self.reject)
        self.nextButton = PrimaryPushButton(self)
        self.nextButton.setText("下一步")
        self.nextButton.clicked.connect(self._next)
        buttons.addWidget(self.backButton)
        buttons.addWidget(self.cancelButton)
        buttons.addWidget(self.nextButton)
        self.vBoxLayout.addLayout(buttons)

        self.stack.setCurrentWidget(self.pathPage)
        self._apply_step()

    # ---------- 页面 ----------
    def _build_path_page(self) -> QWidget:
        page = QWidget(self)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        title = SubtitleLabel(page)
        title.setText("选择保存位置")
        layout.addWidget(title)

        sourceLabel = CaptionLabel(page)
        sourceLabel.setText(f"来源：{self.source}")
        sourceLabel.setWordWrap(True)
        layout.addWidget(sourceLabel)

        row = QHBoxLayout()
        row.setSpacing(10)
        self.saveEdit = LineEdit(page)
        self.saveEdit.setText(self._default_save_path())
        self.saveEdit.setClearButtonEnabled(True)
        browse = PushButton(page)
        browse.setText("浏览…")
        browse.clicked.connect(self._browse)
        row.addWidget(self.saveEdit, 1)
        row.addWidget(browse)
        layout.addLayout(row)

        hint = CaptionLabel(page)
        hint.setText(
            "文件夹会先打包再加密。"
            if self.mode == "encrypt" and self.is_dir
            else (
                "解密后的文件夹会解压到这个目录。"
                if self._folder_mode
                else "可以直接修改路径，或点“浏览”选择。"
            )
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)
        layout.addStretch(1)
        return page

    def _build_factor_page(self) -> QWidget:
        page = QWidget(self)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        title = SubtitleLabel(page)
        title.setText("输入密码" if self.mode == "encrypt" else "验证密码与因子")
        layout.addWidget(title)

        self.passwordEdit = PasswordLineEdit(page)
        self.passwordEdit.setPlaceholderText("主密码")
        self.passwordEdit.returnPressed.connect(self._next)
        layout.addWidget(self.passwordEdit)

        if self.mode == "encrypt":
            self.gridCheck = CheckBox(page)
            self.gridCheck.setText("附加 5×5 宫格")
            layout.addWidget(self.gridCheck)
            self.faceCheck = CheckBox(page)
            self.faceCheck.setText("附加人脸")
            self.faceCheck.setEnabled(FACE_SUPPORT)
            layout.addWidget(self.faceCheck)
            self.voiceCheck = CheckBox(page)
            self.voiceCheck.setText("附加声纹")
            self.voiceCheck.setEnabled(VOICE_SUPPORT)
            layout.addWidget(self.voiceCheck)
            tip = CaptionLabel(page)
            tip.setText("勾选的因子会在下一步依次采集。")
            tip.setWordWrap(True)
            layout.addWidget(tip)
        else:
            label = CaptionLabel(page)
            label.setText(f"该文件需要：{describe_factors(self.factor_mask)}")
            label.setWordWrap(True)
            layout.addWidget(label)
            tip = CaptionLabel(page)
            tip.setText("点击“下一步”后会依次采集宫格 / 人脸 / 声纹。")
            tip.setWordWrap(True)
            layout.addWidget(tip)

        self.factorStatus = CaptionLabel(page)
        self.factorStatus.setText("")
        self.factorStatus.setWordWrap(True)
        layout.addWidget(self.factorStatus)
        layout.addStretch(1)
        return page

    def _build_run_page(self) -> QWidget:
        page = QWidget(self)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self.runTitle = SubtitleLabel(page)
        self.runTitle.setText("正在加密…" if self.mode == "encrypt" else "正在解密…")
        layout.addWidget(self.runTitle)

        self.runStatus = CaptionLabel(page)
        self.runStatus.setText("请稍候")
        self.runStatus.setWordWrap(True)
        layout.addWidget(self.runStatus)

        self.runProgress = IndeterminateProgressBar(page, start=False)
        self.runProgress.setFixedHeight(4)
        layout.addWidget(self.runProgress)
        layout.addStretch(1)
        return page

    # ---------- 路径 ----------
    def _default_save_path(self) -> str:
        directory = os.path.dirname(self.source)
        base = os.path.basename(self.source.rstrip("\\/"))
        if self.mode == "encrypt":
            ext = ".guifeinext" if self.is_dir else ".guifei"
            return os.path.join(directory, base + ext)
        stem = os.path.splitext(base)[0]
        if self.source.lower().endswith(".guifeinext"):
            return os.path.join(directory, stem)
        if self.source.lower().endswith((".guifeitext", ".msc")):
            return os.path.join(directory, stem + ".txt")
        return os.path.join(directory, stem)

    def _browse(self):
        if self.mode == "decrypt" and self._folder_mode:
            path = QFileDialog.getExistingDirectory(
                self, "选择保存文件夹", self.saveEdit.text()
            )
        else:
            path, _ = QFileDialog.getSaveFileName(
                self, "选择保存位置", self.saveEdit.text(), "所有文件 (*.*)"
            )
        if path:
            self.saveEdit.setText(path)

    # ---------- 导航 ----------
    def _apply_step(self):
        current = self.stack.currentWidget()
        is_factor = current not in (self.pathPage, self.optionPage, self.runPage)
        if is_factor:
            self.backButton.hide()
            self.nextButton.hide()
            self.cancelButton.hide()
            return

        self.backButton.show()
        self.nextButton.show()
        self.cancelButton.show()
        if current is self.pathPage:
            self.backButton.setEnabled(False)
            self.nextButton.setText("下一步")
            self.nextButton.setEnabled(True)
        elif current is self.optionPage:
            self.backButton.setEnabled(not self.busy)
            self.nextButton.setText("开始加密" if self.mode == "encrypt" else "开始解密")
            self.nextButton.setEnabled(not self.busy)
        else:
            self.backButton.setEnabled(False)
            self.nextButton.setText("完成" if self._finished else "处理中…")
            self.nextButton.setEnabled(self._finished)

    def _back(self):
        if self.busy:
            return
        if self.stack.currentWidget() is self.optionPage:
            self.stack.setCurrentWidget(self.pathPage)
            self._apply_step()

    def _next(self):
        current = self.stack.currentWidget()
        if current is self.pathPage:
            if not self._validate_path():
                return
            self.stack.setCurrentWidget(self.optionPage)
            self.passwordEdit.setFocus()
            self._apply_step()
            return
        if current is self.optionPage:
            self._start()
            return
        if current is self.runPage and self._finished:
            self.accept()

    def _validate_path(self) -> bool:
        target = self.saveEdit.text().strip()
        if not target:
            self.factorStatus.setText("请填写保存位置")
            return False
        self.saveEdit.setText(os.path.abspath(target))
        return True

    # ---------- 因子序列 ----------
    def _start(self):
        if self.busy:
            return
        password = self.passwordEdit.text()
        if not password:
            self.factorStatus.setText("请输入主密码")
            return

        required_mask = self._required_mask
        pwd = password.encode("utf-8")
        self._parts = [len(pwd).to_bytes(2, "little") + pwd]
        self.factor_mask = FACTOR_PASSWORD
        self._encrypt_helpers = {}

        if self.mode == "encrypt":
            sequence = []
            if self.gridCheck.isChecked():
                sequence.append("grid")
            if self.faceCheck.isChecked():
                sequence.append("face")
            if self.voiceCheck.isChecked():
                sequence.append("voice")
            if self.faceCheck.isChecked() and not FACE_SUPPORT:
                self.factorStatus.setText("当前版本未包含人脸模块")
                return
            if self.voiceCheck.isChecked() and not VOICE_SUPPORT:
                self.factorStatus.setText("当前版本未包含声纹模块")
                return
        else:
            sequence = []
            if required_mask & FACTOR_GRID:
                sequence.append("grid")
            if required_mask & FACTOR_FACE:
                sequence.append("face")
            if required_mask & FACTOR_VOICE:
                sequence.append("voice")
            if "face" in sequence and not FACE_SUPPORT:
                self.factorStatus.setText("该文件需要人脸因子，但当前未加载人脸模块")
                return
            if "voice" in sequence and not VOICE_SUPPORT:
                self.factorStatus.setText("该文件需要声纹因子，但当前未加载声纹模块")
                return

        self._clear_factor_widgets()
        self._sequence = sequence
        self._sequence_index = 0
        self._show_next_factor()

    def _show_next_factor(self):
        if self._sequence_index >= len(self._sequence):
            self._run()
            return

        kind = self._sequence[self._sequence_index]
        if kind == "grid":
            title = "设置 5×5 宫格密码" if self.mode == "encrypt" else "请输入加密时的宫格密码"
            widget = GridFactorWidget(self, title, "按顺序点击至少 4 个点")
        elif kind == "face":
            widget = FaceFactorWidget(self, "采集人脸" if self.mode == "encrypt" else "人脸验证")
        else:
            widget = VoiceFactorWidget(self, "采集声纹" if self.mode == "encrypt" else "声纹验证")

        widget.completed.connect(lambda value, k=kind: self._on_factor_done(k, value))
        widget.cancelled.connect(self._abort_factors)
        self._factor_widgets.append(widget)
        self.stack.addWidget(widget)
        self.stack.setCurrentWidget(widget)
        self._apply_step()

    def _on_factor_done(self, kind: str, value):
        try:
            if kind == "grid":
                data = str(value).encode("utf-8")
                self._parts.append(len(data).to_bytes(2, "little") + data)
                self.factor_mask |= FACTOR_GRID
            elif kind == "face":
                if self.mode == "encrypt":
                    key, helper = generate_bio_key_and_helper(
                        value["avg"], value["features"]
                    )
                    self._parts.append(key)
                    self._encrypt_helpers["face"] = helper
                    self.factor_mask |= FACTOR_FACE
                else:
                    self._parts.append(recover_bio_key(self.helpers["face"], value["avg"]))
            else:
                if self.mode == "encrypt":
                    key, helper = generate_bio_key_and_helper(
                        value["avg"], value["embeddings"]
                    )
                    self._parts.append(key)
                    self._encrypt_helpers["voice"] = helper
                    self.factor_mask |= FACTOR_VOICE
                else:
                    self._parts.append(
                        recover_bio_key(self.helpers["voice"], value["avg"])
                    )
        except Exception:
            logging.error("因子采集失败: %s", traceback.format_exc())
            self._abort_factors()
            return

        self._sequence_index += 1
        self._show_next_factor()

    def _clear_factor_widgets(self):
        for widget in self._factor_widgets:
            try:
                if hasattr(widget, "stop"):
                    widget.stop()
                self.stack.removeWidget(widget)
                widget.deleteLater()
            except Exception:
                pass
        self._factor_widgets = []

    def _abort_factors(self):
        self._clear_factor_widgets()
        self._parts = []
        self._encrypt_helpers = {}
        self.factor_mask = self._required_mask if self.mode == "decrypt" else FACTOR_PASSWORD
        self.stack.setCurrentWidget(self.optionPage)
        self._apply_step()

    # ---------- 执行 ----------
    def _run(self):
        self._pending_factor = b"".join(self._parts)
        self.busy = True
        self.stack.setCurrentWidget(self.runPage)
        self._apply_step()
        self.runProgress.start()
        self.runStatus.setText("正在处理，请稍候…")
        if self.mode == "encrypt":
            self._worker = run_async(self._encrypt_job, self._on_encrypt_done, self._on_failed)
        else:
            self._worker = run_async(self._decrypt_job, self._on_decrypt_done, self._on_failed)

    def _encrypt_job(self):
        if self.is_dir:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                for root, _dirs, files in os.walk(self.source):
                    for name in files:
                        full = os.path.join(root, name)
                        archive.write(full, os.path.relpath(full, self.source))
            data = buffer.getvalue()
            file_type = FILE_TYPE_FOLDER
        else:
            with open(self.source, "rb") as f:
                data = f.read()
            file_type = FILE_TYPE_FILE

        salt = get_random_bytes(SALT_LENGTH)
        header = build_file_header(self.factor_mask, salt, self._encrypt_helpers)
        packet = make_packet(data, file_type, os.path.basename(self.source.rstrip("\\/")))
        payload = encrypt_data(packet, self._pending_factor, salt, header)
        target = self.saveEdit.text().strip()
        parent = os.path.dirname(os.path.abspath(target))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(target, "wb") as f:
            f.write(header + payload)
        return target

    def _decrypt_job(self):
        with open(self.source, "rb") as f:
            raw = f.read()
        mask, salt, helpers, payload = parse_file_header(raw)
        header = build_file_header(mask, salt, helpers)
        packet = decrypt_data(payload, self._pending_factor, salt, header)
        return read_packet(packet)

    def _on_encrypt_done(self, path: str):
        if self._closed:
            return
        self._finish(f"加密完成：{path}")

    def _on_decrypt_done(self, packet: dict):
        if self._closed:
            return
        try:
            target = self._write_decrypted(packet)
        except Exception:
            self._on_failed(traceback.format_exc())
            return
        self._finish(f"解密完成：{target}")

    def _write_decrypted(self, packet: dict) -> str:
        file_type = packet["file_type"]
        content = packet["content"]
        target = self.saveEdit.text().strip()

        if file_type == FILE_TYPE_FOLDER:
            if os.path.isdir(target) and os.listdir(target):
                target = self._unique_dir(os.path.dirname(target), os.path.basename(target))
            os.makedirs(target, exist_ok=True)
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                archive.extractall(target)
            return target

        if file_type == FILE_TYPE_TEXT and not os.path.splitext(target)[1]:
            target += ".txt"
            self.saveEdit.setText(target)
        parent = os.path.dirname(os.path.abspath(target))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(target, "wb") as f:
            f.write(content)
        return target

    @staticmethod
    def _unique_dir(parent_dir: str, base: str) -> str:
        target = os.path.join(parent_dir, base or "decrypted")
        counter = 1
        while os.path.exists(target):
            target = os.path.join(parent_dir, f"{base or 'decrypted'}_{counter}")
            counter += 1
        return target

    # ---------- 收尾 ----------
    def _finish(self, message: str):
        if self._closed:
            return
        self.busy = False
        self._finished = True
        self.result_path = message
        self.runProgress.stop()
        self.runTitle.setText("完成")
        self.runStatus.setText(message)
        self._apply_step()

    def _on_failed(self, detail: str):
        if self._closed:
            return
        self.busy = False
        self.runProgress.stop()
        self.runTitle.setText("失败")
        self.runStatus.setText("处理失败，请检查密码或因子后重试。")
        logging.error("紧凑加解密失败: %s", detail)
        self._clear_factor_widgets()
        self.stack.setCurrentWidget(self.optionPage)
        self._apply_step()

    def closeEvent(self, event):
        self._closed = True
        for widget in self._factor_widgets:
            try:
                if hasattr(widget, "stop"):
                    widget.stop()
            except Exception:
                pass
        super().closeEvent(event)

    def reject(self):
        self._closed = True
        for widget in self._factor_widgets:
            try:
                if hasattr(widget, "stop"):
                    widget.stop()
            except Exception:
                pass
        super().reject()


# ====================== 程序入口 ======================
def install_exception_hook():
    def hook(exc_type, exc_value, exc_tb):
        detail = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        logging.error("全局未捕获异常: %s", detail)
        try:
            app = QApplication.instance()
            if app is None:
                return
            parent = app.activeWindow()
            if parent is not None:
                show_error_detail(parent, "未捕获的异常", detail)
            else:
                MessageBox("未捕获的异常", "程序发生异常，详情已写入错误日志。").exec()
        except Exception:
            pass

    sys.excepthook = hook


def run_selftest() -> int:
    """打包自检：不弹窗，把环境 / 模型 / 加载结果写到临时文件。"""
    _patch_numba_cache_for_frozen()
    lines = [
        f"app {APP_NAME} {APP_VERSION}",
        f"frozen={getattr(sys, 'frozen', False)}",
        f"executable={sys.executable}",
        f"meipass={getattr(sys, '_MEIPASS', None)}",
        f"python={sys.version.split()[0]}",
        f"face_support={FACE_SUPPORT}",
        f"voice_support={VOICE_SUPPORT}",
    ]

    try:
        import onnxruntime as ort

        lines.append(f"onnxruntime={ort.__version__} providers={ort.get_available_providers()}")
    except Exception as exc:
        lines.append(f"onnxruntime=FAILED {exc}")
    try:
        import cv2

        lines.append(f"opencv={cv2.__version__}")
    except Exception as exc:
        lines.append(f"opencv=FAILED {exc}")
    try:
        import insightface

        lines.append(f"insightface={getattr(insightface, '__version__', '?')}")
    except Exception as exc:
        lines.append(f"insightface=FAILED {exc}")

    model_dir = resolve_face_model_dir()
    lines.append(f"model_dir={model_dir}")
    if model_dir:
        for name in FACE_MODEL_FILES:
            try:
                lines.append(
                    f"model_file={name} size={os.path.getsize(os.path.join(model_dir, name))}"
                )
            except OSError as exc:
                lines.append(f"model_file={name} MISSING {exc}")

    ok = False
    message = "skipped"
    if model_dir and FACE_SUPPORT:
        try:
            ok, message = FaceAuthManager.instance().load_model(model_dir)
        except Exception:
            message = traceback.format_exc()
    lines.append(f"load_model={ok} message={message}")

    # BCH 纠错自检（冻结后 galois/numba 是否正常）
    try:
        import numpy as _np

        feats = [_np.random.randn(512) for _ in range(3)]
        avg = _np.mean(feats, axis=0)
        key, helper = generate_bio_key_and_helper(avg, feats)
        recovered = recover_bio_key(helper, avg)
        lines.append(f"bch={'ok' if recovered == key else 'MISMATCH'}")
    except Exception as exc:
        lines.append(f"bch=FAILED {exc}")

    # 声纹模块自检（打包后确认 torch / resemblyzer / 模型都在）
    if VOICE_SUPPORT:
        try:
            import time as _time

            import numpy as _np

            t0 = _time.time()
            encoder = VoiceAuthManager.get_encoder()
            emb = encoder.embed_utterance(_np.zeros(16000, dtype=_np.float32))
            lines.append(
                f"voice_encoder=ok load={_time.time() - t0:.1f}s dim={len(emb)}"
            )
        except Exception as exc:
            lines.append(f"voice_encoder=FAILED {exc}")
    else:
        lines.append("voice_encoder=skipped")

    report_path = os.path.join(tempfile.gettempdir(), "guifei_selftest.txt")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
    except OSError:
        pass
    return 0 if ok else 1


def _cli_value(args, flag: str):
    if flag not in args:
        return None
    index = args.index(flag)
    if index + 1 < len(args) and not args[index + 1].startswith("--"):
        return args[index + 1]
    return None


def main():
    _patch_numba_cache_for_frozen()
    args = sys.argv[1:]

    if "--selftest" in args:
        sys.exit(run_selftest())
    if "--register-shell" in args:
        try:
            register_shell_menus()
            register_uninstall_entry()
        except Exception:
            logging.error("注册系统集成失败: %s", traceback.format_exc())
        sys.exit(0)
    if "--unregister-shell" in args:
        unregister_shell_menus()
        remove_uninstall_entry()
        sys.exit(0)

    decrypt_path = _cli_value(args, "--decrypt")
    encrypt_path = _cli_value(args, "--encrypt")
    start_in_tray = "--tray" in args

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setFont(QFont("Microsoft YaHei UI", 10))
    setTheme(Theme.AUTO)

    # 右键菜单：不开主界面，直接弹紧凑加/解密窗
    if decrypt_path or encrypt_path:
        mode = "decrypt" if decrypt_path else "encrypt"
        target_path = decrypt_path or encrypt_path
        try:
            dialog = CompactCryptoDialog(None, mode, target_path)
        except Exception:
            logging.error("紧凑窗口打开失败: %s", traceback.format_exc())
            MessageBox(
                "无法打开文件",
                "文件无法读取，或不是有效的 GuifeiCrypto 加密文件。",
                None,
            ).exec()
            sys.exit(2)
        dialog.exec()
        sys.exit(0)

    app.setQuitOnLastWindowClosed(not start_in_tray)

    try:
        threading.Thread(target=register_shell_menus, daemon=True).start()
    except Exception:
        logging.error("注册右键菜单失败: %s", traceback.format_exc())

    window = GuifeiCryptoWindow()

    if start_in_tray:
        window.ensure_tray()
        window.hide()
        if encrypt_path:
            QTimer.singleShot(600, lambda: window.begin_encryption(encrypt_path))
        sys.exit(app.exec())

    try:
        icon = window.windowIcon()
        splash = SplashScreen(
            icon if not icon.isNull() else FluentIcon.ASTERISK, window
        )
        splash.setIconSize(QSize(112, 112))
        window.show()
        splash.show()
        splash.raise_()

        def _close_splash(s=splash):
            try:
                s.finish()
                s.deleteLater()
            except Exception:
                pass

        QTimer.singleShot(950, _close_splash)
    except Exception:
        logging.error("启动画面失败: %s", traceback.format_exc())
        window.show()

    if encrypt_path:
        QTimer.singleShot(700, lambda: window.begin_encryption(encrypt_path))

    sys.exit(app.exec())


if __name__ == "__main__":
    install_exception_hook()
    main()

