# ========== 前置：屏蔽人脸识别相关弃用警告 ==========
import warnings
warnings.filterwarnings("ignore", category=FutureWarning, module="insightface")
warnings.filterwarnings("ignore", category=FutureWarning, module="skimage")
 
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import os
import sys
import io
import re
import hashlib
import struct
import tempfile
import zipfile
import traceback
import logging 
import numpy as np
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes 
import time
import tkinterdnd2
import base64
import json
import threading
import cv2 
from insightface.app import FaceAnalysis
import onnxruntime as ort
import sounddevice as sd
from resemblyzer import VoiceEncoder, preprocess_wav
import galois
 
# ====================== 全局日志配置 ======================
LOG_FILE = os.path.join(os.path.expanduser('~'), 'guifei_crypto_error.log')
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)
 
# ====================== stderr 重定向（仅写入日志，不弹窗） ======================
class _LogStderr:
    def __init__(self):
        self.buffer = io.StringIO()
    def write(self, s):
        self.buffer.write(s)
        if s.strip():
            logging.error(f"STDERR: {s.strip()}")
    def flush(self):
        pass
    def getvalue(self):
        return self.buffer.getvalue()
 
sys.stderr = _LogStderr()
 
# ====================== 核心常量定义 ======================
ENCRYPTION_MAGIC = b'guifeiCRYPT3'
VERSION = b'\x03'
AES_KEY_LENGTH = 32 
GCM_NONCE_LENGTH = 12
SALT_LENGTH = 16
# 降低内存需求：N=2^14 (16384) 内存需求约 16MB，避免 OpenSSL 内存限制错误
SCRYPT_N = 2**14
SCRYPT_R = 8 
SCRYPT_P = 1
 
FILE_TYPE_TEXT = b'msc'
FILE_TYPE_FILE = b'guifei'
FILE_TYPE_FOLDER = b'guifeinext'
 
GRID_SIZE = 5
GRID_POINT_SIZE = 24
GRID_SPACING = 8 
 
FACE_SIMILARITY_THRESHOLD = 0.75
FACE_MODEL_NAME = "buffalo_l"
FACE_PREVIEW_SIZE = (480, 360)
 
VOICE_SAMPLE_RATE = 16000
VOICE_DURATION = 3
VOICE_EMBEDDING_THRESHOLD = 0.75
 
# BCH 参数 (galois 库自动计算纠错能力)
BCH_N = 127
BCH_K = 64
BCH_K_BYTES = BCH_K // 8   # 8 字节
BCH_N_BITS = BCH_N
 
FACTOR_PASSWORD = 0b0001
FACTOR_GRID    = 0b0010
FACTOR_FACE    = 0b0100
FACTOR_VOICE   = 0b1000
 
def stable_feature_bits(features_avg, num_bits, selected_indices=None):
    vec = features_avg 
    if selected_indices is not None:
        selected_vals = vec[selected_indices]
    else:
        selected_vals = vec[:num_bits]
    bits = (selected_vals >= 0).astype(np.uint8)
    bit_bytes = np.packbits(bits, bitorder='little')
    expected_len = (num_bits + 7) // 8 
    if len(bit_bytes) < expected_len:
        bit_bytes = np.pad(bit_bytes, (0, expected_len - len(bit_bytes)))
    full_bytes = bit_bytes[:expected_len]
    # 转换为 Python bytes 以避免 numpy 数组与 bytes 拼接错误 
    full_bytes = bytes(full_bytes)
    if num_bits % 8 != 0:
        mask = (1 << (num_bits % 8)) - 1
        full_bytes = full_bytes[:-1] + bytes([full_bytes[-1] & mask])
    return full_bytes
 
def select_stable_indices(features_list, num_bits=BCH_N_BITS):
    avg = np.mean(features_list, axis=0)
    if len(avg) < num_bits:
        raise ValueError(f"特征维度({len(avg)})小于所需位数({num_bits})，无法提取稳定位")
    abs_avg = np.abs(avg)
    indices = np.argsort(-abs_avg)[:num_bits]
    return indices.tolist()
 
def generate_bio_key_and_helper(avg_feature, features_list=None):
    if features_list:
        indices = select_stable_indices(features_list, BCH_N_BITS)
    else:
        if len(avg_feature) < BCH_N_BITS:
            raise ValueError(f"特征维度({len(avg_feature)})小于BCH所需位数({BCH_N_BITS})")
        indices = list(range(BCH_N_BITS))
 
    bch = galois.BCH(n=BCH_N, k=BCH_K)
    key = get_random_bytes(BCH_K_BYTES)
    key_bits = np.unpackbits(np.frombuffer(key, dtype=np.uint8), bitorder='little')[:BCH_K]
    key_gf = galois.GF(2)(key_bits.tolist())
    codeword_gf = bch.encode(key_gf)
    codeword_bits = np.array(codeword_gf.tolist(), dtype=np.uint8)
    codeword_bytes = np.packbits(codeword_bits, bitorder='little')
    expected_len = (BCH_N + 7) // 8
    codeword_bytes = codeword_bytes[:expected_len]
    # 转换为 Python bytes
    codeword_bytes = bytes(codeword_bytes)
    if BCH_N % 8 != 0:
        mask = (1 << (BCH_N % 8)) - 1
        codeword_bytes = codeword_bytes[:-1] + bytes([codeword_bytes[-1] & mask])
 
    bio_bits_raw = stable_feature_bits(avg_feature, BCH_N_BITS, indices)
    if len(codeword_bytes) != len(bio_bits_raw):
        raise RuntimeError(f"码字长度({len(codeword_bytes)})与生物比特长度({len(bio_bits_raw)})不匹配")
    helper_bytes = bytes(a ^ b for a, b in zip(codeword_bytes, bio_bits_raw))
    helper_data = {
        'helper': base64.b64encode(helper_bytes).decode(),
        'indices': indices 
    }
    return key, helper_data
 
def recover_bio_key(helper_data, avg_feature):
    bch = galois.BCH(n=BCH_N, k=BCH_K)
    helper_bytes = base64.b64decode(helper_data['helper'])
    indices = helper_data['indices']
 
    if len(avg_feature) < BCH_N_BITS:
        raise ValueError(f"特征维度({len(avg_feature)})小于BCH所需位数({BCH_N_BITS})")
    bio_bits_raw = stable_feature_bits(avg_feature, BCH_N_BITS, indices)
 
    if len(helper_bytes) != len(bio_bits_raw):
        raise RuntimeError("辅助数据长度与生物比特长度不匹配")
 
    noisy_codeword_bytes = bytes(a ^ b for a, b in zip(helper_bytes, bio_bits_raw))
    noisy_bits = np.unpackbits(np.frombuffer(noisy_codeword_bytes, dtype=np.uint8), bitorder='little')[:BCH_N]
    noisy_gf = galois.GF(2)(noisy_bits.tolist())
    decoded_gf = bch.decode(noisy_gf)
    decoded_bits = np.array(decoded_gf.tolist(), dtype=np.uint8)
 
    if len(decoded_bits) < BCH_K:
        decoded_bits = np.pad(decoded_bits, (0, BCH_K - len(decoded_bits)), 'constant')
    else:
        decoded_bits = decoded_bits[:BCH_K]
 
    key_bytes = np.packbits(decoded_bits, bitorder='little')
    return key_bytes[:BCH_K_BYTES]
 
# ====================== UI 组件 ======================
class LoadingWindow(tk.Toplevel):
    def __init__(self, parent, callback=None):
        super().__init__(parent)
        self.title("加载中")
        self.configure(bg="#f0f0f0")
        self.attributes('-alpha', 0.8)
        self.attributes('-topmost', True)
        self.transient(parent)
        self.grab_set()
        tk.Label(self, text="GuìFē! :)超级加密工具努力加载中...", bg="#f0f0f0", font=("微软雅黑", 12)).pack(pady=20)
        self.progress = ttk.Progressbar(self, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=20, pady=10)
        self.progress.start(20)
        self.after(10, self._center_window)
        if callback:
            self.after(1500, self._safe_callback)
        self._callback = callback
 
    def _safe_callback(self):
        if self.winfo_exists() and self._callback:
            self._callback()
 
    def _center_window(self):
        self.update_idletasks()
        width = self.winfo_reqwidth() + 20
        height = self.winfo_reqheight() + 10 
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
 
class PasswordDialog(tk.Toplevel):
    def __init__(self, parent, title, prompt, show_strength=True):
        super().__init__(parent)
        self.title(title)
        self.parent = parent 
        self.result = None 
        self.show_strength = show_strength 
        self.configure(bg="#e0e0e0")
        self.attributes('-alpha', 0.9)
        self.attributes('-topmost', True)
        self.transient(parent)
        self.grab_set()
        tk.Label(self, text=prompt, font=("微软雅黑", 11), bg="#e0e0e0").pack(pady=15)
        self.password_var = tk.StringVar()
        self.password_var.trace_add("write", self.update_strength)
        self.password_entry = tk.Entry(self, textvariable=self.password_var, show="*",
                                       font=("微软雅黑", 12), bg="#f5f5f5", relief=tk.FLAT, bd=1)
        self.password_entry.pack(pady=5, padx=20, fill=tk.X)
        if show_strength:
            self.strength_frame = tk.Frame(self, height=10, bg="#f5f5f5")
            self.strength_frame.pack(pady=5, padx=20, fill=tk.X)
            self.strength_label = tk.Label(self, text="密码强度: 无", font=("微软雅黑", 9), bg="#e0e0e0")
            self.strength_label.pack(pady=2)
        btn_frame = tk.Frame(self, bg="#e0e0e0")
        btn_frame.pack(pady=15)
        tk.Button(btn_frame, text="确定", command=self.ok, width=10,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="取消", command=self.cancel, width=10,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(side=tk.LEFT)
        self.password_entry.focus_set()
        self.after(10, self._center_window)
 
    def _center_window(self):
        self.update_idletasks()
        self.after(30, self._do_center)
 
    def _do_center(self):
        width = self.winfo_reqwidth() + 20
        height = self.winfo_reqheight() + 10
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
 
    def calculate_strength(self, password):
        score = 0
        length = len(password)
        if length >= 8: score += 20
        if length >= 12: score += 10
        if length >= 16: score += 10
        if length >= 20: score += 10
        if re.search(r'[A-Z]', password): score += 15
        if re.search(r'[a-z]', password): score += 15
        if re.search(r'[0-9]', password): score += 15
        if re.search(r'[^A-Za-z0-9]', password): score += 15
        common_passwords = {"12345678", "password", "01234567", "1234567890", "abcd1234", "11111111"}
        if password.lower() in common_passwords:
            score = max(0, score - 30)
        return min(score, 100)
 
    def update_strength(self, *args):
        if not self.show_strength: return 
        password = self.password_var.get()
        strength = self.calculate_strength(password)
        for widget in self.strength_frame.winfo_children():
            widget.destroy()
        color = "#ff4444" if strength < 30 else "#ffaa00" if strength < 60 else "#aacc00" if strength < 80 else "#44dd00"
        bar = tk.Frame(self.strength_frame, bg=color, width=int(strength * 4), height=10)
        bar.pack(side=tk.LEFT, fill=tk.Y)
        strength_text = "弱" if strength < 30 else "中" if strength < 60 else "强" if strength < 80 else "极强"
        self.strength_label.config(text=f"密码强度: {strength_text} ({strength}%)")
 
    def ok(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("警告", "密码不能为空！", parent=self)
            return 
        self.result = password 
        self.destroy()
 
    def cancel(self):
        self.result = None
        self.destroy()
 
    def show(self):
        self.wait_window()
        return self.result
 
class GridSignaturePad(tk.Toplevel):
    def __init__(self, parent, title="宫格加密", existing_signature=None):
        super().__init__(parent)
        self.title(title)
        self.parent = parent
        self.result = None
        self.existing_signature = existing_signature 
        self.is_verified = False
        self.configure(bg="#e0e0e0")
        self.attributes('-alpha', 0.9)
        self.attributes('-topmost', True)
        self.transient(parent)
        self.grab_set()
        self.selected_points = []
        self.grid_canvas = None 
        self.point_positions = {}
        self.setup_ui()
        self.after(10, self._center_window)
 
    def _center_window(self):
        self.update_idletasks()
        self.after(30, self._do_center)
 
    def _do_center(self):
        width = self.winfo_reqwidth() + 20
        height = self.winfo_reqheight() + 10 
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
 
    def setup_ui(self):
        prompt_text = "请按顺序点击宫格点完成连接（至少选择4格）"
        if self.existing_signature:
            prompt_text = "请按之前顺序点击宫格点完成验证"
        tk.Label(self, text=prompt_text, font=("微软雅黑", 10), bg="#e0e0e0").pack(pady=10)
        canvas_width = GRID_SIZE * (GRID_POINT_SIZE + GRID_SPACING) + GRID_SPACING
        canvas_height = canvas_width 
        self.grid_canvas = tk.Canvas(self, width=canvas_width, height=canvas_height,
                                     bg="white", bd=1, relief=tk.SOLID)
        self.grid_canvas.pack(pady=10)
        self.draw_grid()
        self.grid_canvas.bind("<Button-1>", self.on_point_click)
        btn_frame = tk.Frame(self, bg="#e0e0e0")
        btn_frame.pack(pady=20)
        tk.Button(btn_frame, text="清除", command=self.clear, width=10,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="确定", command=self.ok, width=10,
                  bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00").pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="取消", command=self.cancel, width=10,
                  bg="#ff4444", fg="white", relief=tk.FLAT, activebackground="#dd2222").pack(side=tk.LEFT, padx=10)
        self.point_label = tk.Label(self, text="已选点：无", font=("微软雅黑", 9), bg="#e0e0e0")
        self.point_label.pack(pady=5)
 
    def draw_grid(self):
        self.grid_canvas.delete("all")
        self.point_positions.clear()
        start_x = GRID_SPACING + GRID_POINT_SIZE // 2
        start_y = GRID_SPACING + GRID_POINT_SIZE // 2 
        for row in range(GRID_SIZE):
            for col in range(GRID_SIZE):
                x = start_x + col * (GRID_POINT_SIZE + GRID_SPACING)
                y = start_y + row * (GRID_POINT_SIZE + GRID_SPACING)
                self.grid_canvas.create_oval(
                    x - GRID_POINT_SIZE//2, y - GRID_POINT_SIZE//2,
                    x + GRID_POINT_SIZE//2, y + GRID_POINT_SIZE//2,
                    fill="#cccccc", outline="#666666", width=2,
                    tags=(f"point_{row}_{col}", "grid_point")
                )
                self.grid_canvas.create_text(
                    x, y, text=f"{row+1},{col+1}", fill="#666666", font=("微软雅黑", 8),
                    tags=(f"coord_{row}_{col}", "point_coord")
                )
                self.point_positions[(row, col)] = (x, y)
        self.draw_connections()
 
    def draw_connections(self):
        if len(self.selected_points) < 2: return
        for i in range(1, len(self.selected_points)):
            prev_point = self.selected_points[i-1]
            curr_point = self.selected_points[i]
            x1, y1 = self.point_positions[prev_point]
            x2, y2 = self.point_positions[curr_point]
            self.grid_canvas.create_line(x1, y1, x2, y2, fill="#44dd00", width=3, tags="connection_line")
        for idx, (row, col) in enumerate(self.selected_points):
            x, y = self.point_positions[(row, col)]
            self.grid_canvas.create_oval(
                x - GRID_POINT_SIZE//2, y - GRID_POINT_SIZE//2,
                x + GRID_POINT_SIZE//2, y + GRID_POINT_SIZE//2,
                fill="#44dd00", outline="#22bb00", width=2,
                tags=(f"selected_{row}_{col}", "selected_point")
            )
            self.grid_canvas.create_text(x, y, text=str(idx+1), fill="white", font=("微软雅黑", 10, "bold"),
                                         tags=(f"num_{row}_{col}", "point_number"))
 
    def on_point_click(self, event):
        click_x, click_y = event.x, event.y
        selected_point = None
        for (row, col), (x, y) in self.point_positions.items():
            if (click_x - x)**2 + (click_y - y)**2 <= (GRID_POINT_SIZE//2)**2:
                selected_point = (row, col); break
        if selected_point:
            if len(self.selected_points) == 0 or self.selected_points[-1] != selected_point:
                self.selected_points.append(selected_point)
                self.draw_grid()
                self.update_point_label()
 
    def update_point_label(self):
        if not self.selected_points:
            self.point_label.config(text="已选点：无")
        else:
            point_list = [f"({r+1},{c+1})" for r, c in self.selected_points]
            self.point_label.config(text="已选点：" + "+".join(point_list))
 
    def clear(self):
        self.selected_points = []; self.draw_grid(); self.update_point_label()
 
    def get_signature_string(self):
        return "+".join([f"({r+1},{c+1})" for r, c in self.selected_points])
 
    def parse_signature_string(self, signature_str):
        if not signature_str: return []
        matches = re.findall(r'\((\d+),(\d+)\)', signature_str)
        points = []
        for row_str, col_str in matches:
            row, col = int(row_str)-1, int(col_str)-1 
            if 0 <= row < GRID_SIZE and 0 <= col < GRID_SIZE:
                points.append((row, col))
        return points
 
    def get_signature_data(self):
        signature_str = self.get_signature_string()
        return {
            'version': '1.0', 'grid_size': GRID_SIZE,
            'signature_string': signature_str, 'point_sequence': self.selected_points,
            'sequence_length': len(self.selected_points), 'created_at': time.time(),
            'hash': hashlib.sha256(signature_str.encode()).hexdigest()
        }
 
    def verify_signature(self):
        if not self.existing_signature or not self.selected_points: return False
        ref_str = self.existing_signature.get('signature_string', '')
        return self.selected_points == self.parse_signature_string(ref_str)
 
    def ok(self):
        if len(self.selected_points) < 4:
            messagebox.showwarning("警告", "至少需要选择4个点完成连接！", parent=self); return
        if self.existing_signature:
            self.is_verified = self.verify_signature()
            if not self.is_verified:
                messagebox.showerror("错误", "宫格连接顺序不匹配，验证失败！", parent=self)
                self.clear(); return 
        self.result = self.get_signature_data()
        self.destroy()
 
    def cancel(self): self.result = None; self.destroy()
 
    def show(self): self.wait_window(); return self.result, self.is_verified 
 
# ====================== 人脸识别核心组件（带CPU降级） ======================
class FaceAuthManager:
    _instance = None 
    _face_app = None
    def __new__(cls):
        if cls._instance is None: cls._instance = super().__new__(cls)
        return cls._instance
 
    def load_model(self):
        if self._face_app is not None:
            return True, "模型已加载"
        original_stdout, original_stderr = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = io.StringIO()
        try:
            try:
                providers = ['DmlExecutionProvider']
                self._face_app = FaceAnalysis(name=FACE_MODEL_NAME, providers=providers)
                self._face_app.prepare(ctx_id=0, det_size=(640, 640))
                return True, "人脸识别启用 GPU 加速"
            except Exception:
                providers = ['CPUExecutionProvider']
                self._face_app = FaceAnalysis(name=FACE_MODEL_NAME, providers=providers)
                self._face_app.prepare(ctx_id=-1, det_size=(640, 640))
                return True, "未检测到 GPU 加速，将使用 CPU 进行人脸识别，速度可能较慢"
        except Exception as e:
            return False, f"人脸模型加载失败：{e}"
        finally:
            sys.stdout, sys.stderr = original_stdout, original_stderr
 
    def extract_feature(self, frame):
        faces = self._face_app.get(frame)
        if not faces: return None 
        best_face = max(faces, key=lambda f: f.det_score)
        return best_face.embedding.copy()
 
    @staticmethod
    def calc_similarity(feat1, feat2):
        return np.dot(feat1, feat2) / (np.linalg.norm(feat1) * np.linalg.norm(feat2))
 
class FaceAuthDialog(tk.Toplevel):
    def __init__(self, parent, mode="collect", reference_features=None, title="人脸验证"):
        super().__init__(parent)
        self.title(title); self.parent = parent; self.mode = mode
        self.reference_features = reference_features
        self.result = None; self.is_verified = False; self.running = True 
        self.current_frame = None; self.collected_features = []; self.capture_count = 0
        self.configure(bg="#e0e0e0"); self.attributes('-alpha', 0.9); self.attributes('-topmost', True)
        self.transient(parent); self.grab_set()
        self.setup_ui(); self.init_camera_and_model()
        self.after(10, self._center_window)
 
    def _center_window(self):
        self.update_idletasks()
        self.after(30, self._do_center)
 
    def _do_center(self):
        w, h = self.winfo_reqwidth()+20, self.winfo_reqheight()+10
        x = (self.winfo_screenwidth()//2) - (w//2)
        y = (self.winfo_screenheight()//2) - (h//2)
        self.geometry(f"{w}x{h}+{x}+{y}")
 
    def setup_ui(self):
        prompt = "请正对摄像头，点击按钮采集第1张人脸（共3张）" if self.mode=="collect" else "请正对摄像头，点击按钮完成人脸验证"
        self.status_label = tk.Label(self, text=prompt, font=("微软雅黑",11), bg="#e0e0e0"); self.status_label.pack(pady=10)
        self.preview_label = tk.Label(self, bd=2, relief=tk.SUNKEN, bg="black"); self.preview_label.pack(pady=5)
        self.result_label = tk.Label(self, text="", font=("微软雅黑",10), bg="#e0e0e0", fg="#333"); self.result_label.pack(pady=5)
        btn_frame = tk.Frame(self, bg="#e0e0e0"); btn_frame.pack(pady=15)
        self.capture_btn = tk.Button(btn_frame, text="拍照采集", command=self.on_capture, width=12,
                                     bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00", state=tk.DISABLED)
        self.capture_btn.pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="取消", command=self.cancel, width=10,
                  bg="#ff4444", fg="white", relief=tk.FLAT, activebackground="#dd2222").pack(side=tk.LEFT, padx=10)
 
    def init_camera_and_model(self):
        def task():
            try:
                manager = FaceAuthManager()
                success, msg = manager.load_model()
                if not success:
                    raise Exception(msg)
                self.after(0, lambda m=msg: messagebox.showinfo("提示", m, parent=self))
 
                cap_backend = cv2.CAP_DSHOW if sys.platform=="win32" else 0
                self.cap = cv2.VideoCapture(0, cap_backend)
                if not self.cap.isOpened():
                    raise Exception("无法打开摄像头设备")
                
                self.after(0, lambda: (
                    self.capture_btn.config(state=tk.NORMAL),
                    self.update_preview()
                ))
            except Exception as e:
                logging.error(f"人脸初始化失败: {str(e)}")
                self.after(0, lambda e=e: (
                    messagebox.showerror("错误", str(e), parent=self),
                    self.destroy()
                ))
        threading.Thread(target=task, daemon=True).start()
 
    def update_preview(self):
        if not self.running or not hasattr(self, 'cap') or not self.cap.isOpened():
            return
        if not self.winfo_exists():
            return
        try:
            ret, frame = self.cap.read()
            if ret:
                self.current_frame = frame.copy()
                frame_show = cv2.resize(frame, FACE_PREVIEW_SIZE)
                frame_rgb = cv2.cvtColor(frame_show, cv2.COLOR_BGR2RGB)
                img = Image.fromarray(frame_rgb)
                imgtk = ImageTk.PhotoImage(image=img)
                self.preview_label.imgtk = imgtk 
                self.preview_label.configure(image=imgtk)
        except Exception as e:
            logging.error(f"预览更新异常: {str(e)}")
            return
        self.after(20, self.update_preview)
 
    def on_capture(self):
        if self.current_frame is None: return
        manager = FaceAuthManager()
        feat = manager.extract_feature(self.current_frame)
        if feat is None: 
            messagebox.showwarning("提示","未检测到人脸，请正对摄像头",parent=self)
            return
        if self.mode == "collect":
            self.collected_features.append(feat); self.capture_count += 1
            self.result_label.config(text=f"✅ 第 {self.capture_count} 张采集成功")
            if self.capture_count < 3:
                self.status_label.config(text=f"继续采集第 {self.capture_count+1} 张人脸（共3张）")
            else:
                self.status_label.config(text="3张人脸采集完成！")
                self.capture_btn.config(text="确认使用", bg="#44dd00"); self.capture_btn.config(command=self.confirm_collect)
        else:
            sim_list = [manager.calc_similarity(feat, ref) for ref in self.reference_features]
            avg_sim = float(np.mean(sim_list))
            self.is_verified = avg_sim >= FACE_SIMILARITY_THRESHOLD
            if self.is_verified:
                self.result_label.config(text=f"✅ 验证通过  相似度：{avg_sim:.4f}", fg="#2e7d32")
                self.capture_btn.config(state=tk.DISABLED); self.after(800, self.confirm_verify)
            else:
                self.result_label.config(text=f"❌ 验证失败  相似度：{avg_sim:.4f}", fg="#c62828")
 
    def confirm_collect(self):
        avg_feat = np.mean(self.collected_features, axis=0)
        self.result = {'features': self.collected_features, 'avg': avg_feat, 'count': self.capture_count}
        self.destroy()
 
    def confirm_verify(self): self.result = self.is_verified; self.destroy()
    def cancel(self): self.result = None; self.destroy()
    def show(self): self.wait_window(); return self.result, self.is_verified
 
    def destroy(self):
        self.running = False
        try:
            if hasattr(self, 'cap') and self.cap.isOpened():
                self.cap.release()
            cv2.destroyAllWindows()
        except Exception as e:
            logging.error(f"摄像头释放异常: {str(e)}")
        super().destroy()
 
# ====================== 声纹识别核心组件 ======================
class VoiceAuthManager:
    _encoder = None
    @classmethod
    def get_encoder(cls):
        if cls._encoder is None: cls._encoder = VoiceEncoder()
        return cls._encoder
    @staticmethod 
    def record_audio(duration=VOICE_DURATION, sample_rate=VOICE_SAMPLE_RATE):
        recording = sd.rec(int(duration*sample_rate), samplerate=sample_rate, channels=1, dtype='float32')
        sd.wait(); return recording.flatten()
    @staticmethod
    def extract_embedding(audio, sample_rate=VOICE_SAMPLE_RATE):
        wav = preprocess_wav(audio, source_sr=sample_rate)
        return VoiceAuthManager.get_encoder().embed_utterance(wav)
    @staticmethod
    def calc_similarity(embed1, embed2):
        embed1 = embed1 / np.linalg.norm(embed1)
        embed2 = embed2 / np.linalg.norm(embed2)
        return float(np.dot(embed1, embed2))
 
class VoiceAuthDialog(tk.Toplevel):
    def __init__(self, parent, mode="collect", reference_embeddings=None, title="声纹验证"):
        super().__init__(parent)
        self.title(title); self.parent = parent; self.mode = mode
        self.reference_embeddings = reference_embeddings
        self.result = None; self.is_verified = False
        self.collected_embeddings = []; self.capture_count = 0
        self.configure(bg="#e0e0e0"); self.attributes('-alpha',0.9); self.attributes('-topmost',True)
        self.transient(parent); self.grab_set()
        self.setup_ui(); self.after(10, self._center_window)
 
    def _center_window(self):
        self.update_idletasks()
        self.after(30, self._do_center)
 
    def _do_center(self):
        w, h = self.winfo_reqwidth()+20, self.winfo_reqheight()+10
        x = (self.winfo_screenwidth()//2) - (w//2)
        y = (self.winfo_screenheight()//2) - (h//2)
        self.geometry(f"{w}x{h}+{x}+{y}")
 
    def setup_ui(self):
        prompt = "请点击按钮录制声音（每次3秒，共3次）" if self.mode=="collect" else "请点击按钮录制声音以验证身份"
        self.status_label = tk.Label(self, text=prompt, font=("微软雅黑",11), bg="#e0e0e0"); self.status_label.pack(pady=20)
        self.progress_label = tk.Label(self, text="", font=("微软雅黑",10), bg="#e0e0e0", fg="#333"); self.progress_label.pack(pady=10)
        btn_frame = tk.Frame(self, bg="#e0e0e0"); btn_frame.pack(pady=20)
        self.record_btn = tk.Button(btn_frame, text="开始录音", command=self.on_record, width=12,
                                    bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00")
        self.record_btn.pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="取消", command=self.cancel, width=10,
                  bg="#ff4444", fg="white", relief=tk.FLAT, activebackground="#dd2222").pack(side=tk.LEFT, padx=10)
 
    def on_record(self):
        self.record_btn.config(state=tk.DISABLED, text="录音中..."); self.progress_label.config(text="正在录音... 请说话"); self.update()
        def task():
            try:
                audio = VoiceAuthManager.record_audio()
                embed = VoiceAuthManager.extract_embedding(audio)
                self.after(0, lambda emb=embed: self._safe_process_recording(emb))
            except Exception as e:
                logging.error(f"录音失败: {str(e)}")
                self.after(0, lambda e=e: self._safe_record_error(str(e)))
        threading.Thread(target=task, daemon=True).start()
 
    def _safe_process_recording(self, embed):
        try:
            if not self.winfo_exists(): return
            self.process_recording(embed)
        except: pass
 
    def _safe_record_error(self, error_msg):
        try:
            if not self.winfo_exists(): return
            self.record_btn.config(state=tk.NORMAL, text="开始录音"); self.progress_label.config(text="")
            # 显示详细错误窗口
            self.master.show_error_window("录音失败", error_msg)
        except: pass
 
    def process_recording(self, embed):
        try: self.record_btn.config(state=tk.NORMAL, text="开始录音")
        except tk.TclError: return
        if self.mode == "collect":
            self.collected_embeddings.append(embed); self.capture_count += 1 
            self.progress_label.config(text=f"✅ 第 {self.capture_count} 次录音成功")
            if self.capture_count < 3:
                self.status_label.config(text=f"继续录制第 {self.capture_count+1} 次声音（共3次）")
            else:
                self.status_label.config(text="3次声音录制完成！")
                self.record_btn.config(text="确认使用", command=self.confirm_collect)
        else:
            sim_list = [VoiceAuthManager.calc_similarity(embed, ref) for ref in self.reference_embeddings]
            avg_sim = float(np.mean(sim_list))
            self.is_verified = avg_sim >= VOICE_EMBEDDING_THRESHOLD
            if self.is_verified:
                self.progress_label.config(text=f"✅ 验证通过  相似度：{avg_sim:.4f}", fg="#2e7d32")
                self.record_btn.config(state=tk.DISABLED); self.after(800, self.confirm_verify)
            else:
                self.progress_label.config(text=f"❌ 验证失败  相似度：{avg_sim:.4f}", fg="#c62828")
 
    def confirm_collect(self):
        avg_emb = np.mean(self.collected_embeddings, axis=0)
        self.result = {'embeddings': self.collected_embeddings, 'avg': avg_emb, 'count': self.capture_count}
        self.destroy()
 
    def confirm_verify(self): self.result = self.is_verified; self.destroy()
    def cancel(self): self.result = None; self.destroy()
    def show(self): self.wait_window(); return self.result, self.is_verified
 
# ====================== 主程序 ======================
class GuifeiCryptoTool(tkinterdnd2.Tk):
    def __init__(self):
        super().__init__()
        self.title("GuìFē! :) 超级加密工具 v17.6.3")
        self.geometry("1370x770")
        self.configure(bg="#f0f0f0")
        self.attributes('-alpha', 0.97)
        self.center_window()
        self.current_mode = "main"
        self.selected_path = None
        self.use_grid_signature = tk.BooleanVar(value=False)
        self.use_face_verification = tk.BooleanVar(value=False)
        self.use_voice_verification = tk.BooleanVar(value=False)
        self.file_path_var = tk.StringVar(value="未选择文件")
        self.save_path_var = tk.StringVar(value="")
        self.folder_path_var = tk.StringVar(value="未选择文件夹")
        self.folder_save_var = tk.StringVar(value="")
        self.decrypt_path_var = tk.StringVar(value="未选择加密文件")
        self.doc_text = None
        self.progress_var = tk.DoubleVar()
        self.progress_bar = None
        self.status_bar = None 
        self.loading = None
        self.after(100, self._finish_loading)
 
    def _finish_loading(self):
        self.loading = LoadingWindow(self, callback=self._on_loading_complete)
 
    def _on_loading_complete(self):
        if self.loading and self.loading.winfo_exists():
            self.loading.destroy()
        self.loading = None
        self.setup_main_ui()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
 
    def show_about(self):
        messagebox.showinfo("关于",
                            "GuìFē! :) 超级加密工具 v17.6.3\n\n"
                            "多因子军用级加密\nAES‑256‑GCM + scrypt + 模糊生物密钥\n"
                            "宫格/人脸/声纹 按需组合\n\n"
                            "⚠️ 仅供学习交流使用，请勿用于商业用途")
 
    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
 
    def setup_main_ui(self):
        self.current_mode = "main"
        for widget in self.winfo_children():
            widget.destroy()
        tk.Label(self, text="GuìFē! :) 超级加密工具 v17.6.3", font=("微软雅黑", 16, "bold"), bg="#f0f0f0").pack(pady=30)
        func_frame = tk.Frame(self, bg="#f0f0f0"); func_frame.pack(fill=tk.X, padx=120, pady=10)
        buttons = [
            ("文件加密", self.show_file_encrypt_ui),
            ("文件夹加密", self.show_folder_encrypt_ui),
            ("文档加密", self.show_doc_encrypt_ui),
            ("一键解密", self.show_auto_decrypt_ui),
            ("关于", self.show_about)
        ]
        for text, cmd in buttons:
            btn_frame = tk.Frame(func_frame, bg="#cccccc", height=60, relief=tk.RAISED, bd=2)
            btn_frame.pack_propagate(False); btn_frame.pack(fill=tk.X, pady=5)
            btn_label = tk.Label(btn_frame, text=text, font=("微软雅黑", 13), bg="#cccccc"); btn_label.pack(expand=True)
            btn_frame.bind("<Button-1>", lambda e, c=cmd: c())
            btn_label.bind("<Button-1>", lambda e, c=cmd: c())
        self.enable_drag_and_drop()
        self.status_bar = tk.Label(self, text="就绪 | 支持拖拽文件/文件夹，加密文件拖入自动解密", bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)
 
    def show_error_window(self, title, detail):
        """创建居中显示的错误详情窗口"""
        win = tk.Toplevel(self)
        win.title(title)
        win.config(bg="#f0f0f0")
        win.attributes('-topmost', True)
 
        # 设置窗口内容
        txt = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Consolas", 9))
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        txt.insert(tk.END, detail)
        txt.config(state=tk.DISABLED)
        btn_frame = tk.Frame(win, bg="#f0f0f0")
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="关闭", command=win.destroy, width=10,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(side=tk.LEFT, padx=5)
 
        # 窗口居中并设置合理大小
        win.update_idletasks()
        width = max(800, win.winfo_reqwidth())
        height = max(600, win.winfo_reqheight())
        x = (win.winfo_screenwidth() // 2) - (width // 2)
        y = (win.winfo_screenheight() // 2) - (height // 2)
        win.geometry(f"{width}x{height}+{x}+{y}")
 
    def enable_drag_and_drop(self):
        self.drop_target_register(tkinterdnd2.DND_FILES)
        self.dnd_bind('<<Drop>>', self.on_drop)
 
    def _is_encrypted_file(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                return f.read(len(ENCRYPTION_MAGIC)) == ENCRYPTION_MAGIC
        except:
            return False
 
    def on_drop(self, event):
        files = self.tk.splitlist(event.data)
        if not files: return
        dropped_path = files[0]
        self.selected_path = dropped_path
        if self.current_mode == "main":
            if os.path.isfile(dropped_path) and self._is_encrypted_file(dropped_path):
                self.show_auto_decrypt_ui()
                self.decrypt_path_var.set(dropped_path)
                return
            if os.path.isdir(dropped_path):
                self.show_folder_encrypt_ui()
                self.folder_path_var.set(dropped_path)
            else:
                self.show_file_encrypt_ui()
                self.file_path_var.set(dropped_path)
            return 
        if self.current_mode == "file": self.file_path_var.set(dropped_path)
        elif self.current_mode == "folder": self.folder_path_var.set(dropped_path) if os.path.isdir(dropped_path) else None
        elif self.current_mode == "decrypt": self.decrypt_path_var.set(dropped_path)
 
    def show_back_button(self, parent):
        tk.Button(parent, text="← 返回主界面", command=self.setup_main_ui,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(anchor=tk.NW, padx=10, pady=10)
 
    def _add_verification_options(self, parent_frame):
        frame = tk.Frame(parent_frame, bg="white" if parent_frame.cget('bg')=='white' else "#f0f0f0")
        frame.pack(fill=tk.X, padx=10, pady=10)
        bg = frame.cget('bg')
        tk.Label(frame, text="附加因子（可多选）：", bg=bg, font=("微软雅黑",10)).pack(anchor=tk.W)
        opts = tk.Frame(frame, bg=bg); opts.pack(anchor=tk.W, pady=5)
        tk.Checkbutton(opts, text="宫格密码", variable=self.use_grid_signature, bg=bg).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(opts, text="人脸因子", variable=self.use_face_verification, bg=bg).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(opts, text="声纹因子", variable=self.use_voice_verification, bg=bg).pack(side=tk.LEFT, padx=5)
 
    # ========== 各功能界面 ==========
    def show_file_encrypt_ui(self):
        self.current_mode = "file"
        for widget in self.winfo_children():
            widget.destroy()
        self.show_back_button(self)
        tk.Label(self, text="文件加密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0").pack(pady=10)
        main_frame = tk.Frame(self, bg="#f0f0f0"); main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        left_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)
        left_frame.pack_propagate(False)
        tk.Label(left_frame, text="选择文件", font=("微软雅黑", 12), bg="white").pack(pady=10)
        self.file_path_var = tk.StringVar(value=self.selected_path or "未选择文件")
        tk.Label(left_frame, textvariable=self.file_path_var, bg="white", font=("微软雅黑", 10), wraplength=450, fg="#666666").pack(pady=5, padx=10)
        tk.Button(left_frame, text="浏览文件", command=self.select_file, bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(pady=10)
        self._add_verification_options(left_frame)
        right_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10)
        right_frame.pack_propagate(False)
        tk.Label(right_frame, text="保存设置", font=("微软雅黑", 12), bg="white").pack(pady=10)
        self.save_path_var = tk.StringVar(value="")
        tk.Label(right_frame, text="保存路径：", bg="white", font=("微软雅黑", 10)).pack(anchor=tk.W, padx=10)
        tk.Entry(right_frame, textvariable=self.save_path_var, bg="#f5f5f5", relief=tk.FLAT).pack(fill=tk.X, padx=10, pady=5)
        tk.Button(right_frame, text="选择保存位置", command=self.select_file_save_path, bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(pady=5)
        tk.Button(right_frame, text="开始加密", command=self.start_file_encryption, bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00", font=("微软雅黑", 12)).pack(side=tk.BOTTOM, pady=20, ipady=5)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100, mode='indeterminate')
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=10)
        self.enable_drag_and_drop()
        self.status_bar = tk.Label(self, text="文件加密界面 | 支持拖拽文件到此处", bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)
 
    def show_folder_encrypt_ui(self):
        self.current_mode = "folder"
        for widget in self.winfo_children():
            widget.destroy()
        self.show_back_button(self)
        tk.Label(self, text="文件夹加密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0").pack(pady=10)
        main_frame = tk.Frame(self, bg="#f0f0f0"); main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        left_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)
        left_frame.pack_propagate(False)
        tk.Label(left_frame, text="选择文件夹", font=("微软雅黑", 12), bg="white").pack(pady=10)
        self.folder_path_var = tk.StringVar(value=self.selected_path or "未选择文件夹")
        tk.Label(left_frame, textvariable=self.folder_path_var, bg="white", font=("微软雅黑", 10), wraplength=450, fg="#666666").pack(pady=5, padx=10)
        tk.Button(left_frame, text="浏览文件夹", command=self.select_folder, bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(pady=10)
        self._add_verification_options(left_frame)
        right_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10)
        right_frame.pack_propagate(False)
        tk.Label(right_frame, text="保存设置", font=("微软雅黑", 12), bg="white").pack(pady=10)
        self.folder_save_var = tk.StringVar(value="")
        tk.Label(right_frame, text="保存路径：", bg="white", font=("微软雅黑", 10)).pack(anchor=tk.W, padx=10)
        tk.Entry(right_frame, textvariable=self.folder_save_var, bg="#f5f5f5", relief=tk.FLAT).pack(fill=tk.X, padx=10, pady=5)
        tk.Button(right_frame, text="选择保存位置", command=self.select_folder_save_path, bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(pady=5)
        tk.Button(right_frame, text="开始加密", command=self.start_folder_encryption, bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00", font=("微软雅黑", 12)).pack(side=tk.BOTTOM, pady=20, ipady=5)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100, mode='indeterminate')
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=10)
        self.enable_drag_and_drop()
        self.status_bar = tk.Label(self, text="文件夹加密界面 | 支持拖拽文件夹到此处", bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)
 
    def show_doc_encrypt_ui(self):
        self.current_mode = "doc"
        for widget in self.winfo_children():
            widget.destroy()
        self.show_back_button(self)
        tk.Label(self, text="文档加密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0").pack(pady=10)
        text_frame = tk.Frame(self, bg="#f0f0f0"); text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        self.doc_text = scrolledtext.ScrolledText(text_frame, font=("Consolas", 10), wrap=tk.WORD,
                                                  bg="#f5f5f5", relief=tk.FLAT, bd=1, height=25)
        self.doc_text.pack(fill=tk.BOTH, expand=True, pady=5)
        ver_frame = tk.Frame(self, bg="#f0f0f0"); ver_frame.pack(fill=tk.X, padx=20, pady=5)
        self._add_verification_options(ver_frame)
        btn_frame = tk.Frame(self, bg="#f0f0f0"); btn_frame.pack(fill=tk.X, padx=20, pady=10)
        tk.Button(btn_frame, text="保存加密文档", command=self.save_encrypted_doc,
                  bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00",
                  font=("微软雅黑", 10)).pack(side=tk.RIGHT, padx=5)
        tk.Button(btn_frame, text="打开加密文档", command=self.open_encrypted_doc,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777",
                  font=("微软雅黑", 10)).pack(side=tk.RIGHT, padx=5)
        tk.Button(btn_frame, text="清空内容", command=lambda: self.doc_text.delete(1.0, tk.END),
                  bg="#ff4444", fg="white", relief=tk.FLAT, activebackground="#dd2222",
                  font=("微软雅黑", 10)).pack(side=tk.RIGHT, padx=5)
        # 添加进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100, mode='indeterminate')
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=10)
        self.status_bar = tk.Label(self, text="文档加密界面 | 直接编辑文本内容", bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)
 
    def show_auto_decrypt_ui(self):
        self.current_mode = "decrypt"
        for widget in self.winfo_children():
            widget.destroy()
        self.show_back_button(self)
        tk.Label(self, text="自动解密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0").pack(pady=10)
        self.decrypt_path_var = tk.StringVar(value=self.selected_path or "未选择加密文件")
        tk.Label(self, textvariable=self.decrypt_path_var, bg="#f0f0f0", font=("微软雅黑", 10), fg="#666666").pack(pady=10)
        btn_frame = tk.Frame(self, bg="#f0f0f0"); btn_frame.pack(pady=20)
        tk.Button(btn_frame, text="选择加密文件", command=self.select_encrypted_file,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777",
                  font=("微软雅黑", 10)).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="开始解密", command=self.start_auto_decryption,
                  bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00",
                  font=("微软雅黑", 10)).pack(side=tk.LEFT, padx=10)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100, mode='indeterminate')
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=10)
        self.enable_drag_and_drop()
        self.status_bar = tk.Label(self, text="自动解密界面 | 支持拖拽加密文件到此处", bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)
 
    # ---------- 进度条安全操作方法 ----------
    def _start_progress(self):
        if self.progress_bar and self.progress_bar.winfo_exists():
            try:
                self.progress_bar.start(10)
            except tk.TclError:
                pass
 
    def _stop_progress(self):
        if self.progress_bar and self.progress_bar.winfo_exists():
            try:
                self.progress_bar.stop()
            except tk.TclError:
                pass
 
    # ---------- 加密/解密核心 ----------
    def _derive_key_scrypt(self, total_factor, salt):
        return hashlib.scrypt(total_factor, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=AES_KEY_LENGTH)
 
    def _encrypt_data(self, plaindata, total_factor, salt, aad):
        key = self._derive_key_scrypt(total_factor, salt)
        nonce = get_random_bytes(GCM_NONCE_LENGTH)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaindata)
        return nonce + tag + ciphertext 
 
    def _decrypt_data(self, encrypted_payload, total_factor, salt, aad):
        key = self._derive_key_scrypt(total_factor, salt)
        nonce = encrypted_payload[:GCM_NONCE_LENGTH]
        tag = encrypted_payload[GCM_NONCE_LENGTH:GCM_NONCE_LENGTH+16]
        ciphertext = encrypted_payload[GCM_NONCE_LENGTH+16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext, tag)
 
    def _build_file_header(self, factor_mask, salt, helpers):
        header = ENCRYPTION_MAGIC + VERSION + bytes([factor_mask]) + salt 
        for factor, key_name in [(FACTOR_FACE, 'face'), (FACTOR_VOICE, 'voice')]:
            if factor_mask & factor:
                helper_json = json.dumps(helpers[key_name], sort_keys=True).encode('utf-8')
                header += struct.pack('<H', len(helper_json)) + helper_json 
        return header
 
    def _parse_file_header(self, data):
        pos = 0
        if data[pos:pos+len(ENCRYPTION_MAGIC)] != ENCRYPTION_MAGIC:
            raise ValueError("无效的加密文件")
        pos += len(ENCRYPTION_MAGIC)
        if data[pos:pos+1] != VERSION:
            raise ValueError("文件版本不匹配")
        pos += 1
        factor_mask = data[pos]; pos += 1
        salt = data[pos:pos+SALT_LENGTH]; pos += SALT_LENGTH
        helpers = {}
        if factor_mask & FACTOR_FACE:
            length = struct.unpack('<H', data[pos:pos+2])[0]; pos += 2
            helpers['face'] = json.loads(data[pos:pos+length].decode('utf-8')); pos += length
        if factor_mask & FACTOR_VOICE:
            length = struct.unpack('<H', data[pos:pos+2])[0]; pos += 2
            helpers['voice'] = json.loads(data[pos:pos+length].decode('utf-8')); pos += length 
        return factor_mask, salt, helpers, data[pos:]
 
    # ---------- 因子采集（主线程） ----------
    def _collect_factors_for_encrypt(self):
        factor_mask = FACTOR_PASSWORD
        factor_parts = []
        helpers = {}
 
        pwd = PasswordDialog(self, "加密密码", "请输入主密码:").show()
        if not pwd: return None
        pwd_bytes = pwd.encode('utf-8')
        factor_parts.append(len(pwd_bytes).to_bytes(2, 'little') + pwd_bytes)
 
        if self.use_grid_signature.get():
            grid_pad = GridSignaturePad(self, "设置5×5宫格密码")
            sig, _ = grid_pad.show()
            if not sig: return None
            grid_bytes = sig['signature_string'].encode('utf-8')
            factor_parts.append(len(grid_bytes).to_bytes(2, 'little') + grid_bytes)
            factor_mask |= FACTOR_GRID
 
        if self.use_face_verification.get():
            face_dialog = FaceAuthDialog(self, mode="collect", title="采集人脸因子")
            face_result, _ = face_dialog.show()
            if not face_result:
                return None
            features = face_result['features']
            avg_feature = face_result['avg']
            key, helper = generate_bio_key_and_helper(avg_feature, features)
            factor_parts.append(key)
            helpers['face'] = helper
            factor_mask |= FACTOR_FACE 
 
        if self.use_voice_verification.get():
            voice_dialog = VoiceAuthDialog(self, mode="collect", title="采集声纹因子")
            voice_result, _ = voice_dialog.show()
            if not voice_result: return None
            embeddings = voice_result['embeddings']
            avg_emb = voice_result['avg']
            key, helper = generate_bio_key_and_helper(avg_emb, embeddings)
            factor_parts.append(key)
            helpers['voice'] = helper
            factor_mask |= FACTOR_VOICE
 
        total_factor = b''.join(factor_parts)
        return factor_mask, total_factor, helpers 
 
    def _collect_factors_for_decrypt(self, factor_mask, helpers):
        factor_parts = []
 
        pwd = PasswordDialog(self, "解密密码", "请输入主密码:", show_strength=False).show()
        if not pwd: return None
        pwd_bytes = pwd.encode('utf-8')
        factor_parts.append(len(pwd_bytes).to_bytes(2, 'little') + pwd_bytes)
 
        if factor_mask & FACTOR_GRID:
            grid_pad = GridSignaturePad(self, "请输入加密时的宫格密码")
            sig, _ = grid_pad.show()
            if not sig: return None
            grid_bytes = sig['signature_string'].encode('utf-8')
            factor_parts.append(len(grid_bytes).to_bytes(2, 'little') + grid_bytes)
 
        if factor_mask & FACTOR_FACE:
            face_dialog = FaceAuthDialog(self, mode="collect", title="采集人脸因子以恢复密钥")
            face_result, _ = face_dialog.show()
            if not face_result: return None
            avg_feature = face_result['avg']
            try:
                key = recover_bio_key(helpers['face'], avg_feature)
            except Exception:
                raise ValueError("生物因子验证失败")
            factor_parts.append(key)
 
        if factor_mask & FACTOR_VOICE:
            voice_dialog = VoiceAuthDialog(self, mode="collect", title="采集声纹因子以恢复密钥")
            voice_result, _ = voice_dialog.show()
            if not voice_result: return None
            avg_emb = voice_result['avg']
            try:
                key = recover_bio_key(helpers['voice'], avg_emb)
            except Exception:
                raise ValueError("生物因子验证失败")
            factor_parts.append(key)
 
        return b''.join(factor_parts)
 
    # ---------- 加密/解密工作线程 ----------
    def _safe_progress_stop_and_show(self, title, message):
        self._stop_progress()
        # 使用错误窗口显示详细信息
        self.show_error_window(title, message)
 
    def _run_encryption_worker(self, data, file_type, save_path, original_filename, factor_mask, total_factor, helpers):
        try:
            salt = get_random_bytes(SALT_LENGTH)
            packet = json.dumps({
                'content': base64.b64encode(data).decode('ascii'),
                'type': base64.b64encode(file_type).decode('ascii'),
                'original_filename': original_filename,
                'original_basename': os.path.basename(original_filename),
                'timestamp': time.time()
            }).encode('utf-8')
            header = self._build_file_header(factor_mask, salt, helpers)
            encrypted_payload = self._encrypt_data(packet, total_factor, salt, header)
            with open(save_path, 'wb') as f:
                f.write(header + encrypted_payload)
            self.after(0, lambda: self._safe_progress_stop_and_show("成功", "加密完成！"))
        except Exception as e:
            err_detail = f"加密失败：{str(e)}\n\n详细堆栈：\n{traceback.format_exc()}"
            logging.error(err_detail)
            self.after(0, lambda d=err_detail: self._safe_progress_stop_and_show("错误", d))
 
    def _run_decryption_calc(self, file_path, total_factor):
        try:
            with open(file_path, 'rb') as f:
                raw = f.read()
            factor_mask, salt, helpers, encrypted_payload = self._parse_file_header(raw)
            aad = self._build_file_header(factor_mask, salt, helpers)
            plain_packet = self._decrypt_data(encrypted_payload, total_factor, salt, aad)
            data = json.loads(plain_packet.decode('utf-8'))
            content = base64.b64decode(data['content'])
            file_type = base64.b64decode(data['type'])
            orig_fn = data.get('original_filename', '')
            orig_bn = data.get('original_basename', '')
            self.after(0, lambda: self._handle_decryption_result(content, file_type, orig_fn, orig_bn))
        except Exception:
            err_detail = f"解密失败：\n{traceback.format_exc()}"
            logging.error(err_detail)
            self.after(0, lambda d=err_detail: self._safe_progress_stop_and_show("错误", d))
 
    def _handle_decryption_result(self, content, file_type, orig_fn, orig_bn):
        self._safe_progress_stop_and_show("成功", "解密完成，请选择保存位置。")
        if file_type == FILE_TYPE_TEXT:
            self._show_decrypted_text(content, orig_bn)
        elif file_type == FILE_TYPE_FILE:
            def save_file():
                sp = filedialog.asksaveasfilename(title="保存文件位置",
                                                  initialfile=orig_bn or os.path.splitext(os.path.basename(self.decrypt_path_var.get()))[0])
                if sp:
                    try:
                        with open(sp, 'wb') as f: f.write(content)
                        messagebox.showinfo("成功", f"文件解密完成：{os.path.basename(sp)}")
                    except Exception as e:
                        err_detail = f"保存文件失败：{e}"
                        logging.error(err_detail)
                        self.show_error_window("错误", err_detail)
            self.after(0, save_file)
        elif file_type == FILE_TYPE_FOLDER:
            def extract_folder():
                parent_dir = filedialog.askdirectory(title="选择文件夹保存位置")
                if not parent_dir: return
                target_dir = os.path.join(parent_dir, orig_bn)
                counter = 1; base = orig_bn
                while os.path.exists(target_dir):
                    target_dir = os.path.join(parent_dir, f"{base}_{counter}"); counter += 1
                temp_zip = None
                try:
                    os.makedirs(target_dir, exist_ok=True)
                    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
                    temp_zip.write(content); temp_zip.close()
                    with zipfile.ZipFile(temp_zip.name, 'r') as zipf: zipf.extractall(target_dir)
                    messagebox.showinfo("成功", f"文件夹解密完成：{target_dir}")
                except Exception as e:
                    err_detail = f"解压文件夹失败：{e}\n{traceback.format_exc()}"
                    logging.error(err_detail)
                    self.show_error_window("错误", err_detail)
                finally:
                    try:
                        if temp_zip and os.path.exists(temp_zip.name):
                            os.unlink(temp_zip.name)
                    except: pass
            self.after(0, extract_folder)
 
    # ---------- UI 事件入口 ----------
    def start_file_encryption(self):
        if not self.selected_path:
            messagebox.showwarning("警告", "请先选择要加密的文件！"); return
        save_path = self.save_path_var.get()
        if not save_path:
            original_basename = os.path.basename(self.selected_path)
            save_path = filedialog.asksaveasfilename(defaultextension='.guifei', filetypes=[("加密文件","*.guifei")],
                                                     title="选择保存位置", initialfile=f"{original_basename}.guifei")
            if not save_path: return 
            self.save_path_var.set(save_path)
        res = self._collect_factors_for_encrypt()
        if res is None:
            messagebox.showinfo("取消", "已取消加密操作。")
            return
        factor_mask, total_factor, helpers = res
        try:
            file_size = os.path.getsize(self.selected_path)
            if file_size > 200 * 1024 * 1024:
                if not messagebox.askyesno("大文件确认", f"文件大小 {file_size//(1024*1024)} MB，加密可能占用大量内存，是否继续？"):
                    return
            with open(self.selected_path, 'rb') as f:
                file_data = f.read()
        except Exception as e:
            err_detail = f"读取文件失败：{e}\n{traceback.format_exc()}"
            logging.error(err_detail)
            self.show_error_window("错误", err_detail)
            return 
        self._start_progress()
        self.update_status("正在加密...")
        threading.Thread(target=self._run_encryption_worker, args=(
            file_data, FILE_TYPE_FILE, save_path, self.selected_path,
            factor_mask, total_factor, helpers), daemon=True).start()
 
    def start_folder_encryption(self):
        if not self.selected_path:
            messagebox.showwarning("警告", "请先选择要加密的文件夹！"); return
        save_path = self.folder_save_var.get()
        if not save_path:
            original_basename = os.path.basename(self.selected_path)
            save_path = filedialog.asksaveasfilename(defaultextension='.guifeinext', filetypes=[("加密文件夹","*.guifeinext")],
                                                     title="选择保存位置", initialfile=f"{original_basename}.guifeinext")
            if not save_path: return
            self.folder_save_var.set(save_path)
        res = self._collect_factors_for_encrypt()
        if res is None:
            messagebox.showinfo("取消", "已取消加密操作。")
            return
        factor_mask, total_factor, helpers = res
        temp_file = None
        zip_data = None
        try:
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
            with zipfile.ZipFile(temp_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(self.selected_path):
                    for file in files:
                        full = os.path.join(root, file)
                        arcname = os.path.relpath(full, self.selected_path)
                        zipf.write(full, arcname)
            temp_file.close()
            with open(temp_file.name, 'rb') as f:
                zip_data = f.read()
            if len(zip_data) > 200 * 1024 * 1024:
                if not messagebox.askyesno("大文件确认", f"压缩包大小 {len(zip_data)//(1024*1024)} MB，加密可能占用大量内存，是否继续？"):
                    return
        except Exception as e:
            err_detail = f"压缩文件夹失败：{e}\n{traceback.format_exc()}"
            logging.error(err_detail)
            self.show_error_window("错误", err_detail)
            return
        finally:
            try:
                if temp_file and os.path.exists(temp_file.name):
                    os.unlink(temp_file.name)
            except: pass
        self._start_progress()
        self.update_status("正在加密...")
        threading.Thread(target=self._run_encryption_worker, args=(
            zip_data, FILE_TYPE_FOLDER, save_path, self.selected_path,
            factor_mask, total_factor, helpers), daemon=True).start()
 
    def save_encrypted_doc(self):
        content = self.doc_text.get(1.0, "end-1c").encode('utf-8')
        if not content.strip():
            messagebox.showwarning("警告","文档内容不能为空！")
            return
        save_path = filedialog.asksaveasfilename(defaultextension='.msc', filetypes=[("加密文档","*.msc")],
                                                 title="选择保存位置", initialfile="document.msc")
        if not save_path: return
        res = self._collect_factors_for_encrypt()
        if res is None:
            messagebox.showinfo("取消", "已取消加密操作。")
            return
        factor_mask, total_factor, helpers = res
        self._start_progress()
        self.update_status("正在加密...")
        threading.Thread(target=self._run_encryption_worker, args=(
            content, FILE_TYPE_TEXT, save_path, "document.msc",
            factor_mask, total_factor, helpers), daemon=True).start()
 
    def open_encrypted_doc(self):
        file_path = filedialog.askopenfilename(filetypes=[("加密文档","*.msc"),("所有文件","*.*")], title="打开加密文档")
        if not file_path: return
        try:
            with open(file_path, 'rb') as f:
                raw = f.read()
            factor_mask, salt, helpers, _ = self._parse_file_header(raw)
            total_factor = self._collect_factors_for_decrypt(factor_mask, helpers)
            if total_factor is None:
                messagebox.showinfo("取消", "已取消解密操作。")
                return
        except Exception:
            err_detail = f"解密失败：密码或验证因子错误\n{traceback.format_exc()}"
            logging.error(err_detail)
            self.show_error_window("错误", err_detail)
            return
        self._start_progress()
        threading.Thread(target=self._run_decryption_calc, args=(file_path, total_factor), daemon=True).start()
 
    def start_auto_decryption(self):
        file_path = self.decrypt_path_var.get()
        if file_path == "未选择加密文件":
            messagebox.showwarning("警告","请先选择要解密的文件！")
            return
        try:
            with open(file_path, 'rb') as f:
                raw = f.read()
            factor_mask, salt, helpers, _ = self._parse_file_header(raw)
            total_factor = self._collect_factors_for_decrypt(factor_mask, helpers)
            if total_factor is None:
                messagebox.showinfo("取消", "已取消解密操作。")
                return
        except Exception:
            err_detail = f"解密失败：密码或验证因子错误\n{traceback.format_exc()}"
            logging.error(err_detail)
            self.show_error_window("错误", err_detail)
            return
        self._start_progress()
        threading.Thread(target=self._run_decryption_calc, args=(file_path, total_factor), daemon=True).start()
 
    def _show_decrypted_text(self, plain_data, original_basename):
        if not hasattr(self, 'doc_text') or not self.doc_text.winfo_exists():
            self.show_doc_encrypt_ui()
        self.after(100, lambda p=plain_data, b=original_basename: self._safe_display_text(p, b))
 
    def _safe_display_text(self, plain_data, original_basename):
        try:
            self.doc_text.delete(1.0, tk.END)
            self.doc_text.insert(tk.END, plain_data.decode('utf-8', errors='replace'))
            self.update_status(f"文本解密完成：原文件名 {original_basename}")
            messagebox.showinfo("成功", f"文本解密完成！\n原文件名：{original_basename}\n已加载到文档编辑区")
        except Exception as e:
            err_detail = f"文本显示失败：{str(e)}\n{traceback.format_exc()}"
            logging.error(err_detail)
            self.show_error_window("错误", err_detail)
 
    def update_status(self, text):
        self.after(0, lambda t=text: self._safe_update_status(t))
 
    def _safe_update_status(self, text):
        try:
            if self.status_bar and self.status_bar.winfo_exists():
                self.status_bar.config(text=text)
        except: pass 
 
    def select_file(self):
        path = filedialog.askopenfilename(title="选择要加密的文件")
        if path:
            self.selected_path = path
            self.file_path_var.set(path)
 
    def select_folder(self):
        path = filedialog.askdirectory(title="选择要加密的文件夹")
        if path:
            self.selected_path = path
            self.folder_path_var.set(path)
 
    def select_file_save_path(self):
        if not self.selected_path:
            messagebox.showwarning("警告","请先选择要加密的文件！")
            return
        original_basename = os.path.basename(self.selected_path)
        path = filedialog.asksaveasfilename(defaultextension='.guifei', filetypes=[("加密文件","*.guifei")],
                                            title="保存", initialfile=f"{original_basename}.guifei")
        if path: self.save_path_var.set(path)
 
    def select_folder_save_path(self):
        if not self.selected_path:
            messagebox.showwarning("警告","请先选择要加密的文件夹！")
            return
        original_basename = os.path.basename(self.selected_path)
        path = filedialog.asksaveasfilename(defaultextension='.guifeinext', filetypes=[("加密文件夹","*.guifeinext")],
                                            title="保存", initialfile=f"{original_basename}.guifeinext")
        if path: self.folder_save_var.set(path)
 
    def select_encrypted_file(self):
        path = filedialog.askopenfilename(filetypes=[("所有支持的文件","*.guifei *.guifeinext *.msc"),
                                                     ("加密文件","*.guifei"), ("加密文件夹","*.guifeinext"),
                                                     ("加密文本","*.msc"), ("所有文件","*.*")],
                                          title="选择要解密的文件")
        if path: self.decrypt_path_var.set(path)
 
    def on_close(self):
        if messagebox.askokcancel("退出", "确定要退出吗？"):
            self.destroy()
            sys.exit(0)
 
# ====================== 程序入口 ======================
if __name__ == "__main__":
    def _global_exception_hook(exc_type, exc_value, exc_tb):
        err_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
        logging.error(f"全局未捕获异常: {err_msg}")
        try:
            if 'app' in globals() and app.winfo_exists():
                app.show_error_window("未捕获的异常", err_msg)
            else:
                temp_root = tk.Tk()
                temp_root.withdraw()
                win = tk.Toplevel(temp_root)
                win.title("未捕获的异常")
                win.config(bg="#f0f0f0")
                win.attributes('-topmost', True)
                txt = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Consolas", 9))
                txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                txt.insert(tk.END, err_msg)
                txt.config(state=tk.DISABLED)
                btn = tk.Button(win, text="关闭", command=temp_root.destroy, width=10,
                                bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777")
                btn.pack(pady=5)
                win.update_idletasks()
                width = max(800, win.winfo_reqwidth())
                height = max(600, win.winfo_reqheight())
                x = (win.winfo_screenwidth() // 2) - (width // 2)
                y = (win.winfo_screenheight() // 2) - (height // 2)
                win.geometry(f"{width}x{height}+{x}+{y}")
                temp_root.mainloop()
        except Exception:
            pass
 
    sys.excepthook = _global_exception_hook
    try:
        from ctypes import windll 
        windll.shcore.SetProcessDpiAwareness(1)
    except: pass
    app = GuifeiCryptoTool()
    baseicon='''
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xgfa2N4ANEBoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAx727AMa9ugTIwscTt7TFBMfDzQAREVoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA///////////////////B///DAf//AgD//gMAP/wDAB/4A4AP8AeAD+AQBAfgYAYH4GAHA8DgBwPA4AeDwOAHg8DgBwPA4AcDwPAPA+BxjgfgMAwH4AAQB/AAAA/4AYAf/ACAP/4AwH//gMH//4HH//+P//////////////////8='''
    try:
        ico_bytes = base64.b64decode(baseicon)  
        ico_stream = io.BytesIO(ico_bytes)
        ico_image = Image.open(ico_stream)
        app_icon = ImageTk.PhotoImage(ico_image)
        app.iconphoto(True, app_icon)
    except Exception as e:
        logging.error(f"图标加载失败: {str(e)}")
    app.mainloop()