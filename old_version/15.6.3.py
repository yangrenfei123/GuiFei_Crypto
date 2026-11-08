# ========== 前置：屏蔽人脸识别相关弃用警告 ==========
import warnings

warnings.filterwarnings("ignore", category=FutureWarning, module="insightface")
warnings.filterwarnings("ignore", category=FutureWarning, module="skimage")

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import os
import sys
import io
import zlib
import re
import hashlib
import hmac
import struct
import tempfile
import zipfile
import traceback
import numpy as np
from PIL import Image, ImageDraw, ImageTk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import pickle
import time
from scipy.spatial.distance import cdist
from scipy.interpolate import interp1d
import tkinterdnd2  # 拖拽核心库
import base64
import json
import threading
import cv2
from insightface.app import FaceAnalysis
import onnxruntime as ort
import librosa
import sounddevice as sd
import soundfile as sf

from resemblyzer import VoiceEncoder, preprocess_wav


# ========== 全局输出静默与弹窗化 ==========

class _MessageBoxStderr:
    """重定向 stderr，将严重错误信息收集到缓冲区，不打印到控制台"""

    def __init__(self):
        self.buffer = io.StringIO()
        self.full_log = []  # 完整日志

    def write(self, s):
        self.buffer.write(s)
        self.full_log.append(s)
        # 如果是严重错误（包含 Traceback/Error 等），可立即弹窗
        if "Error" in s or "Traceback" in s:
            # 延迟到主线程弹窗，避免跨线程问题
            try:
                root = None
                for w in tk._default_root.winfo_children() if hasattr(tk, '_default_root') else []:
                    root = w.winfo_toplevel()
                    break
                if root and root.winfo_exists():
                    root.after(100, self._show_error, s)
            except:
                pass

    def _show_error(self, msg):
        """在主线程弹出错误消息（仅对关键错误弹窗）"""
        if msg.strip():
            messagebox.showwarning("控制台错误", msg[:500])

    def flush(self):
        pass

    def getvalue(self):
        return self.buffer.getvalue()


# 替换 stderr（所有原本打印到控制台的错误都会被收集）
sys.stderr = _MessageBoxStderr()


# 捕获未处理的异常，用 messagebox 显示
def _global_exception_hook(exc_type, exc_value, exc_tb):
    import traceback
    err_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
    messagebox.showerror("未捕获的异常", err_msg[:800])
    # 同时写入我们自己的日志（可选）
    with open("guifei_error.log", "a", encoding="utf-8") as f:
        f.write(err_msg)


sys.excepthook = _global_exception_hook

# ====================== 核心常量定义 ======================
# 加密常量
AES_KEY_LENGTH = 32  # 256位AES密钥
GCM_NONCE_LENGTH = 12  # GCM推荐nonce长度
KDF_ITERATIONS = 310000  # NIST推荐迭代次数
KDF_HASH_ALG = 'sha256'
SIGNATURE_HASH_ALG = 'sha3-256'
ENCRYPTION_MAGIC = b'guifeiCRYPT11'  # 魔数
VERSION = b'1.0'  # 版本号
HMAC_LENGTH = 32  # SHA3-256 HMAC长度
SALT_LENGTH = 16  # 盐长度

# 文件类型标识
FILE_TYPE_TEXT = b'msc'  # 文本文档
FILE_TYPE_FILE = b'guifei'  # 单文件
FILE_TYPE_FOLDER = b'guifeinext'  # 文件夹
GRID_SIGNATURE_MATCH_REQUIRED = True  # 宫格签名必须完全匹配

# 4×4宫格常量
GRID_SIZE = 4  # 4×4宫格
GRID_POINT_SIZE = 30  # 宫格点大小（像素）
GRID_SPACING = 10  # 宫格间距（像素）

# 人脸识别常量
FACE_SIMILARITY_THRESHOLD = 0.75
FACE_MODEL_NAME = "buffalo_l"
FACE_PREVIEW_SIZE = (480, 360)

# 声纹识别常量（基于Resemblyzer）
VOICE_SAMPLE_RATE = 16000  # 采样率，必须16kHz
VOICE_DURATION = 3  # 录音时长（秒）
VOICE_EMBEDDING_THRESHOLD = 0.75  # 声纹相似度阈值（余弦相似度，范围[-1,1]）


# ====================== 核心组件 ======================
class LoadingWindow(tk.Toplevel):
    """加载窗口"""

    def __init__(self, parent):
        super().__init__(parent)
        self.title("加载中")
        self.geometry("320x100")
        self.configure(bg="#f0f0f0")
        self.attributes('-alpha', 0.8)
        self.attributes('-topmost', True)
        self.transient(parent)
        self.grab_set()

        # 居中显示
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (300 // 2)
        y = (self.winfo_screenheight() // 2) - (100 // 2)
        self.geometry(f"300x100+{x}+{y}")

        tk.Label(self, text="GuìFē! :)防破密专家努力加载中...", bg="#f0f0f0", font=("微软雅黑", 12)).pack(pady=20)
        self.progress = ttk.Progressbar(self, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=20, pady=10)
        self.progress.start(20)


class PasswordDialog(tk.Toplevel):
    """密码输入对话框"""

    def __init__(self, parent, title, prompt, show_strength=True):
        super().__init__(parent)
        self.title(title)
        self.geometry("400x200")
        self.parent = parent
        self.result = None
        self.show_strength = show_strength

        # 半透明灰色样式
        self.configure(bg="#e0e0e0")
        self.attributes('-alpha', 0.9)
        self.attributes('-topmost', True)
        self.transient(parent)
        self.grab_set()

        # 居中
        self.update_idletasks()
        x = (parent.winfo_screenwidth() // 2) - (400 // 2)
        y = (parent.winfo_screenheight() // 2) - (200 // 2)
        self.geometry(f"400x200+{x}+{y}")

        tk.Label(self, text=prompt, font=("微软雅黑", 11), bg="#e0e0e0").pack(pady=15)

        self.password_var = tk.StringVar()
        self.password_var.trace_add("write", self.update_strength)

        self.password_entry = tk.Entry(self, textvariable=self.password_var, show="*",
                                       font=("微软雅黑", 12), bg="#f5f5f5", relief=tk.FLAT, bd=1)
        self.password_entry.pack(pady=5, padx=20, fill=tk.X)

        # 密码强度显示
        if show_strength:
            self.strength_frame = tk.Frame(self, height=10, bg="#f5f5f5")
            self.strength_frame.pack(pady=5, padx=20, fill=tk.X)
            self.strength_label = tk.Label(self, text="密码强度: 无", font=("微软雅黑", 9), bg="#e0e0e0")
            self.strength_label.pack(pady=2)

        # 按钮样式
        btn_frame = tk.Frame(self, bg="#e0e0e0")
        btn_frame.pack(pady=15)

        tk.Button(btn_frame, text="确定", command=self.ok, width=10,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="取消", command=self.cancel, width=10,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(side=tk.LEFT)

        self.password_entry.focus_set()

    def calculate_strength(self, password):
        """密码强度计算规则"""
        score = 0
        length = len(password)

        # 长度加分
        if length >= 8: score += 20
        if length >= 12: score += 10
        if length >= 16: score += 10
        if length >= 20: score += 10

        # 字符类型加分
        if re.search(r'[A-Z]', password): score += 15
        if re.search(r'[a-z]', password): score += 15
        if re.search(r'[0-9]', password): score += 15
        if re.search(r'[^A-Za-z0-9]', password): score += 15

        # 常见密码扣分
        common_passwords = {"12345678", "password", "01234567", "1234567890", "abcd1234", "11111111"}
        if password.lower() in common_passwords:
            score = max(0, score - 30)

        return min(score, 100)

    def update_strength(self, *args):
        """实时更新强度显示"""
        if not self.show_strength: return

        password = self.password_var.get()
        strength = self.calculate_strength(password)

        for widget in self.strength_frame.winfo_children():
            widget.destroy()

        # 强度条颜色
        color = "#ff4444" if strength < 30 else "#ffaa00" if strength < 60 else "#aacc00" if strength < 80 else "#44dd00"
        bar = tk.Frame(self.strength_frame, bg=color, width=int(strength * 4), height=10)
        bar.pack(side=tk.LEFT, fill=tk.Y)

        # 强度文字
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
    """4×4宫格点线连接签名面板"""

    def __init__(self, parent, title="宫格验证", existing_signature=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("400x450")
        self.parent = parent
        self.result = None
        self.existing_signature = existing_signature
        self.is_verified = False

        # 样式设置
        self.configure(bg="#e0e0e0")
        self.attributes('-alpha', 0.9)
        self.attributes('-topmost', True)
        self.transient(parent)
        self.grab_set()

        # 居中
        self.update_idletasks()
        x = (parent.winfo_screenwidth() // 2) - (400 // 2)
        y = (parent.winfo_screenheight() // 2) - (450 // 2)
        self.geometry(f"400x450+{x}+{y}")

        # 宫格数据
        self.selected_points = []
        self.grid_canvas = None
        self.point_positions = {}

        # 创建UI
        self.setup_ui()

    def setup_ui(self):
        """创建宫格UI"""
        # 提示标签
        prompt_text = "请按顺序点击宫格点完成连接（至少选择4格）"
        if self.existing_signature:
            prompt_text = "请按之前顺序点击宫格点完成验证"

        tk.Label(self, text=prompt_text, font=("微软雅黑", 10), bg="#e0e0e0").pack(pady=10)

        # 宫格画布
        canvas_width = GRID_SIZE * (GRID_POINT_SIZE + GRID_SPACING) + GRID_SPACING
        canvas_height = canvas_width
        self.grid_canvas = tk.Canvas(self, width=canvas_width, height=canvas_height,
                                     bg="white", bd=1, relief=tk.SOLID)
        self.grid_canvas.pack(pady=10)

        # 绘制4×4宫格
        self.draw_grid()

        # 绑定点击事件
        self.grid_canvas.bind("<Button-1>", self.on_point_click)

        # 按钮区域
        btn_frame = tk.Frame(self, bg="#e0e0e0")
        btn_frame.pack(pady=20)

        tk.Button(btn_frame, text="清除", command=self.clear, width=10,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="确定", command=self.ok, width=10,
                  bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00").pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="取消", command=self.cancel, width=10,
                  bg="#ff4444", fg="white", relief=tk.FLAT, activebackground="#dd2222").pack(side=tk.LEFT, padx=10)

        # 选中点提示
        self.point_label = tk.Label(self, text="已选点：无", font=("微软雅黑", 9), bg="#e0e0e0")
        self.point_label.pack(pady=5)

    def draw_grid(self):
        """绘制4×4宫格点"""
        self.grid_canvas.delete("all")
        self.point_positions.clear()

        # 计算每个点的位置
        start_x = GRID_SPACING + GRID_POINT_SIZE // 2
        start_y = GRID_SPACING + GRID_POINT_SIZE // 2

        for row in range(GRID_SIZE):
            for col in range(GRID_SIZE):
                x = start_x + col * (GRID_POINT_SIZE + GRID_SPACING)
                y = start_y + row * (GRID_POINT_SIZE + GRID_SPACING)

                # 绘制圆点
                self.grid_canvas.create_oval(
                    x - GRID_POINT_SIZE // 2, y - GRID_POINT_SIZE // 2,
                    x + GRID_POINT_SIZE // 2, y + GRID_POINT_SIZE // 2,
                    fill="#cccccc", outline="#666666", width=2,
                    tags=(f"point_{row}_{col}", "grid_point")
                )

                # 显示宫格坐标（1开始）
                self.grid_canvas.create_text(
                    x, y, text=f"{row + 1},{col + 1}", fill="#666666", font=("微软雅黑", 8),
                    tags=(f"coord_{row}_{col}", "point_coord")
                )

                # 存储点位置
                self.point_positions[(row, col)] = (x, y)

        # 绘制已选点的连接线
        self.draw_connections()

    def draw_connections(self):
        """绘制选中点的连接线"""
        if len(self.selected_points) < 2:
            return

        # 绘制连接线
        for i in range(1, len(self.selected_points)):
            prev_point = self.selected_points[i - 1]
            curr_point = self.selected_points[i]

            x1, y1 = self.point_positions[prev_point]
            x2, y2 = self.point_positions[curr_point]

            self.grid_canvas.create_line(
                x1, y1, x2, y2,
                fill="#44dd00", width=3, tags="connection_line"
            )

        # 标记选中的点
        for idx, (row, col) in enumerate(self.selected_points):
            x, y = self.point_positions[(row, col)]
            # 填充选中的点
            self.grid_canvas.create_oval(
                x - GRID_POINT_SIZE // 2, y - GRID_POINT_SIZE // 2,
                x + GRID_POINT_SIZE // 2, y + GRID_POINT_SIZE // 2,
                fill="#44dd00", outline="#22bb00", width=2,
                tags=(f"selected_{row}_{col}", "selected_point")
            )
            # 显示顺序编号
            self.grid_canvas.create_text(
                x, y, text=str(idx + 1), fill="white", font=("微软雅黑", 10, "bold"),
                tags=(f"num_{row}_{col}", "point_number")
            )

    def on_point_click(self, event):
        """点击宫格点事件"""
        # 找到点击的点
        click_x, click_y = event.x, event.y
        selected_point = None

        for (row, col), (x, y) in self.point_positions.items():
            if (click_x - x) ** 2 + (click_y - y) ** 2 <= (GRID_POINT_SIZE // 2) ** 2:
                selected_point = (row, col)
                break

        if selected_point:
            # 避免重复点击同一个点（连续）
            if len(self.selected_points) == 0 or self.selected_points[-1] != selected_point:
                self.selected_points.append(selected_point)
                # 更新UI
                self.draw_grid()
                self.update_point_label()

    def update_point_label(self):
        """更新选中点提示（显示1开始的坐标）"""
        if not self.selected_points:
            self.point_label.config(text="已选点：无")
        else:
            # 转换为1开始的坐标并格式化为指定字符串
            point_list = [f"({r + 1},{c + 1})" for r, c in self.selected_points]
            point_text = "已选点：" + "+".join(point_list)
            self.point_label.config(text=point_text)

    def clear(self):
        """清除选中的点"""
        self.selected_points = []
        self.draw_grid()
        self.update_point_label()

    def get_signature_string(self):
        """获取指定格式的签名字符串：(4,1)+(4,3)+(2,2)+(1,2)"""
        # 转换为1开始的坐标
        point_list = [f"({r + 1},{c + 1})" for r, c in self.selected_points]
        return "+".join(point_list)

    def parse_signature_string(self, signature_str):
        """解析指定格式的签名字符串为内部点序列（0开始）"""
        if not signature_str:
            return []

        # 正则匹配 (数字,数字) 格式
        pattern = r'\((\d+),(\d+)\)'
        matches = re.findall(pattern, signature_str)
        # 转换为0开始的坐标，过滤超出范围的点
        points = []
        for row_str, col_str in matches:
            row = int(row_str) - 1
            col = int(col_str) - 1
            if 0 <= row < GRID_SIZE and 0 <= col < GRID_SIZE:
                points.append((row, col))
        return points

    def get_signature_data(self):
        """获取签名数据（特殊保存格式）"""
        # 生成指定格式的字符串
        signature_str = self.get_signature_string()

        # 特殊格式：包含指定字符串、哈希值、长度等信息
        signature_data = {
            'version': '1.0',
            'grid_size': GRID_SIZE,
            'signature_string': signature_str,
            'point_sequence': self.selected_points,
            'sequence_length': len(self.selected_points),
            'created_at': time.time()
        }

        # 生成唯一哈希（用于验证）
        signature_data['hash'] = hashlib.sha256(signature_str.encode()).hexdigest()

        return signature_data

    def verify_signature(self):
        """验证签名（必须完全匹配）"""
        if not self.existing_signature or not self.selected_points:
            return False

        # 获取参考签名的字符串并解析
        ref_signature_str = self.existing_signature.get('signature_string', '')
        ref_points = self.parse_signature_string(ref_signature_str)

        # 对比点序列是否完全一致
        return self.selected_points == ref_points

    def ok(self):
        """确认按钮"""
        # 验证最少选点数量
        if len(self.selected_points) < 4:
            messagebox.showwarning("警告", "至少需要选择4个点完成连接！", parent=self)
            return

        # 如果是验证模式，检查是否匹配
        if self.existing_signature:
            self.is_verified = self.verify_signature()
            if not self.is_verified:
                messagebox.showerror("错误", "宫格连接顺序不匹配，验证失败！", parent=self)
                self.clear()
                return

        # 生成签名数据
        self.result = self.get_signature_data()
        self.destroy()

    def cancel(self):
        """取消按钮"""
        self.result = None
        self.destroy()

    def show(self):
        """显示面板并返回结果"""
        self.wait_window()
        return self.result, self.is_verified


# ====================== 人脸识别核心组件 ======================
class FaceAuthManager:
    """人脸识别管理器（单例懒加载）"""
    _instance = None
    _face_app = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load_model(self):
        """加载人脸识别模型（强制GPU加速，不可用则弹窗报错）"""
        if self._face_app is not None:
            return True

        try:
            # 静默重定向输出，不打印到控制台
            original_stdout = sys.stdout
            original_stderr = sys.stderr
            sys.stdout = io.StringIO()
            sys.stderr = io.StringIO()

            # 第一步：检测DirectML加速环境是否存在
            available_providers = ort.get_available_providers()
            if 'DmlExecutionProvider' not in available_providers:
                sys.stdout = original_stdout
                sys.stderr = original_stderr
                raise RuntimeError(
                    "未检测到可用的GPU加速环境（DirectML）\n"
                    "请检查：\n"
                    "1. 显卡驱动是否为最新版本\n"
                    "2. 显卡是否支持 DirectX 12"
                )

            # 第二步：强制仅使用GPU加速，移除CPU回退，确保必须用GPU计算
            providers = ['DmlExecutionProvider']
            self._face_app = FaceAnalysis(
                name=FACE_MODEL_NAME,
                providers=providers
            )
            self._face_app.prepare(ctx_id=0, det_size=(640, 640))

            # 第三步：二次校验实际生效的加速后端，防止静默降级
            rec_model = self._face_app.models['recognition']
            actual_providers = rec_model.session.get_providers()
            if 'DmlExecutionProvider' not in actual_providers:
                sys.stdout = original_stdout
                sys.stderr = original_stderr
                raise RuntimeError("GPU加速启动失败，已禁止CPU回退，请检查显卡硬件环境")

            sys.stdout = original_stdout
            sys.stderr = original_stderr
            return True
        except Exception as e:
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__
            raise Exception(f"人脸模型加载失败：{str(e)}")

    def extract_feature(self, frame):
        """从帧中提取单张人脸特征，失败返回None"""
        faces = self._face_app.get(frame)
        if len(faces) == 0:
            return None
        # 取置信度最高的人脸
        best_face = max(faces, key=lambda f: f.det_score)
        return best_face.embedding.copy()

    @staticmethod
    def calc_similarity(feat1, feat2):
        """计算余弦相似度"""
        return np.dot(feat1, feat2) / (np.linalg.norm(feat1) * np.linalg.norm(feat2))


class FaceAuthDialog(tk.Toplevel):
    """人脸认证对话框（采集/验证双模式）"""

    def __init__(self, parent, mode="collect", reference_features=None, title="人脸验证"):
        super().__init__(parent)
        self.title(title)
        self.geometry("520x520")
        self.parent = parent
        self.mode = mode  # collect:采集3次 | verify:验证1次
        self.reference_features = reference_features  # 验证模式传入基准特征列表
        self.result = None
        self.is_verified = False
        self.running = True
        self.current_frame = None
        self.collected_features = []
        self.capture_count = 0

        # 样式统一
        self.configure(bg="#e0e0e0")
        self.attributes('-alpha', 0.9)
        self.attributes('-topmost', True)
        self.transient(parent)
        self.grab_set()

        # 居中
        self.update_idletasks()
        x = (parent.winfo_screenwidth() // 2) - (520 // 2)
        y = (parent.winfo_screenheight() // 2) - (520 // 2)
        self.geometry(f"520x520+{x}+{y}")

        # 初始化UI
        self.setup_ui()
        # 后台加载模型+打开摄像头
        self.init_camera_and_model()

    def setup_ui(self):
        """搭建界面"""
        # 状态提示
        prompt = "请正对摄像头，点击按钮采集第1张人脸（共3张）" if self.mode == "collect" else "请正对摄像头，点击按钮完成人脸验证"
        self.status_label = tk.Label(self, text=prompt, font=("微软雅黑", 11), bg="#e0e0e0")
        self.status_label.pack(pady=10)

        # 预览画面
        self.preview_label = tk.Label(self, bd=2, relief=tk.SUNKEN, bg="black")
        self.preview_label.pack(pady=5)

        # 结果提示
        self.result_label = tk.Label(self, text="", font=("微软雅黑", 10), bg="#e0e0e0", fg="#333")
        self.result_label.pack(pady=5)

        # 按钮区
        btn_frame = tk.Frame(self, bg="#e0e0e0")
        btn_frame.pack(pady=15)

        self.capture_btn = tk.Button(
            btn_frame, text="拍照采集", command=self.on_capture, width=12,
            bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00",
            state=tk.DISABLED
        )
        self.capture_btn.pack(side=tk.LEFT, padx=10)

        tk.Button(
            btn_frame, text="取消", command=self.cancel, width=10,
            bg="#ff4444", fg="white", relief=tk.FLAT, activebackground="#dd2222"
        ).pack(side=tk.LEFT, padx=10)

    def init_camera_and_model(self):
        """异步加载模型和摄像头"""

        def task():
            try:
                # 加载模型
                manager = FaceAuthManager()
                manager.load_model()
                # 打开摄像头
                self.cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
                if not self.cap.isOpened():
                    raise Exception("无法打开摄像头，请检查设备是否被占用")

                self.after(0, lambda: (
                    self.capture_btn.config(state=tk.NORMAL),
                    self.update_preview()
                ))
            except Exception as e:
                self.after(0, lambda: (
                    messagebox.showerror("错误", str(e), parent=self),
                    self.destroy()
                ))

        threading.Thread(target=task, daemon=True).start()

    def update_preview(self):
        """刷新预览画面"""
        if not self.running:
            return
        ret, frame = self.cap.read()
        if ret:
            self.current_frame = frame.copy()
            frame_show = cv2.resize(frame, FACE_PREVIEW_SIZE)
            frame_rgb = cv2.cvtColor(frame_show, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(frame_rgb)
            imgtk = ImageTk.PhotoImage(image=img)
            self.preview_label.imgtk = imgtk
            self.preview_label.configure(image=imgtk)
        self.after(20, self.update_preview)

    def on_capture(self):
        """拍照按钮事件"""
        if self.current_frame is None:
            return

        manager = FaceAuthManager()
        feat = manager.extract_feature(self.current_frame)

        if feat is None:
            messagebox.showwarning("提示", "未检测到人脸，请正对摄像头", parent=self)
            return

        if self.mode == "collect":
            self.collected_features.append(feat)
            self.capture_count += 1
            self.result_label.config(text=f"✅ 第 {self.capture_count} 张采集成功")

            if self.capture_count < 3:
                self.status_label.config(text=f"继续采集第 {self.capture_count + 1} 张人脸（共3张）")
            else:
                self.status_label.config(text="3张人脸采集完成！")
                self.capture_btn.config(text="确认使用", bg="#44dd00")
                # 替换按钮事件为确认
                self.capture_btn.config(command=self.confirm_collect)

        else:  # verify模式
            # 计算与所有基准特征的平均相似度
            sim_list = [manager.calc_similarity(feat, ref) for ref in self.reference_features]
            avg_sim = float(np.mean(sim_list))
            max_sim = float(np.max(sim_list))

            self.is_verified = avg_sim >= FACE_SIMILARITY_THRESHOLD
            if self.is_verified:
                self.result_label.config(text=f"✅ 验证通过  相似度：{avg_sim:.4f}", fg="#2e7d32")
                self.capture_btn.config(state=tk.DISABLED)
                self.after(800, self.confirm_verify)
            else:
                self.result_label.config(text=f"❌ 验证失败  相似度：{avg_sim:.4f}", fg="#c62828")

    def confirm_collect(self):
        """确认采集结果"""
        self.result = {
            'version': '1.0',
            'features': [f.tolist() for f in self.collected_features],
            'count': self.capture_count,
            'threshold': FACE_SIMILARITY_THRESHOLD,
            'created_at': time.time()
        }
        self.destroy()

    def confirm_verify(self):
        """确认验证结果"""
        self.result = self.is_verified
        self.destroy()

    def cancel(self):
        """取消"""
        self.result = None
        self.destroy()

    def show(self):
        """显示并返回结果"""
        self.wait_window()
        return self.result, self.is_verified

    def destroy(self):
        """释放资源"""
        self.running = False
        if hasattr(self, 'cap') and self.cap.isOpened():
            self.cap.release()
        cv2.destroyAllWindows()
        super().destroy()


# ====================== 声纹识别核心组件 ======================
class VoiceAuthManager:
    """声纹特征管理（基于Resemblyzer说话人嵌入）"""
    _encoder = None

    @classmethod
    def get_encoder(cls):
        """懒加载VoiceEncoder（单例）"""
        if cls._encoder is None:
            cls._encoder = VoiceEncoder()
        return cls._encoder

    @staticmethod
    def record_audio(duration=VOICE_DURATION, sample_rate=VOICE_SAMPLE_RATE):
        """录制音频并返回numpy数组（float32, 单声道）"""
        recording = sd.rec(int(duration * sample_rate), samplerate=sample_rate, channels=1, dtype='float32')
        sd.wait()
        return recording.flatten()

    @staticmethod
    def extract_embedding(audio, sample_rate=VOICE_SAMPLE_RATE):
        """
        提取说话人嵌入向量（256维）
        参数 audio: numpy数组，形状(n_samples,)
        返回: numpy数组，形状(256,)
        """
        wav = preprocess_wav(audio, source_sr=sample_rate)
        encoder = VoiceAuthManager.get_encoder()
        embed = encoder.embed_utterance(wav)
        return embed

    @staticmethod
    def calc_similarity(embed1, embed2):
        """计算两个嵌入向量的余弦相似度（返回值范围约-1到1）"""
        embed1 = embed1 / np.linalg.norm(embed1)
        embed2 = embed2 / np.linalg.norm(embed2)
        return float(np.dot(embed1, embed2))


class VoiceAuthDialog(tk.Toplevel):
    """声纹认证对话框（采集/验证双模式）"""

    def __init__(self, parent, mode="collect", reference_embeddings=None, title="声纹验证"):
        super().__init__(parent)
        self.title(title)
        self.geometry("480x380")
        self.parent = parent
        self.mode = mode
        self.reference_embeddings = reference_embeddings  # list of embeddings (numpy arrays)
        self.result = None
        self.is_verified = False
        self.collected_embeddings = []
        self.capture_count = 0

        self.configure(bg="#e0e0e0")
        self.attributes('-alpha', 0.9)
        self.attributes('-topmost', True)
        self.transient(parent)
        self.grab_set()

        self.update_idletasks()
        x = (parent.winfo_screenwidth() // 2) - (480 // 2)
        y = (parent.winfo_screenheight() // 2) - (380 // 2)
        self.geometry(f"480x380+{x}+{y}")

        self.setup_ui()

    def setup_ui(self):
        prompt = "请点击按钮录制声音（每次3秒，共3次）" if self.mode == "collect" else "请点击按钮录制声音以验证身份"
        self.status_label = tk.Label(self, text=prompt, font=("微软雅黑", 11), bg="#e0e0e0")
        self.status_label.pack(pady=20)

        self.progress_label = tk.Label(self, text="", font=("微软雅黑", 10), bg="#e0e0e0", fg="#333")
        self.progress_label.pack(pady=10)

        btn_frame = tk.Frame(self, bg="#e0e0e0")
        btn_frame.pack(pady=20)

        self.record_btn = tk.Button(
            btn_frame, text="开始录音", command=self.on_record, width=12,
            bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00"
        )
        self.record_btn.pack(side=tk.LEFT, padx=10)

        tk.Button(
            btn_frame, text="取消", command=self.cancel, width=10,
            bg="#ff4444", fg="white", relief=tk.FLAT, activebackground="#dd2222"
        ).pack(side=tk.LEFT, padx=10)

    def on_record(self):
        self.record_btn.config(state=tk.DISABLED, text="录音中...")
        self.progress_label.config(text="正在录音... 请说话")
        self.update()

        def task():
            try:
                audio = VoiceAuthManager.record_audio(duration=VOICE_DURATION)
                embed = VoiceAuthManager.extract_embedding(audio)
                self.after(0, lambda emb=embed: self._safe_process_recording(emb))
            except Exception as e:
                err_msg = str(e)
                self.after(0, lambda msg=err_msg: self._safe_record_error(msg))

        threading.Thread(target=task, daemon=True).start()

    def _safe_process_recording(self, embed):
        try:
            if not self.winfo_exists():
                return
            self.process_recording(embed)
        except Exception:
            pass

    def _safe_record_error(self, error_msg):
        try:
            if not self.winfo_exists():
                return
            self.record_btn.config(state=tk.NORMAL, text="开始录音")
            self.progress_label.config(text="")
            messagebox.showerror("错误", f"录音失败：{error_msg}", parent=self)
        except Exception:
            pass

    def process_recording(self, embed):
        try:
            self.record_btn.config(state=tk.NORMAL, text="开始录音")
        except tk.TclError:
            return

        if self.mode == "collect":
            self.collected_embeddings.append(embed)
            self.capture_count += 1
            self.progress_label.config(text=f"✅ 第 {self.capture_count} 次录音成功")
            if self.capture_count < 3:
                self.status_label.config(text=f"继续录制第 {self.capture_count + 1} 次声音（共3次）")
            else:
                self.status_label.config(text="3次声音录制完成！")
                try:
                    self.record_btn.config(text="确认使用", command=self.confirm_collect)
                except tk.TclError:
                    pass
        else:  # verify
            sim_list = [VoiceAuthManager.calc_similarity(embed, ref) for ref in self.reference_embeddings]
            avg_sim = float(np.mean(sim_list))
            self.is_verified = avg_sim >= VOICE_EMBEDDING_THRESHOLD
            if self.is_verified:
                self.progress_label.config(text=f"✅ 验证通过  相似度：{avg_sim:.4f}", fg="#2e7d32")
                try:
                    self.record_btn.config(state=tk.DISABLED)
                except tk.TclError:
                    pass
                self.after(800, self.confirm_verify)
            else:
                self.progress_label.config(text=f"❌ 验证失败  相似度：{avg_sim:.4f}", fg="#c62828")

    def confirm_collect(self):
        self.result = {
            'version': '1.0',
            'embeddings': [emb.tolist() for emb in self.collected_embeddings],
            'count': self.capture_count,
            'threshold': VOICE_EMBEDDING_THRESHOLD,
            'created_at': time.time()
        }
        self.destroy()

    def confirm_verify(self):
        self.result = self.is_verified
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()

    def show(self):
        self.wait_window()
        return self.result, self.is_verified


# ====================== 主程序 ======================
class guifeiCryptoTool(tkinterdnd2.Tk):
    """主程序类（guifei防破密专家核心类）"""

    def __init__(self):
        super().__init__()
        self.title("GuìFē! :) 防破密专家 v15.6.3")
        self.geometry("1370x770")
        self.configure(bg="#f0f0f0")
        self.attributes('-alpha', 0.97)
        # 居中显示
        self.center_window()

        # 状态变量
        self.current_mode = "main"
        self.selected_path = None
        # 原模式变量保留为兼容，新增多选变量
        self.encryption_mode = tk.StringVar(value="aes_only")
        self.use_grid_signature = tk.BooleanVar(value=False)
        self.use_face_verification = tk.BooleanVar(value=False)
        self.use_voice_verification = tk.BooleanVar(value=False)

        # 显示加载窗口
        self.show_loading()

        # 设置主界面
        self.setup_main_ui()

        # 绑定关闭事件
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def show_about(self):
        """显示关于信息弹窗"""
        about_content = """
名称：GuìFē! :)防破密专家

版本：v15.6.3

特点：
    AES-256 军用级加密
    scipy密钥派生安全无虞
    16 宫格密码再防护
    新增人脸与声纹多认证
    操作直观，零门槛
    极简程序，稳定及时相应
    真全方位文件数据铠甲

    2025 GuìFē! :) 加密技术团队™

⚠️本产品仅供学习交流使用，
        请勿用于商业用途"""
        messagebox.showinfo("关于 GuìFē! :) 防破密专家", about_content)

    def show_loading(self):
        """显示加载窗口"""
        loading = LoadingWindow(self)
        self.update()
        time.sleep(1.5)
        loading.destroy()

    def center_window(self):
        """窗口居中"""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def setup_main_ui(self):
        """设置主界面（5项竖向横条布局）"""
        # 更新当前模式
        self.current_mode = "main"

        # 清空现有组件
        for widget in self.winfo_children():
            widget.destroy()

        # 标题
        title_label = tk.Label(self, text="GuìFē! :) 防破密专家 v15.6.3", font=("微软雅黑", 16, "bold"), bg="#f0f0f0")
        title_label.pack(pady=30)

        # 功能按钮容器
        func_frame = tk.Frame(self, bg="#f0f0f0")
        func_frame.pack(fill=tk.X, padx=120, pady=10)

        # 5项功能横条（从上到下）
        buttons = [
            ("文件加密", self.show_file_encrypt_ui),
            ("文件夹加密", self.show_folder_encrypt_ui),
            ("文档加密", self.show_doc_encrypt_ui),
            ("一键解密", self.show_auto_decrypt_ui),
            ("关于", self.show_about)
        ]

        for text, cmd in buttons:
            btn_frame = tk.Frame(func_frame, bg="#cccccc", height=70, relief=tk.RAISED, bd=2)
            btn_frame.pack_propagate(False)
            btn_frame.pack(fill=tk.X, pady=8)

            # 悬停效果
            def on_enter(e):
                e.widget.configure(bg="#dddddd")

            def on_leave(e):
                e.widget.configure(bg="#cccccc")

            btn_frame.bind("<Enter>", on_enter)
            btn_frame.bind("<Leave>", on_leave)

            # 按钮文字
            btn_label = tk.Label(btn_frame, text=text, font=("微软雅黑", 14), bg="#cccccc")
            btn_label.pack(expand=True)

            # 绑定点击事件（同时绑定框体和文字，确保点击任意位置都生效）
            btn_frame.bind("<Button-1>", lambda e, c=cmd: c())
            btn_label.bind("<Button-1>", lambda e, c=cmd: c())

        # 启用拖拽功能
        self.enable_drag_and_drop()

        # 状态栏
        self.status_bar = tk.Label(self, text="就绪 | 支持拖拽文件/文件夹到对应功能界面",
                                   bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)

    def enable_drag_and_drop(self):
        """启用拖拽功能"""
        self.drop_target_register(tkinterdnd2.DND_FILES)
        self.dnd_bind('<<Drop>>', self.on_drop)
        self.dnd_bind('<<DragEnter>>', self.on_drag_enter)
        self.dnd_bind('<<DragLeave>>', self.on_drag_leave)
        self.dnd_bind('<<DragOver>>', self.on_drag_over)

    def on_drag_enter(self, event):
        """拖拽进入：背景变色"""
        self.configure(bg="#e8f0fe")

    def on_drag_leave(self, event):
        """拖拽离开：恢复背景"""
        self.configure(bg="#f0f0f0")

    def on_drag_over(self, event):
        """拖拽悬停：允许放下"""
        event.data = event.data

    def on_drop(self, event):
        """拖拽放下处理"""
        self.configure(bg="#f0f0f0")
        files = self.tk.splitlist(event.data)
        if not files:
            return

        dropped_path = files[0]
        self.selected_path = dropped_path

        # 根据当前界面模式填充对应路径
        if self.current_mode == "file":
            self.file_path_var.set(dropped_path)
            self.update_status(f"已加载文件：{os.path.basename(dropped_path)}")
        elif self.current_mode == "folder":
            if os.path.isdir(dropped_path):
                self.folder_path_var.set(dropped_path)
                self.update_status(
                    f"已加载文件夹：{os.path.basename(dropped_path)}\n⚠️提示：解密地址应为单独空文件夹\n因为解密后将释放原文件夹内文件")
            else:
                messagebox.showwarning("提示", "当前为文件夹加密界面，请拖拽文件夹！")
        elif self.current_mode == "decrypt":
            self.decrypt_path_var.set(dropped_path)
            self.update_status(f"已加载待解密文件：{os.path.basename(dropped_path)}")
        elif self.current_mode == "main":
            if os.path.isdir(dropped_path):
                self.show_folder_encrypt_ui()
                self.folder_path_var.set(dropped_path)
            else:
                self.show_file_encrypt_ui()
                self.file_path_var.set(dropped_path)
        elif self.current_mode == "doc":
            messagebox.showinfo("提示", "文档加密界面不支持文件拖拽，请直接编辑文本！")

    def show_back_button(self, parent):
        """显示返回按钮"""
        back_btn = tk.Button(parent, text="← 返回主界面", command=self.setup_main_ui,
                             bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777")
        back_btn.pack(anchor=tk.NW, padx=10, pady=10)
        return back_btn

    # ====================== 功能界面 ======================
    def _add_verification_options(self, parent_frame):
        """通用验证方式多选组件，返回包含三个BooleanVar的字典"""
        frame = tk.Frame(parent_frame, bg="white" if parent_frame.cget('bg') == 'white' else "#f0f0f0")
        frame.pack(fill=tk.X, padx=10, pady=10)
        bg_color = frame.cget('bg')
        tk.Label(frame, text="附加验证方式（可多选）：", bg=bg_color, font=("微软雅黑", 10)).pack(anchor=tk.W)
        opts = tk.Frame(frame, bg=bg_color)
        opts.pack(anchor=tk.W, pady=5)
        tk.Checkbutton(opts, text="宫格签名", variable=self.use_grid_signature, bg=bg_color).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(opts, text="人脸验证", variable=self.use_face_verification, bg=bg_color).pack(side=tk.LEFT,
                                                                                                     padx=5)
        tk.Checkbutton(opts, text="声纹验证", variable=self.use_voice_verification, bg=bg_color).pack(side=tk.LEFT,
                                                                                                      padx=5)
        return frame

    def show_file_encrypt_ui(self):
        """文件加密界面"""
        # 更新当前模式
        self.current_mode = "file"

        # 清空界面
        for widget in self.winfo_children():
            widget.destroy()

        # 返回按钮
        self.show_back_button(self)

        # 标题
        tk.Label(self, text="文件加密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0").pack(pady=10)

        # 主框架
        main_frame = tk.Frame(self, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # 左侧：文件选择
        left_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)
        left_frame.pack_propagate(False)

        tk.Label(left_frame, text="选择文件", font=("微软雅黑", 12), bg="white").pack(pady=10)

        # 文件路径显示
        self.file_path_var = tk.StringVar(value=self.selected_path or "未选择文件")
        path_label = tk.Label(left_frame, textvariable=self.file_path_var, bg="white",
                              font=("微软雅黑", 10), wraplength=450, fg="#666666")
        path_label.pack(pady=5, padx=10)

        # 选择文件按钮
        tk.Button(left_frame, text="浏览文件", command=self.select_file,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(pady=10)

        # 使用新的多选模式
        self._add_verification_options(left_frame)

        # 右侧：保存设置
        right_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10)
        right_frame.pack_propagate(False)

        tk.Label(right_frame, text="保存设置", font=("微软雅黑", 12), bg="white").pack(pady=10)

        # 保存路径
        self.save_path_var = tk.StringVar(value="")
        tk.Label(right_frame, text="保存路径：", bg="white", font=("微软雅黑", 10)).pack(anchor=tk.W, padx=10)
        tk.Entry(right_frame, textvariable=self.save_path_var, bg="#f5f5f5", relief=tk.FLAT).pack(fill=tk.X, padx=10,
                                                                                                  pady=5)
        tk.Button(right_frame, text="选择保存位置", command=self.select_file_save_path,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(pady=5)

        # 开始加密按钮
        tk.Button(right_frame, text="开始加密", command=self.start_file_encryption,
                  bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00",
                  font=("微软雅黑", 12)).pack(side=tk.BOTTOM, pady=20, ipady=5)

        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=10)

        # 修复进度条样式
        style = ttk.Style()
        style.configure("grey.Horizontal.TProgressbar", troughcolor='#e0e0e0', background='#44dd00')
        self.progress_bar.config(style="grey.Horizontal.TProgressbar")

        # 启用拖拽
        self.enable_drag_and_drop()

        # 状态栏
        self.status_bar = tk.Label(self, text="文件加密界面 | 支持拖拽文件到此处 | 加密后默认使用原文件名",
                                   bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)

    def show_folder_encrypt_ui(self):
        """文件夹加密界面"""
        # 更新当前模式
        self.current_mode = "folder"

        # 清空界面
        for widget in self.winfo_children():
            widget.destroy()

        # 返回按钮
        self.show_back_button(self)

        # 标题
        tk.Label(self, text="文件夹加密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0").pack(pady=10)

        # 主框架
        main_frame = tk.Frame(self, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # 左侧：文件夹选择
        left_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)
        left_frame.pack_propagate(False)

        tk.Label(left_frame, text="选择文件夹", font=("微软雅黑", 12), bg="white").pack(pady=10)

        # 文件夹路径显示
        self.folder_path_var = tk.StringVar(value=self.selected_path or "未选择文件夹")
        path_label = tk.Label(left_frame, textvariable=self.folder_path_var, bg="white",
                              font=("微软雅黑", 10), wraplength=450, fg="#666666")
        path_label.pack(pady=5, padx=10)

        # 选择文件夹按钮
        tk.Button(left_frame, text="浏览文件夹", command=self.select_folder,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(pady=10)

        # 多选验证方式
        self._add_verification_options(left_frame)

        # 右侧：保存设置
        right_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10)
        right_frame.pack_propagate(False)

        tk.Label(right_frame, text="保存设置", font=("微软雅黑", 12), bg="white").pack(pady=10)

        # 保存路径
        self.folder_save_var = tk.StringVar(value="")
        tk.Label(right_frame, text="保存路径：", bg="white", font=("微软雅黑", 10)).pack(anchor=tk.W, padx=10)
        tk.Entry(right_frame, textvariable=self.folder_save_var, bg="#f5f5f5", relief=tk.FLAT).pack(fill=tk.X, padx=10,
                                                                                                    pady=5)
        tk.Button(right_frame, text="选择保存位置", command=self.select_folder_save_path,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(pady=5)

        # 开始加密按钮
        tk.Button(right_frame, text="开始加密", command=self.start_folder_encryption,
                  bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00",
                  font=("微软雅黑", 12)).pack(side=tk.BOTTOM, pady=20, ipady=5)

        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=10)

        # 启用拖拽
        self.enable_drag_and_drop()

        # 状态栏
        self.status_bar = tk.Label(self, text="文件夹加密界面 | 支持拖拽文件夹到此处 | 加密后默认使用原文件夹名",
                                   bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)

    def show_doc_encrypt_ui(self):
        """文档加密界面"""
        # 更新当前模式
        self.current_mode = "doc"

        # 清空界面
        for widget in self.winfo_children():
            widget.destroy()

        # 返回按钮
        self.show_back_button(self)

        # 标题
        tk.Label(self, text="文档加密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0").pack(pady=10)

        # 文本编辑区
        text_frame = tk.Frame(self, bg="#f0f0f0")
        text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.doc_text = scrolledtext.ScrolledText(text_frame, font=("Consolas", 10), wrap=tk.WORD,
                                                  bg="#f5f5f5", relief=tk.FLAT, bd=1, height=25)
        self.doc_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # 多选验证方式
        ver_frame = tk.Frame(self, bg="#f0f0f0")
        ver_frame.pack(fill=tk.X, padx=20, pady=5)
        self._add_verification_options(ver_frame)

        # 按钮框架
        btn_frame = tk.Frame(self, bg="#f0f0f0")
        btn_frame.pack(fill=tk.X, padx=20, pady=10)

        # 保存按钮
        tk.Button(btn_frame, text="保存加密文档", command=self.save_encrypted_doc,
                  bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00",
                  font=("微软雅黑", 10)).pack(side=tk.RIGHT, padx=5)

        # 打开按钮
        tk.Button(btn_frame, text="打开加密文档", command=self.open_encrypted_doc,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777",
                  font=("微软雅黑", 10)).pack(side=tk.RIGHT, padx=5)

        # 清空按钮
        tk.Button(btn_frame, text="清空内容", command=lambda: self.doc_text.delete(1.0, tk.END),
                  bg="#ff4444", fg="white", relief=tk.FLAT, activebackground="#dd2222",
                  font=("微软雅黑", 10)).pack(side=tk.RIGHT, padx=5)

        # 状态栏
        self.status_bar = tk.Label(self, text="文档加密界面 | 直接编辑文本内容",
                                   bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)

    def show_auto_decrypt_ui(self):
        """自动解密界面"""
        # 更新当前模式
        self.current_mode = "decrypt"

        # 清空界面
        for widget in self.winfo_children():
            widget.destroy()

        # 返回按钮
        self.show_back_button(self)

        # 标题
        tk.Label(self, text="自动解密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0").pack(pady=10)

        # 选择加密文件
        self.decrypt_path_var = tk.StringVar(value=self.selected_path or "未选择加密文件")
        tk.Label(self, textvariable=self.decrypt_path_var, bg="#f0f0f0", font=("微软雅黑", 10), fg="#666666").pack(
            pady=10)

        # 按钮
        btn_frame = tk.Frame(self, bg="#f0f0f0")
        btn_frame.pack(pady=20)

        tk.Button(btn_frame, text="选择加密文件", command=self.select_encrypted_file,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777",
                  font=("微软雅黑", 10)).pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="开始解密", command=self.start_auto_decryption,
                  bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00",
                  font=("微软雅黑", 10)).pack(side=tk.LEFT, padx=10)

        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=10)

        # 启用拖拽
        self.enable_drag_and_drop()

        # 状态栏
        self.status_bar = tk.Label(self, text="自动解密界面 | 支持拖拽加密文件到此处 | 解密后默认显示原文件名",
                                   bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)

    # ====================== 核心加密解密逻辑 ======================
    def _derive_keys(self, password, salt):
        """密钥派生"""
        key_material = hashlib.pbkdf2_hmac(
            KDF_HASH_ALG,
            password.encode('utf-8'),
            salt,
            KDF_ITERATIONS,
            dklen=AES_KEY_LENGTH * 2
        )
        return key_material[:AES_KEY_LENGTH], key_material[AES_KEY_LENGTH:]

    def _encrypt_single_layer(self, data, password):
        """单层加密"""
        salt = get_random_bytes(SALT_LENGTH)
        nonce = get_random_bytes(GCM_NONCE_LENGTH)
        encryption_key, hmac_key = self._derive_keys(password, salt)

        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(pad(data, AES.block_size))

        # 组装数据包
        packet = ENCRYPTION_MAGIC + VERSION + salt + nonce + tag + ciphertext
        hmac_digest = hmac.new(hmac_key, packet, SIGNATURE_HASH_ALG).digest()

        return hmac_digest + packet

    def _decrypt_single_layer(self, encrypted_data, password):
        """单层解密"""
        # 验证长度
        if len(encrypted_data) < HMAC_LENGTH + len(ENCRYPTION_MAGIC) + len(
                VERSION) + SALT_LENGTH + GCM_NONCE_LENGTH + 16:
            raise ValueError("无效的加密数据")

        # 分离HMAC和数据包
        hmac_digest = encrypted_data[:HMAC_LENGTH]
        packet = encrypted_data[HMAC_LENGTH:]

        # 验证魔数
        if packet[:len(ENCRYPTION_MAGIC)] != ENCRYPTION_MAGIC:
            raise ValueError("无效的加密文件")

        # 解析数据包
        salt = packet[len(ENCRYPTION_MAGIC) + len(VERSION):len(ENCRYPTION_MAGIC) + len(VERSION) + SALT_LENGTH]
        nonce = packet[len(ENCRYPTION_MAGIC) + len(VERSION) + SALT_LENGTH:len(ENCRYPTION_MAGIC) + len(
            VERSION) + SALT_LENGTH + GCM_NONCE_LENGTH]
        tag = packet[len(ENCRYPTION_MAGIC) + len(VERSION) + SALT_LENGTH + GCM_NONCE_LENGTH:len(ENCRYPTION_MAGIC) + len(
            VERSION) + SALT_LENGTH + GCM_NONCE_LENGTH + 16]
        ciphertext = packet[len(ENCRYPTION_MAGIC) + len(VERSION) + SALT_LENGTH + GCM_NONCE_LENGTH + 16:]

        # 派生密钥
        encryption_key, hmac_key = self._derive_keys(password, salt)

        # 验证HMAC
        calculated_hmac = hmac.new(hmac_key, packet, SIGNATURE_HASH_ALG).digest()
        if not hmac.compare_digest(hmac_digest, calculated_hmac):
            raise ValueError("密码错误或文件已被篡改")

        # 解密
        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
        plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)

        return plaintext

    # 宫格签名格式转换
    def _convert_grid_signature(self, signature):
        """宫格签名转换为特殊保存格式"""
        if not signature:
            return b''

        # 获取核心的指定格式字符串
        signature_str = signature.get('signature_string', '')
        # 特殊保存格式：Base64编码的指定字符串
        return base64.b64encode(signature_str.encode('utf-8'))

    def _restore_grid_signature(self, special_data):
        """从特殊格式恢复宫格签名"""
        if not special_data:
            return {}

        # 解码Base64
        signature_str = base64.b64decode(special_data).decode('utf-8')
        # 构建签名数据
        grid_pad = GridSignaturePad(self)
        point_sequence = grid_pad.parse_signature_string(signature_str)

        return {
            'version': '1.0',
            'grid_size': GRID_SIZE,
            'signature_string': signature_str,
            'point_sequence': point_sequence,
            'sequence_length': len(point_sequence),
            'hash': hashlib.sha256(signature_str.encode()).hexdigest()
        }

    # 人脸特征格式转换
    def _convert_face_signature(self, face_data):
        """人脸特征转为可加密的字节流"""
        if not face_data:
            return b''
        return pickle.dumps(face_data)

    def _restore_face_signature(self, face_bytes):
        """从字节流恢复人脸特征数据"""
        if not face_bytes:
            return {}
        return pickle.loads(face_bytes)

    # 声纹特征格式转换
    def _convert_voice_signature(self, voice_data):
        if not voice_data:
            return b''
        return pickle.dumps(voice_data)

    def _restore_voice_signature(self, voice_bytes):
        if not voice_bytes:
            return {}
        return pickle.loads(voice_bytes)

    def encrypt_multi_layer(self, data, password, file_type, signature=None, face_signature=None, voice_signature=None,
                            verifications=None, original_filename=""):
        """三层加密结构（包含原文件名+后缀+多重生物特征加密）"""
        try:
            self.update_progress(10)

            # 第一层：加密原始数据
            layer1 = self._encrypt_single_layer(data, password)
            self.update_progress(30)

            # 第二层：分别加密各验证数据
            encrypted_signature = b''
            if signature:
                special_signature = self._convert_grid_signature(signature)
                encrypted_signature = self._encrypt_single_layer(special_signature, password)

            encrypted_face = b''
            if face_signature:
                face_bytes = self._convert_face_signature(face_signature)
                encrypted_face = self._encrypt_single_layer(face_bytes, password)

            encrypted_voice = b''
            if voice_signature:
                voice_bytes = self._convert_voice_signature(voice_signature)
                encrypted_voice = self._encrypt_single_layer(voice_bytes, password)

            self.update_progress(50)

            # 组装文件夹结构
            folder_data = {
                'content': layer1,
                'signature': encrypted_signature,
                'face_signature': encrypted_face,
                'voice_signature': encrypted_voice,
                'type': file_type,
                'verifications': verifications if verifications else [],
                'mode': self.encryption_mode.get().encode('utf-8'),  # 保持兼容
                'timestamp': time.time(),
                'original_filename': original_filename.encode('utf-8'),
                'original_basename': os.path.basename(original_filename).encode('utf-8')
            }
            folder_bytes = pickle.dumps(folder_data)
            self.update_progress(70)

            # 第三层：加密整个文件夹结构
            final_encrypted = self._encrypt_single_layer(folder_bytes, password)
            self.update_progress(100)

            return final_encrypted

        except Exception as e:
            self.update_progress(0)
            raise Exception(f"加密失败: {str(e)}")

    def decrypt_multi_layer(self, encrypted_data, password, verify_signature=True, verify_face=True, verify_voice=True):
        """三层解密结构（自动验证所有存储的生物特征）"""
        try:
            self.update_progress(10)

            # 第一层：解密文件夹结构
            folder_bytes = self._decrypt_single_layer(encrypted_data, password)
            self.update_progress(30)

            # 解析文件夹
            folder_data = pickle.loads(folder_bytes)
            content_data = folder_data['content']
            signature_data = folder_data.get('signature', b'')
            face_signature_data = folder_data.get('face_signature', b'')
            voice_signature_data = folder_data.get('voice_signature', b'')
            file_type = folder_data.get('type', FILE_TYPE_TEXT)
            verifications = folder_data.get('verifications', [])
            # 解析原文件名
            original_filename = folder_data.get('original_filename', b'').decode('utf-8')
            original_basename = folder_data.get('original_basename', b'').decode('utf-8')
            self.update_progress(50)

            # 依次验证存储的各项
            is_verified_all = True

            # 宫格验证
            if verify_signature and 'grid' in verifications and signature_data:
                special_signature = self._decrypt_single_layer(signature_data, password)
                ref_signature = self._restore_grid_signature(special_signature)
                grid_pad = GridSignaturePad(self, "宫格验证", ref_signature)
                _, is_verified = grid_pad.show()
                if not is_verified:
                    raise ValueError("宫格验证失败：连接顺序不匹配")
                is_verified_all = is_verified_all and is_verified

            # 人脸验证
            if verify_face and 'face' in verifications and face_signature_data:
                face_bytes = self._decrypt_single_layer(face_signature_data, password)
                ref_face_data = self._restore_face_signature(face_bytes)
                ref_features = [np.array(feat) for feat in ref_face_data['features']]
                face_dialog = FaceAuthDialog(self, mode="verify", reference_features=ref_features, title="人脸验证")
                _, face_verified = face_dialog.show()
                if not face_verified:
                    raise ValueError("人脸验证失败：身份不匹配")
                is_verified_all = is_verified_all and face_verified

            # 声纹验证
            if verify_voice and 'voice' in verifications and voice_signature_data:
                voice_bytes = self._decrypt_single_layer(voice_signature_data, password)
                ref_voice_data = self._restore_voice_signature(voice_bytes)
                ref_embeddings = [np.array(emb) for emb in ref_voice_data['embeddings']]
                voice_dialog = VoiceAuthDialog(self, mode="verify", reference_embeddings=ref_embeddings,
                                               title="声纹验证")
                _, voice_verified = voice_dialog.show()
                if not voice_verified:
                    raise ValueError("声纹验证失败：身份不匹配")
                is_verified_all = is_verified_all and voice_verified

            self.update_progress(70)

            # 第二层：解密内容
            plain_data = self._decrypt_single_layer(content_data, password)
            self.update_progress(100)

            return plain_data, file_type, is_verified_all, original_filename, original_basename

        except Exception as e:
            self.update_progress(0)
            raise Exception(f"解密失败: {str(e)}")

    # ====================== 辅助方法 ======================
    def update_progress(self, value):
        """线程安全的进度条更新"""
        self.after(0, lambda: self._safe_update_progress(value))

    def _safe_update_progress(self, value):
        """线程安全的进度条更新"""
        try:
            if hasattr(self, 'progress_var') and self.progress_var:
                self.progress_var.set(value)
                self.update_idletasks()
        except:
            pass

    def update_status(self, text):
        """线程安全的状态栏更新"""
        self.after(0, lambda: self._safe_update_status(text))

    def _safe_update_status(self, text):
        """线程安全的状态栏更新"""
        try:
            if not hasattr(self, 'status_bar') or not self.status_bar.winfo_exists():
                self.status_bar = tk.Label(self, text=text, bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
                self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)
            else:
                self.status_bar.config(text=text)
            self.update_idletasks()
        except:
            pass

    def select_file(self):
        """选择文件"""
        path = filedialog.askopenfilename(title="选择要加密的文件")
        if path:
            self.selected_path = path
            self.file_path_var.set(path)

    def select_folder(self):
        """选择文件夹"""
        path = filedialog.askdirectory(title="选择要加密的文件夹")
        if path:
            self.selected_path = path
            self.folder_path_var.set(path)

    def select_file_save_path(self):
        """选择文件保存路径 - 默认使用原文件名"""
        if not self.selected_path:
            messagebox.showwarning("警告", "请先选择要加密的文件！")
            return

        # 获取原文件名
        original_basename = os.path.basename(self.selected_path)
        default_filename = f"{original_basename}.guifei"

        path = filedialog.asksaveasfilename(
            defaultextension='.guifei',
            filetypes=[("加密文件", "*.guifei"), ("所有文件", "*.*")],
            title="保存",
            initialfile=default_filename
        )
        if path:
            self.save_path_var.set(path)

    def select_folder_save_path(self):
        """选择文件夹保存路径 - 默认使用原文件夹名"""
        if not self.selected_path:
            messagebox.showwarning("警告", "请先选择要加密的文件夹！")
            return

        # 获取原文件夹名
        original_basename = os.path.basename(self.selected_path)
        default_filename = f"{original_basename}.guifeinext"

        path = filedialog.asksaveasfilename(
            defaultextension='.guifeinext',
            filetypes=[("加密文件夹", "*.guifeinext"), ("所有文件", "*.*")],
            title="保存",
            initialfile=default_filename
        )
        if path:
            self.folder_save_var.set(path)

    def select_encrypted_file(self):
        """选择加密文件"""
        try:
            path = filedialog.askopenfilename(
                filetypes=[
                    ("下拉可选↓", ".guifei "".guifeinext "".msc"),
                    ("加密文件", "*.guifei"),
                    ("加密文件夹", "*.guifeinext"),
                    ("加密文本", "*.msc"),
                ],
                title="选择要解密的文件"
            )
        except Exception as e:
            messagebox.showerror(title="错误", message=f"Error{e}")
        if path:
            self.decrypt_path_var.set(path)

    # ====================== 加密解密入口 ======================
    def _collect_verifications(self):
        """根据当前多选状态采集验证数据，返回 (signature, face, voice, verifications_list)"""
        verifications = []
        signature = None
        face_sig = None
        voice_sig = None

        if self.use_grid_signature.get():
            grid_pad = GridSignaturePad(self, "设置宫格验证")
            sig, _ = grid_pad.show()
            if not sig:
                return None, None, None, None
            signature = sig
            verifications.append('grid')

        if self.use_face_verification.get():
            face_dialog = FaceAuthDialog(self, mode="collect", title="设置人脸验证")
            fs, _ = face_dialog.show()
            if not fs:
                return None, None, None, None
            face_sig = fs
            verifications.append('face')

        if self.use_voice_verification.get():
            voice_dialog = VoiceAuthDialog(self, mode="collect", title="设置声纹验证")
            vs, _ = voice_dialog.show()
            if not vs:
                return None, None, None, None
            voice_sig = vs
            verifications.append('voice')

        return signature, face_sig, voice_sig, verifications

    def start_file_encryption(self):
        """开始文件加密"""
        if not self.selected_path:
            messagebox.showwarning("警告", "请先选择要加密的文件！")
            return

        # 获取保存路径
        save_path = self.save_path_var.get()
        if not save_path:
            original_basename = os.path.basename(self.selected_path)
            default_filename = f"{original_basename}.guifei"
            save_path = filedialog.asksaveasfilename(
                defaultextension='.guifei',
                filetypes=[("加密文件", "*.guifei")],
                title="选择保存位置",
                initialfile=default_filename
            )
            if not save_path:
                return
            self.save_path_var.set(save_path)

        # 获取密码
        password = PasswordDialog(self, "加密密码", "请输入加密密码:").show()
        if not password:
            return

        # 收集验证数据
        signature, face_sig, voice_sig, verifications = self._collect_verifications()
        if verifications is None:  # 用户取消了某个采集
            return

        # 后台加密
        def encrypt_task():
            try:
                self.update_progress(0)
                self.update_status("正在加密文件...")

                # 读取文件
                with open(self.selected_path, 'rb') as f:
                    file_data = f.read()
                self.update_progress(20)

                # 三层加密
                encrypted_data = self.encrypt_multi_layer(
                    file_data,
                    password,
                    FILE_TYPE_FILE,
                    signature=signature,
                    face_signature=face_sig,
                    voice_signature=voice_sig,
                    verifications=verifications,
                    original_filename=self.selected_path
                )
                self.update_progress(80)

                # 保存文件
                with open(save_path, 'wb') as f:
                    f.write(encrypted_data)
                self.update_progress(100)

                self.update_status(f"文件加密完成：{os.path.basename(save_path)}")
                self.after(0, lambda: messagebox.showinfo("成功", "文件加密完成！"))

            except Exception as e:
                error_msg = f"加密失败：{str(e)}"
                self.update_progress(0)
                self.update_status(error_msg)
                self.after(0, lambda: messagebox.showerror("错误", error_msg))

        threading.Thread(target=encrypt_task, daemon=True).start()

    def start_folder_encryption(self):
        """开始文件夹加密"""
        if not self.selected_path:
            messagebox.showwarning("警告", "请先选择要加密的文件夹！")
            return

        # 获取保存路径
        save_path = self.folder_save_var.get()
        if not save_path:
            original_basename = os.path.basename(self.selected_path)
            default_filename = f"{original_basename}.guifeinext"
            save_path = filedialog.asksaveasfilename(
                defaultextension='.guifeinext',
                filetypes=[("加密文件夹", "*.guifeinext")],
                title="选择保存位置",
                initialfile=default_filename
            )
            if not save_path:
                return
            self.folder_save_var.set(save_path)

        # 获取密码
        password = PasswordDialog(self, "加密密码", "请输入加密密码:").show()
        if not password:
            return

        # 收集验证数据
        signature, face_sig, voice_sig, verifications = self._collect_verifications()
        if verifications is None:
            return

        # 后台加密
        def encrypt_task():
            try:
                self.update_progress(0)
                self.update_status("正在压缩并加密文件夹...")

                # 压缩文件夹
                temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
                with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root, dirs, files in os.walk(self.selected_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, self.selected_path)
                            zipf.write(file_path, arcname)
                temp_zip.close()
                self.update_progress(30)

                # 读取压缩文件
                with open(temp_zip.name, 'rb') as f:
                    zip_data = f.read()
                os.unlink(temp_zip.name)
                self.update_progress(50)

                # 三层加密
                encrypted_data = self.encrypt_multi_layer(
                    zip_data,
                    password,
                    FILE_TYPE_FOLDER,
                    signature=signature,
                    face_signature=face_sig,
                    voice_signature=voice_sig,
                    verifications=verifications,
                    original_filename=self.selected_path
                )
                self.update_progress(80)

                # 保存文件
                with open(save_path, 'wb') as f:
                    f.write(encrypted_data)
                self.update_progress(100)

                self.update_status(f"文件夹加密完成：{os.path.basename(save_path)}")
                self.after(0, lambda: messagebox.showinfo("成功", "文件夹加密完成！"))

            except Exception as e:
                error_msg = f"加密失败：{str(e)}"
                self.update_progress(0)
                self.update_status(error_msg)
                self.after(0, lambda: messagebox.showerror("错误", error_msg))

        threading.Thread(target=encrypt_task, daemon=True).start()

    def save_encrypted_doc(self):
        """保存加密文档"""
        content = self.doc_text.get(1.0, tk.END).encode('utf-8')
        if not content.strip():
            messagebox.showwarning("警告", "文档内容不能为空！")
            return

        # 选择保存路径
        save_path = filedialog.asksaveasfilename(
            defaultextension='.msc',
            filetypes=[("加密文档", "*.msc")],
            title="选择保存位置",
            initialfile="document.msc"
        )
        if not save_path:
            return

        # 获取密码
        password = PasswordDialog(self, "加密密码", "请输入加密密码:").show()
        if not password:
            return

        # 收集验证数据
        signature, face_sig, voice_sig, verifications = self._collect_verifications()
        if verifications is None:
            return

        # 加密保存
        try:
            encrypted_data = self.encrypt_multi_layer(
                content,
                password,
                FILE_TYPE_TEXT,
                signature=signature,
                face_signature=face_sig,
                voice_signature=voice_sig,
                verifications=verifications,
                original_filename="document.msc"
            )
            with open(save_path, 'wb') as f:
                f.write(encrypted_data)
            messagebox.showinfo("成功", "文档加密保存完成！")
        except Exception as e:
            messagebox.showerror("错误", f"保存失败：{str(e)}")

    def open_encrypted_doc(self):
        """打开加密文档"""
        file_path = filedialog.askopenfilename(
            filetypes=[("加密文档", "*.msc"), ("所有文件", "*.*")],
            title="打开加密文档"
        )
        if not file_path:
            return

        # 获取密码
        password = PasswordDialog(self, "解密密码", "请输入解密密码:", show_strength=False).show()
        if not password:
            return

        # 解密
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            plain_data, _, _, _, original_basename = self.decrypt_multi_layer(encrypted_data, password)

            # 显示内容
            self.doc_text.delete(1.0, tk.END)
            self.doc_text.insert(tk.END, plain_data.decode('utf-8', errors='replace'))
            messagebox.showinfo("成功", f"文档解密完成！原文件名：{original_basename}")

        except Exception as e:
            messagebox.showerror("错误", f"解密失败：{str(e)}")

    def start_auto_decryption(self):
        """自动解密（核心修复：文本解密时组件不存在问题）"""
        file_path = self.decrypt_path_var.get()
        if file_path == "未选择加密文件":
            messagebox.showwarning("警告", "请先选择要解密的文件！")
            return

        # 获取密码
        password = PasswordDialog(self, "解密密码", "请输入解密密码:", show_strength=False).show()
        if not password:
            return

        # 后台解密
        def decrypt_task():
            try:
                self.update_progress(0)
                self.update_status("正在解密文件...")

                # 读取加密文件
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                self.update_progress(20)

                # 三层解密（自动触发宫格/人脸/声纹验证）
                plain_data, file_type, _, original_filename, original_basename = self.decrypt_multi_layer(
                    encrypted_data, password)
                self.update_progress(60)

                # 根据类型处理
                if file_type == FILE_TYPE_TEXT:
                    # 文本文件：修复组件不存在问题
                    self.after(0, lambda: self._show_decrypted_text(plain_data, original_basename))

                elif file_type == FILE_TYPE_FILE:
                    # 单文件：保存
                    def save_file():
                        save_path = filedialog.asksaveasfilename(
                            title="保存文件位置",
                            initialfile=original_basename or os.path.splitext(os.path.basename(file_path))[0]
                        )
                        if save_path:
                            with open(save_path, 'wb') as f:
                                f.write(plain_data)
                            self.update_status(f"文件解密完成：{os.path.basename(save_path)}")
                            messagebox.showinfo("成功", f"文件解密完成：{os.path.basename(save_path)}")

                    self.after(0, save_file)

                elif file_type == FILE_TYPE_FOLDER:
                    # 文件夹：解压保存
                    def extract_folder():
                        # 选择保存的父目录
                        parent_dir = filedialog.askdirectory(title="选择文件夹保存位置")
                        if not parent_dir:
                            self.update_status("解密取消：未选择保存位置")
                            return

                        # 以原文件夹名创建目标子文件夹
                        target_dir = os.path.join(parent_dir, original_basename)
                        # 重名自动追加序号，避免覆盖
                        counter = 1
                        base_name = original_basename
                        while os.path.exists(target_dir):
                            target_dir = os.path.join(parent_dir, f"{base_name}_{counter}")
                            counter += 1
                        os.makedirs(target_dir, exist_ok=True)

                        # 创建临时zip文件
                        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
                        temp_zip.write(plain_data)
                        temp_zip.close()

                        # 解压到目标文件夹内
                        with zipfile.ZipFile(temp_zip.name, 'r') as zipf:
                            total_files = len(zipf.namelist())
                            processed = 0

                            for file_info in zipf.infolist():
                                zipf.extract(file_info, target_dir)
                                processed += 1
                                self.update_progress(60 + int(30 * processed / total_files))

                        # 删除临时文件
                        os.unlink(temp_zip.name)
                        self.update_progress(100)

                        # 提示
                        self.update_status(f"文件夹解密完成：已解压到 {target_dir}")
                        self.after(0, lambda: messagebox.showinfo(
                            "成功",
                            f"文件夹解密完成！\n已解压到：{target_dir}"
                        ))

                    self.after(0, extract_folder)

                self.update_progress(100)

            except Exception as e:
                error_msg = f"解密失败：{str(e)}"
                self.update_progress(0)
                self.update_status(error_msg)
                self.after(0, lambda: messagebox.showerror("错误", error_msg))

        threading.Thread(target=decrypt_task, daemon=True).start()

    def _show_decrypted_text(self, plain_data, original_basename):
        """修复：显示解密后的文本内容（检查组件是否存在）"""
        # 检查doc_text组件是否存在，不存在则创建
        if not hasattr(self, 'doc_text') or not self.doc_text.winfo_exists():
            self.show_doc_encrypt_ui()

        # 延迟确保组件加载完成
        self.after(100, lambda: self._safe_display_text(plain_data, original_basename))

    def _safe_display_text(self, plain_data, original_basename):
        """安全显示文本内容（异常兜底）"""
        try:
            self.doc_text.delete(1.0, tk.END)
            self.doc_text.insert(tk.END, plain_data.decode('utf-8', errors='replace'))
            self.update_status(f"文本解密完成：原文件名 {original_basename}")
            messagebox.showinfo(
                "成功",
                f"文本解密完成！\n原文件名：{original_basename}\n已加载到文档编辑区"
            )
        except Exception as e:
            self.update_status(f"文本显示失败：{str(e)}")
            messagebox.showwarning(
                "提示",
                f"文本解密成功但显示失败！\n原文件名：{original_basename}\n错误：{str(e)}\n请手动打开文档加密界面查看"
            )

    def on_close(self):
        """程序关闭事件"""
        if messagebox.askokcancel("退出", "确定要退出GuìFē! :)防破密专家吗？"):
            self.destroy()
            sys.exit(0)


# ====================== 主程序入口 ======================

ICO_BASE64 = '''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xgfa2N4ANEBoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAx727AMa9ugTIwscTt7TFBMfDzQAREVoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA///////////////////B///DAf//AgD//gMAP/wDAB/4A4AP8AeAD+AQBAfgYAYH4GAHA8DgBwPA4AeDwOAHg8DgBwPA4AcDwPAPA+BxjgfgMAwH4AAQB/AAAA/4AYAf/ACAP/4AwH//gMH//4HH//+P//////////////////8='''

if __name__ == "__main__":
    # 高DPI适配
    try:
        from ctypes import windll

        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    # 启动程序
    app = guifeiCryptoTool()
    try:
        # 解码 Base64 为字节数据
        ico_bytes = base64.b64decode(ICO_BASE64.strip())
        # 将字节数据转为内存中的文件流
        ico_stream = io.BytesIO(ico_bytes)
        # 用 PIL 打开流并转换为 tkinter 图标
        ico_image = Image.open(ico_stream)
        app_icon = ImageTk.PhotoImage(ico_image)
        # 设置窗口图标（兼容多平台）
        app.iconphoto(True, app_icon)

        # Windows 下额外设置 taskbar 图标（可选）
        try:
            app.iconbitmap(default=app_icon)
        except Exception:
            pass
    except Exception as e:
        messagebox.showerror(title="错误", message=f"Error{e}")
    app.mainloop()

