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
import sounddevice as sd
import soundfile as sf
import librosa

# ====================== 核心常量定义 ======================
# 加密常量
AES_KEY_LENGTH = 32  # 256位AES密钥
GCM_NONCE_LENGTH = 12  # GCM推荐nonce长度
KDF_ITERATIONS = 310000  # NIST推荐迭代次数
KDF_HASH_ALG = 'sha256'
SIGNATURE_HASH_ALG = 'sha3-256'
ENCRYPTION_MAGIC = b'BombCRYPT11'  # 魔数
VERSION = b'1.0'  # 版本号
HMAC_LENGTH = 32  # SHA3-256 HMAC长度
SALT_LENGTH = 16  # 盐长度

# 文件类型标识
FILE_TYPE_TEXT = b'msc'  # 文本文档
FILE_TYPE_FILE = b'Bomb'  # 单文件
FILE_TYPE_FOLDER = b'Bombnext'  # 文件夹
GRID_SIGNATURE_MATCH_REQUIRED = True  # 宫格签名必须完全匹配

# 4×4宫格常量
GRID_SIZE = 4  # 4×4宫格
GRID_POINT_SIZE = 30  # 宫格点大小（像素）
GRID_SPACING = 10  # 宫格间距（像素）

# 人脸识别常量
FACE_SIMILARITY_THRESHOLD = 0.75
FACE_MODEL_NAME = "buffalo_l"
FACE_PREVIEW_SIZE = (480, 360)

# 声纹识别常量
VOICE_SAMPLE_RATE = 16000
VOICE_DURATION = 3
VOICE_SIM_THRESHOLD = 0.72
# 如果你有本地ecapa.onnx模型，填写路径；若无，代码预留接口，后续自行导出ECAPA-TDNN
VOICE_ONNX_MODEL_PATH = "ecapa.onnx"


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

        tk.Label(self, text="Bomb防破密专家努力加载中...", bg="#f0f0f0", font=("微软雅黑", 12)).pack(pady=20)
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


# ====================== 声纹认证模块 ======================
class VoiceAuthManager:
    _instance = None
    _sess = None
    model_ready = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load_model(self):
        if self._sess is not None:
            return True
        if not os.path.exists(VOICE_ONNX_MODEL_PATH):
            raise FileNotFoundError(f"声纹模型文件不存在：{VOICE_ONNX_MODEL_PATH}\n请放置ecapa.onnx到程序目录")
        try:
            providers = ort.get_available_providers()
            if "DmlExecutionProvider" in providers:
                self._sess = ort.InferenceSession(VOICE_ONNX_MODEL_PATH, providers=["DmlExecutionProvider"])
            else:
                self._sess = ort.InferenceSession(VOICE_ONNX_MODEL_PATH, providers=["CPUExecutionProvider"])
            self.model_ready = True
            return True
        except Exception as e:
            raise Exception(f"声纹模型加载失败：{str(e)}")

    def record_voice(self, save_path):
        """录音保存wav"""
        audio_data = sd.rec(int(VOICE_DURATION * VOICE_SAMPLE_RATE), samplerate=VOICE_SAMPLE_RATE, channels=1,
                            dtype="float32")
        sd.wait()
        sf.write(save_path, audio_data, VOICE_SAMPLE_RATE)
        return save_path

    def extract_embedding(self, wav_path):
        if not self.model_ready:
            raise Exception("声纹模型未加载")
        wav, sr = librosa.load(wav_path, sr=VOICE_SAMPLE_RATE)
        wav = np.expand_dims(wav, axis=0).astype(np.float32)
        input_name = self._sess.get_inputs()[0].name
        emb = self._sess.run(None, {input_name: wav})[0][0]
        return emb

    @staticmethod
    def sim(emb1, emb2):
        return np.dot(emb1, emb2) / (np.linalg.norm(emb1) * np.linalg.norm(emb2))


class VoiceAuthDialog(tk.Toplevel):
    """声纹采集/验证窗口"""

    def __init__(self, parent, mode="collect", ref_emb=None):
        super().__init__(parent)
        self.title("声纹验证")
        self.geometry("420x300")
        self.parent = parent
        self.mode = mode
        self.ref_emb = ref_emb
        self.result = None
        self.verified = False
        self.configure(bg="#e0e0e0")
        self.attributes('-alpha', 0.9)
        self.attributes('-topmost', True)
        self.transient(parent)
        self.grab_set()
        self.update_idletasks()
        x = (parent.winfo_screenwidth() // 2) - 210
        y = (parent.winfo_screenheight() // 2) - 150
        self.geometry(f"420x300+{x}+{y}")
        self.setup_ui()

    def setup_ui(self):
        tip = "请朗读屏幕文字，点击开始录音（采集，共3次）" if self.mode == "collect" else "朗读文字，完成声纹验证"
        tk.Label(self, text=tip, font=("微软雅黑", 11), bg="#e0e0e0").pack(pady=12)
        tk.Label(self, text="示例朗读：欢迎使用加密系统", font=("微软雅黑", 10, "bold"), bg="#e0e0e0",
                 fg="#222222").pack(pady=4)
        self.status_label = tk.Label(self, text="就绪", font=("微软雅黑", 10), bg="#e0e0e0")
        self.status_label.pack(pady=8)
        self.emb_list = []
        self.rec_count = 0

        btn_frame = tk.Frame(self, bg="#e0e0e0")
        btn_frame.pack(pady=20)
        self.rec_btn = tk.Button(btn_frame, text="开始录音", command=self.on_record, bg="#44dd00", fg="white", width=12)
        self.rec_btn.pack(side=tk.LEFT, padx=8)
        tk.Button(btn_frame, text="取消", command=self.cancel, bg="#ff4444", fg="white", width=10).pack(side=tk.LEFT,
                                                                                                        padx=8)

    def on_record(self):
        vm = VoiceAuthManager()
        try:
            self.status_label.config(text="录音中...请朗读！")
            self.update()
            tmp_wav = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
            tmp_path = tmp_wav.name
            tmp_wav.close()
            vm.record_voice(tmp_path)
            emb = vm.extract_embedding(tmp_path)
            os.unlink(tmp_path)
        except Exception as e:
            messagebox.showerror("录音失败", str(e), parent=self)
            self.status_label.config(text="录音失败")
            return

        if self.mode == "collect":
            self.emb_list.append(emb)
            self.rec_count += 1
            self.status_label.config(text=f"采集成功 {self.rec_count}/3")
            if self.rec_count >= 3:
                self.rec_btn.config(text="确认保存", command=self.confirm_collect)
        else:
            sims = [vm.sim(emb, e) for e in self.ref_emb]
            avg = np.mean(sims)
            self.verified = avg >= VOICE_SIM_THRESHOLD
            if self.verified:
                self.status_label.config(text=f"✅验证通过 相似度{avg:.3f}", fg="green")
                self.after(1000, self.confirm_verify)
            else:
                self.status_label.config(text=f"❌验证失败 相似度{avg:.3f}", fg="red")

    def confirm_collect(self):
        self.result = {
            "version": "1.0",
            "embeddings": [e.tolist() for e in self.emb_list],
            "threshold": VOICE_SIM_THRESHOLD
        }
        self.destroy()

    def confirm_verify(self):
        self.result = self.verified
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()

    def show(self):
        self.wait_window()
        return self.result, self.verified


# ====================== 主程序 ======================
class BombCryptoTool(tkinterdnd2.Tk):
    """主程序类（Bomb防破密专家核心类）"""

    def __init__(self):
        super().__init__()
        self.title("Bomb 防破密专家 v14.3.2")
        self.geometry("1370x770")
        self.configure(bg="#f0f0f0")
        self.attributes('-alpha', 0.97)
        # 居中显示
        self.center_window()

        # 状态变量
        self.current_mode = "main"
        self.selected_path = None
        # 【重点】扩展全部组合模式
        self.encryption_mode = tk.StringVar(value="aes_only")

        # 显示加载窗口
        self.show_loading()

        # 设置主界面
        self.setup_main_ui()

        # 绑定关闭事件
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def show_about(self):
        """显示关于信息弹窗【更新文案，加入声纹】"""
        about_content = """名称：Bomb防破密专家

版本：v14.3.2

特点：
        使用世界级加密算法AES-GCM-256
        利用scipy进行密钥派生
        支持多重身份组合验证：十六宫格、人脸、声纹自由搭配
        全程本地运算，不上传云端
        ——安全无忧

        界面简洁、功能丰富
        操作方法一目了然
        ——使用方便

        占用空间可控
        电脑硬盘轻负担
        ——轻量化设计

        运行稳定不卡顿

支持所有组合（基础AES）
AES｜AES+宫格｜AES+人脸｜AES+声纹
AES+宫格+人脸｜AES+宫格+声纹｜AES+人脸+声纹
AES+宫格+人脸+声纹

2025 Bomb加密技术团队™

⚠️本产品仅供学习交流使用，
        请勿用于商业用途"""
        messagebox.showinfo("关于 Bomb 防破密专家", about_content)

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
        title_label = tk.Label(self, text="Bomb 防破密专家 v14.3.2", font=("微软雅黑", 16, "bold"), bg="#f0f0f0")
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

    # ====================== 功能界面（更新单选框，全部组合） ======================
    def show_file_encrypt_ui(self):
        """文件加密界面"""
        self.current_mode = "file"
        for widget in self.winfo_children():
            widget.destroy()
        self.show_back_button(self)
        tk.Label(self, text="文件加密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0").pack(pady=10)
        main_frame = tk.Frame(self, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        left_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)
        left_frame.pack_propagate(False)
        tk.Label(left_frame, text="选择文件", font=("微软雅黑", 12), bg="white").pack(pady=10)
        self.file_path_var = tk.StringVar(value=self.selected_path or "未选择文件")
        path_label = tk.Label(left_frame, textvariable=self.file_path_var, bg="white", font=("微软雅黑", 10),
                              wraplength=450, fg="#666666")
        path_label.pack(pady=5, padx=10)
        tk.Button(left_frame, text="浏览文件", command=self.select_file, bg="#999999", fg="white", relief=tk.FLAT).pack(
            pady=10)

        mode_frame = tk.Frame(left_frame, bg="white")
        mode_frame.pack(fill=tk.X, padx=10, pady=20)
        tk.Label(mode_frame, text="加密模式：", bg="white", font=("微软雅黑", 10)).grid(row=0, column=0, sticky="w")
        mode_list = [
            ("仅AES", "aes_only"),
            ("AES+宫格", "aes_grid"),
            ("AES+人脸", "aes_face"),
            ("AES+声纹", "aes_voice"),
            ("AES+宫格+人脸", "aes_grid_face"),
            ("AES+宫格+声纹", "aes_grid_voice"),
            ("AES+人脸+声纹", "aes_face_voice"),
            ("AES+宫格+人脸+声纹", "aes_grid_face_voice")
        ]
        r = 1
        col = 0
        for txt, val in mode_list:
            tk.Radiobutton(mode_frame, text=txt, variable=self.encryption_mode, value=val, bg="white").grid(row=r,
                                                                                                            column=col,
                                                                                                            sticky="w")
            col += 1
            if col >= 2:
                col = 0
                r += 1

        right_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10)
        right_frame.pack_propagate(False)
        tk.Label(right_frame, text="保存设置", font=("微软雅黑", 12), bg="white").pack(pady=10)
        self.save_path_var = tk.StringVar(value="")
        tk.Label(right_frame, text="保存路径：", bg="white", font=("微软雅黑", 10)).pack(anchor=tk.W, padx=10)
        tk.Entry(right_frame, textvariable=self.save_path_var, bg="#f5f5f5", relief=tk.FLAT).pack(fill=tk.X, padx=10,
                                                                                                  pady=5)
        tk.Button(right_frame, text="选择保存位置", command=self.select_file_save_path, bg="#999999", fg="white").pack(
            pady=5)
        tk.Button(right_frame, text="开始加密", command=self.start_file_encryption, bg="#44dd00", fg="white",
                  font=("微软雅黑", 12)).pack(side=tk.BOTTOM, pady=20, ipady=5)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=10)
        style = ttk.Style()
        style.configure("grey.Horizontal.TProgressbar", troughcolor='#e0e0e0', background='#44dd00')
        self.progress_bar.config(style="grey.Horizontal.TProgressbar")
        self.enable_drag_and_drop()
        self.status_bar = tk.Label(self, text="文件加密界面 | 支持拖拽文件到此处", bg="#f0f0f0", anchor=tk.W,
                                   font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)

        def show_folder_encrypt_ui(self):
            # 清空当前主面板
            self.clear_main_panel()

            # 标题
            title_label = tk.Label(self.main_panel, text="文件夹加密", font=("Microsoft YaHei", 16, "bold"))
            title_label.pack(pady=15)

            # 文件夹选择区域
            frame_path = tk.Frame(self.main_panel)
            frame_path.pack(pady=8, fill=tk.X, padx=30)

            tk.Label(frame_path, text="目标文件夹：").pack(side=tk.LEFT)
            self.folder_path_var = tk.StringVar()
            entry_folder = tk.Entry(frame_path, textvariable=self.folder_path_var, width=45)
            entry_folder.pack(side=tk.LEFT, padx=8, expand=True, fill=tk.X)

            btn_select_folder = tk.Button(frame_path, text="浏览", command=self.select_target_folder)
            btn_select_folder.pack(side=tk.LEFT)

            # 密码输入区域
            frame_pwd = tk.Frame(self.main_panel)
            frame_pwd.pack(pady=8, fill=tk.X, padx=30)
            tk.Label(frame_pwd, text="加密密码：").pack(side=tk.LEFT)
            self.folder_pwd_var = tk.StringVar()
            entry_pwd = tk.Entry(frame_pwd, textvariable=self.folder_pwd_var, show="*", width=45)
            entry_pwd.pack(side=tk.LEFT, padx=8, expand=True, fill=tk.X)

            # 确认密码
            frame_pwd2 = tk.Frame(self.main_panel)
            frame_pwd2.pack(pady=8, fill=tk.X, padx=30)
            tk.Label(frame_pwd2, text="确认密码：").pack(side=tk.LEFT)
            self.folder_pwd2_var = tk.StringVar()
            entry_pwd2 = tk.Entry(frame_pwd2, textvariable=self.folder_pwd2_var, show="*", width=45)
            entry_pwd2.pack(side=tk.LEFT, padx=8, expand=True, fill=tk.X)

            # 加密模式选项
            frame_mode = tk.Frame(self.main_panel)
            frame_mode.pack(pady=10, padx=30, anchor="w")
            self.folder_mode_var = tk.StringVar(value="archive")
            tk.Radiobutton(frame_mode, text="打包加密(生成加密包)", variable=self.folder_mode_var,
                           value="archive").pack(side=tk.LEFT, padx=5)
            tk.Radiobutton(frame_mode, text="原地文件加密(直接加密内部文件)", variable=self.folder_mode_var,
                           value="inline").pack(side=tk.LEFT, padx=15)

            # 进度条
            self.folder_progress_var = tk.DoubleVar()
            progress_bar = tk.ttk.Progressbar(self.main_panel, variable=self.folder_progress_var, maximum=100)
            progress_bar.pack(pady=12, fill=tk.X, padx=30)

            # 状态文本
            self.folder_status_var = tk.StringVar(value="就绪")
            status_label = tk.Label(self.main_panel, textvariable=self.folder_status_var)
            status_label.pack(pady=4)

            # 功能按钮区
            frame_btn = tk.Frame(self.main_panel)
            frame_btn.pack(pady=15)
            btn_start_encrypt = tk.Button(frame_btn, text="开始加密", width=12, command=self.start_folder_encrypt)
            btn_start_encrypt.pack(side=tk.LEFT, padx=10)
            btn_back = tk.Button(frame_btn, text="返回主页", width=12, command=self.show_home_ui)
            btn_back.pack(side=tk.LEFT, padx=10)

        def select_target_folder(self):
            folder = filedialog.askdirectory(title="选择需要加密的文件夹")
            if folder:
                self.folder_path_var.set(folder)

        def start_folder_encrypt(self):
            folder_path = self.folder_path_var.get().strip()
            pwd1 = self.folder_pwd_var.get()
            pwd2 = self.folder_pwd2_var.get()
            mode = self.folder_mode_var.get()

            if not folder_path:
                messagebox.showwarning("提示", "请先选择目标文件夹！")
                return
            if not pwd1:
                messagebox.showwarning("提示", "请输入加密密码！")
                return
            if pwd1 != pwd2:
                messagebox.showerror("错误", "两次输入的密码不一致！")
                return

            # 后台线程执行加密，防止界面卡死
            threading.Thread(target=self._folder_encrypt_task, args=(folder_path, pwd1, mode), daemon=True).start()

        def _folder_encrypt_task(self, folder_path, password, mode):
            try:
                self.folder_status_var.set("正在处理文件夹...")
                self.folder_progress_var.set(0)
                # ======================
                # 此处接入你的文件夹加密逻辑
                # ======================
                self.folder_progress_var.set(100)
                self.folder_status_var.set("文件夹加密完成！")
                messagebox.showinfo("完成", "文件夹加密操作执行完毕！")
            except Exception as e:
                self.folder_status_var.set("加密失败")
                messagebox.showerror("加密出错", f"错误信息：{str(e)}")

        def show_folder_decrypt_ui(self):
            self.clear_main_panel()

            title_label = tk.Label(self.main_panel, text="文件夹解密", font=("Microsoft YaHei", 16, "bold"))
            title_label.pack(pady=15)

            frame_path = tk.Frame(self.main_panel)
            frame_path.pack(pady=8, fill=tk.X, padx=30)
            tk.Label(frame_path, text="加密目录/加密包：").pack(side=tk.LEFT)
            self.decrypt_folder_path_var = tk.StringVar()
            entry_path = tk.Entry(frame_path, textvariable=self.decrypt_folder_path_var, width=45)
            entry_path.pack(side=tk.LEFT, padx=8, expand=True, fill=tk.X)
            btn_select = tk.Button(frame_path, text="浏览", command=self.select_decrypt_path)
            btn_select.pack(side=tk.LEFT)

            frame_pwd = tk.Frame(self.main_panel)
            frame_pwd.pack(pady=8, fill=tk.X, padx=30)
            tk.Label(frame_pwd, text="解密密码：").pack(side=tk.LEFT)
            self.decrypt_pwd_var = tk.StringVar()
            entry_pwd = tk.Entry(frame_pwd, textvariable=self.decrypt_pwd_var, show="*", width=45)
            entry_pwd.pack(side=tk.LEFT, padx=8, expand=True, fill=tk.X)

            self.decrypt_progress_var = tk.DoubleVar()
            progress_bar = tk.ttk.Progressbar(self.main_panel, variable=self.decrypt_progress_var, maximum=100)
            progress_bar.pack(pady=12, fill=tk.X, padx=30)

            self.decrypt_status_var = tk.StringVar(value="就绪")
            status_label = tk.Label(self.main_panel, textvariable=self.decrypt_status_var)
            status_label.pack(pady=4)

            frame_btn = tk.Frame(self.main_panel)
            frame_btn.pack(pady=15)
            btn_decrypt = tk.Button(frame_btn, text="开始解密", width=12, command=self.start_folder_decrypt)
            btn_decrypt.pack(side=tk.LEFT, padx=10)
            btn_back = tk.Button(frame_btn, text="返回主页", width=12, command=self.show_home_ui)
            btn_back.pack(side=tk.LEFT, padx=10)

        def select_decrypt_path(self):
            path = filedialog.askdirectory(title="选择加密文件夹")
            if path:
                self.decrypt_folder_path_var.set(path)

        def start_folder_decrypt(self):
            target_path = self.decrypt_folder_path_var.get().strip()
            password = self.decrypt_pwd_var.get()
            if not target_path:
                messagebox.showwarning("提示", "请选择加密文件夹！")
                return
            if not password:
                messagebox.showwarning("提示", "请输入解密密码！")
                return
            threading.Thread(target=self._folder_decrypt_task, args=(target_path, password), daemon=True).start()

        def _folder_decrypt_task(self, target_path, password):
            try:
                self.decrypt_status_var.set("正在解密...")
                self.decrypt_progress_var.set(0)
                # ======================
                # 接入你的解密逻辑
                # ======================
                self.decrypt_progress_var.set(100)
                self.decrypt_status_var.set("解密完成！")
                messagebox.showinfo("完成", "文件夹解密成功！")
            except Exception as e:
                self.decrypt_status_var.set("解密失败")
                messagebox.showerror("解密错误", str(e))

        def clear_main_panel(self):
            # 清空主面板所有组件
            for widget in self.main_panel.winfo_children():
                widget.destroy()

        def show_home_ui(self):
            self.clear_main_panel()
            title = tk.Label(self.main_panel, text="加密工具箱", font=("Microsoft YaHei", 20, "bold"))
            title.pack(pady=30)

            frame_btn = tk.Frame(self.main_panel)
            frame_btn.pack()

            btn_file_enc = tk.Button(frame_btn, text="文件加密", width=15, height=2, command=self.show_file_encrypt_ui)
            btn_file_enc.grid(row=0, column=0, padx=12, pady=10)

            btn_folder_enc = tk.Button(frame_btn, text="文件夹加密", width=15, height=2,
                                       command=self.show_folder_encrypt_ui)
            btn_folder_enc.grid(row=0, column=1, padx=12, pady=10)

            btn_folder_dec = tk.Button(frame_btn, text="文件夹解密", width=15, height=2,
                                       command=self.show_folder_decrypt_ui)
            btn_folder_dec.grid(row=1, column=0, padx=12, pady=10)

            btn_settings = tk.Button(frame_btn, text="软件设置", width=15, height=2, command=self.show_settings_ui)
            btn_settings.grid(row=1, column=1, padx=12, pady=10)

        def show_settings_ui(self):
            self.clear_main_panel()
            title = tk.Label(self.main_panel, text="软件设置", font=("Microsoft YaHei", 16, "bold"))
            title.pack(pady=15)

            # 示例设置项，自行扩展
            frame = tk.Frame(self.main_panel)
            frame.pack(pady=10)
            tk.Label(frame, text="加密算法配置、缓存、日志路径等设置区域").pack()

            btn_back = tk.Button(self.main_panel, text="返回主页", command=self.show_home_ui)
            btn_back.pack(pady=20)

    if __name__ == "__main__":
        root = tk.Tk()
        app = EncryptToolApp(root)
        root.mainloop()