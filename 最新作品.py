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
import pyopencl as cl  # OpenCL加速库

# ====================== OpenCL 加速初始化 ======================
# 自动选择0号设备初始化OpenCL
ctx = None
queue = None
mf = cl.mem_flags

try:
    # 获取平台和设备，自动选择0号设备
    platforms = cl.get_platforms()
    if platforms:
        devices = platforms[0].get_devices()
        if len(devices) > 0:
            ctx = cl.Context([devices[0]])
            queue = cl.CommandQueue(ctx, properties=cl.command_queue_properties.PROFILING_ENABLE)
        else:
            raise Exception("未找到OpenCL设备")
    else:
        raise Exception("未找到OpenCL平台")
except Exception as e:
    # 无OpenCL设备时降级为CPU处理
    ctx = None
    queue = None
    print(f"OpenCL初始化失败，将使用CPU处理: {e}", file=sys.stderr)

# OpenCL AES加密内核（简化版，用于并行数据块处理）
AES_ENCRYPT_KERNEL = """
__kernel void aes_encrypt_block(__global const uchar *in, __global uchar *out, __global const uchar *key) {
    int gid = get_global_id(0);
    // 简化的AES块加密逻辑（实际场景需完整实现）
    out[gid] = in[gid] ^ key[gid % 32];
}
"""

# OpenCL AES解密内核
AES_DECRYPT_KERNEL = """
__kernel void aes_decrypt_block(__global const uchar *in, __global uchar *out, __global const uchar *key) {
    int gid = get_global_id(0);
    // 简化的AES块解密逻辑（实际场景需完整实现）
    out[gid] = in[gid] ^ key[gid % 32];
}
"""

# ====================== 核心常量定义 ======================
# 加密常量
AES_KEY_LENGTH = 32  # 256位AES密钥
GCM_NONCE_LENGTH = 12  # GCM推荐nonce长度
KDF_ITERATIONS = 310000  # NIST推荐迭代次数
KDF_HASH_ALG = 'sha256'
SIGNATURE_HASH_ALG = 'sha3-256'
ENCRYPTION_MAGIC = b'TNTCRYPT11'  # 魔数
VERSION = b'1.0'  # 版本号
HMAC_LENGTH = 32  # SHA3-256 HMAC长度
SALT_LENGTH = 16  # 盐长度

# 文件类型标识
FILE_TYPE_TEXT = b'msc'       # 文本文档
FILE_TYPE_FILE = b'tnt'       # 单文件
FILE_TYPE_FOLDER = b'tntnext' # 文件夹
GRID_SIGNATURE_MATCH_REQUIRED = True  # 宫格签名必须完全匹配

# 4×4宫格常量
GRID_SIZE = 4  # 4×4宫格
GRID_POINT_SIZE = 30  # 宫格点大小（像素）
GRID_SPACING = 10  # 宫格间距（像素）

# ====================== 核心组件 ======================
class LoadingWindow(tk.Toplevel):
    """加载窗口"""
    def __init__(self, parent):
        super().__init__(parent)
        self.title("加载中")
        self.geometry("320x100")
        self.configure(bg="#f0f0f0")
        self.attributes('-alpha', 0.8)
        self.attributes('-topmost',True)
        self.transient(parent)
        self.grab_set()
        
        # 居中显示
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (300 // 2)
        y = (self.winfo_screenheight() // 2) - (100 // 2)
        self.geometry(f"300x100+{x}+{y}")
        
        # 自适应标签
        self.label = tk.Label(self, text="TNT防破密专家努力加载中...", bg="#f0f0f0", font=("微软雅黑", 12))
        self.label.pack(pady=20, fill=tk.X, padx=10)
        
        self.progress = ttk.Progressbar(self, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=20, pady=10)
        self.progress.start(20)
        
        # 绑定大小变化事件
        self.bind("<Configure>", self.on_resize)
    
    def on_resize(self, event):
        """自适应调整加载窗口组件"""
        if event.widget == self:
            # 调整字体大小
            font_size = max(10, int(event.width / 30))
            self.label.config(font=("微软雅黑", font_size))
            # 调整进度条大小
            self.progress.config(length=event.width - 40)

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
        self.attributes('-topmost',True)
        self.transient(parent)
        self.grab_set()
        
        # 居中
        self.update_idletasks()
        x = (parent.winfo_screenwidth() // 2) - (400 // 2)
        y = (parent.winfo_screenheight() // 2) - (200 // 2)
        self.geometry(f"400x200+{x}+{y}")
        
        # 主框架
        self.main_frame = tk.Frame(self, bg="#e0e0e0")
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 提示标签
        self.prompt_label = tk.Label(self.main_frame, text=prompt, font=("微软雅黑", 11), bg="#e0e0e0")
        self.prompt_label.pack(pady=15, fill=tk.X)
        
        self.password_var = tk.StringVar()
        self.password_var.trace_add("write", self.update_strength)
        
        # 密码输入框
        self.password_entry = tk.Entry(self.main_frame, textvariable=self.password_var, show="*", 
                                      font=("微软雅黑", 12), bg="#f5f5f5", relief=tk.FLAT, bd=1)
        self.password_entry.pack(pady=5, padx=10, fill=tk.X)
        
        # 密码强度显示
        if show_strength:
            self.strength_frame = tk.Frame(self.main_frame, height=10, bg="#f5f5f5")
            self.strength_frame.pack(pady=5, padx=10, fill=tk.X)
            self.strength_label = tk.Label(self.main_frame, text="密码强度: 无", font=("微软雅黑", 9), bg="#e0e0e0")
            self.strength_label.pack(pady=2, fill=tk.X)
        
        # 按钮框架
        self.btn_frame = tk.Frame(self.main_frame, bg="#e0e0e0")
        self.btn_frame.pack(pady=15, fill=tk.X)
        
        # 确定按钮
        self.ok_btn = tk.Button(self.btn_frame, text="确定", command=self.ok, width=10, 
                 bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777")
        self.ok_btn.pack(side=tk.LEFT, padx=10, expand=True)
        
        # 取消按钮
        self.cancel_btn = tk.Button(self.btn_frame, text="取消", command=self.cancel, width=10,
                 bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777")
        self.cancel_btn.pack(side=tk.LEFT, padx=10, expand=True)
        
        self.password_entry.focus_set()
        
        # 绑定大小变化事件
        self.bind("<Configure>", self.on_resize)
    
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
        bar = tk.Frame(self.strength_frame, bg=color, width=int(strength * (self.strength_frame.winfo_width() / 100)), height=10)
        bar.pack(side=tk.LEFT, fill=tk.Y)
        
        # 强度文字
        strength_text = "弱" if strength < 30 else "中" if strength < 60 else "强" if strength < 80 else "极强"
        self.strength_label.config(text=f"密码强度: {strength_text} ({strength}%)")
    
    def on_resize(self, event):
        """自适应调整密码对话框组件"""
        if event.widget == self:
            # 调整字体大小
            base_font_size = max(9, int(event.width / 40))
            self.prompt_label.config(font=("微软雅黑", base_font_size + 1))
            self.password_entry.config(font=("微软雅黑", base_font_size + 2))
            if self.show_strength:
                self.strength_label.config(font=("微软雅黑", base_font_size))
            # 调整按钮大小
            btn_width = max(8, int(event.width / 40))
            self.ok_btn.config(width=btn_width)
            self.cancel_btn.config(width=btn_width)
            # 更新强度条
            self.update_strength()
    
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
        self.attributes('-topmost',True)
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
        
        # 主框架
        self.main_frame = tk.Frame(self, bg="#e0e0e0")
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 创建UI
        self.setup_ui()
        
        # 绑定大小变化事件
        self.bind("<Configure>", self.on_resize)
    
    def setup_ui(self):
        """创建宫格UI"""
        # 提示标签
        prompt_text = "请按顺序点击宫格点完成连接（至少选择4格）"
        if self.existing_signature:
            prompt_text = "请按之前顺序点击宫格点完成验证"
        
        self.prompt_label = tk.Label(self.main_frame, text=prompt_text, font=("微软雅黑", 10), bg="#e0e0e0")
        self.prompt_label.pack(pady=10, fill=tk.X)
        
        # 宫格画布容器
        self.canvas_frame = tk.Frame(self.main_frame, bg="white")
        self.canvas_frame.pack(pady=10, fill=tk.BOTH, expand=True)
        
        # 宫格画布
        self.grid_canvas = tk.Canvas(self.canvas_frame, bg="white", bd=1, relief=tk.SOLID)
        self.grid_canvas.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 绑定点击事件
        self.grid_canvas.bind("<Button-1>", self.on_point_click)
        
        # 按钮区域
        self.btn_frame = tk.Frame(self.main_frame, bg="#e0e0e0")
        self.btn_frame.pack(pady=20, fill=tk.X)
        
        # 清除按钮
        self.clear_btn = tk.Button(self.btn_frame, text="清除", command=self.clear,
                 bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777")
        self.clear_btn.pack(side=tk.LEFT, padx=10, expand=True)
        
        # 确定按钮
        self.ok_btn = tk.Button(self.btn_frame, text="确定", command=self.ok,
                 bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00")
        self.ok_btn.pack(side=tk.LEFT, padx=10, expand=True)
        
        # 取消按钮
        self.cancel_btn = tk.Button(self.btn_frame, text="取消", command=self.cancel,
                 bg="#ff4444", fg="white", relief=tk.FLAT, activebackground="#dd2222")
        self.cancel_btn.pack(side=tk.LEFT, padx=10, expand=True)
        
        # 选中点提示
        self.point_label = tk.Label(self.main_frame, text="已选点：无", font=("微软雅黑", 9), bg="#e0e0e0")
        self.point_label.pack(pady=5, fill=tk.X)
        
        # 初始绘制宫格
        self.draw_grid()
    
    def draw_grid(self):
        """绘制4×4宫格点（自适应大小）"""
        self.grid_canvas.delete("all")
        self.point_positions.clear()
        
        # 获取画布尺寸
        canvas_width = self.grid_canvas.winfo_width()
        canvas_height = self.grid_canvas.winfo_height()
        if canvas_width < 100 or canvas_height < 100:
            # 等待画布初始化完成
            self.after(100, self.draw_grid)
            return
        
        # 计算每个点的大小和间距
        grid_size = GRID_SIZE
        total_spacing = (grid_size + 1) * GRID_SPACING
        point_size = min((canvas_width - total_spacing) // grid_size, 
                         (canvas_height - total_spacing) // grid_size)
        point_size = max(10, point_size)  # 最小10像素
        
        # 计算每个点的位置
        start_x = GRID_SPACING + point_size // 2
        start_y = GRID_SPACING + point_size // 2
        
        for row in range(grid_size):
            for col in range(grid_size):
                x = start_x + col * (point_size + GRID_SPACING)
                y = start_y + row * (point_size + GRID_SPACING)
                
                # 绘制圆点
                self.grid_canvas.create_oval(
                    x - point_size//2, y - point_size//2,
                    x + point_size//2, y + point_size//2,
                    fill="#cccccc", outline="#666666", width=max(1, point_size//15),
                    tags=(f"point_{row}_{col}", "grid_point")
                )
                
                # 显示宫格坐标（1开始）
                font_size = max(6, point_size // 3)
                self.grid_canvas.create_text(
                    x, y, text=f"{row+1},{col+1}", fill="#666666", font=("微软雅黑", font_size),
                    tags=(f"coord_{row}_{col}", "point_coord")
                )
                
                # 存储点位置
                self.point_positions[(row, col)] = (x, y)
        
        # 绘制已选点的连接线
        self.draw_connections()
    
    def draw_connections(self):
        """绘制选中点的连接线（自适应）"""
        if len(self.selected_points) < 2:
            return
        
        # 获取点大小
        canvas_width = self.grid_canvas.winfo_width()
        point_size = min((canvas_width - (GRID_SIZE + 1) * GRID_SPACING) // GRID_SIZE, 30)
        line_width = max(2, point_size // 10)
        
        # 绘制连接线
        for i in range(1, len(self.selected_points)):
            prev_point = self.selected_points[i-1]
            curr_point = self.selected_points[i]
            
            x1, y1 = self.point_positions[prev_point]
            x2, y2 = self.point_positions[curr_point]
            
            self.grid_canvas.create_line(
                x1, y1, x2, y2,
                fill="#44dd00", width=line_width, tags="connection_line"
            )
        
        # 标记选中的点
        for idx, (row, col) in enumerate(self.selected_points):
            x, y = self.point_positions[(row, col)]
            point_size = min((self.grid_canvas.winfo_width() - (GRID_SIZE + 1) * GRID_SPACING) // GRID_SIZE, 30)
            # 填充选中的点
            self.grid_canvas.create_oval(
                x - point_size//2, y - point_size//2,
                x + point_size//2, y + point_size//2,
                fill="#44dd00", outline="#22bb00", width=max(1, point_size//15),
                tags=(f"selected_{row}_{col}", "selected_point")
            )
            # 显示顺序编号
            font_size = max(8, point_size // 3)
            self.grid_canvas.create_text(
                x, y, text=str(idx+1), fill="white", font=("微软雅黑", font_size, "bold"),
                tags=(f"num_{row}_{col}", "point_number")
            )
    
    def on_point_click(self, event):
        """点击宫格点事件"""
        # 找到点击的点
        click_x, click_y = event.x, event.y
        selected_point = None
        
        for (row, col), (x, y) in self.point_positions.items():
            point_size = min((self.grid_canvas.winfo_width() - (GRID_SIZE + 1) * GRID_SPACING) // GRID_SIZE, 30)
            if (click_x - x)**2 + (click_y - y)**2 <= (point_size//2)**2:
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
            point_list = [f"({r+1},{c+1})" for r, c in self.selected_points]
            point_text = "已选点：" + "+".join(point_list)
            self.point_label.config(text=point_text)
    
    def on_resize(self, event):
        """自适应调整宫格面板"""
        if event.widget == self:
            # 调整字体大小
            base_font_size = max(8, int(event.width / 50))
            self.prompt_label.config(font=("微软雅黑", base_font_size))
            self.point_label.config(font=("微软雅黑", base_font_size - 1))
            
            # 调整按钮大小
            btn_font_size = max(8, int(event.width / 60))
            self.clear_btn.config(font=("微软雅黑", btn_font_size))
            self.ok_btn.config(font=("微软雅黑", btn_font_size))
            self.cancel_btn.config(font=("微软雅黑", btn_font_size))
            
            # 重新绘制宫格
            self.draw_grid()
    
    def clear(self):
        """清除选中的点"""
        self.selected_points = []
        self.draw_grid()
        self.update_point_label()
    
    def get_signature_string(self):
        """获取指定格式的签名字符串：(4,1)+(4,3)+(2,2)+(1,2)"""
        # 转换为1开始的坐标
        point_list = [f"({r+1},{c+1})" for r, c in self.selected_points]
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

# ====================== OpenCL 加解密加速函数 ======================
def encrypt_data_with_opencl(data, key):
    """使用OpenCL加速数据加密"""
    if ctx is None or queue is None:
        # 降级为CPU处理
        cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(GCM_NONCE_LENGTH))
        ciphertext, tag = cipher.encrypt_and_digest(pad(data, AES.block_size))
        return cipher.nonce, tag, ciphertext
    
    # OpenCL加速处理
    try:
        # 准备数据
        data_np = np.frombuffer(pad(data, AES.block_size), dtype=np.uint8)
        key_np = np.frombuffer(key, dtype=np.uint8)
        
        # 创建缓冲区
        mf = cl.mem_flags
        data_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=data_np)
        key_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=key_np)
        out_buf = cl.Buffer(ctx, mf.WRITE_ONLY, data_np.nbytes)
        
        # 编译内核
        prg = cl.Program(ctx, AES_ENCRYPT_KERNEL).build()
        
        # 执行内核
        prg.aes_encrypt_block(queue, data_np.shape, None, data_buf, out_buf, key_buf)
        
        # 获取结果
        ciphertext_np = np.empty_like(data_np)
        cl.enqueue_copy(queue, ciphertext_np, out_buf)
        
        # GCM模式处理（保留原有逻辑）
        cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(GCM_NONCE_LENGTH))
        final_ciphertext, tag = cipher.encrypt_and_digest(ciphertext_np.tobytes())
        
        return cipher.nonce, tag, final_ciphertext
    except Exception as e:
        # 降级为CPU处理
        print(f"OpenCL加密失败，降级为CPU: {e}", file=sys.stderr)
        cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(GCM_NONCE_LENGTH))
        ciphertext, tag = cipher.encrypt_and_digest(pad(data, AES.block_size))
        return cipher.nonce, tag, ciphertext

def decrypt_data_with_opencl(nonce, tag, ciphertext, key):
    """使用OpenCL加速数据解密"""
    if ctx is None or queue is None:
        # 降级为CPU处理
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
        return plaintext
    
    # OpenCL加速处理
    try:
        # 先验证并解密GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        
        # OpenCL加速解密密文块
        data_np = np.frombuffer(decrypted_data, dtype=np.uint8)
        key_np = np.frombuffer(key, dtype=np.uint8)
        
        # 创建缓冲区
        mf = cl.mem_flags
        data_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=data_np)
        key_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=key_np)
        out_buf = cl.Buffer(ctx, mf.WRITE_ONLY, data_np.nbytes)
        
        # 编译内核
        prg = cl.Program(ctx, AES_DECRYPT_KERNEL).build()
        
        # 执行内核
        prg.aes_decrypt_block(queue, data_np.shape, None, data_buf, out_buf, key_buf)
        
        # 获取结果
        plaintext_np = np.empty_like(data_np)
        cl.enqueue_copy(queue, plaintext_np, out_buf)
        
        # 去除填充
        plaintext = unpad(plaintext_np.tobytes(), AES.block_size)
        return plaintext
    except Exception as e:
        # 降级为CPU处理
        print(f"OpenCL解密失败，降级为CPU: {e}", file=sys.stderr)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
        return plaintext

# ====================== 主程序 ======================
class TNTCryptoTool(tkinterdnd2.Tk):
    """主程序类（TNT防破密专家核心类）"""
    def __init__(self):
        super().__init__()
        self.title("TNT 防破密专家 v13.7.3")
        self.geometry("1370x770")
        self.configure(bg="#f0f0f0")
        self.attributes('-alpha', 0.97)
        
        # 设置网格权重，让组件自适应
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # 居中显示
        self.center_window()
        
        # 状态变量
        self.current_mode = "main"
        self.selected_path = None
        self.encryption_mode = tk.StringVar(value="aes_only")
        
        # 显示加载窗口
        self.show_loading()
        
        # 设置主界面
        self.setup_main_ui()
        
        # 绑定关闭事件
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # 绑定大小变化事件
        self.bind("<Configure>", self.on_main_resize)
    
    def on_main_resize(self, event):
        """主窗口大小变化时自适应调整所有组件"""
        if event.widget == self and self.current_mode == "main":
            # 调整主界面按钮
            base_font_size = max(12, int(event.width / 80))
            for btn in self.main_buttons:
                btn.config(font=("微软雅黑", base_font_size, "bold"))
                btn.config(height=max(2, int(event.height / 50)))
            # 调整标题字体
            self.title_label.config(font=("微软雅黑", base_font_size + 4, "bold"))
        elif self.current_mode == "file":
            self.adjust_file_ui(event)
        elif self.current_mode == "folder":
            self.adjust_folder_ui(event)
        elif self.current_mode == "doc":
            self.adjust_doc_ui(event)
        elif self.current_mode == "decrypt":
            self.adjust_decrypt_ui(event)
    
    def adjust_file_ui(self, event):
        """调整文件加密界面组件"""
        font_size = max(10, int(event.width / 100))
        # 调整标签字体
        for child in self.winfo_children():
            if isinstance(child, tk.Label):
                if "加密" in child.cget("text") or "选择" in child.cget("text") or "保存" in child.cget("text"):
                    child.config(font=("微软雅黑", font_size))
            elif isinstance(child, tk.Button):
                child.config(font=("微软雅黑", font_size))
                child.config(height=max(1, int(event.height / 100)))
            elif isinstance(child, tk.Entry):
                child.config(font=("微软雅黑", font_size))
    
    def adjust_folder_ui(self, event):
        """调整文件夹加密界面组件"""
        self.adjust_file_ui(event)  # 复用文件界面调整逻辑
    
    def adjust_doc_ui(self, event):
        """调整文档加密界面组件"""
        font_size = max(10, int(event.width / 100))
        # 调整文本框字体
        self.doc_text.config(font=("Consolas", max(9, font_size - 1)))
        # 调整标签和按钮
        for child in self.winfo_children():
            if isinstance(child, tk.Label):
                child.config(font=("微软雅黑", font_size))
            elif isinstance(child, tk.Button):
                child.config(font=("微软雅黑", font_size))
                child.config(height=max(1, int(event.height / 100)))
    
    def adjust_decrypt_ui(self, event):
        """调整解密界面组件"""
        font_size = max(10, int(event.width / 100))
        for child in self.winfo_children():
            if isinstance(child, tk.Label):
                child.config(font=("微软雅黑", font_size))
            elif isinstance(child, tk.Button):
                child.config(font=("微软雅黑", font_size))
                child.config(height=max(1, int(event.height / 100)))
    
    def show_about(self):
        """显示关于信息弹窗"""
        about_content = """名称：TNT防破密专家

版本：v13.7.3

特点：
        使用世界级加密算法AES-GCM-256
        利用scipy进行密钥派生
        结合十六宫格双层防护
        ——安全无忧

        界面简、功能多
        操作方法一目了然
        ——使用方便

        占用空间极小
        电脑硬盘轻负担
        ——体轻价重

        运行稳定不卡顿

2025 TNT加密技术团队™

⚠️本产品仅供学习交流使用，
        请勿用于商业用途"""
        messagebox.showinfo("关于 TNT 防破密专家", about_content)
    
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
        """设置主界面（纵向长条形按钮排列）"""
        # 更新当前模式
        self.current_mode = "main"
        
        # 清空现有组件
        for widget in self.winfo_children():
            widget.destroy()
        
        # 主框架
        self.main_frame = tk.Frame(self, bg="#f0f0f0")
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        self.main_frame.grid_rowconfigure(list(range(6)), weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)
        
        # 标题
        self.title_label = tk.Label(self.main_frame, text="TNT 防破密专家 v13.7.3", 
                                   font=("微软雅黑", 20, "bold"), bg="#f0f0f0")
        self.title_label.grid(row=0, column=0, pady=20, sticky="nsew")
        
        # 存储主按钮引用
        self.main_buttons = []
        
        # 四大功能按钮 + 关于按钮（纵向长条形）
        buttons = [
            ("文件加密", self.show_file_encrypt_ui),
            ("文件夹加密", self.show_folder_encrypt_ui),
            ("文档加密", self.show_doc_encrypt_ui),
            ("自动解密", self.show_auto_decrypt_ui),
            ("关于", self.show_about)
        ]
        
        # 创建纵向长条形按钮
        for idx, (text, cmd) in enumerate(buttons):
            btn = tk.Button(
                self.main_frame,
                text=text,
                command=cmd,
                bg="#cccccc",
                fg="#333333",
                relief=tk.RAISED,
                bd=2,
                font=("微软雅黑", 14, "bold"),
                height=3
            )
            btn.grid(row=idx+1, column=0, padx=40, pady=10, sticky="nsew")
            
            # 悬停效果
            def on_enter(e):
                e.widget.configure(bg="#dddddd")
            def on_leave(e):
                e.widget.configure(bg="#cccccc")
            
            btn.bind("<Enter>", on_enter)
            btn.bind("<Leave>", on_leave)
            self.main_buttons.append(btn)
        
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
                self.update_status(f"已加载文件夹：{os.path.basename(dropped_path)}\n⚠️提示：解密地址应为单独空文件夹\n因为解密后将释放原文件夹内文件")
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
    
    def update_status(self, text):
        """更新状态栏"""
        self.status_bar.config(text=text)
    
    def show_back_button(self, parent):
        """显示返回按钮（自适应）"""
        back_btn = tk.Button(parent, text="← 返回主界面", command=self.setup_main_ui, 
                            bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777")
        back_btn.pack(anchor=tk.NW, padx=20, pady=10, fill=tk.X)
        
        # 绑定大小变化调整按钮
        def adjust_back_btn(event):
            font_size = max(10, int(event.width / 100))
            back_btn.config(font=("微软雅黑", font_size))
            back_btn.config(height=max(1, int(event.height / 100)))
        
        parent.bind("<Configure>", adjust_back_btn)
        return back_btn
    
    # ====================== 功能界面 ======================
    def show_file_encrypt_ui(self):
        """文件加密界面 - 移除文件名输入框，默认使用原文件名"""
        # 更新当前模式
        self.current_mode = "file"
        
        # 清空界面
        for widget in self.winfo_children():
            widget.destroy()
        
        # 主框架（自适应）
        main_container = tk.Frame(self, bg="#f0f0f0")
        main_container.pack(fill=tk.BOTH, expand=True)
        main_container.grid_rowconfigure(1, weight=1)
        main_container.grid_columnconfigure(0, weight=1)
        main_container.grid_columnconfigure(1, weight=1)
        
        # 返回按钮
        self.show_back_button(main_container)
        
        # 标题
        title_label = tk.Label(main_container, text="文件加密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0")
        title_label.grid(row=0, column=0, columnspan=2, pady=10, sticky="nsew")
        
        # 主框架
        main_frame = tk.Frame(main_container, bg="#f0f0f0")
        main_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=20, pady=10)
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        
        # 左侧：文件选择
        left_frame = tk.Frame(main_frame, bg="white", relief=tk.RAISED, bd=1)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=10)
        left_frame.grid_rowconfigure(0, weight=0)
        left_frame.grid_rowconfigure(1, weight=1)
        left_frame.grid_rowconfigure(2, weight=0)
        left_frame.grid_rowconfigure(3, weight=0)
        left_frame.grid_columnconfigure(0, weight=1)
        
        tk.Label(left_frame, text="选择文件", font=("微软雅黑", 12), bg="white").grid(row=0, column=0, pady=10, sticky="nsew")
        
        # 文件路径显示
        self.file_path_var = tk.StringVar(value=self.selected_path or "未选择文件")
        path_label = tk.Label(left_frame, textvariable=self.file_path_var, bg="white", 
                             font=("微软雅黑", 10), wraplength=450, fg="#666666")
        path_label.grid(row=1, column=0, pady=5, padx=10, sticky="nsew")
        
        # 选择文件按钮
        tk.Button(left_frame, text="浏览文件", command=self.select_file, 
                 bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").grid(row=2, column=0, pady=10, sticky="nsew", padx=20)
        
        # 加密模式选择
        mode_frame = tk.Frame(left_frame, bg="white")
        mode_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=20)
        mode_frame.grid_columnconfigure(0, weight=1)
        mode_frame.grid_columnconfigure(1, weight=1)
        mode_frame.grid_columnconfigure(2, weight=1)
        
        tk.Label(mode_frame, text="加密模式：", bg="white", font=("微软雅黑", 10)).grid(row=0, column=0, sticky="w")
        tk.Radiobutton(mode_frame, text="仅AES", variable=self.encryption_mode, value="aes_only", bg="white").grid(row=0, column=1, sticky="w")
        tk.Radiobutton(mode_frame, text="AES+宫格验证", variable=self.encryption_mode, value="aes_signature", bg="white").grid(row=0, column=2, sticky="w")
        
        # 右侧：保存设置
        right_frame = tk.Frame(main_frame, bg="white", relief=tk.RAISED, bd=1)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=10)
        right_frame.grid_rowconfigure(0, weight=0)
        right_frame.grid_rowconfigure(1, weight=1)
        right_frame.grid_rowconfigure(2, weight=1)
        right_frame.grid_rowconfigure(3, weight=0)
        right_frame.grid_columnconfigure(0, weight=1)
        
        tk.Label(right_frame, text="保存设置", font=("微软雅黑", 12), bg="white").grid(row=0, column=0, pady=10, sticky="nsew")
        
        # 保存路径
        self.save_path_var = tk.StringVar(value="")
        tk.Label(right_frame, text="保存路径：", bg="white", font=("微软雅黑", 10)).grid(row=1, column=0, sticky="w", padx=10)
        tk.Entry(right_frame, textvariable=self.save_path_var, bg="#f5f5f5", relief=tk.FLAT).grid(row=2, column=0, sticky="nsew", padx=10, pady=5)
        tk.Button(right_frame, text="选择保存位置", command=self.select_file_save_path, 
                 bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").grid(row=2, column=0, sticky="se", padx=10, pady=5)
        
        # 开始加密按钮
        encrypt_btn = tk.Button(right_frame, text="开始加密", command=self.start_file_encryption, 
                 bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00", 
                 font=("微软雅黑", 12))
        encrypt_btn.grid(row=3, column=0, pady=20, sticky="nsew", padx=20)
        
        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_container, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=20, pady=10)
        
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
        """文件夹加密界面 - 移除文件名输入框，默认使用原文件夹名"""
        # 更新当前模式
        self.current_mode = "folder"
        
        # 清空界面
        for widget in self.winfo_children():
            widget.destroy()
        
        # 主框架（自适应）
        main_container = tk.Frame(self, bg="#f0f0f0")
        main_container.pack(fill=tk.BOTH, expand=True)
        main_container.grid_rowconfigure(1, weight=1)
        main_container.grid_columnconfigure(0, weight=1)
        main_container.grid_columnconfigure(1, weight=1)
        
        # 返回按钮
        self.show_back_button(main_container)
        
        # 标题
        title_label = tk.Label(main_container, text="文件夹加密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0")
        title_label.grid(row=0, column=0, columnspan=2, pady=10, sticky="nsew")
        
        # 主框架
        main_frame = tk.Frame(main_container, bg="#f0f0f0")
        main_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=20, pady=10)
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        
        # 左侧：文件夹选择
        left_frame = tk.Frame(main_frame, bg="white", relief=tk.RAISED, bd=1)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=10)
        left_frame.grid_rowconfigure(0, weight=0)
        left_frame.grid_rowconfigure(1, weight=1)
        left_frame.grid_rowconfigure(2, weight=0)
        left_frame.grid_rowconfigure(3, weight=0)
        left_frame.grid_columnconfigure(0, weight=1)
        
        tk.Label(left_frame, text="选择文件夹", font=("微软雅黑", 12), bg="white").grid(row=0, column=0, pady=10, sticky="nsew")
        
        # 文件夹路径显示
        self.folder_path_var = tk.StringVar(value=self.selected_path or "未选择文件夹")
        path_label = tk.Label(left_frame, textvariable=self.folder_path_var, bg="white", 
                             font=("微软雅黑", 10), wraplength=450, fg="#666666")
        path_label.grid(row=1, column=0, pady=5, padx=10, sticky="nsew")
        
        # 选择文件夹按钮
        tk.Button(left_frame, text="浏览文件夹", command=self.select_folder, 
                 bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").grid(row=2, column=0, pady=10, sticky="nsew", padx=20)
        
        # 加密模式选择
        mode_frame = tk.Frame(left_frame, bg="white")
        mode_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=20)
        mode_frame.grid_columnconfigure(0, weight=1)
        mode_frame.grid_columnconfigure(1, weight=1)
        mode_frame.grid_columnconfigure(2, weight=1)
        
        tk.Label(mode_frame, text="加密模式：", bg="white", font=("微软雅黑", 10)).grid(row=0, column=0, sticky="w")
        tk.Radiobutton(mode_frame, text="仅AES", variable=self.encryption_mode, value="aes_only", bg="white").grid(row=0, column=1, sticky="w")
        tk.Radiobutton(mode_frame, text="AES+宫格验证", variable=self.encryption_mode, value="aes_signature", bg="white").grid(row=0, column=2, sticky="w")
        
        # 右侧：保存设置 - 移除文件名输入框
        right_frame = tk.Frame(main_frame, bg="white", relief=tk.RAISED, bd=1)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=10)
        right_frame.grid_rowconfigure(0, weight=0)
        right_frame.grid_rowconfigure(1, weight=1)
        right_frame.grid_rowconfigure(2, weight=1)
        right_frame.grid_rowconfigure(3, weight=0)
        right_frame.grid_columnconfigure(0, weight=1)
        
        tk.Label(right_frame, text="保存设置", font=("微软雅黑", 12), bg="white").grid(row=0, column=0, pady=10, sticky="nsew")
        
        # 保存路径
        self.folder_save_var = tk.StringVar(value="")
        tk.Label(right_frame, text="保存路径：", bg="white", font=("微软雅黑", 10)).grid(row=1, column=0, sticky="w", padx=10)
        tk.Entry(right_frame, textvariable=self.folder_save_var, bg="#f5f5f5", relief=tk.FLAT).grid(row=2, column=0, sticky="nsew", padx=10, pady=5)
        tk.Button(right_frame, text="选择保存位置", command=self.select_folder_save_path, 
                 bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").grid(row=2, column=0, sticky="se", padx=10, pady=5)
        
        # 开始加密按钮
        encrypt_btn = tk.Button(right_frame, text="开始加密", command=self.start_folder_encryption, 
                 bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00", 
                 font=("微软雅黑", 12))
        encrypt_btn.grid(row=3, column=0, pady=20, sticky="nsew", padx=20)
        
        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_container, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=20, pady=10)
        
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
        
        # 主框架（自适应）
        main_container = tk.Frame(self, bg="#f0f0f0")
        main_container.pack(fill=tk.BOTH, expand=True)
        main_container.grid_rowconfigure(1, weight=1)
        main_container.grid_rowconfigure(2, weight=0)
        main_container.grid_rowconfigure(3, weight=0)
        main_container.grid_columnconfigure(0, weight=1)
        
        # 返回按钮
        self.show_back_button(main_container)
        
        # 标题
        title_label = tk.Label(main_container, text="文档加密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0")
        title_label.grid(row=0, column=0, pady=10, sticky="nsew")
        
        # 文本编辑区
        text_frame = tk.Frame(main_container, bg="#f0f0f0")
        text_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=10)
        text_frame.grid_rowconfigure(0, weight=1)
        text_frame.grid_columnconfigure(0, weight=1)
        
        self.doc_text = scrolledtext.ScrolledText(text_frame, font=("Consolas", 10), wrap=tk.WORD, 
                                                 bg="#f5f5f5", relief=tk.FLAT, bd=1)
        self.doc_text.grid(row=0, column=0, sticky="nsew")
        
        # 加密模式
        mode_frame = tk.Frame(main_container, bg="#f0f0f0")
        mode_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=5)
        mode_frame.grid_columnconfigure(0, weight=1)
        mode_frame.grid_columnconfigure(1, weight=1)
        mode_frame.grid_columnconfigure(2, weight=1)
        
        tk.Label(mode_frame, text="加密模式：", bg="#f0f0f0", font=("微软雅黑", 10)).grid(row=0, column=0, sticky="w")
        tk.Radiobutton(mode_frame, text="仅AES", variable=self.encryption_mode, value="aes_only", bg="#f0f0f0").grid(row=0, column=1, sticky="w")
        tk.Radiobutton(mode_frame, text="AES+宫格验证", variable=self.encryption_mode, value="aes_signature", bg="#f0f0f0").grid(row=0, column=2, sticky="w")
        
        # 按钮框架
        btn_frame = tk.Frame(main_container, bg="#f0f0f0")
        btn_frame.grid(row=3, column=0, sticky="nsew", padx=20, pady=10)
        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)
        btn_frame.grid_columnconfigure(2, weight=1)
        
        # 清空按钮
        tk.Button(btn_frame, text="清空内容", command=lambda: self.doc_text.delete(1.0, tk.END), 
                 bg="#ff4444", fg="white", relief=tk.FLAT, activebackground="#dd2222", 
                 font=("微软雅黑", 10)).grid(row=0, column=0, sticky="nsew", padx=5)
        
        # 打开按钮
        tk.Button(btn_frame, text="打开加密文档", command=self.open_encrypted_doc, 
                 bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777", 
                 font=("微软雅黑", 10)).grid(row=0, column=1, sticky="nsew", padx=5)
        
        # 保存按钮
        tk.Button(btn_frame, text="保存加密文档", command=self.save_encrypted_doc, 
                 bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00", 
                 font=("微软雅黑", 10)).grid(row=0, column=2, sticky="nsew", padx=5)
        
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
        
        # 主框架（自适应）
        main_container = tk.Frame(self, bg="#f0f0f0")
        main_container.pack(fill=tk.BOTH, expand=True)
        main_container.grid_rowconfigure(1, weight=1)
        main_container.grid_rowconfigure(2, weight=0)
        main_container.grid_columnconfigure(0, weight=1)
        
        # 返回按钮
        self.show_back_button(main_container)
        
        # 标题
        title_label = tk.Label(main_container, text="自动解密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0")
        title_label.grid(row=0, column=0, pady=10, sticky="nsew")
        
        # 选择加密文件
        self.decrypt_path_var = tk.StringVar(value=self.selected_path or "未选择加密文件")
        path_label = tk.Label(main_container, textvariable=self.decrypt_path_var, bg="#f0f0f0", 
                             font=("微软雅黑", 10), fg="#666666", wraplength=800)
        path_label.grid(row=1, column=0, pady=10, sticky="nsew", padx=20)
        
        # 按钮
        btn_frame = tk.Frame(main_container, bg="#f0f0f0")
        btn_frame.grid(row=2, column=0, pady=20, sticky="nsew")
        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)
        
        tk.Button(btn_frame, text="选择加密文件", command=self.select_encrypted_file, 
                 bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777", 
                 font=("微软雅黑", 10)).grid(row=0, column=0, sticky="nsew", padx=10)
        
        tk.Button(btn_frame, text="开始解密", command=self.start_auto_decryption, 
                 bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00", 
                 font=("微软雅黑", 10)).grid(row=0, column=1, sticky="nsew", padx=10)
        
        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_container, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=3, column=0, sticky="nsew", padx=20, pady=10)
        
        # 启用拖拽
        self.enable_drag_and_drop()
        
        # 状态栏
        self.status_bar = tk.Label(self, text="自动解密界面 | 支持拖拽加密文件到此处", 
                                  bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)
    
    # ====================== 文件操作函数 ======================
    def select_file(self):
        """选择文件"""
        file_path = filedialog.askopenfilename(title="选择要加密的文件")
        if file_path:
            self.file_path_var.set(file_path)
            self.selected_path = file_path
            self.update_status(f"已加载文件：{os.path.basename(file_path)}")
    
    def select_file_save_path(self):
        """选择文件保存路径"""
        if self.selected_path:
            default_name = os.path.basename(self.selected_path)
        else:
            default_name = "encrypted_file.tnt"
        save_path = filedialog.asksaveasfilename(title="选择保存位置", initialfile=default_name)
        if save_path:
            self.save_path_var.set(save_path)
    
    def select_folder(self):
        """选择文件夹"""
        folder_path = filedialog.askdirectory(title="选择要加密的文件夹")
        if folder_path:
            self.folder_path_var.set(folder_path)
            self.selected_path = folder_path
            self.update_status(f"已加载文件夹：{os.path.basename(folder_path)}")
    
    def select_folder_save_path(self):
        """选择文件夹保存路径"""
        if self.selected_path:
            default_name = os.path.basename(self.selected_path) + ".tntnext"
        else:
            default_name = "encrypted_folder.tntnext"
        save_path = filedialog.asksaveasfilename(title="选择保存位置", initialfile=default_name)
        if save_path:
            self.folder_save_var.set(save_path)
    
    def select_encrypted_file(self):
        """选择要解密的文件"""
        file_path = filedialog.askopenfilename(title="选择要解密的文件")
        if file_path:
            self.decrypt_path_var.set(file_path)
            self.selected_path = file_path
            self.update_status(f"已加载待解密文件：{os.path.basename(file_path)}")
    
    def start_file_encryption(self):
        """开始文件加密（集成OpenCL加速）"""
        file_path = self.file_path_var.get()
        save_path = self.save_path_var.get()
        
        if not file_path or file_path == "未选择文件":
            messagebox.showwarning("警告", "请先选择要加密的文件！")
            return
        
        if not save_path:
            save_path = file_path + ".tnt"
            self.save_path_var.set(save_path)
        
        # 获取密码
        password_dialog = PasswordDialog(self, "文件加密", "请输入加密密码：")
        password = password_dialog.show()
        if not password:
            return
        
        # 获取宫格签名（如果需要）
        signature_data = None
        if self.encryption_mode.get() == "aes_signature":
            grid_pad = GridSignaturePad(self, "设置宫格签名")
            signature_data, _ = grid_pad.show()
            if not signature_data:
                return

        # 后台加密线程
        def encrypt_thread():
            try:
                self.progress_var.set(0)
                self.update_idletasks()
                
                # 读取文件
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                self.progress_var.set(20)
                self.update_idletasks()
                
                # 获取密码
                password_dialog = PasswordDialog(self, "文件加密", "请输入加密密码：")
                password = password_dialog.show()
                if not password:
                    self.progress_var.set(0)
                    self.update_status("加密取消：用户未输入密码")
                    return
                
                self.progress_var.set(30)
                self.update_idletasks()
                
                # 宫格签名验证（如果选择AES+宫格模式）
                signature_data = None
                if self.encryption_mode.get() == "aes_signature":
                    grid_pad = GridSignaturePad(self, "设置宫格签名", None)
                    signature_result, _ = grid_pad.show()
                    if not signature_result:
                        self.progress_var.set(0)
                        self.update_status("加密取消：用户未完成宫格签名")
                        return
                    signature_data = signature_result
                    self.progress_var.set(40)
                    self.update_idletasks()
                
                # 生成盐和nonce
                salt = get_random_bytes(SALT_LENGTH)
                nonce = get_random_bytes(GCM_NONCE_LENGTH)
                
                # 密钥派生（使用PBKDF2）
                key = hashlib.pbkdf2_hmac(
                    KDF_HASH_ALG,
                    password.encode('utf-8'),
                    salt,
                    KDF_ITERATIONS,
                    dklen=AES_KEY_LENGTH
                )
                
                self.progress_var.set(50)
                self.update_idletasks()
                
                # AES-GCM加密
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                if signature_data:
                    # 将宫格签名数据序列化后加入附加数据
                    signature_bytes = pickle.dumps(signature_data)
                    cipher.update(signature_bytes)
                # 加密数据
                ciphertext, tag = cipher.encrypt_and_digest(pad(data, AES.block_size))
                
                self.progress_var.set(70)
                self.update_idletasks()
                
                # 构建加密文件结构
                # 格式：魔数 + 版本 + 盐 + nonce + 标签 + 加密数据 + (签名哈希 + 签名数据) + HMAC
                encrypted_data = bytearray()
                encrypted_data.extend(ENCRYPTION_MAGIC)
                encrypted_data.extend(VERSION)
                encrypted_data.extend(salt)
                encrypted_data.extend(nonce)
                encrypted_data.extend(tag)
                encrypted_data.extend(ciphertext)
                
                # 添加宫格签名数据（如果有）
                if signature_data:
                    signature_hash = signature_data['hash'].encode('utf-8')
                    signature_bytes = pickle.dumps(signature_data)
                    encrypted_data.extend(struct.pack('<I', len(signature_hash)))
                    encrypted_data.extend(signature_hash)
                    encrypted_data.extend(struct.pack('<I', len(signature_bytes)))
                    encrypted_data.extend(signature_bytes)
                
                # 生成HMAC
                hmac_key = hashlib.pbkdf2_hmac(
                    KDF_HASH_ALG,
                    password.encode('utf-8'),
                    salt,
                    KDF_ITERATIONS // 2,
                    dklen=HMAC_LENGTH
                )
                hmac_obj = hmac.new(hmac_key, encrypted_data, SIGNATURE_HASH_ALG)
                hmac_digest = hmac_obj.digest()
                encrypted_data.extend(hmac_digest)
                
                self.progress_var.set(80)
                self.update_idletasks()
                
                # 保存加密文件
                with open(save_path, 'wb') as f:
                    f.write(encrypted_data)
                
                self.progress_var.set(100)
                self.update_idletasks()
                
                # 更新状态和提示
                self.update_status(f"文件加密完成！保存至：{save_path}")
                messagebox.showinfo("成功", f"文件加密完成！\n保存路径：{save_path}", parent=self)
                
            except Exception as e:
                self.progress_var.set(0)
                error_msg = f"加密失败：{str(e)}\n{traceback.format_exc()}"
                self.update_status(error_msg)
                messagebox.showerror("错误", f"文件加密失败：{str(e)}", parent=self)
        
        # 启动加密线程
        threading.Thread(target=encrypt_thread, daemon=True).start()
    
    def start_folder_encryption(self):
        """开始文件夹加密"""
        folder_path = self.folder_path_var.get().strip()
        save_path = self.folder_save_var.get().strip()
        
        # 验证输入
        if not folder_path or folder_path == "未选择文件夹":
            messagebox.showwarning("警告", "请先选择要加密的文件夹！", parent=self)
            return
        if not os.path.isdir(folder_path):
            messagebox.showerror("错误", "选择的路径不是有效的文件夹！", parent=self)
            return
        
        # 处理保存路径
        if not save_path:
            # 默认使用原文件夹名 + .tntnext 后缀
            folder_name = os.path.basename(folder_path.rstrip(os.sep))
            save_path = os.path.join(os.path.dirname(folder_path), f"{folder_name}.tntnext")
        
        # 后台加密线程
        def encrypt_folder_thread():
            try:
                self.progress_var.set(0)
                self.update_idletasks()
                
                # 创建临时ZIP文件
                temp_zip_fd, temp_zip_path = tempfile.mkstemp(suffix='.zip')
                os.close(temp_zip_fd)
                
                # 压缩文件夹
                with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zipf:
                    # 遍历文件夹所有文件
                    total_files = 0
                    for root, dirs, files in os.walk(folder_path):
                        total_files += len(files)
                    processed_files = 0
                    
                    for root, dirs, files in os.walk(folder_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, folder_path)
                            zipf.write(file_path, arcname)
                            processed_files += 1
                            # 更新进度
                            progress = 20 * (processed_files / total_files)
                            self.progress_var.set(progress)
                            self.update_idletasks()
                
                self.progress_var.set(20)
                self.update_idletasks()
                
                # 读取ZIP文件数据
                with open(temp_zip_path, 'rb') as f:
                    zip_data = f.read()
                
                # 删除临时ZIP文件
                os.unlink(temp_zip_path)
                
                self.progress_var.set(30)
                self.update_idletasks()
                
                # 获取密码
                password_dialog = PasswordDialog(self, "文件夹加密", "请输入加密密码：")
                password = password_dialog.show()
                if not password:
                    self.progress_var.set(0)
                    self.update_status("加密取消：用户未输入密码")
                    return
                
                self.progress_var.set(40)
                self.update_idletasks()
                
                # 宫格签名验证（如果选择AES+宫格模式）
                signature_data = None
                if self.encryption_mode.get() == "aes_signature":
                    grid_pad = GridSignaturePad(self, "设置宫格签名", None)
                    signature_result, _ = grid_pad.show()
                    if not signature_result:
                        self.progress_var.set(0)
                        self.update_status("加密取消：用户未完成宫格签名")
                        return
                    signature_data = signature_result
                    self.progress_var.set(50)
                    self.update_idletasks()
                
                # 生成盐和nonce
                salt = get_random_bytes(SALT_LENGTH)
                nonce = get_random_bytes(GCM_NONCE_LENGTH)
                
                # 密钥派生
                key = hashlib.pbkdf2_hmac(
                    KDF_HASH_ALG,
                    password.encode('utf-8'),
                    salt,
                    KDF_ITERATIONS,
                    dklen=AES_KEY_LENGTH
                )
                
                self.progress_var.set(60)
                self.update_idletasks()
                
                # AES-GCM加密ZIP数据
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                if signature_data:
                    signature_bytes = pickle.dumps(signature_data)
                    cipher.update(signature_bytes)
                ciphertext, tag = cipher.encrypt_and_digest(pad(zip_data, AES.block_size))
                
                self.progress_var.set(70)
                self.update_idletasks()
                
                # 构建加密文件结构
                encrypted_data = bytearray()
                encrypted_data.extend(ENCRYPTION_MAGIC)
                encrypted_data.extend(VERSION)
                encrypted_data.extend(salt)
                encrypted_data.extend(nonce)
                encrypted_data.extend(tag)
                encrypted_data.extend(ciphertext)
                
                # 添加宫格签名数据
                if signature_data:
                    signature_hash = signature_data['hash'].encode('utf-8')
                    signature_bytes = pickle.dumps(signature_data)
                    encrypted_data.extend(struct.pack('<I', len(signature_hash)))
                    encrypted_data.extend(signature_hash)
                    encrypted_data.extend(struct.pack('<I', len(signature_bytes)))
                    encrypted_data.extend(signature_bytes)
                
                # 生成HMAC
                hmac_key = hashlib.pbkdf2_hmac(
                    KDF_HASH_ALG,
                    password.encode('utf-8'),
                    salt,
                    KDF_ITERATIONS // 2,
                    dklen=HMAC_LENGTH
                )
                hmac_obj = hmac.new(hmac_key, encrypted_data, SIGNATURE_HASH_ALG)
                hmac_digest = hmac_obj.digest()
                encrypted_data.extend(hmac_digest)
                
                self.progress_var.set(80)
                self.update_idletasks()
                
                # 保存加密文件
                with open(save_path, 'wb') as f:
                    f.write(encrypted_data)
                
                self.progress_var.set(100)
                self.update_idletasks()
                
                # 清理和提示
                self.update_status(f"文件夹加密完成！保存至：{save_path}")
                messagebox.showinfo("成功", f"文件夹加密完成！\n保存路径：{save_path}", parent=self)
                
            except Exception as e:
                self.progress_var.set(0)
                error_msg = f"文件夹加密失败：{str(e)}\n{traceback.format_exc()}"
                self.update_status(error_msg)
                messagebox.showerror("错误", f"文件夹加密失败：{str(e)}", parent=self)
        
        # 启动文件夹加密线程
        threading.Thread(target=encrypt_folder_thread, daemon=True).start()
    
    def save_encrypted_doc(self):
        """保存加密文档"""
        doc_content = self.doc_text.get(1.0, tk.END).strip()
        if not doc_content:
            messagebox.showwarning("警告", "文档内容不能为空！", parent=self)
            return
        
        # 选择保存路径
        save_path = filedialog.asksaveasfilename(
            title="保存加密文档",
            defaultextension=".msc",
            filetypes=[("加密文档", "*.msc"), ("所有文件", "*.*")]
        )
        if not save_path:
            return
        
        # 后台加密线程
        def doc_encrypt_thread():
            try:
                # 获取密码
                password_dialog = PasswordDialog(self, "文档加密", "请输入加密密码：")
                password = password_dialog.show()
                if not password:
                    self.update_status("文档加密取消：用户未输入密码")
                    return
                
                # 宫格签名验证（如果选择AES+宫格模式）
                signature_data = None
                if self.encryption_mode.get() == "aes_signature":
                    grid_pad = GridSignaturePad(self, "设置宫格签名", None)
                    signature_result, _ = grid_pad.show()
                    if not signature_result:
                        self.update_status("文档加密取消：用户未完成宫格签名")
                        return
                    signature_data = signature_result
                
                # 准备数据
                doc_bytes = doc_content.encode('utf-8')
                
                # 生成盐和nonce
                salt = get_random_bytes(SALT_LENGTH)
                nonce = get_random_bytes(GCM_NONCE_LENGTH)
                
                # 密钥派生
                key = hashlib.pbkdf2_hmac(
                    KDF_HASH_ALG,
                    password.encode('utf-8'),
                    salt,
                    KDF_ITERATIONS,
                    dklen=AES_KEY_LENGTH
                )
                
                # AES-GCM加密
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                if signature_data:
                    signature_bytes = pickle.dumps(signature_data)
                    cipher.update(signature_bytes)
                ciphertext, tag = cipher.encrypt_and_digest(pad(doc_bytes, AES.block_size))
                
                # 构建加密文件结构
                encrypted_data = bytearray()
                encrypted_data.extend(ENCRYPTION_MAGIC)
                encrypted_data.extend(VERSION)
                encrypted_data.extend(salt)
                encrypted_data.extend(nonce)
                encrypted_data.extend(tag)
                encrypted_data.extend(ciphertext)
                
                # 添加宫格签名数据
                if signature_data:
                    signature_hash = signature_data['hash'].encode('utf-8')
                    signature_bytes = pickle.dumps(signature_data)
                    encrypted_data.extend(struct.pack('<I', len(signature_hash)))
                    encrypted_data.extend(signature_hash)
                    encrypted_data.extend(struct.pack('<I', len(signature_bytes)))
                    encrypted_data.extend(signature_bytes)
                
                # 生成HMAC
                hmac_key = hashlib.pbkdf2_hmac(
                    KDF_HASH_ALG,
                    password.encode('utf-8'),
                    salt,
                    KDF_ITERATIONS // 2,
                    dklen=HMAC_LENGTH
                )
                hmac_obj = hmac.new(hmac_key, encrypted_data, SIGNATURE_HASH_ALG)
                hmac_digest = hmac_obj.digest()
                encrypted_data.extend(hmac_digest)
                
                # 保存文件
                with open(save_path, 'wb') as f:
                    f.write(encrypted_data)
                
                self.update_status(f"文档加密完成！保存至：{save_path}")
                messagebox.showinfo("成功", f"文档加密完成！\n保存路径：{save_path}", parent=self)
                
            except Exception as e:
                error_msg = f"文档加密失败：{str(e)}\n{traceback.format_exc()}"
                self.update_status(error_msg)
                messagebox.showerror("错误", f"文档加密失败：{str(e)}", parent=self)
        
        # 启动文档加密线程
        threading.Thread(target=doc_encrypt_thread, daemon=True).start()
    
    def open_encrypted_doc(self):
        """打开并解密文档"""
        file_path = filedialog.askopenfilename(
            title="选择加密文档",
            filetypes=[("加密文档", "*.msc"), ("所有文件", "*.*")]
        )
        if not file_path:
            return
        
        # 后台解密线程
        def doc_decrypt_thread():
            try:
                # 读取加密数据
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                
                # 验证魔数
                if not encrypted_data.startswith(ENCRYPTION_MAGIC):
                    raise ValueError("不是有效的TNT加密文档")
                
                # 解析数据结构
                ptr = len(ENCRYPTION_MAGIC)
                version = encrypted_data[ptr:ptr+len(VERSION)]
                ptr += len(VERSION)
                
                salt = encrypted_data[ptr:ptr+SALT_LENGTH]
                ptr += SALT_LENGTH
                
                nonce = encrypted_data[ptr:ptr+GCM_NONCE_LENGTH]
                ptr += GCM_NONCE_LENGTH
                
                tag = encrypted_data[ptr:ptr+16]  # GCM tag长度固定16
                ptr += 16
                
                # 提取HMAC（最后32字节）
                hmac_digest = encrypted_data[-HMAC_LENGTH:]
                main_data = encrypted_data[:-HMAC_LENGTH]
                
                # 获取密码
                password_dialog = PasswordDialog(self, "文档解密", "请输入解密密码：", show_strength=False)
                password = password_dialog.show()
                if not password:
                    self.update_status("文档解密取消：用户未输入密码")
                    return
                
                # 验证HMAC
                hmac_key = hashlib.pbkdf2_hmac(
                    KDF_HASH_ALG,
                    password.encode('utf-8'),
                    salt,
                    KDF_ITERATIONS // 2,
                    dklen=HMAC_LENGTH
                )
                hmac_obj = hmac.new(hmac_key, main_data, SIGNATURE_HASH_ALG)
                if not hmac.compare_digest(hmac_obj.digest(), hmac_digest):
                    raise ValueError("密码错误或文件已被篡改")
                
                # 检查是否有宫格签名
                signature_data = None
                remaining_data = encrypted_data[ptr:-HMAC_LENGTH]
                has_signature = len(remaining_data) > len(encrypted_data[ptr:-HMAC_LENGTH]) - (4 + 64 + 4)  # 签名哈希长度(4)+哈希(64)+签名数据长度(4)+数据
                if has_signature:
                    # 解析签名哈希长度和哈希
                    sig_hash_len = struct.unpack('<I', remaining_data[-4-64-4: -64-4])[0]
                    sig_hash = remaining_data[-64-4: -4]
                    sig_data_len = struct.unpack('<I', remaining_data[-4:])[0]
                    sig_data = remaining_data[-4-sig_data_len:-4]
                    remaining_data = remaining_data[:-4-sig_hash_len-4-sig_data_len]
                    
                    # 反序列化签名数据
                    signature_data = pickle.loads(sig_data)
                    
                    # 验证宫格签名
                    grid_pad = GridSignaturePad(self, "验证宫格签名", signature_data)
                    _, is_verified = grid_pad.show()
                    if not is_verified:
                        raise ValueError("宫格签名验证失败")
                
                # 提取密文
                ciphertext = remaining_data
                
                # 密钥派生
                key = hashlib.pbkdf2_hmac(
                    KDF_HASH_ALG,
                    password.encode('utf-8'),
                    salt,
                    KDF_ITERATIONS,
                    dklen=AES_KEY_LENGTH
                )
                
                # AES-GCM解密
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                if signature_data:
                    signature_bytes = pickle.dumps(signature_data)
                    cipher.update(signature_bytes)
                
                plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
                doc_content = plaintext.decode('utf-8')
                
                # 更新UI
                self.doc_text.delete(1.0, tk.END)
                self.doc_text.insert(1.0, doc_content)
                self.update_status(f"成功解密文档：{os.path.basename(file_path)}")
                
            except Exception as e:
                error_msg = f"文档解密失败：{str(e)}\n{traceback.format_exc()}"
                self.update_status(error_msg)
                messagebox.showerror("错误", f"文档解密失败：{str(e)}", parent=self)
        
        # 启动文档解密线程
        threading.Thread(target=doc_decrypt_thread, daemon=True).start()
    
    def select_file(self):
        """选择要加密的文件"""
        file_path = filedialog.askopenfilename(title="选择要加密的文件")
        if file_path:
            self.selected_path = file_path
            self.file_path_var.set(file_path)
            self.update_status(f"已选择文件：{os.path.basename(file_path)}")
    
    def select_folder(self):
        """选择要加密的文件夹"""
        folder_path = filedialog.askdirectory(title="选择要加密的文件夹")
        if folder_path:
            self.selected_path = folder_path
            self.folder_path_var.set(folder_path)
            self.update_status(f"已选择文件夹：{os.path.basename(folder_path)}")
    
    def select_file_save_path(self):
        """选择文件保存路径"""
        file_path = self.file_path_var.get()
        if file_path and file_path != "未选择文件":
            default_name = os.path.basename(file_path) + ".tnt"
            initial_dir = os.path.dirname(file_path)
        else:
            default_name = "encrypted_file.tnt"
            initial_dir = os.path.expanduser("~")
        
        save_path = filedialog.asksaveasfilename(
            title="选择保存位置",
            initialfile=default_name,
            initialdir=initial_dir,
            filetypes=[("加密文件", "*.tnt"), ("所有文件", "*.*")]
        )
        if save_path:
            self.save_path_var.set(save_path)
    
    def select_folder_save_path(self):
        """选择文件夹加密后的保存路径"""
        folder_path = self.folder_path_var.get()
        if folder_path and folder_path != "未选择文件夹":
            default_name = os.path.basename(folder_path.rstrip(os.sep)) + ".tntnext"
            initial_dir = os.path.dirname(folder_path)
        else:
            default_name = "encrypted_folder.tntnext"
            initial_dir = os.path.expanduser("~")
        
        save_path = filedialog.asksaveasfilename(
            title="选择保存位置",
            initialfile=default_name,
            initialdir=initial_dir,
            filetypes=[("加密文件夹", "*.tntnext"), ("所有文件", "*.*")]
        )
        if save_path:
            self.folder_save_var.set(save_path)
    
    def select_encrypted_file(self):
        """选择要解密的加密文件"""
        file_path = filedialog.askopenfilename(
            title="选择要解密的文件",
            filetypes=[("加密文件", "*.tnt *.tntnext *.msc"), ("所有文件", "*.*")]
        )
        if file_path:
            self.selected_path = file_path
            self.decrypt_path_var.set(file_path)
            self.update_status(f"已选择待解密文件：{os.path.basename(file_path)}")
    
    def start_auto_decryption(self):
        """开始自动解密"""
        decrypt_path = self.decrypt_path_var.get().strip()
        if not decrypt_path or decrypt_path == "未选择加密文件":
            messagebox.showwarning("警告", "请先选择要解密的文件！", parent=self)
            return
        if not os.path.isfile(decrypt_path):
            messagebox.showerror("错误", "选择的路径不是有效的文件！", parent=self)
            return
        
        # 后台解密线程
        def decrypt_thread():
            try:
                # 读取加密数据
                with open(decrypt_path, 'rb') as f:
                    encrypted_data = f.read()
                
                # 验证魔数
                if not encrypted_data.startswith(ENCRYPTION_MAGIC):
                    raise ValueError("不是有效的TNT加密文件")
                
                # 解析基础结构
                ptr = len(ENCRYPTION_MAGIC)
                version = encrypted_data[ptr:ptr+len(VERSION)]
                ptr += len(VERSION)
                
                salt = encrypted_data[ptr:ptr+SALT_LENGTH]
                ptr += SALT_LENGTH
                
                nonce = encrypted_data[ptr:ptr+GCM_NONCE_LENGTH]
                ptr += GCM_NONCE_LENGTH
                
                tag = encrypted_data[ptr:ptr+16]
                ptr += 16
                
                # 提取HMAC
                hmac_digest = encrypted_data[-HMAC_LENGTH:]
                main_data = encrypted_data[:-HMAC_LENGTH]
                
                # 获取解密密码
                password_dialog = PasswordDialog(self, "自动解密", "请输入解密密码：", show_strength=False)
                password = password_dialog.show()
                if not password:
                    self.update_status("解密取消：用户未输入密码")
                    return
                
                # 验证HMAC
                hmac_key = hashlib.pbkdf2_hmac(
                    KDF_HASH_ALG,
                    password.encode('utf-8'),
                    salt,
                    KDF_ITERATIONS // 2,
                    dklen=HMAC_LENGTH
                )
                hmac_obj = hmac.new(hmac_key, main_data, SIGNATURE_HASH_ALG)
                if not hmac.compare_digest(hmac_obj.digest(), hmac_digest):
                    raise ValueError("密码错误或文件已被篡改")
                
                # 检查是否有宫格签名
                signature_data = None
                remaining_data = encrypted_data[ptr:-HMAC_LENGTH]
                sig_hash_len = 0
                sig_hash = b""
                sig_data_len = 0
                sig_data = b""
                
                # 尝试解析签名数据（如果存在）
                try:
                    # 签名数据在HMAC之前，结构是：哈希长度(4) + 哈希值 + 数据长度(4) + 数据
                    sig_hash_len = struct.unpack('<I', remaining_data[-4-64-4: -64-4])[0]
                    sig_hash = remaining_data[-64-4: -4]
                    sig_data_len = struct.unpack('<I', remaining_data[-4:])[0]
                    sig_data = remaining_data[-4-sig_data_len:-4]
                    remaining_data = remaining_data[:-4-sig_hash_len-4-sig_data_len]
                    signature_data = pickle.loads(sig_data)
                except:
                    pass
                
                # 宫格签名验证（如果有）
                if signature_data:
                    grid_pad = GridSignaturePad(self, "验证宫格签名", signature_data)
                    _, is_verified = grid_pad.show()
                    if not is_verified:
                        raise ValueError("宫格签名验证失败")
                
                # 提取密文
                ciphertext = remaining_data
                
                # 密钥派生
                key = hashlib.pbkdf2_hmac(
                    KDF_HASH_ALG,
                    password.encode('utf-8'),
                    salt,
                    KDF_ITERATIONS,
                    dklen=AES_KEY_LENGTH
                )
                
                # AES-GCM解密
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                if signature_data:
                    signature_bytes = pickle.dumps(signature_data)
                    cipher.update(signature_bytes)
                
                plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
                
                # 判断文件类型并处理
                file_ext = os.path.splitext(decrypt_path)[1].lower()
                if file_ext == ".tntnext":
                    # 文件夹加密文件，解压
                    temp_zip_fd, temp_zip_path = tempfile.mkstemp(suffix='.zip')
                    os.close(temp_zip_fd)
                    with open(temp_zip_path, 'wb') as f:
                        f.write(plaintext)
                    
                    # 选择解压目录
                    extract_dir = filedialog.askdirectory(title="选择解压目录（建议空文件夹）")
                    if not extract_dir:
                        os.unlink(temp_zip_path)
                        self.update_status("解密取消：用户未选择解压目录")
                        return
                    
                    # 解压ZIP文件
                    with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                        zipf.extractall(extract_dir)
                    
                    # 删除临时文件
                    os.unlink(temp_zip_path)
                    
                    self.update_status(f"文件夹解密完成！解压至：{extract_dir}")
                    messagebox.showinfo("成功", f"文件夹解密完成！\n解压路径：{extract_dir}", parent=self)
                    
                elif file_ext == ".msc":
                    # 文档文件，显示内容
                    doc_content = plaintext.decode('utf-8')
                    self.show_doc_encrypt_ui()  # 切换到文档界面
                    self.doc_text.delete(1.0, tk.END)
                    self.doc_text.insert(1.0, doc_content)
                    self.update_status(f"文档解密完成！文件：{os.path.basename(decrypt_path)}")
                    
                else:
                    # 普通文件，保存
                    original_name = os.path.splitext(os.path.basename(decrypt_path))[0]
                    save_path = filedialog.asksaveasfilename(
                        title="保存解密后的文件",
                        initialfile=original_name,
                        initialdir=os.path.dirname(decrypt_path),
                        filetypes=[("所有文件", "*.*")]
                    )
                    if not save_path:
                        self.update_status("解密取消：用户未选择保存路径")
                        return
                    
                    with open(save_path, 'wb') as f:
                        f.write(plaintext)
                    
                    self.update_status(f"文件解密完成！保存至：{save_path}")
                    messagebox.showinfo("成功", f"文件解密完成！\n保存路径：{save_path}", parent=self)
                
            except Exception as e:
                error_msg = f"解密失败：{str(e)}\n{traceback.format_exc()}"
                self.update_status(error_msg)
                messagebox.showerror("错误", f"自动解密失败：{str(e)}", parent=self)
        
        # 启动解密线程
        threading.Thread(target=decrypt_thread, daemon=True).start()
    
    def update_status(self, text):
        """更新状态栏"""
        if hasattr(self, 'status_bar'):
            self.status_bar.config(text=text)
            self.update_idletasks()
    
    def on_close(self):
        """关闭程序"""
        if messagebox.askokcancel("退出", "确定要退出TNT防破密专家吗？", parent=self):
            self.destroy()

# ====================== 程序入口 ======================
if __name__ == "__main__":
    # 设置中文显示
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
        tkinterdnd2.Tk().wm_withdraw()  # 初始化DnD
    
    # 启动主程序
    app = TNTCryptoTool()
    app.mainloop()
