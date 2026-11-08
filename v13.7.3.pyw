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
        
        tk.Label(self, text="TNT防破密专家努力加载中...", bg="#f0f0f0", font=("微软雅黑", 12)).pack(pady=20)
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
        self.attributes('-topmost',True)
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
                    x - GRID_POINT_SIZE//2, y - GRID_POINT_SIZE//2,
                    x + GRID_POINT_SIZE//2, y + GRID_POINT_SIZE//2,
                    fill="#cccccc", outline="#666666", width=2,
                    tags=(f"point_{row}_{col}", "grid_point")
                )
                
                # 显示宫格坐标（1开始）
                self.grid_canvas.create_text(
                    x, y, text=f"{row+1},{col+1}", fill="#666666", font=("微软雅黑", 8),
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
            prev_point = self.selected_points[i-1]
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
                x - GRID_POINT_SIZE//2, y - GRID_POINT_SIZE//2,
                x + GRID_POINT_SIZE//2, y + GRID_POINT_SIZE//2,
                fill="#44dd00", outline="#22bb00", width=2,
                tags=(f"selected_{row}_{col}", "selected_point")
            )
            # 显示顺序编号
            self.grid_canvas.create_text(
                x, y, text=str(idx+1), fill="white", font=("微软雅黑", 10, "bold"),
                tags=(f"num_{row}_{col}", "point_number")
            )
    
    def on_point_click(self, event):
        """点击宫格点事件"""
        # 找到点击的点
        click_x, click_y = event.x, event.y
        selected_point = None
        
        for (row, col), (x, y) in self.point_positions.items():
            if (click_x - x)**2 + (click_y - y)**2 <= (GRID_POINT_SIZE//2)**2:
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

# ====================== 主程序 ======================
class TNTCryptoTool(tkinterdnd2.Tk):
    """主程序类（TNT防破密专家核心类）"""
    def __init__(self):
        super().__init__()
        self.title("TNT 防破密专家 v13.7.3")
        self.geometry("1370x770")
        self.configure(bg="#f0f0f0")
        self.attributes('-alpha', 0.97)
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
        """设置主界面（四大功能模块 + 关于按钮）"""
        # 更新当前模式
        self.current_mode = "main"
        
        # 清空现有组件
        for widget in self.winfo_children():
            widget.destroy()
        
        # 标题
        title_label = tk.Label(self, text="TNT 防破密专家 v13.7.3", font=("微软雅黑", 16, "bold"), bg="#f0f0f0")
        title_label.pack(pady=20)
        
        # 功能按钮框架
        func_frame = tk.Frame(self, bg="#f0f0f0")
        func_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 四大功能按钮
        buttons = [
            ("文件加密", self.show_file_encrypt_ui),
            ("文件夹加密", self.show_folder_encrypt_ui),
            ("文档加密", self.show_doc_encrypt_ui),
            ("自动解密", self.show_auto_decrypt_ui)
        ]
        
        # 创建按钮
        for idx, (text, cmd) in enumerate(buttons):
            btn_frame = tk.Frame(func_frame, bg="#cccccc", width=300, height=300, relief=tk.RAISED, bd=2)
            btn_frame.pack_propagate(False)
            btn_frame.grid(row=0, column=idx, padx=15, pady=10)
            
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
            
            # 绑定点击事件
            btn_frame.bind("<Button-1>", lambda e, c=cmd: c())
        
        # 关于按钮
        about_frame = tk.Frame(self, bg="#f0f0f0")
        about_frame.pack(pady=10)
        about_btn = tk.Button(
            about_frame, 
            text="关于", 
            command=self.show_about,
            bg="#999999", 
            fg="white", 
            relief=tk.FLAT, 
            activebackground="#777777",
            width=10,
            font=("微软雅黑", 10)
        )
        about_btn.pack()
        
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
    
    def show_back_button(self, parent):
        """显示返回按钮"""
        back_btn = tk.Button(parent, text="← 返回主界面", command=self.setup_main_ui, 
                            bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777")
        back_btn.pack(anchor=tk.NW, padx=10, pady=10)
        return back_btn
    
    # ====================== 功能界面 ======================
    def show_file_encrypt_ui(self):
        """文件加密界面 - 移除文件名输入框，默认使用原文件名"""
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
        
        # 加密模式选择
        mode_frame = tk.Frame(left_frame, bg="white")
        mode_frame.pack(fill=tk.X, padx=10, pady=20)
        tk.Label(mode_frame, text="加密模式：", bg="white", font=("微软雅黑", 10)).pack(side=tk.LEFT)
        tk.Radiobutton(mode_frame, text="仅AES", variable=self.encryption_mode, value="aes_only", bg="white").pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(mode_frame, text="AES+宫格验证", variable=self.encryption_mode, value="aes_signature", bg="white").pack(side=tk.LEFT)
        
        # 右侧：保存设置
        right_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10)
        right_frame.pack_propagate(False)
        
        tk.Label(right_frame, text="保存设置", font=("微软雅黑", 12), bg="white").pack(pady=10)
        
        # 保存路径
        self.save_path_var = tk.StringVar(value="")
        tk.Label(right_frame, text="保存路径：", bg="white", font=("微软雅黑", 10)).pack(anchor=tk.W, padx=10)
        tk.Entry(right_frame, textvariable=self.save_path_var, bg="#f5f5f5", relief=tk.FLAT).pack(fill=tk.X, padx=10, pady=5)
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
        """文件夹加密界面 - 移除文件名输入框，默认使用原文件夹名"""
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
        
        # 加密模式选择
        mode_frame = tk.Frame(left_frame, bg="white")
        mode_frame.pack(fill=tk.X, padx=10, pady=20)
        tk.Label(mode_frame, text="加密模式：", bg="white", font=("微软雅黑", 10)).pack(side=tk.LEFT)
        tk.Radiobutton(mode_frame, text="仅AES", variable=self.encryption_mode, value="aes_only", bg="white").pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(mode_frame, text="AES+宫格验证", variable=self.encryption_mode, value="aes_signature", bg="white").pack(side=tk.LEFT)
        
        # 右侧：保存设置 - 移除文件名输入框
        right_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10)
        right_frame.pack_propagate(False)
        
        tk.Label(right_frame, text="保存设置", font=("微软雅黑", 12), bg="white").pack(pady=10)
        
        # 保存路径
        self.folder_save_var = tk.StringVar(value="")
        tk.Label(right_frame, text="保存路径：", bg="white", font=("微软雅黑", 10)).pack(anchor=tk.W, padx=10)
        tk.Entry(right_frame, textvariable=self.folder_save_var, bg="#f5f5f5", relief=tk.FLAT).pack(fill=tk.X, padx=10, pady=5)
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
        
        # 加密模式
        mode_frame = tk.Frame(self, bg="#f0f0f0")
        mode_frame.pack(fill=tk.X, padx=20, pady=5)
        tk.Label(mode_frame, text="加密模式：", bg="#f0f0f0", font=("微软雅黑", 10)).pack(side=tk.LEFT)
        tk.Radiobutton(mode_frame, text="仅AES", variable=self.encryption_mode, value="aes_only", bg="#f0f0f0").pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(mode_frame, text="AES+宫格验证", variable=self.encryption_mode, value="aes_signature", bg="#f0f0f0").pack(side=tk.LEFT)
        
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
        tk.Label(self, textvariable=self.decrypt_path_var, bg="#f0f0f0", font=("微软雅黑", 10), fg="#666666").pack(pady=10)
        
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
        if len(encrypted_data) < HMAC_LENGTH + len(ENCRYPTION_MAGIC) + len(VERSION) + SALT_LENGTH + GCM_NONCE_LENGTH + 16:
            raise ValueError("无效的加密数据")
        
        # 分离HMAC和数据包
        hmac_digest = encrypted_data[:HMAC_LENGTH]
        packet = encrypted_data[HMAC_LENGTH:]
        
        # 验证魔数
        if packet[:len(ENCRYPTION_MAGIC)] != ENCRYPTION_MAGIC:
            raise ValueError("无效的加密文件")
        
        # 解析数据包
        salt = packet[len(ENCRYPTION_MAGIC)+len(VERSION):len(ENCRYPTION_MAGIC)+len(VERSION)+SALT_LENGTH]
        nonce = packet[len(ENCRYPTION_MAGIC)+len(VERSION)+SALT_LENGTH:len(ENCRYPTION_MAGIC)+len(VERSION)+SALT_LENGTH+GCM_NONCE_LENGTH]
        tag = packet[len(ENCRYPTION_MAGIC)+len(VERSION)+SALT_LENGTH+GCM_NONCE_LENGTH:len(ENCRYPTION_MAGIC)+len(VERSION)+SALT_LENGTH+GCM_NONCE_LENGTH+16]
        ciphertext = packet[len(ENCRYPTION_MAGIC)+len(VERSION)+SALT_LENGTH+GCM_NONCE_LENGTH+16:]
        
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
    
    def encrypt_multi_layer(self, data, password, file_type, signature=None, original_filename=""):
        """三层加密结构（包含原文件名+后缀加密）"""
        try:
            self.update_progress(10)
            
            # 第一层：加密原始数据
            layer1 = self._encrypt_single_layer(data, password)
            self.update_progress(30)
            
            # 第二层：加密宫格签名（如果有）
            encrypted_signature = b''
            if signature:
                special_signature = self._convert_grid_signature(signature)
                encrypted_signature = self._encrypt_single_layer(special_signature, password)
            self.update_progress(50)
            
            # 组装文件夹结构 - 加入原文件名和后缀
            folder_data = {
                'content': layer1,
                'signature': encrypted_signature,
                'type': file_type,
                'mode': self.encryption_mode.get().encode('utf-8'),
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
    
    def decrypt_multi_layer(self, encrypted_data, password, verify_signature=True):
        """三层解密结构（解析原文件名）"""
        try:
            self.update_progress(10)
            
            # 第一层：解密文件夹结构
            folder_bytes = self._decrypt_single_layer(encrypted_data, password)
            self.update_progress(30)
            
            # 解析文件夹
            folder_data = pickle.loads(folder_bytes)
            content_data = folder_data['content']
            signature_data = folder_data.get('signature', b'')
            file_type = folder_data.get('type', FILE_TYPE_TEXT)
            encryption_mode = folder_data.get('mode', b'aes_only').decode('utf-8')
            # 解析原文件名
            original_filename = folder_data.get('original_filename', b'').decode('utf-8')
            original_basename = folder_data.get('original_basename', b'').decode('utf-8')
            self.update_progress(50)
            
            # 验证宫格签名
            is_verified = True
            if verify_signature and encryption_mode == "aes_signature" and signature_data:
                # 解密签名
                special_signature = self._decrypt_single_layer(signature_data, password)
                ref_signature = self._restore_grid_signature(special_signature)
                
                # 显示宫格验证面板
                grid_pad = GridSignaturePad(self, "宫格验证", ref_signature)
                _, is_verified = grid_pad.show()
                
                if not is_verified:
                    raise ValueError("宫格验证失败：连接顺序不匹配")
            self.update_progress(70)
            
            # 第二层：解密内容
            plain_data = self._decrypt_single_layer(content_data, password)
            self.update_progress(100)
            
            return plain_data, file_type, is_verified, original_filename, original_basename
            
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
        default_filename = f"{original_basename}.tnt"
        
        path = filedialog.asksaveasfilename(
            defaultextension='.tnt',
            filetypes=[("加密文件", "*.tnt"), ("所有文件", "*.*")],
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
        default_filename = f"{original_basename}.tntnext"
        
        path = filedialog.asksaveasfilename(
            defaultextension='.tntnext',
            filetypes=[("加密文件夹", "*.tntnext"), ("所有文件", "*.*")],
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
                    ("下拉可选↓",".tnt "".tntnext "".msc"),
                    ("加密文件", "*.tnt"),
                    ("加密文件夹", "*.tntnext"),
                    ("加密文本", "*.msc"),
                ],
                title="选择要解密的文件"
            )
        except Exception as e:
            messagebox.showerror(title="错误",message=f"Error{e}")
        if path:
            self.decrypt_path_var.set(path)

    
    # ====================== 加密解密入口 ======================
    def start_file_encryption(self):
        """开始文件加密"""
        if not self.selected_path:
            messagebox.showwarning("警告", "请先选择要加密的文件！")
            return
        
        # 获取保存路径
        save_path = self.save_path_var.get()
        if not save_path:
            original_basename = os.path.basename(self.selected_path)
            default_filename = f"{original_basename}.tnt"
            save_path = filedialog.asksaveasfilename(
                defaultextension='.tnt',
                filetypes=[("加密文件", "*.tnt")],
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
        
        # 获取宫格签名
        signature = None
        if self.encryption_mode.get() == "aes_signature":
            grid_pad = GridSignaturePad(self, "设置宫格验证")
            signature, _ = grid_pad.show()
            if not signature:
                messagebox.showinfo("提示", "宫格验证取消，加密终止")
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
                    signature, 
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
            default_filename = f"{original_basename}.tntnext"
            save_path = filedialog.asksaveasfilename(
                defaultextension='.tntnext',
                filetypes=[("加密文件夹", "*.tntnext")],
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
        
        # 获取宫格签名
        signature = None
        if self.encryption_mode.get() == "aes_signature":
            grid_pad = GridSignaturePad(self, "设置宫格验证")
            signature, _ = grid_pad.show()
            if not signature:
                messagebox.showinfo("提示", "宫格验证取消，加密终止")
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
                    signature, 
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
        
        # 获取宫格签名
        signature = None
        if self.encryption_mode.get() == "aes_signature":
            grid_pad = GridSignaturePad(self, "设置宫格验证")
            signature, _ = grid_pad.show()
            if not signature:
                messagebox.showinfo("提示", "宫格验证取消，保存终止")
                return
        
        # 加密保存
        try:
            encrypted_data = self.encrypt_multi_layer(
                content, 
                password, 
                FILE_TYPE_TEXT, 
                signature, 
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
                
                # 三层解密
                plain_data, file_type, _, original_filename, original_basename = self.decrypt_multi_layer(encrypted_data, password)
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
                        save_dir = filedialog.askdirectory(title="选择文件夹保存位置")
                        if not save_dir:
                            self.update_status("解密取消：未选择保存位置")
                            return
                        
                        # 创建临时文件
                        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
                        temp_zip.write(plain_data)
                        temp_zip.close()
                        
                        # 解压
                        with zipfile.ZipFile(temp_zip.name, 'r') as zipf:
                            total_files = len(zipf.namelist())
                            processed = 0
                            
                            for file_info in zipf.infolist():
                                zipf.extract(file_info, save_dir)
                                processed += 1
                                self.update_progress(60 + int(30 * processed / total_files))
                        
                        # 删除临时文件
                        os.unlink(temp_zip.name)
                        self.update_progress(100)
                        
                        # 提示
                        self.update_status(f"文件夹解密完成：已解压到 {save_dir}")
                        self.after(0, lambda: messagebox.showinfo(
                            "成功", 
                            f"文件夹解密完成！\n已解压到：{save_dir}"
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
        if messagebox.askokcancel("退出", "确定要退出TNT防破密专家吗？"):
            self.destroy()
            sys.exit(0)

# ====================== 主程序入口 ======================


ICO_BASE64 = '''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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAADAAAABgAAAAAQAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA3NzcOFhYWOwsLC2EKCgp7CwsLiQsLC4oKCgp8EBAQYhoaGjszMzMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABISEg4MDAwrCwsLcAgICMICAgL2AAAA/gAAAP4AAAD+AAAA/gAAAP4AAAD+AAAA/gAA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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='''


if __name__ == "__main__":
    # 高DPI适配
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    
    # 启动程序
    app = TNTCryptoTool()
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
        messagebox.showerror(title="错误",message=f"Error{e}")
    app.mainloop()
