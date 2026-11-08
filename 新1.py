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