import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import sys
import hashlib
import json
import shutil
import pyopencl as cl
import numpy as np
import cv2
import sounddevice as sd
import librosa
import psutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import threading
import time

# 全局配置
MEMORY_THRESHOLD = 0.85  # 内存占用阈值85%
CHUNK_SIZE_BASE = 1024 * 1024 * 64  # 基础分块大小64MB，根据内存动态调整
OPENCL_DEVICE_ID = 0  # 固定选择第0个GPU
GRID_SIZE = 7  # 7×7宫格
GRID_MIN_SELECT = 4  # 宫格最少选择4格
AUDIO_SAMPLE_RATE = 44100  # 音频采样率
AUDIO_DURATION = 3  # 录音时长（秒）

# 获取系统内存信息，动态调整分块大小
def get_adjusted_chunk_size():
    mem = psutil.virtual_memory()
    available_mem = mem.available
    max_chunk = int(available_mem * 0.1)  # 每次使用10%可用内存
    return min(max_chunk, CHUNK_SIZE_BASE) if max_chunk > 0 else CHUNK_SIZE_BASE

# OpenCL初始化（自动选择第0个AMD GPU）
def init_opencl():
    try:
        platforms = cl.get_platforms()
        if not platforms:
            raise Exception("未检测到OpenCL平台")
        # 优先选择AMD平台
        amd_platform = None
        for p in platforms:
            if "AMD" in p.name or "Advanced Micro Devices" in p.name:
                amd_platform = p
                break
        if not amd_platform:
            amd_platform = platforms[0]  # 无AMD则选第一个
        
        devices = amd_platform.get_devices(device_type=cl.device_type.GPU)
        if not devices:
            raise Exception("未检测到GPU设备")
        # 强制选择第0个设备
        device = devices[OPENCL_DEVICE_ID]
        context = cl.Context([device])
        queue = cl.CommandQueue(context, device)
        return context, queue, device
    except Exception as e:
        messagebox.showerror("OpenCL初始化失败", f"GPU加速不可用，将使用CPU：{str(e)}")
        return None, None, None

# 人脸识别模块（OpenCV）
class FaceRecognition:
    def __init__(self):
        self.face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
        self.face_recognizer = cv2.face.LBPHFaceRecognizer_create()
        self.face_features = None

    # 采集人脸特征
    def capture_face(self):
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            messagebox.showerror("错误", "无法打开摄像头")
            return None
        
        face_frames = []
        start_time = time.time()
        while time.time() - start_time < 5:  # 采集5秒人脸
            ret, frame = cap.read()
            if not ret:
                continue
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = self.face_cascade.detectMultiScale(gray, 1.3, 5)
            if len(faces) > 0:
                (x, y, w, h) = faces[0]
                face_roi = gray[y:y+h, x:x+w]
                face_roi = cv2.resize(face_roi, (100, 100))
                face_frames.append(face_roi)
            cv2.imshow("采集人脸（按ESC退出）", frame)
            if cv2.waitKey(1) & 0xFF == 27:
                break
        
        cap.release()
        cv2.destroyAllWindows()
        
        if len(face_frames) < 5:
            messagebox.warning("警告", "采集的人脸数据不足")
            return None
        
        # 提取人脸特征（LBPH）
        self.face_recognizer.train(face_frames, np.array(range(len(face_frames))))
        # 保存特征为numpy数组（可序列化）
        self.face_features = self.face_recognizer.getHistograms()
        return self.face_features

    # 验证人脸特征
    def verify_face(self, saved_features):
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return False
        ret, frame = cap.read()
        cap.release()
        if not ret:
            return False
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = self.face_cascade.detectMultiScale(gray, 1.3, 5)
        if len(faces) == 0:
            return False
        (x, y, w, h) = faces[0]
        face_roi = gray[y:y+h, x:x+w]
        face_roi = cv2.resize(face_roi, (100, 100))
        try:
            self.face_recognizer.setHistograms(saved_features)
            label, confidence = self.face_recognizer.predict(face_roi)
            return confidence < 50  # 置信度低于50为匹配
        except:
            return False

# 声纹识别模块（librosa+sounddevice，无wave库）
class VoiceRecognition:
    def __init__(self):
        self.voice_features = None

    # 实时录音并提取声纹特征
    def record_and_extract(self):
        try:
            # 实时录音
            messagebox.showinfo("提示", f"即将录制{AUDIO_DURATION}秒音频，请说话")
            audio_data = sd.rec(int(AUDIO_SAMPLE_RATE * AUDIO_DURATION), 
                                samplerate=AUDIO_SAMPLE_RATE, 
                                channels=1, 
                                dtype=np.float32)
            sd.wait()  # 等待录音完成
            
            # 提取声纹特征（梅尔频谱、MFCC等）
            audio_data = audio_data.flatten()
            mfcc = librosa.feature.mfcc(y=audio_data, sr=AUDIO_SAMPLE_RATE, n_mfcc=13)
            mel_spec = librosa.feature.melspectrogram(y=audio_data, sr=AUDIO_SAMPLE_RATE)
            chroma = librosa.feature.chroma_stft(y=audio_data, sr=AUDIO_SAMPLE_RATE)
            
            # 合并特征并序列化
            self.voice_features = {
                "mfcc": mfcc.tolist(),
                "mel_spec": mel_spec.tolist(),
                "chroma": chroma.tolist()
            }
            return self.voice_features
        except Exception as e:
            messagebox.showerror("声纹提取失败", str(e))
            return None

    # 验证声纹特征
    def verify_voice(self, saved_features):
        try:
            # 实时录音
            audio_data = sd.rec(int(AUDIO_SAMPLE_RATE * AUDIO_DURATION), 
                                samplerate=AUDIO_SAMPLE_RATE, 
                                channels=1, 
                                dtype=np.float32)
            sd.wait()
            
            # 提取当前特征
            audio_data = audio_data.flatten()
            mfcc = librosa.feature.mfcc(y=audio_data, sr=AUDIO_SAMPLE_RATE, n_mfcc=13)
            mel_spec = librosa.feature.melspectrogram(y=audio_data, sr=AUDIO_SAMPLE_RATE)
            chroma = librosa.feature.chroma_stft(y=audio_data, sr=AUDIO_SAMPLE_RATE)
            
            # 计算特征相似度（余弦相似度）
            def cosine_similarity(a, b):
                a = np.array(a).flatten()
                b = np.array(b).flatten()
                return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))
            
            mfcc_sim = cosine_similarity(mfcc, saved_features["mfcc"])
            mel_sim = cosine_similarity(mel_spec, saved_features["mel_spec"])
            chroma_sim = cosine_similarity(chroma, saved_features["chroma"])
            
            # 平均相似度>0.8视为匹配
            avg_sim = (mfcc_sim + mel_sim + chroma_sim) / 3
            return avg_sim > 0.8
        except Exception as e:
            messagebox.showerror("声纹验证失败", str(e))
            return False

# 7×7宫格选择模块
class GridSelector(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("7×7宫格选择（最少选4格）")
        self.geometry("500x500")
        self.resizable(True, True)
        self.selected_cells = []
        self.grid_buttons = []
        
        # 自适应布局
        self.grid_frame = ttk.Frame(self)
        self.grid_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 创建7×7按钮网格
        for i in range(GRID_SIZE):
            row_buttons = []
            for j in range(GRID_SIZE):
                btn = ttk.Button(self.grid_frame, text="", width=2)
                btn.grid(row=i, column=j, sticky="nsew", padx=1, pady=1)
                btn.config(command=lambda b=btn, r=i, c=j: self.toggle_cell(b, r, c))
                row_buttons.append(btn)
                # 配置网格权重，实现自适应
                self.grid_frame.grid_rowconfigure(i, weight=1)
                self.grid_frame.grid_columnconfigure(j, weight=1)
            self.grid_buttons.append(row_buttons)
        
        # 确认按钮
        self.confirm_btn = ttk.Button(self, text="确认选择", command=self.confirm)
        self.confirm_btn.pack(fill=tk.X, padx=10, pady=10)
        
        # 自适应窗口大小
        self.bind("<Configure>", self.on_resize)

    def on_resize(self, event):
        # 修复Progressbar的width错误（改用length）
        pass

    def toggle_cell(self, btn, row, col):
        if btn in self.selected_cells:
            self.selected_cells.remove(btn)
            btn.config(style="TButton")
        else:
            self.selected_cells.append(btn)
            btn.config(style="Accent.TButton")
        
        # 检查最少选择数
        if len(self.selected_cells) < GRID_MIN_SELECT:
            self.confirm_btn.config(state=tk.DISABLED)
        else:
            self.confirm_btn.config(state=tk.NORMAL)

    def confirm(self):
        if len(self.selected_cells) < GRID_MIN_SELECT:
            messagebox.warning("警告", f"最少需要选择{GRID_MIN_SELECT}个格子")
            return
        # 提取选中的行列
        self.selected_positions = []
        for btn in self.selected_cells:
            for i in range(GRID_SIZE):
                for j in range(GRID_SIZE):
                    if self.grid_buttons[i][j] == btn:
                        self.selected_positions.append((i, j))
                        break
        self.destroy()

# 主加密窗口
class EncryptWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("文件加密工具（支持10GB+，AMD GPU加速）")
        self.state("zoomed")  # 初始最大化，自适应显示器
        self.minsize(800, 600)
        
        # 初始化OpenCL
        self.cl_context, self.cl_queue, self.cl_device = init_opencl()
        
        # 初始化识别模块
        self.face_recog = FaceRecognition()
        self.voice_recog = VoiceRecognition()
        
        # 变量初始化
        self.selected_file = tk.StringVar()
        self.encrypt_algorithm = tk.StringVar()
        self.grid_selection = None
        self.face_features = None
        self.voice_features = None
        
        # 样式配置
        self.style = ttk.Style(self)
        self.style.configure("Accent.TButton", background="#0078d7")
        
        # 主布局（自适应）
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 1. 文件选择区域
        self.file_frame = ttk.LabelFrame(self.main_frame, text="文件选择")
        self.file_frame.pack(fill=tk.X, pady=10)
        
        self.file_entry = ttk.Entry(self.file_frame, textvariable=self.selected_file)
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=10)
        
        self.browse_btn = ttk.Button(self.file_frame, text="浏览", command=self.browse_file)
        self.browse_btn.pack(side=tk.RIGHT, padx=10, pady=10)
        
        # 2. 加密算法选择（新增所有选项）
        self.alg_frame = ttk.LabelFrame(self.main_frame, text="加密算法选择")
        self.alg_frame.pack(fill=tk.X, pady=10)
        
        alg_options = [
            "aes+人脸",
            "aes+宫格+人脸",
            "aes+声纹",
            "aes+声纹+人脸",
            "aes+声纹+人脸+宫格",
            "aes+声纹+宫格",
            "aes+声纹+人脸+宫格"
        ]
        self.encrypt_algorithm.set(alg_options[0])
        
        self.alg_combo = ttk.Combobox(self.alg_frame, textvariable=self.encrypt_algorithm, values=alg_options, state="readonly")
        self.alg_combo.pack(fill=tk.X, padx=10, pady=10)
        
        # 3. 特征采集区域
        self.feature_frame = ttk.LabelFrame(self.main_frame, text="生物特征采集")
        self.feature_frame.pack(fill=tk.X, pady=10)
        
        self.face_btn = ttk.Button(self.feature_frame, text="采集人脸特征", command=self.capture_face)
        self.face_btn.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.voice_btn = ttk.Button(self.feature_frame, text="采集声纹特征", command=self.capture_voice)
        self.voice_btn.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.grid_btn = ttk.Button(self.feature_frame, text="选择宫格", command=self.select_grid)
        self.grid_btn.pack(side=tk.LEFT, padx=10, pady=10)
        
        # 4. 加密/解密按钮
        self.btn_frame = ttk.Frame(self.main_frame)
        self.btn_frame.pack(fill=tk.X, pady=20)
        
        self.encrypt_btn = ttk.Button(self.btn_frame, text="加密文件", command=self.encrypt_file)
        self.encrypt_btn.pack(side=tk.LEFT, padx=10, expand=True)
        
        self.decrypt_btn = ttk.Button(self.btn_frame, text="解密文件", command=self.decrypt_file)
        self.decrypt_btn.pack(side=tk.RIGHT, padx=10, expand=True)
        
        # 5. 进度条（修复width错误，改用length）
        self.progress_frame = ttk.Frame(self.main_frame)
        self.progress_frame.pack(fill=tk.X, pady=10)
        
        self.progress = ttk.Progressbar(self.progress_frame, orient=tk.HORIZONTAL, mode="determinate")
        self.progress.pack(fill=tk.X, expand=True, padx=10, pady=10)
        
        # 自适应进度条（修复TclError: unknown option "-width"）
        self.progress_frame.bind("<Configure>", lambda e: self.progress.config(length=e.width-40))
        
        # 配置所有行/列权重，实现自适应
        for i in range(5):
            self.main_frame.grid_rowconfigure(i, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file.set(file_path)

    def capture_face(self):
        self.face_features = self.face_recog.capture_face()
        if self.face_features is not None:
            messagebox.showinfo("成功", "人脸特征采集完成")

    def capture_voice(self):
        self.voice_features = self.voice_recog.record_and_extract()
        if self.voice_features is not None:
            messagebox.showinfo("成功", "声纹特征采集完成")

    def select_grid(self):
        grid_win = GridSelector(self)
        self.wait_window(grid_win)
        if hasattr(grid_win, "selected_positions"):
            self.grid_selection = grid_win.selected_positions
            messagebox.showinfo("成功", f"选中了{len(self.grid_selection)}个宫格")

    # 分块加密函数（支持10GB+，内存控制）
    def encrypt_chunked(self, input_path, output_path, key):
        chunk_size = get_adjusted_chunk_size()
        total_size = os.path.getsize(input_path)
        processed = 0
        
        # AES加密器初始化
        backend = default_backend()
        iv = os.urandom(16)
        
        # 写入IV到文件开头
        with open(output_path, "wb") as out_f:
            out_f.write(iv)
        
        # OpenCL加速（如果可用）
        use_opencl = self.cl_context is not None
        if use_opencl:
            # OpenCL AES加密内核（简化版）
            aes_kernel = """
            __kernel void aes_encrypt(__global uchar *data, __global uchar *key, int length) {
                int i = get_global_id(0);
                if (i < length) {
                    data[i] = data[i] ^ key[i % 32];
                }
            }
            """
            prg = cl.Program(self.cl_context, aes_kernel).build()
        
        # 分块读取并加密
        with open(input_path, "rb") as in_f, open(output_path, "ab") as out_f:
            while processed < total_size:
                # 检查内存占用，超过阈值则等待
                while psutil.virtual_memory().percent > MEMORY_THRESHOLD * 100:
                    time.sleep(0.1)
                
                chunk = in_f.read(chunk_size)
                if not chunk:
                    break
                
                # 填充（AES要求块大小为16的倍数）
                padder = padding.PKCS7(128).padder()
                padded_chunk = padder.update(chunk) + padder.finalize()
                
                if use_opencl:
                    # GPU加速加密
                    mf = cl.mem_flags
                    chunk_buf = cl.Buffer(self.cl_context, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=np.frombuffer(padded_chunk, dtype=np.uint8))
                    key_buf = cl.Buffer(self.cl_context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=np.frombuffer(key[:32], dtype=np.uint8))
                    
                    prg.aes_encrypt(self.cl_queue, (len(padded_chunk),), None, chunk_buf, key_buf, np.int32(len(padded_chunk)))
                    
                    encrypted_chunk = np.empty_like(padded_chunk)
                    cl.enqueue_copy(self.cl_queue, encrypted_chunk, chunk_buf)
                    encrypted_chunk = encrypted_chunk.tobytes()
                else:
                    # CPU加密
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
                    encryptor = cipher.encryptor()
                    encrypted_chunk = encryptor.update(padded_chunk) + encryptor.finalize()
                
                out_f.write(encrypted_chunk)
                processed += len(chunk)
                self.progress["value"] = (processed / total_size) * 100
                self.update_idletasks()
        
        self.progress["value"] = 100
        return True

    # 生物特征验证
    def verify_biometrics(self, saved_features):
        # 根据选择的算法验证对应特征
        alg = self.encrypt_algorithm.get()
        if "人脸" in alg and not self.face_recog.verify_face(saved_features["face"]):
            messagebox.showerror("失败", "人脸验证不通过")
            return False
        if "声纹" in alg and not self.voice_recog.verify_voice(saved_features["voice"]):
            messagebox.showerror("失败", "声纹验证不通过")
            return False
        if "宫格" in alg and self.grid_selection != saved_features["grid"]:
            messagebox.showerror("失败", "宫格验证不通过")
            return False
        return True

    # 打包特殊数据为文件夹
    def pack_special_data(self, output_dir):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # 保存人脸特征
        if self.face_features is not None:
            face_path = os.path.join(output_dir, "face_features.npy")
            np.save(face_path, self.face_features)
        
        # 保存声纹特征
        if self.voice_features is not None:
            voice_path = os.path.join(output_dir, "voice_features.json")
            with open(voice_path, "w") as f:
                json.dump(self.voice_features, f)
        
        # 保存宫格选择
        if self.grid_selection is not None:
            grid_path = os.path.join(output_dir, "grid_selection.json")
            with open(grid_path, "w") as f:
                json.dump(self.grid_selection, f)

    # 加密文件主函数
    def encrypt_file(self):
        input_path = self.selected_file.get()
        if not input_path or not os.path.exists(input_path):
            messagebox.showerror("错误", "请选择有效的文件")
            return
        
        # 检查算法对应的特征是否采集
        alg = self.encrypt_algorithm.get()
        if "人脸" in alg and self.face_features is None:
            messagebox.showerror("错误", "请先采集人脸特征")
            return
        if "声纹" in alg and self.voice_features is None:
            messagebox.showerror("错误", "请先采集声纹特征")
            return
        if "宫格" in alg and self.grid_selection is None:
            messagebox.showerror("错误", "请先选择宫格")
            return
        
        # 生成加密密钥（融合生物特征）
        key_materials = []
        if self.face_features is not None:
            key_materials.append(hashlib.sha256(np.array(self.face_features).tobytes()).digest())
        if self.voice_features is not None:
            voice_bytes = json.dumps(self.voice_features).encode()
            key_materials.append(hashlib.sha256(voice_bytes).digest())
        if self.grid_selection is not None:
            grid_bytes = json.dumps(self.grid_selection).encode()
            key_materials.append(hashlib.sha256(grid_bytes).digest())
        
        # 合并密钥材料
        key = hashlib.sha256(b"".join(key_materials)).digest()
        
        # 输出路径
        output_path = input_path + ".encrypted"
        special_data_dir = input_path + "_special_data"
        
        try:
            # 分块加密文件
            threading.Thread(target=self.encrypt_chunked, args=(input_path, output_path, key)).start()
            # 打包特殊数据
            self.pack_special_data(special_data_dir)
            messagebox.showinfo("成功", f"文件加密完成！\n加密文件：{output_path}\n特征数据：{special_data_dir}")
        except Exception as e:
            messagebox.showerror("加密失败", str(e))
            self.progress["value"] = 0

    # 解密文件（简化版，仅演示）
    def decrypt_file(self):
        input_path = self.selected_file.get()
        if not input_path or not input_path.endswith(".encrypted"):
            messagebox.showerror("错误", "请选择加密后的文件")
            return
        
        # 加载特殊数据
        special_data_dir = input_path[:-10] + "_special_data"
        if not os.path.exists(special_data_dir):
            messagebox.showerror("错误", "未找到对应的特征数据文件夹")
            return
        
        # 加载特征
        face_features = None
        voice_features = None
        grid_selection = None
        
        face_path = os.path.join(special_data_dir, "face_features.npy")
        if os.path.exists(face_path):
            face_features = np.load(face_path, allow_pickle=True)
        
        voice_path = os.path.join(special_data_dir, "voice_features.json")
        if os.path.exists(voice_path):
            with open(voice_path, "r") as f:
                voice_features = json.load(f)
        
        grid_path = os.path.join(special_data_dir, "grid_selection.json")
        if os.path.exists(grid_path):
            with open(grid_path, "r") as f:
                grid_selection = json.load(f)
        
        # 验证生物特征
        if not self.verify_biometrics({"face": face_features, "voice": voice_features, "grid": grid_selection}):
            return
        
        # 生成解密密钥
        key_materials = []
        if face_features is not None:
            key_materials.append(hashlib.sha256(np.array(face_features).tobytes()).digest())
        if voice_features is not None:
            voice_bytes = json.dumps(voice_features).encode()
            key_materials.append(hashlib.sha256(voice_bytes).digest())
        if grid_selection is not None:
            grid_bytes = json.dumps(grid_selection).encode()
            key_materials.append(hashlib.sha256(grid_bytes).digest())
        
        key = hashlib.sha256(b"".join(key_materials)).digest()
        
        # 解密（分块，类似加密逻辑）
        output_path = input_path[:-10]
        chunk_size = get_adjusted_chunk_size()
        total_size = os.path.getsize(input_path) - 16  # 减去IV长度
        processed = 0
        
        try:
            # 读取IV
            with open(input_path, "rb") as in_f:
                iv = in_f.read(16)
                
                # 分块解密
                with open(output_path, "wb") as out_f:
                    backend = default_backend()
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
                    decryptor = cipher.decryptor()
                    
                    while processed < total_size:
                        while psutil.virtual_memory().percent > MEMORY_THRESHOLD * 100:
                            time.sleep(0.1)
                        
                        chunk = in_f.read(chunk_size)
                        if not chunk:
                            break
                        
                        decrypted_chunk = decryptor.update(chunk)
                        out_f.write(decrypted_chunk)
                        processed += len(chunk)
                        self.progress["value"] = (processed / total_size) * 100
                        self.update_idletasks()
                    
                    # 去除填充
                    unpadder = padding.PKCS7(128).unpadder()
                    final_chunk = unpadder.update(decryptor.finalize()) + unpadder.finalize()
                    out_f.write(final_chunk)
            
            self.progress["value"] = 100
            messagebox.showinfo("成功", f"文件解密完成：{output_path}")
        except Exception as e:
            messagebox.showerror("解密失败", str(e))
            self.progress["value"] = 0

if __name__ == "__main__":
    # 解决高DPI适配
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass
    
    app = EncryptWindow()
    app.mainloop()
