# ========== 前置：屏蔽警告 + 日志级别控制 ==========
import warnings
import logging
import sys
import io

# 屏蔽弃用警告
warnings.filterwarnings("ignore", category=FutureWarning, module="insightface")
warnings.filterwarnings("ignore", category=FutureWarning, module="skimage")

# 屏蔽相关库的INFO/DEBUG级日志，防止漏输出到控制台
logging.getLogger("insightface").setLevel(logging.WARNING)
logging.getLogger("onnxruntime").setLevel(logging.WARNING)

import tkinter as tk
from tkinter import messagebox
import cv2
from PIL import Image, ImageTk
import numpy as np
import pickle
import os
import onnxruntime as ort
from insightface.app import FaceAnalysis

# ========== 全局配置 ==========
DESKTOP = os.path.join(os.path.expanduser("~"), "Desktop")
FEATURE_SAVE_PATH = os.path.join(DESKTOP, "face_features.dat")
SIMILARITY_THRESHOLD = 0.68  # 人脸比对阈值，越高越严格
PREVIEW_SIZE = (640, 480)    # 预览画面分辨率


class FaceTestApp:
    def __init__(self, root):
        self.root = root
        self.root.title("高精度人脸采集验证系统")
        self.root.geometry("720x680")
        self.root.resizable(True, True)

        # 状态变量
        self.capture_count = 0       # 0-3采集，第4次验证
        self.base_features = []      # 基准特征库（3组512维向量）
        self.current_frame = None    # 实时帧（仅存内存，不写盘）
        self.running = True          # 预览循环控制

        # ---------------- 1. 顶部状态区 ----------------
        self.hw_label = tk.Label(root, text="正在加载人脸识别引擎...", 
                                 font=("微软雅黑", 10), fg="#666666")
        self.hw_label.pack(pady=5)

        self.status_label = tk.Label(root, text="模型初始化中，请稍候...", 
                                     font=("微软雅黑", 12, "bold"))
        self.status_label.pack(pady=5)

        # ---------------- 2. 加载人脸识别引擎（捕获日志+静默控制台） ----------------
        self.root.update()
        
        # 保存原始标准输出/错误流
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        # 创建内存缓冲区捕获输出
        log_buffer = io.StringIO()

        try:
            # 临时重定向输出到缓冲区，控制台无任何打印
            sys.stdout = log_buffer
            sys.stderr = log_buffer

            # 优先 DirectML 加速，失败自动回退 CPU
            self.providers = ['DmlExecutionProvider', 'CPUExecutionProvider']
            self.face_app = FaceAnalysis(
                name="buffalo_l",
                providers=self.providers
            )
            self.face_app.prepare(ctx_id=0, det_size=(640, 640))

            # 恢复标准输出
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            
            # 获取完整启动日志
            boot_log = log_buffer.getvalue().strip()
            log_buffer.close()

            # 检测实际生效的加速后端
            available = ort.get_available_providers()
            if 'DmlExecutionProvider' in available:
                hw_status = "✅ 硬件加速：DirectML 已启用（AMD显卡生效）"
                self.hw_label.config(text=hw_status, fg="#2e7d32")
            else:
                hw_status = "⚠️  硬件加速：未启用，当前使用CPU运行"
                self.hw_label.config(text=hw_status, fg="#f57c00")

            # 弹窗展示完整启动日志
            messagebox.showinfo(
                "引擎启动成功",
                f"{hw_status}\n\n"
                f"——— 启动日志 ———\n"
                f"{boot_log}"
            )

        except Exception as e:
            # 出错也先恢复输出，再弹窗报错
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            error_log = log_buffer.getvalue().strip()
            log_buffer.close()
            
            messagebox.showerror(
                "模型加载失败",
                f"错误信息：{str(e)}\n\n"
                f"——— 运行日志 ———\n"
                f"{error_log if error_log else '无额外日志'}"
            )
            root.destroy()
            return

        # ---------------- 3. 打开摄像头 ----------------
        self.cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)  # DSHOW 减少 Windows 延迟
        if not self.cap.isOpened():
            messagebox.showerror("错误", "无法打开摄像头，请检查设备是否被占用")
            root.destroy()
            return
        self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, 960)
        self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)

        # ---------------- 4. 预览画面 ----------------
        self.preview_label = tk.Label(root, bd=2, relief=tk.SUNKEN)
        self.preview_label.pack(pady=8)

        # ---------------- 5. 操作按钮区 ----------------
        self.btn_frame = tk.Frame(root)
        self.btn_frame.pack(pady=10)

        self.capture_btn = tk.Button(
            self.btn_frame, text="拍照采集 (第1张)", font=("微软雅黑", 12, "bold"),
            width=18, height=2, bg="#e3f2fd", activebackground="#bbdefb",
            command=self.on_capture
        )
        self.capture_btn.grid(row=0, column=0, padx=12)

        self.reset_btn = tk.Button(
            self.btn_frame, text="重新开始", font=("微软雅黑", 12),
            width=12, height=2, state=tk.DISABLED,
            command=self.reset_all
        )
        self.reset_btn.grid(row=0, column=1, padx=12)

        # ---------------- 6. 结果显示区 ----------------
        self.result_frame = tk.LabelFrame(root, text="运行结果", font=("微软雅黑", 11, "bold"), padx=10, pady=8)
        self.result_frame.pack(pady=10, fill=tk.X, padx=30)

        self.result_label = tk.Label(
            self.result_frame, text="等待采集第 1 张人脸基准...",
            font=("微软雅黑", 11), justify=tk.LEFT, anchor="w"
        )
        self.result_label.pack(fill=tk.X)

        # ---------------- 7. 启动预览循环 ----------------
        self.update_preview()
        self.status_label.config(text="步骤 1/3：正对摄像头，点击按钮采集第 1 张人脸")

        # 窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def update_preview(self):
        """实时刷新摄像头预览"""
        if not self.running:
            return
        ret, frame = self.cap.read()
        if ret:
            self.current_frame = frame.copy()
            # 缩放预览画面，降低CPU占用
            frame_show = cv2.resize(frame, PREVIEW_SIZE)
            frame_rgb = cv2.cvtColor(frame_show, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(frame_rgb)
            imgtk = ImageTk.PhotoImage(image=img)
            self.preview_label.imgtk = imgtk
            self.preview_label.configure(image=imgtk)
        self.root.after(20, self.update_preview)

    @staticmethod
    def calc_cosine_similarity(feat_a, feat_b):
        """计算两个特征向量的余弦相似度"""
        return np.dot(feat_a, feat_b) / (np.linalg.norm(feat_a) * np.linalg.norm(feat_b))

    def extract_face_feature(self):
        """从当前帧提取单张人脸特征，失败返回None"""
        if self.current_frame is None:
            messagebox.showwarning("警告", "摄像头未就绪")
            return None

        faces = self.face_app.get(self.current_frame)
        if len(faces) == 0:
            messagebox.showwarning("未检测到人脸", "请正对摄像头，保持光线充足")
            return None
        if len(faces) > 1:
            messagebox.showwarning("多张人脸", "请保持画面中只有一人")
            return None

        return faces[0].embedding.copy()

    def save_features_to_file(self):
        """将基准特征序列化保存到桌面dat文件"""
        try:
            with open(FEATURE_SAVE_PATH, "wb") as f:
                pickle.dump(self.base_features, f)
        except Exception as e:
            messagebox.showerror("保存失败", f"特征文件写入错误：{str(e)}")

    def on_capture(self):
        """拍照主逻辑：采集 / 验证"""
        embedding = self.extract_face_feature()
        if embedding is None:
            return

        # ========== 前3次：采集基准 ==========
        if self.capture_count < 3:
            self.base_features.append(embedding)
            self.capture_count += 1
            self.save_features_to_file()

            # 更新界面反馈
            self.result_label.config(
                text=f"✅ 第 {self.capture_count} 张人脸采集成功\n"
                     f"特征已保存到桌面：face_features.dat\n"
                     f"已完成 {self.capture_count}/3 组基准特征"
            )

            if self.capture_count < 3:
                next_num = self.capture_count + 1
                self.status_label.config(text=f"步骤 {next_num}/3：继续采集第 {next_num} 张人脸")
                self.capture_btn.config(text=f"拍照采集 (第{next_num}张)")
            else:
                self.status_label.config(text="采集完成！点击按钮开始人脸验证")
                self.capture_btn.config(text="开始人脸验证", bg="#e8f5e9")

        # ========== 第4次：比对验证 ==========
        else:
            self.do_verify(embedding)

    def do_verify(self, test_feat):
        """执行人脸比对，即时显示结果"""
        # 计算与3个基准的相似度
        sim_list = [round(float(self.calc_cosine_similarity(feat, test_feat)), 4)
                    for feat in self.base_features]
        avg_sim = round(float(np.mean(sim_list)), 4)
        max_sim = round(float(np.max(sim_list)), 4)

        # 判定结果
        is_pass = avg_sim >= SIMILARITY_THRESHOLD
        if is_pass:
            conclusion = "✅ 验证通过 · 判定为同一人"
            color = "#2e7d32"
        else:
            conclusion = "❌ 验证失败 · 判定非同一人"
            color = "#c62828"

        # 拼接结果文本，即时显示
        result_text = (
            f"—————— 人脸比对结果 ——————\n"
            f"与基准1相似度：{sim_list[0]}\n"
            f"与基准2相似度：{sim_list[1]}\n"
            f"与基准3相似度：{sim_list[2]}\n"
            f"平均相似度：{avg_sim}    最高相似度：{max_sim}\n"
            f"判定阈值：{SIMILARITY_THRESHOLD}\n\n"
            f"{conclusion}"
        )
        self.result_label.config(text=result_text, fg=color, font=("微软雅黑", 11, "bold"))
        self.status_label.config(text="验证完成，可点击重新开始再次测试")

        # 按钮状态更新
        self.capture_btn.config(state=tk.DISABLED)
        self.reset_btn.config(state=tk.NORMAL)

    def reset_all(self):
        """重置全部状态，删除临时dat文件"""
        self.capture_count = 0
        self.base_features = []
        self.result_label.config(text="等待采集第 1 张人脸基准...", fg="#000000", font=("微软雅黑", 11))
        self.status_label.config(text="步骤 1/3：正对摄像头，点击按钮采集第 1 张人脸")
        self.capture_btn.config(text="拍照采集 (第1张)", state=tk.NORMAL, bg="#e3f2fd")
        self.reset_btn.config(state=tk.DISABLED)

        # 删除桌面特征文件
        if os.path.exists(FEATURE_SAVE_PATH):
            try:
                os.remove(FEATURE_SAVE_PATH)
            except:
                pass

    def on_close(self):
        """安全释放资源"""
        self.running = False
        self.cap.release()
        cv2.destroyAllWindows()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = FaceTestApp(root)
    root.mainloop()
