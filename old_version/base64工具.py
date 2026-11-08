import base64
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

class Base64Converter:
    def __init__(self, root):
        self.root = root
        self.root.title("文件 → Base64 转换器")
        self.root.geometry("600x450")
        self.root.resizable(True, True)

        # 文件路径显示
        self.file_path_var = tk.StringVar(value="未选择文件")
        tk.Label(root, text="选择文件：").pack(pady=(15, 0))
        tk.Label(root, textvariable=self.file_path_var, fg="gray").pack()

        # 按钮
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="浏览文件...", command=self.select_file, width=12).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="转换为 Base64", command=self.convert_and_print, bg="#4CAF50", fg="white", width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="复制到剪贴板", command=self.copy_to_clipboard, width=12).pack(side=tk.LEFT, padx=5)

        # 结果显示区
        tk.Label(root, text="Base64 结果（同时已打印到控制台）：").pack(pady=(10, 0), anchor='w', padx=20)
        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.NONE, height=15)
        self.text_area.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)

    def select_file(self):
        path = filedialog.askopenfilename(title="选择要转换的文件")
        if path:
            self.file_path_var.set(path)
        else:
            self.file_path_var.set("未选择文件")

    def convert_and_print(self):
        file_path = self.file_path_var.get()
        if not file_path or file_path == "未选择文件":
            messagebox.showwarning("提示", "请先选择一个文件！")
            return

        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
        except Exception as e:
            messagebox.showerror("错误", f"读取文件失败：{e}")
            return

        # 转换为 Base64 字符串
        try:
            base64_str = base64.b64encode(file_data).decode("utf-8")
        except Exception as e:
            messagebox.showerror("错误", f"Base64 编码失败：{e}")
            return

        # 1. 打印到控制台
        print("\n" + "=" * 60)
        print(f"文件：{os.path.basename(file_path)}")
        print(f"大小：{len(file_data)} 字节")
        print("Base64 内容：")
        print(base64_str)
        print("=" * 60 + "\n")

        # 2. 显示在文本框（自动换行关闭，支持横向滚动）
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, base64_str)

        messagebox.showinfo("完成", "Base64 转换成功！\n结果已打印到控制台，并显示在下方文本框。")

    def copy_to_clipboard(self):
        content = self.text_area.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("提示", "没有可复制的内容！")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        messagebox.showinfo("提示", "已复制到剪贴板！")

if __name__ == "__main__":
    root = tk.Tk()
    app = Base64Converter(root)
    root.mainloop()