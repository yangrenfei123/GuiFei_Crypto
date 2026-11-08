
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


ICO_BASE64 = '''AAABAAEAICAAAAEAIACoEAAAFgAAACgAAAAgAAAAQAAAAAEAIAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHtoZgBlUlEEgXBuH4t9e1VyaW15Wl50GV1hdgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJB7dQCLdm8EiHVwI2paXSdLWY0BbW6LAHhoZQCejIcel4eDY6GTkKWuo6Lcvra3+re2vfSWorc8maS4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAK+dkgCplYoGs6KYQLeooZ25rKjioJujyY2YtxiZobkA++jcAsm+uqDHv77/1tDS/+Dc4P/k4ub/zM/Z+HV9l45CQlkiAAAAACkqPgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALGcjwDb0cgAxLSpJcq8s5vTyMLv3tjV/+bi4v/Y2N/4srnOT7rB0wD///8A5uLihuXj5//m4+j+5uLn/uXh5v7a2uH+sbPB/n6BlNhYYHpiOEhrCEVScgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADMua0A////ANXFu0Pbz8jR5N3Z/+rm5f/q5+f+6ebn/+Pi5P/Kzdl/6urrAOjk5QDp5OQc5uTmx+Xi5//m4uf+5eLn/+Ph5v7k4ub+1NTc/5+nufZrfZyNR2KMDlNskgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzrqtAOvh2wDez8VF5drT4Ovl4v/s6Ob+6ufm/unn5//o5+fq5eTlrtvc4Dvt6+kA5dvZAOjm6QDp5eZG5uPn7OPh5vzj4ebe5OLm9+Pi5f/j4+X+39/l/7O9z/x7krWOTXGjCGGAqwAAAAAAAAAAAAAAAAAAAAAAAAAAAKeHbwDl184A49TKJ+re2NPv5uP/7+fk/uzn5f/q5+Xz6efmnOfk5TTf4OMF4t/gAAAAAAAAAAAA7vH2AP7//wHo5+t34uLnstzd4ynk4+Ve5OTm0+Pj5f/j4+f+4ODm/7fD1/eCn8JlydPkAGKFsAAAAAAAAAAAAAAAAAAAAAAA5tXKAODLuwXt4dqa8Ofi//Dn4/7u5uP/6+Xj6Onk42Hm4uIG/zIAANSYXy7NkVdiyYxRacmNUGjKjFFmyY5UY8uUY2bHm3hOonFVBdXFvQDl5OYn4+TmuOLi5//h4ef+293n/6/B19Z9oMYhhabJAAAAAAAAAAAAAAAAAAAAAADw49sA7+HYOPLo4uvx6OT/8Ofj/+zl4vHo4d9diGR7AOq5ggDrt30k4Klo1duhXv/Ynlv/0JNV/9CTUv/Mklj/zJNY/sqUXO2/kWpKw5BiAOPi5gDj4uUj3+Dmyt/f6P/f3+n+z9fk/qS913HM2eYAcJO8AAAAAAAAAAAA5dHEAPz6/ADz5+GC8unl//Ho5P7u5uL/5+DfldjM0QTg19gA7rx/AO68gEjjrWr436Vd/sCLgv6HVY/+ll91/oZcl/66glf+zpZa/8SWbHrPlVUA1tPYANja4wDZ2eBS2dvk9dzd5//a3ef/v8/guXyozwmTs9MAAAAAAAAAAADy49kA9eTZCfXq5bvy6eX/8ejk/+vj4ene2Noz4NrcAAAAAADvvYAA776CTeSva/rfpl7+zJZ5/n1Yxv5eQM/+f1id/sOKWP7Ol1r/xZdsgdOUTAA4KjAAzszSAM3L0A/U1t/D2Nvl/9vc5v/O1+Tgq8beIa3G3gAAAAAAAAAAAPnt5gD67ucZ9ezn2PLo5P/w5+P/5t/evsjBzArOxs8AAAAAAPC/ggDxwIRN5LBs+t+nYP7Dj4H+elbJ/m9Pz/51T6D+u4NX/s+YW//GmW6B1JRLAEEvMQC6sbQA9P//ANDQ2JLU2OP/2Nvl/9Pa5fG8z+I4vtHjAAAAAAAAAAAA+e/qAPrv6iX17Ojm8unl//Do5P/h292iAAA7AaugswAAAAAA88SJAPPEik3ms3D636li/sqXgP6vgJf+wI2C/qV5mf7KlGH+0Zte/8iddIHUlkwASzc4AJSAeQDk8f8A0MzQiNTY4v/X3OX+1Nzm98PU5ETH1+UAAAAAAAAAAAD57+kA+e/pJvXs5+by6eX/8Ojk/9zV261qZZoEoZu0AAAAAAD1y5oA9sybQ+3AhfbjsG3/4a5w/+CtcP/eq2//3alt/9qlaP7VqHv/za+ec9SvkQBFMTQAwK+mAJFLCwHW0NGi2Nrk/9rc5v/V3Ob1xNXkP8bW5QAAAAAAAAAAAPjt5wD57ucZ9evn2fLp5f/x6OT/2tTa1KWhuxirpr0AAAAAAPXOpAD20KkT88ufqOa0e/3iv6zk5tDL1+bRytrozb3h4LF//de8rcrUyNMq1cbMAAAAAADQwroA0cC1GNzW19Lc3ef/3N7o/9Xc5ujB0+MqwtTkAAAAAAAAAAAA9ejfAPjp4Aj16+a38unl//Lp5f7h2t34sq3CWczI2ABrZIIA6MCzAPLEhgD0x4o336pv7s+XfGLn6v8U4Nv3F+zJpzzZqXHqw56AaMCQYwDY1/AAuqidAOjf2wDazsde4N3g+d7f6f7d3uj/09vmxrTM3w+3zd8AAAAAAAAAAADs288A9vDuAPXq5Xnz6ub/8unl/uzk4v/CvczEjoilGZuVrwAAAAAA9MeLAPjMkCbisHXmyYdad+LCcwDmsnIA6LFuP9ancO7DoohUxKCDAGJIOgDXycEA0sO5IODY1Mzj4eb/4eHo/t3f5//O2OSD////AJ230AAAAAAAAAAAAAAAAADz5+EA8ubgLfPp5ePy6eX/8enl/tzW2/6uqLyYfnGKDpCGngD7z48A/96fBvDEiqHaomnnz41We9aWW2XcpmrK0qqD0sWupR7HrqEA1ci/AMm5sBbd0syo5eHh/+Tk5v7i4ef/2d7m48PR4C/J1eIAAAAAAAAAAAAAAAAAAAAAAOja0ADRt6AB8ebhhfLp5f/x6OT+7+fk/tLM0/upnK2ihm11Ir2qmguwoKBmuqOYTe7AhJ/ks3nn4LB97Nyyi8HTtaQ+2KRxAIVpWgHIt60y2s7HtOXf3v3l5Of+5OPl/t/g5v3Q2ON/AFGhAa3B1wAAAAAAAAAAAAAAAAAAAAAAAAAAAO3g2QDr3dUY8ObhvPDo5P/w5+P+7ebj/tXN0v60oqbUu6afoNjOzfa0scOyoJagFO/MpSTlyLQs38rMDqiUigq+q6E5zb+2jNvQyuPl39//5uPo/uTj5v7h4uX/1tvjs7zK2xTDz90AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyrOjAO3k3wDo3dYs7OTgyO7n5P/v5+T+6+bk/uLc2//f1dL/6uTj/9TS2vqnqL9r////AK2enQC+qJwF0cO8ldfMxvLh2dj/5uLl/+fj6P7l4+f+4uLl/9nc473Fz90k09njAGB9pAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyrSmAPHr5wDm29Qn6+Ler+zl4vvr5uT/6+bk/uvm5f7p5OX+5uLk/8PE0t2Sl7EtoaO3AMCpmgXi29mw5eLl/+fk5/7n4+j+5eLn/+Hg5fnY2uGkxMzZH9ja4QB1kbUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoX9rAOfd1wDg0ssQ597abenj4Nfq5eP+6uXj/unk5P7o5OT/3Nrf/7S4yXHQ0t4A7OvtAN/Z2Grk4uT+5ePm/+Pg5vvd3OLO09XeY7vE0wzJztoADCBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM28sQD37ukA5NfQYOrk4P3o5OL/5+Pi/eTh4+re3OC+xsnVPtvb4QDa0tAA2NDOId7c3rrb2+Cw1NXeX8TI1Bj///8Akp+4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOje2QDk2dJF5N/ezuDd4Kfb2d5n1NLaL8HD0QsAABAAfomqALGoqAC2q6kBwL/HDrK2xgfa2N4ANEBoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAx727AMa9ugTIwscTt7TFBMfDzQAREVoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA///////////////////B///DAf//AgD//gMAP/wDAB/4A4AP8AeAD+AQBAfgYAYH4GAHA8DgBwPA4AeDwOAHg8DgBwPA4AcDwPAPA+BxjgfgMAwH4AAQB/AAAA/4AYAf/ACAP/4AwH//gMH//4HH//+P//////////////////8='''

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
