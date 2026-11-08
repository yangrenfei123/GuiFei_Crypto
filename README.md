# GuiFei_Crypto

杨贵妃现在携手 DeepSeek-V4.1-Flash 的加密程序 / 软件。

本仓库只包含 GuiFei Crypto 各版本的源代码。

## 版本目录

### 根目录（早期版本）

| 文件 | 说明 |
| --- | --- |
| `v13.7.3.pyw` | v13.7.3 |
| `新图标v13.7.3.py` | v13.7.3（换图标版） |
| `作品.py` | 迭代版本 |
| `改进版.py` | 迭代版本 |
| `新1.py` | 迭代版本 |
| `新2.py` | 迭代版本 |
| `最新作品.py` | 迭代版本 |

### `old_version/`（历史归档）

| 文件 | 版本 |
| --- | --- |
| `14.1.2.pyw` | v14.1.2 |
| `14.3.2.pyw` | v14.3.2 |
| `14.4.1.py` | v14.4.1 |
| `15.0.0.py` | v15.0.0 |
| `15.4.2.py` | v15.4.2 |
| `15.6.3.py` | v15.6.3 |
| `16.8.9.py` | v16.8.9 |
| `16.9.2.py` | v16.9.2 |
| `16.11.4.py` | v16.11.4 |
| `v17.6.3.py` | v17.6.3 |

### `New/`（当前版本 v18.0.0）

| 路径 | 说明 |
| --- | --- |
| `v18.0.0.py` | 主程序入口 |
| `src/core/` | 加密核心源码（`crypto.cpp`、`crypto.h`、`scrypt.cpp`、`common.h`、`util.cpp`） |
| `src/tests/` | 加密算法单元测试（AES-GCM、BCrypt、HMAC、BCH 等） |
| `src/tools/` | 辅助工具（卸载程序） |
| `_setup_app/` | 安装程序源码（WPF） |
| `build_cpp.py` / `build_exe.py` / `_make_installer.py` | 构建脚本 |
| `models/buffalo_l/` | 人脸因子模型（见下方说明） |

## 安装包

安装程序 `GuifeiCrypto_Setup.exe` 见 [Releases](../../releases) 页面。

## 人脸模型说明

v18.0.0 的人脸因子需要 `models/buffalo_l/` 下的两个模型：

- `det_10g.onnx`（人脸检测）
- `w600k_r50.onnx`（人脸识别，输出 512 维特征）

模型较大，使用 **Git LFS** 托管。克隆前请先安装 Git LFS：

```bash
git lfs install
git clone https://github.com/yangrenfei123/GuiFei_Crypto.git
```

若模型文件只有一百多字节（是 LFS 指针而非真实模型），执行：

```bash
git lfs pull
```

如果不需要人脸功能，构建时可以跳过模型：

```bash
python build_exe.py --no-models
```

## 运行

```bash
cd New
pip install PySide6 onnxruntime opencv-python numpy scipy torch Pillow
python v18.0.0.py
```

## 许可

仅供学习交流使用。
