# GuiFei_Crypto

杨贵妃现在携手 DeepSeek-V4.1-Flash 的加密程序 / 软件。

GuiFei Crypto 工具箱 —— 源码仓库。

## 目录结构

| 目录 | 说明 |
| --- | --- |
| `New/` | 当前主版本 v18.0.0 源码（Qt / PySide6 加密工具） |
| `old_version/` | 历史版本存档（v14.x ~ v16.11.4） |
| `Icon/` | 图标资源 |
| 根目录散落文件 | 各阶段实验性脚本与人脸 / OCR 示例 |

## 安装包

安装程序 `GuifeiCrypto_Setup.exe`（约 603 MB）不放在仓库里，请到
[Releases](../../releases) 页面下载。

## 大文件说明

人脸识别模型 `New/models/buffalo_l/w600k_r50.onnx`（166 MB）使用 **Git LFS** 托管。

克隆仓库前请先安装 Git LFS：

```bash
git lfs install
git clone https://github.com/yangrenfei123/GuiFei_Crypto.git
```

如果已经克隆了，但模型文件只有一百多字节（是 LFS 指针而不是真实模型），执行：

```bash
git lfs pull
```

## 未纳入仓库的内容

- `演示文稿1.pptx`（90 MB，与代码无关）
- `New/dist/`、`New/bin/`、`New/obj/`（PyInstaller 与 .NET 编译产物，可由源码重新构建）
- `GuifeiCrypto_Setup.payload.zip`（安装包载荷，见 Releases）
- `wifi破解2.0-源码.py`、`自动解密.py`（涉及违规用途，不公开）

## 运行

```bash
cd New
pip install PySide6 onnxruntime opencv-python numpy scipy torch Pillow
python v18.0.0.py
```

## 许可

仅供学习交流使用。
