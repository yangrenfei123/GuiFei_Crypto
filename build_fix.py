import os
import sys
import shutil
import subprocess

# 1. 定位 webrtcvad.py 的绝对路径
try:
    import webrtcvad
    vad_path = webrtcvad.__file__
except ImportError:
    print("错误：当前环境没有安装 webrtcvad，请先执行 pip install webrtcvad==2.0.10")
    sys.exit(1)

print(f"找到 webrtcvad 路径：{vad_path}")

# 2. 读取文件内容，注释掉 import pkg_resources 并添加版本号
with open(vad_path, 'r', encoding='utf-8') as f:
    content = f.read()

# 备份原文件
backup_path = vad_path + '.backup'
with open(backup_path, 'w', encoding='utf-8') as f:
    f.write(content)

# 修改：注释掉 import pkg_resources，并确保有 __version__
lines = content.splitlines()
new_lines = []
version_added = False
for line in lines:
    if 'import pkg_resources' in line and not line.strip().startswith('#'):
        new_lines.append('# ' + line + '  # 已被自动脚本注释')
    else:
        new_lines.append(line)
    # 如果文件中没有 __version__，则在文件开头插入版本号
    if '__version__' in line:
        version_added = True

if not version_added:
    # 在第一行前插入版本声明
    new_lines.insert(0, '__version__ = "2.0.10"')

# 写回修改后的内容
with open(vad_path, 'w', encoding='utf-8') as f:
    f.write('\n'.join(new_lines))

print("已修改 webrtcvad.py，移除了 pkg_resources 依赖。")

# 3. 清理上次打包的缓存
desktop = r'C:\Users\Administrator\Desktop'
spec_file = os.path.join(desktop, '15.6.3.spec')
build_dir = os.path.join(desktop, 'build')
dist_dir = os.path.join(desktop, 'dist')

if os.path.exists(spec_file):
    os.remove(spec_file)
    print("已删除旧的 spec 文件。")
if os.path.exists(build_dir):
    shutil.rmtree(build_dir)
    print("已删除 build 缓存。")
if os.path.exists(dist_dir):
    shutil.rmtree(dist_dir)
    print("已删除 dist 目录。")

# 4. 执行打包（窗口程序，禁用控制台，使用单文件模式）
pyw_script = os.path.join(desktop, '15.6.3.pyw')
cmd = [
    'pyinstaller',
    '--onefile',
    '--clean',
    '--noconsole',
    pyw_script
]
print(f"开始打包：{' '.join(cmd)}")
subprocess.run(cmd, shell=True, cwd=desktop)

# 5. 恢复原文件
with open(backup_path, 'r', encoding='utf-8') as f:
    original = f.read()
with open(vad_path, 'w', encoding='utf-8') as f:
    f.write(original)
os.remove(backup_path)
print("已恢复 webrtcvad.py 原文件。")
print("打包完成，exe 在 dist 文件夹内。")