buffalo_l 人脸模型（最小集合）
================================================================
人脸因子只需要下面两个文件，不需要 buffalo_l 里的性别年龄 / 关键点模型：

    det_10g.onnx      16,923,827 字节   （人脸检测）
    w600k_r50.onnx   174,383,860 字节   （人脸识别，输出 512 维特征）

放置位置（任选其一，程序会按顺序查找）：
    1. 源码目录：        <项目>\models\buffalo_l\
    2. 打包时自动带入：  build_exe.py 会把上面这个目录打进 EXE
    3. EXE 同级目录：    <GuifeiCrypto.exe 所在目录>\models\buffalo_l\
    4. 用户目录：        %USERPROFILE%\.insightface\models\buffalo_l\
    5. 环境变量：        GUIFEI_FACE_MODEL_DIR=<模型目录>

获取方式：
    * 直接运行 v18.0.0.py，勾选“人脸因子”，程序会提示自动下载（约 191 MB）；
    * 或者手动下载后放进上面的目录，下载源示例：
        https://hf-mirror.com/DavidHoa/buffalo_l/resolve/main/det_10g.onnx
        https://hf-mirror.com/DavidHoa/buffalo_l/resolve/main/w600k_r50.onnx

提示：
    * 如果下载不完整，程序会保留 .part 文件，下次继续断点续传。
    * 打包后模型会跟随 EXE，换电脑不需要重新下载。
