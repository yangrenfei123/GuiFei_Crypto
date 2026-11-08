import cv2
import insightface
from insightface.app import FaceAnalysis
from insightface.data import get_image as ins_get_image


def real_time_face_detection():
    # 1. 初始化insightface人脸检测模型
    # 设置providers适配不同环境（CPU/GPU），CPU环境用['CPUExecutionProvider']
    app = FaceAnalysis(providers=['CPUExecutionProvider'])
    # 加载人脸检测模型（默认使用retinaface_mnet025_v2）
    app.prepare(ctx_id=0, det_size=(320,320))  # det_size为检测输入尺寸

    # 2. 连接摄像头：0 表示电脑默认摄像头（外接摄像头可尝试 1、2 等）
    cap = cv2.VideoCapture(0)

    # 检查摄像头是否成功打开
    if not cap.isOpened():
        print("错误：无法连接摄像头！请检查摄像头是否被占用或驱动正常")
        return

    print("摄像头已连接，按 'q' 键退出...")

    # 3. 循环读取摄像头每一帧画面
    while True:
        # 读取一帧视频（ret：是否读取成功，frame：当前帧画面）
        ret, frame = cap.read()
        if not ret:
            print("错误：无法读取摄像头画面")
            break

        # 4. 使用insightface检测人脸
        faces = app.get(frame)  # 返回人脸检测结果列表

        # 5. 在画面上绘制人脸框（绿色框，线宽2）
        for face in faces:
            # 获取人脸框坐标（x1, y1, x2, y2）
            bbox = face.bbox.astype(int)  # 转为整数坐标
            x1, y1, x2, y2 = bbox
            # 绘制矩形框
            cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)
        

        # 6. 显示实时画面
        cv2.imshow('InsightFace 实时人脸检测', frame)

        # 7. 退出逻辑：按 'q' 键关闭窗口（等待1ms检测按键）
        # 注意：原代码waitKey(0)会导致画面卡死，改为waitKey(1)
        if cv2.waitKey(1) & 0xFF == ord("q"):
            break

    # 8. 释放资源（关键！避免摄像头被占用）
    cap.release()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    real_time_face_detection()