import cv2

def real_time_face_detection():
    # 1. 加载预训练的人脸检测分类器
    face_cascade = cv2.CascadeClassifier(
        cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
    )
    
    # 2. 连接摄像头：0 表示电脑默认摄像头（外接摄像头可尝试 1、2 等）
    cap = cv2.VideoCapture(0)
    
    # 检查摄像头是否成功打开
    if not cap.isOpened():
        print("错误：无法连接摄像头！请检查摄像头是否被占用或驱动正常")
        return
    
    print("摄像头已连接，按 'esc' 键退出...")
    
    # 3. 循环读取摄像头每一帧画面
    while True:
        # 读取一帧视频（ret：是否读取成功，frame：当前帧画面）
        ret, frame = cap.read()
        if not ret:
            print("错误：无法读取摄像头画面")
            break
        
        # 4. 转为灰度图（人脸检测对灰度图更高效）
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        
        # 5. 检测当前帧中的人脸
        faces = face_cascade.detectMultiScale(
            gray,
            scaleFactor=1.1,  # 图像缩放因子（越小检测越细，但速度慢）
            minNeighbors=10,   # 候选框筛选阈值（越大误检越少）
            minSize=(30, 30)  # 最小人脸尺寸（过滤过小的检测框）
        )
        
        # 6. 在画面上绘制人脸框（绿色框，线宽2）
        for (x, y, w, h) in faces:
            cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)
        
        # 7. 显示实时画面
        cv2.imshow('哟西', frame)
        
        # 8. 退出逻辑：按 'q' 键关闭窗口（等待1ms检测按键）
        if cv2.waitKey(0) & 0xFF == ord("q"):
            break
    
    # 9. 释放资源（关键！避免摄像头被占用）
    cap.release()
    cv2.destroyAllWindows()

if __name__ == "__main__":
    real_time_face_detection()
