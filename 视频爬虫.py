import requests
from bs4 import BeautifulSoup
import os
from urllib.parse import urljoin, urlparse


def get_desktop_path():
    """获取系统桌面路径（跨平台兼容）"""
    if os.name == 'nt':  # Windows系统
        desktop = os.path.join(os.environ['USERPROFILE'], 'Desktop')
    else:  # macOS/Linux系统
        desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
    return desktop


def download_video(video_url, save_path, file_name):
    """
    下载视频文件
    :param video_url: 视频完整链接
    :param save_path: 保存目录（桌面）
    :param file_name: 保存的文件名
    """
    # 避免文件名重复，添加序号
    full_path = os.path.join(save_path, file_name)
    count = 1
    while os.path.exists(full_path):
        name, ext = os.path.splitext(file_name)
        full_path = os.path.join(save_path, f"{name}_{count}{ext}")
        count += 1

    try:
        # 分块下载（处理大文件）
        response = requests.get(video_url, stream=True, headers=headers, timeout=30)
        response.raise_for_status()  # 抛出HTTP错误

        # 写入文件
        with open(full_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

        print(f"✅ 视频下载完成：{full_path}")
        return True
    except Exception as e:
        print(f"❌ 下载失败 {video_url}：{str(e)}")
        return False


def crawl_webpage_videos(url):
    """
    爬取网页中的视频链接并下载
    :param url: 用户输入的网页地址
    """
    # 桌面路径
    desktop_path = get_desktop_path()

    try:
        # 发送请求获取网页内容（模拟浏览器）
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        response.encoding = response.apparent_encoding  # 自动识别编码

        # 解析网页
        soup = BeautifulSoup(response.text, 'html.parser')

        # 查找所有video标签（核心：提取视频源）
        video_tags = soup.find_all('video')
        if not video_tags:
            print("⚠️ 未在该网页中找到可直接访问的视频标签")
            return

        print(f"🔍 找到 {len(video_tags)} 个视频资源，开始下载...")

        # 遍历所有视频标签，提取并下载视频
        for idx, video_tag in enumerate(video_tags):
            # 提取视频源（优先src，再找source标签的src）
            video_src = video_tag.get('src')
            if not video_src:
                source_tag = video_tag.find('source')
                if source_tag:
                    video_src = source_tag.get('src')

            if not video_src:
                print(f"⚠️ 第 {idx + 1} 个视频未找到有效链接，跳过")
                continue

            # 处理相对链接，转换为绝对链接
            video_url = urljoin(url, video_src)

            # 提取文件名（从URL中解析）
            parsed_url = urlparse(video_url)
            file_name = os.path.basename(parsed_url.path)
            if not file_name:  # 如果URL没有文件名，自动生成
                file_name = f"video_{idx + 1}.mp4"

            # 下载视频到桌面
            download_video(video_url, desktop_path, file_name)

    except requests.exceptions.RequestException as e:
        print(f"❌ 网页访问失败：{str(e)}")
    except Exception as e:
        print(f"❌ 程序执行出错：{str(e)}")


# 模拟浏览器的请求头（避免被网站拒绝访问）
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

if __name__ == "__main__":
    # 获取用户输入的网页地址
    webpage_url = input("请输入要爬取视频的网页地址：").strip()

    if not webpage_url:
        print("❌ 网页地址不能为空！")
    else:
        # 补全URL协议（如果用户只输入了域名）
        if not webpage_url.startswith(('http://', 'https://')):
            webpage_url = f"https://{webpage_url}"

        print(f"🚀 开始爬取网页：{webpage_url}")
        crawl_webpage_videos(webpage_url)
        print("\n🏁 爬取任务完成！")