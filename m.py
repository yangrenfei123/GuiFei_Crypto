import tkinter as tk
from tkinter import messagebox as mbox

def get_horse_year_blessings():
    """
    获取不同风格的马年祝福语
    返回值：嵌套字典，key为风格名称，value为对应祝福语列表
    """
    blessings = {
        "温馨版": [
            "2026马年到啦，愿你日子红红火火，平安喜乐，万事顺意～",
            "新岁逢马年，愿你身边有温暖，兜里有小钱，心里有甜，岁岁年年都安然～",
            "马年愿你脚步轻盈，前路坦荡，把日子过成自己喜欢的模样，平安又顺遂～"
        ],
        "幽默版": [
            "马年不卷啦！愿你吃好喝好，烦恼跑光，钱包鼓得像小马的肚子～",
            "2026做匹快乐的小马，不用跑太快，只要没烦恼，干啥都顺溜～",
            "马年主打一个：好运骑马来，霉运被马踹，天天乐开怀～"
        ],
        "学霸版": [
            "马年愿你提笔就会，答题全对，逢考必过，学业一路开挂～",
            "新岁策马前行，知识装满口袋，成绩节节高升，未来闪闪发光～",
            "马年勤学不怠，步步稳扎稳打，把努力都变成满意的结果～"
        ],
        "祝福版": [
            "2026马年大吉，祝您龙马精神，万事兴“龙”（马），阖家幸福～",
            "金马迎春到，福气进门来，祝您马年行大运，财源滚滚，吉祥如意～",
            "策马扬鞭迎新春，祝您新岁事事顺，一马当先，马到功成～"
        ],
        "有趣版": [
            "叮！你的马年好运已送达，请注意查收～愿你骑着小马，奔向所有美好～",
            "马年小目标：吃遍好吃的，玩遍好玩的，快乐多到装不下～",
            "2026做只开心小马，蹦蹦跳跳，没心没肺，快乐翻倍～"
        ],
        "搞笑版": [
            "马年许愿：红包多到数不完，懒觉睡到自然醒，肥肉只长别人身～",
            "警告！马年好运已入侵，症状：嘴角上扬，钱包变鼓，干啥都顺～",
            "马年别客气，烦恼全抛弃，快乐冲第一，干啥都给力～"
        ]
    }
    return blessings


def show_blessings(style=None):
    """
    展示指定风格或所有风格的祝福语
    :param style: 可选，指定要展示的风格（如"温馨版"），None则展示所有
    """
    blessings = get_horse_year_blessings()

    if style in blessings:
        print(f"\n=== {style}马年祝福语 ===")
        for idx, bless in enumerate(blessings[style], 1):
            print(f"{idx}. {bless}")
    elif style:
        print(f"❌ 没有找到「{style}」风格，请选择以下风格：{list(blessings.keys())}")
    else:
        # 展示所有风格
        print("===== 2026马年祝福语合集 =====")
        for style_name, bless_list in blessings.items():
            print(f"\n【{style_name}】")
            for idx, bless in enumerate(bless_list, 1):
                print(f"  {idx}. {bless}")


def interactive_mode():
    """交互模式：让用户选择要查看的祝福语风格"""
    print("🎉 2026马年祝福语生成器 🎉")
    print("可选风格：温馨版、幽默版、学霸版、祝福版、有趣版、搞笑版")
    print("输入「全部」可查看所有风格，输入「退出」结束程序\n")

    while True:
        user_choice = input("请输入你想查看的风格：")
        if user_choice == "退出":
            print("✨ 祝你马年大吉，万事顺遂！✨")
            break
        elif user_choice == "全部":
            show_blessings()
        else:
            show_blessings(user_choice)
        print("\n" + "-" * 40 + "\n")


# 程序入口
if __name__ == "__main__":
    interactive_mode()