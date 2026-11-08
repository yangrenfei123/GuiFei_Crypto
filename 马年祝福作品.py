import tkinter as tk

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
            '2026马年大吉，祝您龙马精神，万事兴"龙" (马），阖家幸福～',
            "金马迎春到，福气进门来，祝您马年行大运，财源滚滚，吉祥如意～",
            "策马扬鞭迎新春，祝您新岁事事顺，一马当先，马到功成～"
        ],
        "有趣版": [
            "叮！你的马年好运已送达，请注意查收～愿你骑着小马，奔向所有美好～",
            "马年小目标：吃遍好吃的，玩遍好玩的，快乐多到装不下～",
            "2026做只开心小马，蹦蹦跳跳，没心没肺，快乐翻倍～"
        ],
        "搞笑版": [
            "马年许愿：红包多到数不完，懒觉睡到自然醒，肥肉不再堆腰上～",
            "警告！马年好运已入侵，症状：嘴角上扬，钱包变鼓，干啥都顺～",
            "马年别客气，烦恼全抛弃，快乐冲第一，干啥都给力～"
        ]
    }

def show_():
    text.delete("1.0",tk.END)
    b = Sbox.get()
    if b != "全部":
        b = blessings[Sbox.get()]
        n = 1
        for i in b:
            text.insert(tk.END,f"{n}、{i}\n\n")
            n += 1
    if b == "全部":
        for b in blessings:
            n = 1
            b_2 = blessings[b]
            text.insert(tk.END,f"{b}:\n")
            for i in b_2:
                text.insert(tk.END,f"{n}、{i}\n\n")
                n += 1
            text.insert(tk.END,"\n\n")
root = tk.Tk()
root.title("🎉 2026马年祝福语生成器 🎉")
root.configure(bg="Red")
root.geometry("350x350+500+200")
root.attributes("-topmost", True)
root.attributes("-alpha",0.95)
root.rowconfigure(0, weight=1)
root.rowconfigure(1, weight=1)
root.rowconfigure(2, weight=1)
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)
root.columnconfigure(2, weight=1)

a = tk.Label(root,text = "选择对应的风格 可生成马年祝福语哦",fg= "blue",bg = "Red",cursor="spider")
a.grid(row = 1, column = 0)

Sbox = tk.Spinbox(root,values= ("温馨版","幽默版","学霸版","祝福版","有趣版","搞笑版","全部"),width=40,state = "readonly",cursor="spider")
Sbox.grid(row = 3, column = 0)

B = tk.Button(root,text = "生成",bg = "white",cursor = "spider",command = show_)
B.grid(row = 3, column = 1)

text = tk.Text(root,width=40,height=20,cursor = "spider")
text.grid(row = 4, column = 0,sticky=tk.NSEW)

if __name__ == "__main__":
    root.mainloop()
