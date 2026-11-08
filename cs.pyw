import tkinter as tk
from tkinter import messagebox as M
def msg():
	M.showinfo(message ='Hello,tkinter')
	root.attributes("-fullscreen", False)
root = tk.Tk()
root.title('OK')
root.geometry("300x300")
root.iconbitmap('图标.ico')
root.attributes("-alpha",0.075)
root.attributes("-topmost",True)
lb = tk.Label(root,text = "鼠标指针变蜘蛛\n鼠标指针变蜘蛛\n鼠标指针变蜘蛛\n鼠标指针变蜘蛛",fg = "red",bg = 'blue',relief = "groove",cursor = 'spider',font = "华文新魏 160 bold",anchor = "n")
lb.pack(fill = tk.BOTH,expand = True)
#root.state('zoomed')
root.attributes("-fullscreen", True)
root.attributes("-topmost",True)

B = tk.Button(root,text = '逃生窗',padx = 20,pady = 20,command = msg)
B.pack()
B.place(relx = 1,rely= 1,anchor = 'center')
if __name__ == "__main__":
	root.mainloop()
