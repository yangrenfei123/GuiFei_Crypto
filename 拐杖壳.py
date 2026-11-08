import time
import os

a = time.time()
b = int(a)
c = str(b)
d = c[-2:]
print(d)
e = int(d)
f = 2 * e
g = 1 + f
time.sleep(10)
i = input("奇怪的数字：\n")
j = int(i)
if j == g:
    print(j)
else:
    print("no")
