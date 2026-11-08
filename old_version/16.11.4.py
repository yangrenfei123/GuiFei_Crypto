# ========== 前置：屏蔽人脸识别相关弃用警告 ==========
import warnings
warnings.filterwarnings("ignore", category=FutureWarning, module="insightface")
warnings.filterwarnings("ignore", category=FutureWarning, module="skimage")

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import os
import sys
import io
import zlib
import re
import hashlib
import hmac
import struct
import tempfile
import zipfile
import traceback
import numpy as np
from PIL import Image, ImageDraw, ImageTk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import pickle
import time
from scipy.spatial.distance import cdist
from scipy.interpolate import interp1d
import tkinterdnd2  # 拖拽核心库
import base64
import json
import threading
import cv2
from insightface.app import FaceAnalysis
import onnxruntime as ort
import librosa
import sounddevice as sd
import soundfile as sf

from resemblyzer import VoiceEncoder, preprocess_wav

# 待内置的 Python 源代码（Base64 编码）
SOURCE_CODE_BASE64 = '''N3q8ryccAANwpEM8wkAAAAAAAABuAAAAAAAAAAy5uQcAEYgEOI4PvBKV/Jc3y2Y/7y0LTtxMCKTaLy4P1mytEmxzK5anFmmYeFSE2rZJqeUEANfQ+xgXGC7AOBtx8epcr8ccPyXYZH92DxyPZLrNbiAtW0gULcXyRPzNxHE1dIjHUygjdqV5hfefTJ9mFyid349kAnF/bas29qw1uLcu6x+hcWIrQxazXr2HZRXFMbiOCRDSaB8KBnbtcb9KyKM5hgLHtpoQfnE8UJTOOwJ5c2xBlnepnoP3zHHdmgzG3tvO7z7v0I+ZJSRyi0BkTUk2SJUCDWaXE6wsleQnhGskVypConshiGl854nOVFkOk1MANgssiJtYozmI3bkJoDUkwrCXiivrPNOuNB8Pitpm9P05qebRFr60/PJSKNx/fUW6izUSMgBGPZSHUcqlNtRsRsSydkAqfa9cEn6rfVR2FbgaCh25V8qVXkNhjFGFQatdzp7IxYVkN9zyfnCrptsBbsI4Mp5ZnE0nwVqrSPYHSQ+sHX8suJg5JF7Y9BTGP3a3sgWgYkDnL9XijTBH/dlACCPbJtUWn8FSN9gqNnEelMNplJqNNvwO4hSTFrEGkA1jHOsQXOz0J1Tdohg2hVgHUm5pv9GK0znTON176xZnbxRttgKmtcmKsehVeqOwpLv1meUT/kzFX666RO0yNvFnqL3wToVsF/kuHbGBL+KDv5XZW+65fZuTFkJTPKt6gPb3OJ75Lng1RkvAloYa0VD/DmruCb9zeEymceglR6IEmGZGew+CtwZKf6SJlECPX+N4mEP9nkuGSNES+X7tngMHVBBa5d3ms9z57OQ2+tDo0lhGX2RZ3cL7pvmcl1jfYijvHq/rP+xRkdY8TNFpBg6FDSOOp3g1MmZFvQW64xB3OSHVMsjgw3CgM/k532U9UEAj6BIin0Jiy/aYgX5yVPedzQdb8yxYU7nVdRS5kufjsw1NQEbmBVmkk3KUrN4Bc/2vuLZpAYN8ZS4tOZKXoYIXfvvkfTC39pmTqTQFVOgtHrVsdn0gqKbcLijOX8LoAqDrGDke2goX3h/wRY2WJ17nRQNIwf75CAG6vFX1WIBZbdBq4LAYdQbmieytrckiZ7ULQy0lXMxU9fNKBniZB7AKwtG7qRPi6F2JChyj3J78oA3wfhJ585rkSyJwCNRQZGZRfblELAGNaeUL4J+O1QXUpKCSC1SDEPSGvql+SCajQL2YojQ/76i2FZdWn4Z7uLL7LRMFdcf8imxsqPiqrfUiQaWdkjU6ttGOP+DVC9S+B6Ic7h204eVPMQbLE8v9F4PEmIgnyHK3bVEEIpCg8Mx5VYXEzAHhhWgcNIxiWXVBunOFn3r9WHHVHjjM2Jotz1a6QtCdNPjxZca6VSLzxRUBtFEaNehUq8dqhGESXB9dRnrSNYpNy0P7WheP02QswN8nrXeakShktPchyTo6FWcV/hnqD/mMVFKLNvXBjeD8Lxo0HsLfK+R0uJ+N7rJeu1owvPt7XtpZdNkzgWa7dj9vneff27GkFyVwc6BKtAVzqAFuFjzz1cQSZLx8ZBdrNnCiQs7Ny/CeNrdYLiQloLurRQrjKWcUnsAsoXjqSbb2LGpqwHrzVbFIUEYNm4uVMtQvxhM/UMTS5hJt1nO7b4otOiCGgBv4hr+S/nXElK1ninTCVPdJE9KgqelHNkJWMk22cMb+OWtXP2CBNnsy8fX0aGxU3k+yq9Vq2FKCiIZhN/9+Rp78rnVcX3CKab5Z52V43XwBQVaQr6DXnAx0ImkdAk4Ia1Dm9KjHqjSRQllKatmbuapBZXtvYjPH23+sz81TvC0TnTF0d6KgqOzRvT6RkE5bbouImqV1d0spjzkPraB6BRN++HnGYc7f0vdoTsU6TfkqgKib3oEiB/WJ3VUpjxJk0/2R9YwKCcQ8ff/pNn2upNUE5k5prHpcg2CQg1GqU/0hT4GI6Y40ipt2+QTFK/EyMBKag1Ve20zzkHsIhwrbYDk+iyYiBvvdCoQTVvg69IglVxnnh8IucwUxB4+ezS5Mr3qxU1PLVitiXa/dDNm0RSvRcdAHScnNfGu0f/FOon/4T5NJyjmNiDNHYSXJFye338hd+crOv6DF59bKSqkZU7uDe34JTHfoc5u08ZPJq3KCOjuc2wnKFhA2cjPA4t9AFferfEGTstYTDMkcvyqCnx1ieKbbNti9NlHEJPzZWg0hfZTh9Oc5yE+3RTvnwmZBIi3JXGfZTunpQeEBl9oSwd5Re7+u3/H38xV8Inns/K+3mj+SORWcqsFfk2SfjuqZLvr/SvrvKY82l5uw8B2X6gWr5KQRkFdaI4viqzPIPVQe1fDD349oJBp4RKo8HEwBjsbezU8+hJBrL4RxDD3ai01FvrI5G6eMEBmwYc06Kz8jR7E5CySbe3ftGHjinQq4fqvAY5QrODA916Ctdt645tODsCAsgtlAnBPAUpGYyhwMN7V9yWgwgCFPhAMHdAFhrANqz+yw9+2cg4vZ5yhmSrhrlkYYzgINK7EGzs80gaS35mZTCDxGHmfkKv0BqzBc5R29KHZnmzZ/rK89q/R6/JRYHcF4+4nxYPNu+davjGbrBXRIpzqFqH8WXndvFuGs96MDRk61cKt/OLnJirNPaKSzETBrPQMmbEqk06ZZmzY2LoQ295ZGVUEpyr5SAE5st2izwM4/jdRN9MMJVbg/LrlprheKBdyWzoJIvHX/TwElssXP32LTMNtiFENCXs7Jt46R6FmeMXkkTnXZVkLUguGUpFfVW53/ZIbvHNSqhB2+kL3JkEawH7vZ8OWTZeXdROfZzr5OKVv3JQ4vRzAXcUiGbN7K4pJchBEafXADVpCzlloea2eRSmquHZk2pA9vEOcDXj/Gzar6Cz5XmxQcu6XdnnxmWqcrnw5mbGasMRjEFkecqdfhPoyApwUMn6b9S9d4ifLj/SlkOSpzM5Q61325nQOJ3B7uK429wIXB9Kn+yavTFZvWq9Bb0crb5nfeuV9aLw2Fvv2tMWYf2ey03XQVXHE9lxysQMNBSz4GxJlgUWvS0E8eYOrhdpf57K2WxGIynHilt2Y6dklK7DHPD8JTa2MM53SDV/730xc2jV2hVw5JQjDLjjFY5JDydtcWRWS5lbbrXg2K9d9HYjGnbwMF6HvkcBlePbdhQuzI94S93xhxKMa2NJHIDNbBKdp94BE/6gy9FerT1T9C4j656d4n6M1u0RT/iUirPcHklHDVroD1eGiIwYKYG30BXCeIpaLkayO3V6GPySTee29yvayStBKRCmadvQ6JAFonrcI11bOlvbMKcZpv+3frxfcSB0Bdq/0/NZgxDbC0aQ4ADV1hkN9v6DHXAK0k0Js93snBXuMARYnsX8gjsDJsMJdYi9GUMt5dmiMTs2z8awGeySO4yVlcpUUKqTmEiJ5S6JxGH9jo9hGBW0l0MU79clbU0gqzVWRRziRAGYoebPqXzQi9MNYBO/CJJX/cptce3GkjbbhtmLGfIPDvLMunyg61VasTgiLbrBnQ7AGdK6FAekLZ9DTU3A53to7VZ9kLZ4TK+XlUR5nfluqtYeV68VxlUdW+VYdZEIXPFOn87GCg0qmxrp1ZpbKlXIZqrMbdiWxcd7jzPeIpaihWiBcph5CdXnfqD4TvbovQZuv7VNCAL80HVLKMoSW35htU6F9ILooHWPWU5tGdS/FVH4Qeu0ihnZy1rF3jZor4bpt6WjVSL0FesT81W4gxQWcGggw0r1ukNmnFzx0BLGl0dAt6MRO5zdW1ZDMsuhVHYpTXfdaJOKMcp/aNTcAIBfEw+qg+fY1VExGeNCpjIQTCQ5UiUrj5qCHz+RwjQUr5m1kbPTUBcX7Ovkl021+IUcBy6520OgrgWPU7llryBej/iprrZWgFqbNX6jYHZc6pHm93s4khUsS+Z1fNKLQ9UbBdHK2oN5gAjS+KyGxUbL4grUbJwX7fJ6C0wHtIZwqGC1+MhaP1XFkSr1rlZqDbfhqP6ZJeJVvx80DpDm52Ldw3GsxtQ1k3ocC6jBZfIqbrGfbycpZ8dNquE1754PHgzUjgIVGEhVcxMozn+/eBLCfmkoL2u/ZyGV4m77ugBex7ekACzf8y5FaEnr4w9OvvvafbinKPdzqSSrc/G1gZyZpG2nzGmjh6EehNMzoAuGOew229vp1ceaolx02wfWnhhuNLVD+Jtczq//keBRo7wSE8V8uXRZkPO7I3njSE7UCXwiotaWCD/LPYGSKqjRQ4gfLXJJ+PTX9eJeV95MeMsoH4yANuLrkXzdn1jihx1hDgePiL6p5vOSwThum5BlEi2cCi+IymL4anag8kN0hliCVFuNHqvDovi7cguXCx6roqj4UVQ5VvQkEK8be8qBh9MW3aC/O+6Z6Y1NnOax8bv47ssd93f5mdGqcwWAT6jcF3hiwNsHOF+6v15hNdjSgBm4zKug2K+iJH6jdNgNMA250ltfNRez7lTnDMmmK1bukGgGyC1rCw96S8JRIiTAq49EB9GrWoVEMSQfzfCCEBJbJZOuoWCOJlQ0FhPmAeYghcDWXdIn3tVGgGmFE95Bwu5CRwXC6HzQmDCSbUFt1uNfQHPVNSqeQeN7oqoVK64MFov3xjWoRlXrx0SQOHgCWEPodWj7GZ7/wut2CXJ+SCD1wEE8Yyc24k+3WHO3Ho3JnhAmwiLzl8+Kcwm++YMPLCJBocJDpMZ7JZLYy1N4XaAHU6A3EAdGG0QPVAFQDgjM/z9Elhb8kp8f3A5AnHY9z4lyoL7AN5rbeFPMp23J/xnAk0lKAlPa5W4nbaxvCWSS1A0nLOscVpcTmKZ859U8YwI00ywjRT2P9/aq5VWMxdsa9Ybjd/13RaqIq4Y+/0ViBi7kndRhEJJ/44I8o19cR6dCL4mgR4xarOtFZyK9G2N5egWxKVLZpnZ6pFY8TCLPPbEN2cMVgxE+1Zd9zPFkOssBgjrUIB/428p3PdXGXo4QgZHHXL3akRNM1s7A65/Sh3vsSnlkWaQ+CdJkmpxz+ODVmBZkAIhhWVtLV7tRLJ0jpllsB4cFFOECDcu1seU2pQyMuDIsqYKFdOgc7ZARvTjypDqk6W0DivfwzoV0+nrnoBptQFc8+/bWaMdLIi3z2Sf5BQQqFyJA2eO6amNgp2GJzuAmLY/gleg9HK25zPhfC1W4pJx0vzn2JdilBsU1jFA58UE0TmkXzwmFu5+F/b8wCDQm0KVOLFw9/IS+ZwkTcmCWQdRJAVKYzbz/FvTacDqYVaIQTrb0fJO7mqA/7jeMDknEJC6AezK5StcIUoVZvWXB1xD+sdaL9gWBKCVfXJJy3LmcRjNc/5TntFpkc9JkCDYGoRYQq25TB8/K9lObWdsnkNXhvn8eLqE+XwId3tMqoCikmaKhTVxWoz87F95iXRs/nKjGjpS5MV9YPXjLTGhIy+rE8myjgYlESjMz/zbVf21tAvWdE/w/KKwg0M+hStF6Z560IyCVbdGj4xgJPUO+eQLtv9iBaLYjaECoYNxvwlk0o5TbCxmRbDyN1dwgBd0ROvFvY+AXKgD7138fdy5EMyviyCa4xHPyBbNa6F1U5K2Er/RH0tYTf8e6hEWQ+R9YllgcMreltrWmPlMmxFfgMvv5Kw7eX/6tB85u6gZW+bB4eY1Byg+ri6nrECLvfQpbKxI5jnsHaMewXsu1uFazIsTeKQBNSCqF3Ub3q8FTg+9Z+sb+FLLhz29Z59Iwz6wgwfVHLc9y0AZBqMhBARUdcoCD2d57qjfJf/LD25In/NKfgSgoYf6z945Dkx99ZM4d7COTXJqy3eNf3vgcLjb9Tmt2IuXmAK1ZQJwcfAJp0JX2gF4qimVmN4uc0JKhKiPtR1fFIxSmvCaIjo21rnPlPnzDC6y2TK2vqF2OPyNjztWptsGPDQyVyT5RecWovRGx2vgsCSCCcrkr3HAaKiEyv3+fhZXmhEE1asPUePgGmTQ7NfVqa/biJFtxURZoXXZqwJphbGOUdyPrWbM3jaIT5OzEhJa+f9+cmyWKv5UTOnTE9Jc1Ec9lWqRKUJmoTa6Zw9O1dvJJOLs/g0vfyWW5srnC5P91ZFsjBHQA9eeTyzjaBOn+HyTKbiIbYSoSzjPyveRxwm/0Yif6SYin7yxOY2GIEg9s73ndnzG988QqMv75UW8OYyFwrW+zD39EZlT4F0YQ+Kdpv35UUHXlXSn5XDMf+Mx9wfgdIpkTxRwzHrgNgxSgJ06/lR8hyj2Gu9hehdmbJISMxjYiHaeB4ukR0iTA1TsUgoW01HrhFQAuzvhp8TMU5akNoAzD3hnzpNyq/suYweOkSbB3/ftJJ0P7MBu7Zy66vmErDIEq2U/dN5x4qAkDpppy35QqkFBYB+LDJoLENu/hyc65gqb3s5taWipyo9S/HA0l4iTObUmp47bFr64mIGua2w62quXBBQSZUP5dKam4dLytmimxopjd3W1gVKnnR5U25WIchNJgtP5EIEbqaaLmUPhyWVYQdLnjxVyAmgZ4vxUvXUMLH5cq0/nYvCCxZzoMBX/K93F9rXKj/USUdHAR0d0Nw7r3xb/kCm7xfdFlJXpJ5sr88OS+ibZl49SLD5fqNP602ujFPj68t7FImTedxIMuDnjCLydT1E7ejTtzGZYJkWW7kmeVakrVDD80gIwKMasrnYq9akKmOqDqukR12+a1bhMpZjVY/ce3wRJv9beDvufymzl5WcVwQwAO3Alx17GFffvrXT2LnUDookXMDBZi4DX7BA/kSPgTdzoeowglPtc5GCq01AFBgimH+0YBkHtNHV5hdO5koKwRrWPp2fCFTpW3BaMgf6n/7RdQK9cletOao1A2pfCWZB5pBCBOy/SD2IcNYMO/khglA/pmlsuRiqIlR51ciKVS4c2gxZwludCAjbUXcU60u7ibr8JTX73sBr9ugidtSzRk9TV5ziUskG8wlaIweZ7bC2B2p2V7Lr3uDu8AAU8oEveQa63rnxbZ0NQjF+Z6jbpcKqGHfx38HBxX9BH7gI8Koh1DjhFjLinaTRLCE3roFdoqd9QHu1QVjtZV4usG1MlBwFYlecTriC5NP375dzU6j7UEnSHQ4abRYLc+mh9lGI6HW9CbAFklCokN8JijCFNobMsjSanqwH58cB0vYCUDNw9oceOBxm48y3mCUVOfqzD+EM1hjgqAbi3gZVWhIxPTgdYYtkbXdkRApJb0MVx+tmvskO47OMJtB2u/l81bCmd7kWKLOHbiroDtvlDdg3VCrkCdGV5ZLF0F/PCfZXoF9kYZaWExQ483plc0TXDZSSX0EW48H+rOdH3T0Y3Q6Zi7eJDTma74Ubltz7mQ+GFTrRORCvEaxIhtcC3ncsK4vfNxeujlizBckbgyl5klHnwTgVlpwbqTosdH4ZsyyVCZtHiHCsG4R9yytvGWM2RNx4juSlESqkL5oTd4HQhPgRwkzIksscJP9dP6GEbL5lsEN/VfXLEdgjrZFWVKGzu2P7rGdLop+zCyHP+jDcHrd90DYnH54sbOR112eA4x35Mu1AFLWnbNS9WF3pfmw3hWLNcWzvSKJek8EzAYMvU96s17+OQxasaP4uwdk46ccHegZHlNyBw7VM30c6jeJ4/AQwqXp84I0LLZi0Axo5Mro/6c5EdVzKB98nkEwl9jaglV/XxnGiFz8d6/vn0fG2BkWNjfnmF7IV48edZsGtUXexQ/MzYGyPMmCIBoHJDMMrQDCmD74FfgRrFU2ixSK7m9Xepj+JdQITp2QWPycweJ6/NSXXBL/ykUX+aGnalWqg5omKndQ18E3lIcV94kdKW+z0SVdOjeDFCcOMScORc4QZ8ZCr6mSwZAsqWcct8weSYsUquxibYPVmIJ+opxzkUiQI+zm0gaZVbNyf0ZZxruBJ2tLC5JZmUKS2LKIuWEMDs2mCJzfRkEwpo7d2PUk31fIMwXcsgEsVEF4q6gwgBvc4PMBo8R3x4BUH33z3Gbp2jwVyeN3hXOE5WOcHC7MesMFX+gP0lPv/LqK7dVsyW+xbsx6HRTd50xYfS7Iu1UqdofoeKmicketoyCA3VJSHth6uOVCXr27i1rONn2g9iG6CunFgdJ04Ci8ysQoAgDe5+ctC1nIVt3CpVmo3S0T86W60HLkqgsZcMTbedg8bwdmRm4lyR4UMmWTWN0WORVZN02ucr6XrxZGfuFZJePHSSVNdu96upNPlm8ECmwPT8F8RbPhfZ51Hm5zGxVnPapw+I39zXiJzGQj3DocZo08xghDmd7kcJNfP5eF/K9uzOORyVvvohyMKAme0hLtKdGuIrrqKhn6NtHN9u9QqHeif8kJNA7dW3v7uY8U19ks0FMRYmqJETZrqZt5isuc4L70DVrQsxipHikn/fZf4Qb+Kxl/LAt2y3q7opzR/H2/sjAe1V+ShozqYzrLrMoPelRyb06AtL1KjVBHbYGqYzh6FMT/tZ7l+N4Ytqv39T3w8ODZkcY9NMSKsOMTVDoKBvs6fpGjHxBdClEDg/t3YX4CYWltX6Sefg6ZSOfJw6nYY/I7fcv47XrXn/P7NsTOXKx+KQjzZqj4mZ0iXiW+Qmx/zwpfh1pZiUy/SXxZS5JYhi+EVbdKWXOZB52zSw66PbV0PebXYWQY2hgecGRUT1ifXmRiifrTS+NDvYBSpzndpC4HhDmhp3BDp1ls6vd/xOTk4Q4HzzG8+ihhFf+RWSAMBVLp4LfOQ255qLEXO1fSia22XYZ0BYTeHgXMVHqzOnmmw76ypB/cgJg9+TSjF2y2QPB1t1QqjWJnTGl5enbi+q1D1YP5JFM2Ira9+iA4Sa7o+2kLys/bguqq6uB8A0zbu1g/Tnktnp4W7AMmEfPhQiNW9+mv0m+2pJ/v5peahcX8ycuXdvVVUXLKFA7tfRbTt/ntEBOy/HOVTmdU/mCIsExkrqXwJ0VuechIuCfZWd6OmgG3Ge128rwp9Pz9aGxc//X9FE3D8o64j+vL5Mp7IoaxfCZxhHn2uIge0nP0cO601cM0QoThLhEcePg7S1tqvB8YA4fZILMqPGhTV+bSEoCPSVc7t01oWOxHajdyB2cNSYrm/cFZZGV00LGh7B4V29YQ+W/X3LHjApF9I4obx1G+PRmLOCBFEquoeCQkdSzP0qqu6mJThJ0WBnntj2A3Z90wZKbl4XA/fupcMEZdrKwpRADCY13w1ZQaVcjyLPvE9jZjL4h+lEKbvzii3eOuXSPduARxcMdWp8/0fV9vnonbi1sA90ddvk47pkKjYO54UXbRlP4iWlUthTpV8IiHsjuLHIDW/Y8mJT2VvmkcvNWhcCl4SAntW0AgaFfCHYpEo8M6sj9xf/iep3zvaQLZ3KJr6a61QZS88eGs3JgOf5/5msv8n4fBZOLKAyeYgpxUrHmB3QNYc6jR/uw/GKT91s5Y7nwoeMDf8a0Lhw5YcyItiA7w/0ZE5PZwESM4BsOA1BRDnqlEX7YvqxNgXZQSowP2pm2l7UHts9uOeNKrslB2q626+iX+ief5d6AZyybtv8cZpJ2KgAmZKewEiGkzrll0E2yDxjSC7gRcSWP0/TkhMANlXqmTD9KQCtjQYNwY2abEoJ2a/2+QVSdwZPYjWSfsTwXCEZJcVj9ihmFOK2BiBiAmMeH13I4XFQOZ7gy5l8WoHMFtYbQ8uBj5xzBS/WPU4yQLHVbRo8PmfzyGuXqpQSrPszPj9JRIPhNWMo1GVA6NN0p0CM2lsQjvC+/xSisQXLw+fMqxxiazp64iHsiDxdjE5LUpQnit1hkgBVYwLFAAKLERnteWjEc9Q6cj6+l8vOnQ0onhaEqGzFJ+gtiSboGON2jDSKBiOdg0gKfYSdG37tlakJLfjfquEnnWpCvUR8l3mlTx4sg59hnukCGo8xgAQG0CJ7x3YE/R08UOoqiJHiDi3k/zC+nJLxkrj+FlfNgKrGA3oWKXosN+WSinNwRrCf6QZElMxAIVNK4o5fG1GFk2tei8PkWQheY66T9R/lyRzwGyC4ejoMksQEBg0f4hkfsFKGPDkjiR3CrAU3dIK1TCyP/1VtfzjPZX8W0jvq3PPG2RulTYTK0RU6ZY3aiaqm8A7yLV0ywSMvd8naioeuMvBrv+kJkWXy1ujNwuzBV/Trz0Ln2EMV63S/TZaWTTzrNrdwjQYpvEIbWY6w85tqxSJsYgQiqu73IUvFFKKgM3kI1U1hKSBw6WQMfZy8dP1Bi6dt/Gvj1rxYafi3RxZGXnQvN0p9LYVfxMVJTYmK5uLXLkYOUUT1BlJYpR3gLFqzaq5lL7SSlDseTaCguIvezI1Keu+QEAx1czXhvfDopHaXYrjg3BLmnSkvLLyxBvBB68wW0wVORguH8KVftMrFWRTsKPszqtsYLuFA1OzYNrfffn8h8831Y0buSsnzMfuZvuC72F6a+3ubp1dyd70qKjs6+T2EPIOwBr2MOb6wRHNoF1S0LREKwQma09t2Za3QR6x2BDQhRgS/yxWD+sNivqJOe0K4xXNHHEKgTWLjAomQeLggElT+c31DwJd7FM6cRYEMpBXKAZyDYeFiDqxjyAg3cH2odzla/Z7ACRcuo5xpymZC7EItgp4NjFoNKoJfMQoGcVlkGnMbWFnG1602OE3i0tUwt2uc16cKaf8RO6oMmmn2I5hXBCdM2JoJHtYw1TWuP0YyBMN2QjqzImAFyUYjUh2lla9Jc4f9+/DZ7ReAtWyQsxVus3mlJS6QNm1ZhFyziM/CAgi+C0lRLFG+Ay1VJVa6HqjtVWA36A3mTaaryv3WpAxFzYByIzss+qS0pgp84Ih31ZeKOtX4wN97iCXar+PCxBkJDCUx6+5w+Y4l10hIx69abYqZWI3+8Uxq0iD1eGgkrhJbEGgSvmZOsSn5JweyQ0dxAgNEaM8m/VG5k1z11K7dp4cc+ShuwX3kTITOTfuhRDn4X9MMJje29QLdNus0sVWl3fPgxFQrGkct7/xeCyZFK60loayANq/1VVGr5SLI5++0SZcyfvwoZudg9eN05e20qBNLpazcZKzGshhCh6kU/873thS+rSJqkVFa5mi2Zf1m/LVOwgr1OjvhKVawdhtVRM7JrgP7tDpZS77NP4iXEos1v5GBPhfLwaiQ7oSDt7q6ocQDl6PP6ubEPE++jk8zEnHCtKTt+KG0BNU1UIxOAqsNVmtQHAgsnKUjDls5QhO7zhsxXJVG/lHrw+flyfEjDd0+AM/W5MBmDBjMuGdeGuq1Nr0QsAWiCmXCHaa9wau0H3C5WSWyE7lzRv4oa3PO0NUxsRPtvzuqff7h1wvLvqaO0TYtJ/iS0iyRqrOvURtUvGucCOysfogMxdEjpXm/s03JcXcN+DxiyNYqWccIilatNpG142+tMQlpOdHQMBdKLrAOyeTuR5mhgTZ9DN6ucXAfjyJY6stoL1uXCLJOyhSfxKne7FYxSSetPgt4Wm7wfcRQt8bhm3icwrxlvrA5qY/Tw/0voG7gVIJDa9UqdEwrp1pCuOGK+M00ZBNlCdWo9GlJY4U4pESCWldMPxoYqgsq0I+uMvMsYU3ACTJqzX5i4MqJHm4W36DukEq2C5T4Kn+Zny5KDw5h5Y6qQetleCXxHwZPDXBfRbvPsVFi0UnrJlPLqGQFeSmadjfXSIqe56hUS5LR8oCLLjEA+JPJV+poLQuxl/e1u7LUPaxIg5z7E9V4DSgSDN9jOopq4bGYY4wE0Yiz100v8z0YEDbT9bJWjSe0i6tdyzCjSHEL7o1Ye8djscNdoxO+IiTmUfQyrY573XQjUJ1+lEEMSsPUpVNWGBIiRUdabKpHkraqeN7oyTiLvTyjWaVaW0SH/iklK0sztTX0IcWKMhJcrdo6mpLwQHYPKT15p4rUfqEtxUf071eEYaIhPKiVs2F2NBAf7YeEVkkzNOku6hviZpZQ6t1/dmZndc0R0VF5PyeVoWmSxEsN2vn59q+KJZ2u59Ac3Dl5v8p/ACEIwFecbjZCwekJT0MAHuovelos6p2wOWfYExkjTgIywNSZHyP/FqzNo7cNxCnyQtUDVTdfig6YnN3QDBUJcGagCv1qEIMYEdXUTtt/7lbjbdyk1PZtdt5SGtQIv/7n4874QJGL84smEU5aog0HrMrDzXf0NyhJUkSSP+EEoerccXjfV4qfi7UnJBatc6pwr8bRKH+GjpnvBXXnr+cPLOcoAhiTW8Ha9tnTueCvVTkUXGWICFuulnOUFeg5AzHkOswjuPMF132rC+21TainzqxqQo1lyI/qyRFo3NrLNcF9RhUeC/XtbD61J5ee42YXEYmqwZLwkGX3IlPD+NYCwqlcezaihRioxQKkTUoq5DX5qBIXSYqvUo58eSYBrfciIQFt5/Q5bBWx6cFGq6xd5ngX7TtNpDFR1+4WM4oo2WmoutmuU0NoexXgWxH51Rcgo7odfzLYPJQrwHc8TXkYjrvxkTkAXo4cnh0ab3k7FsFLvhG7ytPOMf25+ahqK9Ex6suujKf+f1uYIkpmmNXqfQqnjgpZwsnn3+63lc+hUn0hiZeA8vbKykc1cJFR3+F6xNQMxhlcSFmmvbxEpLO14SRAkVoGrZ9ohACMa+HxB3Ds5RTT6xRHPUufTisxhUQeKhPHjjpiYKxL6mqaUxYmea4GPtOWQegaD6506vCo4I6UzammKY6IaZ41d6b9hyAUqWUbyxRtOTjz2FZI/UsGu7RTdtauEMKTK3ua2BfMe82GWTBz0EXLLRWg3Crijuw0Ya/s2bwcph/FMbSOwZ14tl00w9MFUMEbcdqFuivFu8BtjHGu6HfqDX5QqmJ/YVx92yQwIzE74Z+M1Xy3i0LrZW9bQztGzNNIyJP0UA6YZNk0Qd5DW/JCAfF8WDKLi9aj6KKw85p/obLa/gTH120GKFGLLTY+RaAyOfxdUN1THG540Ms5BDWF0/0sJaXCpip72VTw4x6Qff4q+mZtmUcc1253+f20nZMhSot+ApgHSMY10s44QPsp9Vgu0oAk4fTHrnpeS51mCY8FzWbKOAwFTYAJqYsr8yoUUz8/FLf4nFU3aMbJFDaKohYcYb54oqN0vXgE7KHGbKw3yXKn2zlGOpCdW8jP1R876/CKHxdPg9QEri6aEQKljAC6MCzl2qaY95WpwvC7BrsuCWMvY3oewBf3NucgMlNiJCljjGRetvQUK6KvgPFFSqpJXJQVlZpS2R5+AsuIdTpcwW2TVbu7iHkBd55zuby3l7LPTnaCRAQcRkUd1ETMQk237rN4vyl0azJ1tzBP5yZL8dcGfBoW4BSEVM9v5sQCBMhXN9KErCYVwO9CJY0K7u1VBIIXvayUOzLhX1HXkSGyCL/VkFXOuxEEFRCog+63aaGqMNQSCguvH3XsLqpWeNrgBD5M3MlD7VDYsQD3U2aPwVxFQsdIo9M2xec9rebxAX8aJVUzrETPTJKvM/OEUksLYvaTcV90iJ8Q/1KY9cEwrBdo5fDreZ7n/3EWCOPuH8P6DQW22Pt2iVCjTBlTX9LZ6onjCi2GTKtIrd4BNyiVu66kwu6snf96pX+qWFbTXhXX+sCcBDtHTSZdE38KXrXZ15qdOkw/CatJLzfgAz/sW/zNPnheXw9MVnbm8Fd5gGFjlGhmlqq+E339PR8thLZ6rnbdEbB9PK4i1wguF3iTgs3ZvBRR8fee5nuzn6Q/ZKX8NO3pX0uiNSfzUH2mTKbj3SKWJ7YZmIW29D8AmrOAYawPHqr6wg2Ud0nv1XwJcNFkhH2N/AadE79tA18GyFV7ZXQ0/bhODC2ceub3CwChgYfPMu1PMKNn0DYcN7PzYbJwZ9c4VBh4NBlME2XL4IHoV3ub0LhABHFLLMkZNX4C4euxXXmJbHAaNPOgb7mdgemWdTlIEx1zlVNkvf4fy649zNdK4jvvWuYU69lxaZ0Ta8PXMSE2vs6/weNz19/RrKYttyVTmM4wgoKoC4ZJ1RT4Z+O2clfNIk1T3IuPNWDBGGtAQQBYck0JjA+pgCfv9LuTyP4nyw2Z0uz0Uu+jnSF5GjC+V/jWyQ7WbcTO+/lXkovJKJzJKObMf313nip435Bd9LAhK9przeC2RqVdhe1IiHZEkwrT2lxe3J+EEK5BAvTaKeIwGStRsasE3Z+8NP9iDKKYdCEcWcTU+xR+8ro4Xl/c8gLsXKW5NwKFRaO/U4Jt3A6UZC4RYrjJYLOF/YXn1ZzwkBGPu3t1vMUZ/h/LOROwGm6qwBMLW5jfDCtJLzDeYh57ZAsiashxCiycSsmAxT4VouhKXMc9ttO8nCrj7gmvNr9HZA+6MCQRqx9bhfCJjP56iv0m+rtjfK7VUcomHp6pz1hgW/x4cl/z4tY54TIzAuHe0h4lo8ZLe9UMN74NIDQhTOaDKtyDJxiKdDxx3PrPAePx/6ipvJf+q8dL2B7wkfu5X7vUv0GMO57X9dZ8R4psXyRK1Ydvb9YlWkgtwPCzsHUQekryB1p26Q0cPTuLl5Vj2PaLS5fvvNw/pwTTfJjouibrT6l44Gi+9Auk+arwG7BWLeYCsgUCiPhERneIWQqocZLNoTpEK3vXruC/l0crGRURbQGqp8EnQkprz4g8dlaPzBNVDO5ZpKtl4jmDroHqs+Kvvxt4wlt2WhZkGboZ5MaMzEdB3NtpzOO7DIBzjt05OfQBe/+KbW6mzSNWRgLkssRcwPWLtYT5cf5+yDD+zVMg+DYLMMFssp31ekT07BxYAzVc4TeJSQkEck+foiVNdz7pkjXFmziQvS/tR+yAsf0P2I0OumbLGayrgjlmh3+mFA+arIVD18ETEWfmv+cdJSisfdX1LuRhCsLLQY5RXzxOztot0Bys4EecMJLDx1odTnHf6x0j7rEwMAdjJWEeSNvdSvzK77mlM8vCCpkuwhv7T78rEdPXf5DYGvUaRMVLZhSY4xLQV1sKqV+TCgtm63+lqhgkvk5PQTf81kAVVuSyKG6kmGq0vLg2zGlR7Qy1ULPzsBffC8otInjJ+kQFLL6gGaNTWkDuoMd3SThlX8KSxphVfXzUHEg7rl1z0N1nF10CpO+Hdeama8klNyQ5dti4qKz3yCQwM9Q8l8QD8KsdrgAhtmBntSO1garKRtvFK9QY4zVPG6cPLoxB5II/oM80OlZZ9CJpYaxdSMpt5lyyRjDSjMfJCg7o3eo1B0JFwutWrLjbwAkyNyO4uEzZtijLu+u2wQt2S7vjKYibf5rkj1UqKZKMftFr2wOYjX3eS8LbYPd9CzVh3F2EW9sYw1aHRJnPo4iULfu4DVu28uefNZXKrr2lAxXXXM4DQFl+2jTFz+9UTe+4Kl8mHduqy1DyWHmZmbJKEXQeH2MdbJ9yz3JRBfpikyNpG0VEBP7QyRD2d5x74SyVFS9cC/vAVXxMRUWctLv4NNYbfAu1z0ilTPFuIZ99P6WZM+R1ob8I0pL5WeB+D1lYf17UuXa95W+DAcLOaQvyLuvPZrm1H7X3tymJyNtvP9McNKF0ls+J5gWJa7z88BWWRWC4s+aX/vs1kkAqOKfuvr40+VlqgyTdGtTQ4wJjEhU4UihuWA4LEuZw1tuc2ImaPghTybrF4t3xzpfuOBhzDj4bZTb6Ide5sw/gmpl16wO8351CP84pmnTPctzeS6+WPoR7Nt1QLMUpshNwYs/sQf+ihxDa5yzO2qPLdiEbxe0TuOIG4YvYtmgFChpZ75AQ2FtOKfLOfbZSHl19RL3KwjkiFPY1TuufFGWuXHwIvxV3yFdrAbNlGq9nELERO/DGpR1ZPWD5TUeCOg1+I96QrOjla62o+mCn9FmDLCW11a+Q+O6G4YCg69kL9FKUfXKcIWWmJvzV9Y+5HHuBQ+XJLlw45Gvxb88ZND3ia849sAfxBJHdXdTh+YuzwkJ5JOGzZonSl9FpsU8FFk3WsHS+WB74t4FF87M+rAg2aVHEAeu03kVcnhfrPWEb2WNZQ/NZOb+HIX7jDhrffepYEOwbvcKb6R2nvsxy2MH6P6W08IMne6pXYhgapn1iKdg99+GFYRndYJJrUpT9gUTur540/VJzL+s2UAAB2tjiqroT1V6QqHqRNxeBZP4h6m3UebtBfHh5qAhiHT4qt/BdtdjhhBnX43gjlPpvLhgRQQmSpZ2I2cW7IBqGRpaTQ2T3ZSn0UC/mHEPNqOBCVvXuLcQ96pKsKCYuOUjEPngufHnNQ8/JU7ugyXbdxrziWC2wFLl9jE+9YXa5419FzQGO2vJu/DddoIGg+8VoRNQk9yt1aipWYqTi0DrT452zyUL7vYdG+aWpiHdMuzwfnfTtPd+ioglTYRV/pqKJCTvni88Sa2hobSkeJFHISvGpDheH6octRbqyp7ClML5dxp0FKB4kG2qhtBo+1rRUI+2mzgqzzvObbfLmd7I6CftCbbNWTkDq8mSHOBtsWagTw0aOPEy4bCz8qv6Rlz2G6iyYT8t87RG3G0z7iXqGhtcPEDeuCMoosbAnize6HMofuLQAAUvHQAlfUnfbSEnxPOhbIJDlq1nyMmOhMcTLXfNiQ8oM7NgkKelXFcjlOZkZr+NVCOXEcQLHmd3FqQ8bpt6IvuNn+pdnq34QxL8g/8NR2Ba0QHtBsoZYs/13kjukjkx/52tcYP2OpOf/8ryO0Djbsr2p0SEdF/fJ/SnuCJSdrFdF2KTGDiOkPSt9l/eiZaIhcg5MDwLJdzKo1AHRxzp8+v5QJOwI2Bd1d3ImWSbURlJy5+/4dnpix9rLRIlhM4CUDLRbNU53ACfHyxDk67NMgBAKACTIRJFF9NuTnAAnuRwjgLAC20tK4JDXyV+QMqQ6uY7zbeVnK8EGezgu9wNZOwwQPQGt0c+u/VgeGjiY9ShaVVznMMtSDLON6JW1JCei8TH7685J81plSzTrtaGaIuPaxsu+d4R5QAyH5N6ARrSdh5IdrYBOtbm/wLmWyP/Vc8DuIPV+diVJsdGiA2D9+CnukyyUGskXj6p2vJpz4mJS5EutaX7roBitxRMNWHtsC7HG3d58SUvwYLYxQn42JAS532Pg0LPt4MnuQ1mLbazXzAlN0MJkBo0xvLw6/iJ50ZfezR7Qe9val06SrxYkg1pCKtEk60y6s+reAbNg0vaq8bSTEYO/WpeZxV5oBMBsYxNBq6UmSZkLLwxwOLAIcTeUP9mTbCLbIDPmCR0AN0kOdb95QgLDSBXhYyUIbYR0Ocp3TBmF7r1G7OBSYZUeUkuCbbRujLCf19MZl5j+LuNho2A7DhmRUS9YGSbury6Gzi8VHmUXS80zLNVGqw7nEb8R2j8KN8EcbuKaW1rvqe4KetcYrxk+YRaWm0hQrrTO2aW28rBc80o4bd3Drf95rerXyqO7DRocdnlK6etNQcyFGDZYVBlVcZpAJrcqQ2FtQRR8XwEARk3offPFrTuWxHzV4msHvOPy012rZXgiqKLo66QK5h9Df3LgKbMTEdWVr1EHe/0GSAnwhdoP5n4l/I8mADk6VJpo2xSkqvloHmbXEIC9Z/FrpjsfjubUkxErWRfPyO5Wzx/jcRD+ndFbLNa6TkpyHx5TW7mz0cTYdpbQEHkWwKYEunoGqa9Ejeqrm6mBNBI/V2Ltpi/1Dnq6zeVHb/CyRTuApAcFFG9UB7cEqSvGLn+Fln2wFpipzhES6mSbYdS8R2UhJR26bbtGCo8Sat4qySvmtXGZjMdK1ggQ/ZwloTeagZkiQWydCM+MZ5RDY/WsvU4j9hh4FajVaGA4bj0m0nOIANBaQZITqTQDfum1/CRAn92Sfuejf1V9PmzOgON4oayRUhY3l+0bp2ZpqMb801DnGuroR7dXrsIWrSrzDYTI48XDkwG03lYbpg7sXPU7XnrRoyKlW84o0usNmcdDdktdSdmbrSTFxuGlra+UTU9yuzadtBaZoVQNTfKrQjSynjGVt1sC1HcpPAgNE9ebktx+xaQAyILsXPuoy2c9n5FbLFOx0OrbBbIKy7sPf9c7pFiCxaOaYRQO0Xs90CaD0TX/JnKqoU54rXUNPkUFrErMsWc9CCm5SM0w2kI6CYRmdzNQgtLOTbzK0OLHsTT4z0f2fbw2lqRtzcFTTQnAKlhExtzDwLHu3yneDP063yNo/YduPlVmM//inQRM7OA+vJL+b6pjblsTBv6qyQx4Ytw+/Q+P30SUFE8JgsFLXROcfhnedXbFdDpCNWHMoVRtlY33AlZ+N8q4WPeRb9N4xRK5P/E6Rzk3L+Tcz6/34/kEFP2PgcYJqvO8Eqz+0iCwEm3gD+Pms9d1h3uYNBJofScOnZm0yjRuKBSLyvcn37oQ9uVucewQO3yATVcK50NwRukFL9XrqJ/6qS1BLUZ7fxd+52iQNhDtQ0Fp/2e2BSryvqEEte4yYHA5jbV3VsGgL/qxS+hdxIikxRg9/7W3ATxz+4MtV8idvXER77Qk6cqicYS9VJ5SgTz95aOElHHtiEU9zVWnvqEag0QqIIbzpPpDDzzkSBShfImKpW5r4ubAY1uKdKE2YDGWzCqC1aikQmd2ULHLsOSg1EaPTH3yn3Y0udW17MUdMhek25V+DXSPQBkONTbCGiJIbvMYf97HLFbP13tAvZPVbyd/DytzCVc59+yMqJXjL2UNINEh4w1hDfa21drt5bBOUOIo6s0imwcYHAtA7Eu0cfWsxP6GveMSZD3mDdFMd+YGHWF6j/4sHjUI89D903Gi1AP0Z3lBP4rCcUsfVchAA63FixNCLqay0MosTObed34UTffbuq4nf3U7g6jVgyOS6feyGpz0ZWTBp6jVLNoJS0QPPfi1sH6X+l2qkd+8Z9DSg+a9HUl2eZUEsrqGez4x4yqUmG4Bw4CsVJwmRKa5veAOGakiIdxFiwXuVuZ6QqmobyMiRhA/KG8I2J+Xt6qXPT8KdNnsRlPzw435MyoQi/m0nkH/cIJ6FGlBryxxPx25knHhYeQeYgQJC00+Bl8JkDxLtIrU2coYmq8YQGHr9hmD1nEdFVwPgA3XxGFBDLJvKqIHIVKFb7o5Ja/LfVAPd3rW+tTEjuO1fVKh4EQEqtBM52G6k66wEkpXizuToUXxHbW811JKcdgT0TMgPAsnoxtN3VN7IJyPJNxG6wRMqCjHH+/HjGeeL3n15bFeym3LQ7yLLzDAFGqWH09ec3CjTpJdUFWEAMxNVVFGoVpkPIFOmCmRMXdP2dvBalzxF/PsNWRQ02HhwdKpONK1SAvNZwX8RRMOAKh/B+izzYVFupn4jSx06eEd7+O4DlZZ+YLhTZfw2y2Zhgkgtt+cYD87aiQ2RS9V+Uz+jSYpw2rS4JCjOIHU+D2CW9I273afsS2RRWX0jw7//3Gt8eQ+lv3/ijrS1q/LouVueYUW83NVoovwisRY5IMkqlQEI5Szco0Rd419r6xxRW0eU9NuqggXeMmbffCoskZPLgau5cswefC/3X9WoDzJ2Jfe2H7ekg3j73/Id21V3vkFKrUl79FL+L1jOAb9qE9qOpYK/90uCLcdtbq14GxUTSHatX4T7VoR+n+M9JzgXnO9ax4OZ8vpkVKWLOCsBpLz1p607oDM9mPsOnfM2R3j09BCj1V9mbjNX0iQ3INF5++u+GRydQGYaRjDH3Eb3XW/SVU4pYGDZtmITQCtakF5dZigZNY18axZ2N/lIAUDewKUk89nOGkn5Fr/kmV/XGzqFwZyD/YgY/yaxx09kKHQtYPwzL264TB5LvKmTtpDaizKNXzGfeWFS1E2DGnD+1WGNeZlnpbI/XgVwHy++HVWyRWpL3ASrkQbBJxAaUrEO/L3/Poj3bojgLyPI5lgXGZS5lOK1OpcrhGdnzwO9hbYtF8p+QvxSHSTatzu2ERMMpLYW+2w31iaITXZ6LvXxHBo2NuAfZ9SR3MKfJbROseNSqfcPz5OeQQ/iDG71SCmRD9zhdPbqbU5WcuUW2GkC3940gHO3pQGk23Fv/83IZcvk7YVmtoo6fH98zNYH8zXPiAelgd0U89Z+yd1bGBbDotbto2CtqSmPwVTIpHOdWFdef1sbyl8GsbXHyLVEY9/Ej2EAQQCqXky6CdUMwAEGL8PZp9X+GpO4CWNr/MqLaIkD0tTKRgDKlG9Dv0AZVOjgD5l4s1DN7O1U9Lcz3c7tCbWgpjmzCkoIxV4gFLDeowoniCKIgL921V3MxRcxOrbS6xe/DY+VEDiDEFmoZZrckLNjMtRTXivcIcED/Bq5zaOnfeNsRRupZuR58HGG8s09XV9iD5bvj9/GGiBOj4U7r9Nt07/H/w1A0XE20gl8QEozRBr1EeLdjZN4BRM6On4bAhQ48EcucEjGhKwcXk0wWJM8bpAcTbvDW0kuEMihlQ6Xj5ckKgeby6jA9GYUHm4/PL6geR9hiiLixPBjuU0+QT4Fd8EkEhUhQ4qWn2OWdn9hn4hpwreVhMv//rjdban+xmjC41wwjp/cq5ZYbicrOiHZmNRdgTdVmQC7VJmKR2OuGnfo2jFUCgHdS+tTfnQjeTD/0g9iJa2qgtytEfDJqpPeDoXXgqt5JPAe1WZkcLm/ZClvdFtPtyI6PMWeZNqOYQL6rwvFyyQmwID9/hoNe0Tz1Buv6kImnpHKWi6h+z8IQhoorXyYbIn2aZJzpx1mJ6sIJ3+rB21mV1PTVoNkWG2P74VgREITMWQqZdDamI9UZPY8CbKC/LZm+2qk9q/Ufda8Q//+bcjvPVSrcvWlbvIZiXq7UvmCRvi3QmaU/SH/shaeiMVhhCVChRTeqfK03VIUAM4CSujlmm/JXPqeGJcxvV+nkgR33DLdfLTbGiy9bnPl1simO3XHbuEs3uVe8Q5SnUUR2T+UT5uVdsCEvgXTPnS8xcaGJhPui+2zZsiEroffeYLnlcYmbNF8EZ6k4kAgy5W1GIPP2WR68/5RY1UOfVeV49C27yyLc8c2RMOwJqSFo9mspI9moTfuTRfSe7NAG+KmMhRES9M2N/tcf5dDsHlwGSQp+dI9Kumk1MUh1SteSTo1nARKdmzS2+Fxk8a6nqSQ7IkTn4euvlMSeVM/XMqohncP55lD6DAn1PTVnF2FBKTzRp2XYTnpzCIK1g1FbUjJW1Ec7rHgTtv40z4PiAVXYClbbtiILkf1YOITaOm0uvipkTpDRFzcgEw/FCw3CDxYMq1NZkWlAibd6o7Etqhb0GOA/za7izaEdU47I3soIWIzMTzH3T8p6Y4SoWFqwbpSpPVUUM/8hEv5KLTvgwUYOQyPVqL2v1tsRJ2rA1D2tjQMDHnGoU3ruQ+3jVbWX00SQ6KDH4kvRjMQkzReER2PB7qAxj8cQoiC93jGNFSk3VIpfKpLdnDsJu97C/JpRPMLabz5y/Tj7eN5bwvJ9ZWmBl3UrMeTgWAK+DcpcKSnETGHWCDcxVSbAl4q4AafGj1aZKJdiD1MAyLJK97AETFg/KkOB8Pyz/DJGxlOnmT8lxK+jfXYfsm6VbJo4TVPQde19kYqbWBzWGUlClog1yP4n6/nXjWiKoRejx4AkQzy2+0uHTJ2Dzwf9Wtiwz42+b0RM+8fAzWYWsQCB1PovePpyizwqXTaUJPoQCsPgXyjWC4QEqOw0gfsXPQKZJsiK6n5Hflny0SeTUX/V4kDbD6s5tzEVL8fagirhwyRpU36ZYVv93hxo681Ae3trodXDY9KjzwpgiiY9VOK2Drs+h5awmQi0oRIzFMspvTPvIVE/tTwBKiV7FfHNCUbk0c3suXFwLQC0I20n4VgSTrXtNzM0T6qPfqODhuG9y33aR8xHml9zQO039qnGxobyihBHUby9zW7J8t38/fZamg0nGhlq+zk7a+lzXKmS4+D2b1u0Q2ZUYaxcNRzHAd10MWR55twrwDo0MeYfjmC2skCW+kjIU5onUr0kxsgAdWm7AJ6Y/ci1vv+X9uvd9EH+qzyJQkzOhVUuadVxt1HmGyZdDpz+jCQpXodQjln5z4zPDQI9cZUk1qWavU/nlYwRLTZRNZPRDWmpgvtDk5XRUqxhEHoukjGny88Drt6poIcWLOmqQnWd0y0CxTDF/pfRMrEJSmjRJUWDWayR86ee+mikdjOo9gDW7p3sI2FB9NpCbyvskqHn+2jUZW4ckYAItcDDHAW758b9PkcxW/4gXyN7yLbaNFdCK0+7KtoZ2QWWOFvhA8DfRYdZgUa3pJms8ew1vWt5ZVd6xufMQUArrSdXYThMnflxwctWqNZwF3YvmKwi4eQ55zfML//jj8KgBBAYAAQnAwkAABwsBAAEjAwEBBV0AAIAADMFvRwAICgED6KyyAAAFAREVADEANgAuADkALgAyAC4AcAB5AAAAFAoBANP4LuoVIN0BEgoBAObYjAEPIN0BEwoBAIApP9E6IN0BFQYBACCAtoEAAA==
============================================================'''  # 请替换为实际的 Base64 字符串

# ========== 全局输出静默与弹窗化 ==========

class _MessageBoxStderr:
    """重定向 stderr，将严重错误信息收集到缓冲区，不打印到控制台"""
    def __init__(self):
        self.buffer = io.StringIO()
        self.full_log = []  # 完整日志

    def write(self, s):
        self.buffer.write(s)
        self.full_log.append(s)
        if "Error" in s or "Traceback" in s:
            try:
                root = None
                for w in tk._default_root.winfo_children() if hasattr(tk, '_default_root') else []:
                    root = w.winfo_toplevel()
                    break
                if root and root.winfo_exists():
                    root.after(100, self._show_error, s)
            except:
                pass

    def _show_error(self, msg):
        if msg.strip():
            messagebox.showwarning("控制台错误", msg[:500])

    def flush(self):
        pass

    def getvalue(self):
        return self.buffer.getvalue()

# 注意：sys.excepthook 的全局设置已移至主程序块内，避免在导入模块时影响其他程序
# 在此仅重定向 stderr
sys.stderr = _MessageBoxStderr()

# ====================== 核心常量定义 ======================
# 加密常量
AES_KEY_LENGTH = 32          # 256位AES密钥
GCM_NONCE_LENGTH = 12        # GCM推荐nonce长度
KDF_ITERATIONS = 310000      # NIST推荐迭代次数
KDF_HASH_ALG = 'sha256'
SIGNATURE_HASH_ALG = 'sha3-256'
ENCRYPTION_MAGIC = b'guifeiCRYPT11'   # 魔数
VERSION = b'1.0'             # 版本号
HMAC_LENGTH = 32             # SHA3-256 HMAC长度
SALT_LENGTH = 16             # 盐长度

# 文件类型标识
FILE_TYPE_TEXT = b'msc'       # 文本文档
FILE_TYPE_FILE = b'guifei'    # 单文件
FILE_TYPE_FOLDER = b'guifeinext' # 文件夹
GRID_SIGNATURE_MATCH_REQUIRED = True

# 4×4宫格常量
GRID_SIZE = 4
GRID_POINT_SIZE = 30
GRID_SPACING = 10

# 人脸识别常量
FACE_SIMILARITY_THRESHOLD = 0.75
FACE_MODEL_NAME = "buffalo_l"
FACE_PREVIEW_SIZE = (480, 360)

# 声纹识别常量
VOICE_SAMPLE_RATE = 16000
VOICE_DURATION = 3
VOICE_EMBEDDING_THRESHOLD = 0.75

# 宫格外层加密标志字节
GRID_FLAG_BYTE = b'\x01'
NO_GRID_FLAG_BYTE = b'\x00'

# ====================== 核心组件 ======================
class LoadingWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("加载中")
        self.configure(bg="#f0f0f0")
        self.attributes('-alpha', 0.8)
        self.attributes('-topmost', True)
        self.transient(parent)
        self.grab_set()

        tk.Label(self, text="GuìFē! :)超级加密工具努力加载中...", bg="#f0f0f0", font=("微软雅黑", 12)).pack(pady=20)
        self.progress = ttk.Progressbar(self, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=20, pady=10)
        self.progress.start(20)

        self.after(10, self._center_window)

    def _center_window(self):
        self.update_idletasks()
        width = self.winfo_reqwidth() + 20
        height = self.winfo_reqheight() + 10
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

class PasswordDialog(tk.Toplevel):
    def __init__(self, parent, title, prompt, show_strength=True):
        super().__init__(parent)
        self.title(title)
        self.parent = parent
        self.result = None
        self.show_strength = show_strength

        self.configure(bg="#e0e0e0")
        self.attributes('-alpha', 0.9)
        self.attributes('-topmost', True)
        self.transient(parent)
        self.grab_set()

        tk.Label(self, text=prompt, font=("微软雅黑", 11), bg="#e0e0e0").pack(pady=15)

        self.password_var = tk.StringVar()
        self.password_var.trace_add("write", self.update_strength)

        self.password_entry = tk.Entry(self, textvariable=self.password_var, show="*",
                                       font=("微软雅黑", 12), bg="#f5f5f5", relief=tk.FLAT, bd=1)
        self.password_entry.pack(pady=5, padx=20, fill=tk.X)

        if show_strength:
            self.strength_frame = tk.Frame(self, height=10, bg="#f5f5f5")
            self.strength_frame.pack(pady=5, padx=20, fill=tk.X)
            self.strength_label = tk.Label(self, text="密码强度: 无", font=("微软雅黑", 9), bg="#e0e0e0")
            self.strength_label.pack(pady=2)

        btn_frame = tk.Frame(self, bg="#e0e0e0")
        btn_frame.pack(pady=15)

        tk.Button(btn_frame, text="确定", command=self.ok, width=10,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="取消", command=self.cancel, width=10,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(side=tk.LEFT)

        self.password_entry.focus_set()

        self.after(10, self._center_window)

    def _center_window(self):
        self.update_idletasks()
        width = self.winfo_reqwidth() + 20
        height = self.winfo_reqheight() + 10
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def calculate_strength(self, password):
        score = 0
        length = len(password)
        if length >= 8: score += 20
        if length >= 12: score += 10
        if length >= 16: score += 10
        if length >= 20: score += 10
        if re.search(r'[A-Z]', password): score += 15
        if re.search(r'[a-z]', password): score += 15
        if re.search(r'[0-9]', password): score += 15
        if re.search(r'[^A-Za-z0-9]', password): score += 15
        common_passwords = {"12345678", "password", "01234567", "1234567890", "abcd1234", "11111111"}
        if password.lower() in common_passwords:
            score = max(0, score - 30)
        return min(score, 100)

    def update_strength(self, *args):
        if not self.show_strength: return
        password = self.password_var.get()
        strength = self.calculate_strength(password)
        for widget in self.strength_frame.winfo_children():
            widget.destroy()
        color = "#ff4444" if strength < 30 else "#ffaa00" if strength < 60 else "#aacc00" if strength < 80 else "#44dd00"
        bar = tk.Frame(self.strength_frame, bg=color, width=int(strength * 4), height=10)
        bar.pack(side=tk.LEFT, fill=tk.Y)
        strength_text = "弱" if strength < 30 else "中" if strength < 60 else "强" if strength < 80 else "极强"
        self.strength_label.config(text=f"密码强度: {strength_text} ({strength}%)")

    def ok(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("警告", "密码不能为空！", parent=self)
            return
        self.result = password
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()

    def show(self):
        self.wait_window()
        return self.result

class AboutDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("关于 GuìFē! :) 超级加密工具")
        self.configure(bg="#f0f0f0")
        self.attributes('-alpha', 0.95)
        self.attributes('-topmost', True)
        self.transient(parent)
        self.grab_set()

        # 显示关于信息（原文本），设置 wraplength 以限制宽度
        about_text = (
            "名称：GuìFē! :)超级加密工具\n"
            "           Windows版\n\n"
            "版本：v16.11.4\n\n"
            "特点：\n"
            "    AES-256 军用级加密\n"
            "    scipy密钥派生安全无虞\n"
            "    16 宫格密码再防护\n"
            "    新增人脸与声纹多认证\n"
            "    操作直观，零门槛\n"
            "    极简程序，稳定及时响应\n"
            "    真全方位文件数据铠甲\n\n"
            "    2025 GuìFē! :) 加密技术团队™\n\n"
            "附：上次更新版本 v16.9.2\n"
            "       本次更新内容:\n"
            "       修复了一些已知问题\n\n"
            "⚠️本产品仅供学习交流使用，\n"
            "        请勿用于商业用途\n\n"
            "上一次更新版本Python原代码开放：\n"
        )
        label = tk.Label(self, text=about_text, font=("微软雅黑", 9), bg="#f0f0f0",
                         justify=tk.LEFT, wraplength=400)
        label.pack(pady=10, padx=20, anchor=tk.W)

        # “下载链接” 蓝色带下划线可点击标签
        link_frame = tk.Frame(self, bg="#f0f0f0")
        link_frame.pack(pady=5)
        self.link_label = tk.Label(
            link_frame,
            text="下载链接",
            font=("微软雅黑", 10, "underline"),
            fg="blue",
            cursor="hand2",
            bg="#f0f0f0"
        )
        self.link_label.pack(side=tk.LEFT)
        self.link_label.bind("<Button-1>", self.download_source)

        # 关闭按钮
        tk.Button(self, text="关闭", command=self.destroy, width=10,
                  bg="#999999", fg="white", relief=tk.FLAT,
                  activebackground="#777777").pack(pady=15)

        # 延迟执行居中，确保布局已完成
        self.after(10, self._center_window)

    def _center_window(self):
        """根据实际请求尺寸将窗口居中"""
        self.update_idletasks()           # 强制刷新布局计算
        width = self.winfo_reqwidth() + 20
        height = self.winfo_reqheight() + 10
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def download_source(self, event=None):
        try:
            source_code = base64.b64decode(SOURCE_CODE_BASE64)
            download_dir = os.path.join(os.path.expanduser('~'), 'Downloads')
            if not os.path.exists(download_dir):
                os.makedirs(download_dir, exist_ok=True)
            file_path = os.path.join(download_dir, "16.9.2.7z")
            with open(file_path, "wb") as f:
                f.write(source_code)
            messagebox.showinfo("下载完成", f"源代码7z压缩文件已保存到：\n{file_path}", parent=self)
        except Exception as e:
            messagebox.showerror("下载失败", f"保存源代码7z压缩文件时出错：\n{str(e)}", parent=self)

class GridSignaturePad(tk.Toplevel):
    def __init__(self, parent, title="宫格加密", existing_signature=None):
        super().__init__(parent)
        self.title(title)
        self.parent = parent
        self.result = None
        self.existing_signature = existing_signature
        self.is_verified = False

        self.configure(bg="#e0e0e0")
        self.attributes('-alpha', 0.9)
        self.attributes('-topmost', True)
        self.transient(parent)
        self.grab_set()

        self.selected_points = []
        self.grid_canvas = None
        self.point_positions = {}
        self.setup_ui()

        self.after(10, self._center_window)

    def _center_window(self):
        self.update_idletasks()
        width = self.winfo_reqwidth() + 20
        height = self.winfo_reqheight() + 10
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def setup_ui(self):
        prompt_text = "请按顺序点击宫格点完成连接（至少选择4格）"
        if self.existing_signature:
            prompt_text = "请按之前顺序点击宫格点完成验证"
        tk.Label(self, text=prompt_text, font=("微软雅黑", 10), bg="#e0e0e0").pack(pady=10)

        canvas_width = GRID_SIZE * (GRID_POINT_SIZE + GRID_SPACING) + GRID_SPACING
        canvas_height = canvas_width
        self.grid_canvas = tk.Canvas(self, width=canvas_width, height=canvas_height,
                                     bg="white", bd=1, relief=tk.SOLID)
        self.grid_canvas.pack(pady=10)
        self.draw_grid()
        self.grid_canvas.bind("<Button-1>", self.on_point_click)

        btn_frame = tk.Frame(self, bg="#e0e0e0")
        btn_frame.pack(pady=20)

        tk.Button(btn_frame, text="清除", command=self.clear, width=10,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="确定", command=self.ok, width=10,
                  bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00").pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="取消", command=self.cancel, width=10,
                  bg="#ff4444", fg="white", relief=tk.FLAT, activebackground="#dd2222").pack(side=tk.LEFT, padx=10)

        self.point_label = tk.Label(self, text="已选点：无", font=("微软雅黑", 9), bg="#e0e0e0")
        self.point_label.pack(pady=5)

    def draw_grid(self):
        self.grid_canvas.delete("all")
        self.point_positions.clear()
        start_x = GRID_SPACING + GRID_POINT_SIZE // 2
        start_y = GRID_SPACING + GRID_POINT_SIZE // 2
        for row in range(GRID_SIZE):
            for col in range(GRID_SIZE):
                x = start_x + col * (GRID_POINT_SIZE + GRID_SPACING)
                y = start_y + row * (GRID_POINT_SIZE + GRID_SPACING)
                self.grid_canvas.create_oval(
                    x - GRID_POINT_SIZE//2, y - GRID_POINT_SIZE//2,
                    x + GRID_POINT_SIZE//2, y + GRID_POINT_SIZE//2,
                    fill="#cccccc", outline="#666666", width=2,
                    tags=(f"point_{row}_{col}", "grid_point")
                )
                self.grid_canvas.create_text(
                    x, y, text=f"{row+1},{col+1}", fill="#666666", font=("微软雅黑", 8),
                    tags=(f"coord_{row}_{col}", "point_coord")
                )
                self.point_positions[(row, col)] = (x, y)
        self.draw_connections()

    def draw_connections(self):
        if len(self.selected_points) < 2:
            return
        for i in range(1, len(self.selected_points)):
            prev_point = self.selected_points[i-1]
            curr_point = self.selected_points[i]
            x1, y1 = self.point_positions[prev_point]
            x2, y2 = self.point_positions[curr_point]
            self.grid_canvas.create_line(
                x1, y1, x2, y2,
                fill="#44dd00", width=3, tags="connection_line"
            )
        for idx, (row, col) in enumerate(self.selected_points):
            x, y = self.point_positions[(row, col)]
            self.grid_canvas.create_oval(
                x - GRID_POINT_SIZE//2, y - GRID_POINT_SIZE//2,
                x + GRID_POINT_SIZE//2, y + GRID_POINT_SIZE//2,
                fill="#44dd00", outline="#22bb00", width=2,
                tags=(f"selected_{row}_{col}", "selected_point")
            )
            self.grid_canvas.create_text(
                x, y, text=str(idx+1), fill="white", font=("微软雅黑", 10, "bold"),
                tags=(f"num_{row}_{col}", "point_number")
            )

    def on_point_click(self, event):
        click_x, click_y = event.x, event.y
        selected_point = None
        for (row, col), (x, y) in self.point_positions.items():
            if (click_x - x)**2 + (click_y - y)**2 <= (GRID_POINT_SIZE//2)**2:
                selected_point = (row, col)
                break
        if selected_point:
            if len(self.selected_points) == 0 or self.selected_points[-1] != selected_point:
                self.selected_points.append(selected_point)
                self.draw_grid()
                self.update_point_label()

    def update_point_label(self):
        if not self.selected_points:
            self.point_label.config(text="已选点：无")
        else:
            point_list = [f"({r+1},{c+1})" for r, c in self.selected_points]
            point_text = "已选点：" + "+".join(point_list)
            self.point_label.config(text=point_text)

    def clear(self):
        self.selected_points = []
        self.draw_grid()
        self.update_point_label()

    def get_signature_string(self):
        point_list = [f"({r+1},{c+1})" for r, c in self.selected_points]
        return "+".join(point_list)

    def parse_signature_string(self, signature_str):
        if not signature_str:
            return []
        pattern = r'\((\d+),(\d+)\)'
        matches = re.findall(pattern, signature_str)
        points = []
        for row_str, col_str in matches:
            row = int(row_str) - 1
            col = int(col_str) - 1
            if 0 <= row < GRID_SIZE and 0 <= col < GRID_SIZE:
                points.append((row, col))
        return points

    def get_signature_data(self):
        signature_str = self.get_signature_string()
        signature_data = {
            'version': '1.0',
            'grid_size': GRID_SIZE,
            'signature_string': signature_str,
            'point_sequence': self.selected_points,
            'sequence_length': len(self.selected_points),
            'created_at': time.time()
        }
        signature_data['hash'] = hashlib.sha256(signature_str.encode()).hexdigest()
        return signature_data

    def verify_signature(self):
        if not self.existing_signature or not self.selected_points:
            return False
        ref_signature_str = self.existing_signature.get('signature_string', '')
        ref_points = self.parse_signature_string(ref_signature_str)
        return self.selected_points == ref_points

    def ok(self):
        if len(self.selected_points) < 4:
            messagebox.showwarning("警告", "至少需要选择4个点完成连接！", parent=self)
            return
        if self.existing_signature:
            self.is_verified = self.verify_signature()
            if not self.is_verified:
                messagebox.showerror("错误", "宫格连接顺序不匹配，验证失败！", parent=self)
                self.clear()
                return
        self.result = self.get_signature_data()
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()

    def show(self):
        self.wait_window()
        return self.result, self.is_verified

# ====================== 人脸识别核心组件 ======================
class FaceAuthManager:
    _instance = None
    _face_app = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load_model(self):
        if self._face_app is not None:
            return True

        original_stdout = sys.stdout
        original_stderr = sys.stderr
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()

        try:
            available_providers = ort.get_available_providers()
            if 'DmlExecutionProvider' not in available_providers:
                raise RuntimeError(
                    "未检测到可用的GPU加速环境（DirectML）\n"
                    "请检查：\n"
                    "1. 显卡驱动是否为最新版本\n"
                    "2. 显卡是否支持 DirectX 12"
                )

            providers = ['DmlExecutionProvider']
            self._face_app = FaceAnalysis(name=FACE_MODEL_NAME, providers=providers)
            self._face_app.prepare(ctx_id=0, det_size=(640, 640))

            rec_model = self._face_app.models['recognition']
            actual_providers = rec_model.session.get_providers()
            if 'DmlExecutionProvider' not in actual_providers:
                raise RuntimeError("GPU加速启动失败，已禁止CPU回退，请检查显卡硬件环境")

            return True
        except Exception as e:
            raise Exception(f"人脸模型加载失败：{str(e)}")
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr

    def extract_feature(self, frame):
        faces = self._face_app.get(frame)
        if len(faces) == 0:
            return None
        best_face = max(faces, key=lambda f: f.det_score)
        return best_face.embedding.copy()

    @staticmethod
    def calc_similarity(feat1, feat2):
        return np.dot(feat1, feat2) / (np.linalg.norm(feat1) * np.linalg.norm(feat2))

class FaceAuthDialog(tk.Toplevel):
    def __init__(self, parent, mode="collect", reference_features=None, title="人脸验证"):
        super().__init__(parent)
        self.title(title)
        self.parent = parent
        self.mode = mode
        self.reference_features = reference_features
        self.result = None
        self.is_verified = False
        self.running = True
        self.current_frame = None
        self.collected_features = []
        self.capture_count = 0

        self.configure(bg="#e0e0e0")
        self.attributes('-alpha', 0.9)
        self.attributes('-topmost', True)
        self.transient(parent)
        self.grab_set()

        self.setup_ui()
        self.init_camera_and_model()

        self.after(10, self._center_window)

    def _center_window(self):
        self.update_idletasks()
        width = self.winfo_reqwidth() + 20
        height = self.winfo_reqheight() + 10
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def setup_ui(self):
        prompt = "请正对摄像头，点击按钮采集第1张人脸（共3张）" if self.mode == "collect" else "请正对摄像头，点击按钮完成人脸验证"
        self.status_label = tk.Label(self, text=prompt, font=("微软雅黑", 11), bg="#e0e0e0")
        self.status_label.pack(pady=10)

        self.preview_label = tk.Label(self, bd=2, relief=tk.SUNKEN, bg="black")
        self.preview_label.pack(pady=5)

        self.result_label = tk.Label(self, text="", font=("微软雅黑", 10), bg="#e0e0e0", fg="#333")
        self.result_label.pack(pady=5)

        btn_frame = tk.Frame(self, bg="#e0e0e0")
        btn_frame.pack(pady=15)

        self.capture_btn = tk.Button(
            btn_frame, text="拍照采集", command=self.on_capture, width=12,
            bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00",
            state=tk.DISABLED
        )
        self.capture_btn.pack(side=tk.LEFT, padx=10)

        tk.Button(
            btn_frame, text="取消", command=self.cancel, width=10,
            bg="#ff4444", fg="white", relief=tk.FLAT, activebackground="#dd2222"
        ).pack(side=tk.LEFT, padx=10)

    def init_camera_and_model(self):
        def task():
            try:
                manager = FaceAuthManager()
                manager.load_model()
                if sys.platform == "win32":
                    self.cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
                else:
                    self.cap = cv2.VideoCapture(0)
                if not self.cap.isOpened():
                    raise Exception("无法打开摄像头，请检查设备是否被占用")

                self.after(0, lambda: (
                    self.capture_btn.config(state=tk.NORMAL),
                    self.update_preview()
                ))
            except Exception as e:
                self.after(0, lambda e=e: (
                    messagebox.showerror("错误", str(e), parent=self),
                    self.destroy()
                ))
        threading.Thread(target=task, daemon=True).start()

    def update_preview(self):
        if not self.running:
            return
        ret, frame = self.cap.read()
        if ret:
            self.current_frame = frame.copy()
            frame_show = cv2.resize(frame, FACE_PREVIEW_SIZE)
            frame_rgb = cv2.cvtColor(frame_show, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(frame_rgb)
            imgtk = ImageTk.PhotoImage(image=img)
            self.preview_label.imgtk = imgtk
            self.preview_label.configure(image=imgtk)
        self.after(20, self.update_preview)

    def on_capture(self):
        if self.current_frame is None:
            return

        manager = FaceAuthManager()
        feat = manager.extract_feature(self.current_frame)

        if feat is None:
            messagebox.showwarning("提示", "未检测到人脸，请正对摄像头", parent=self)
            return

        if self.mode == "collect":
            self.collected_features.append(feat)
            self.capture_count += 1
            self.result_label.config(text=f"✅ 第 {self.capture_count} 张采集成功")
            if self.capture_count < 3:
                self.status_label.config(text=f"继续采集第 {self.capture_count + 1} 张人脸（共3张）")
            else:
                self.status_label.config(text="3张人脸采集完成！")
                self.capture_btn.config(text="确认使用", bg="#44dd00")
                self.capture_btn.config(command=self.confirm_collect)
        else:
            sim_list = [manager.calc_similarity(feat, ref) for ref in self.reference_features]
            avg_sim = float(np.mean(sim_list))
            max_sim = float(np.max(sim_list))
            self.is_verified = avg_sim >= FACE_SIMILARITY_THRESHOLD
            if self.is_verified:
                self.result_label.config(text=f"✅ 验证通过  相似度：{avg_sim:.4f}", fg="#2e7d32")
                self.capture_btn.config(state=tk.DISABLED)
                self.after(800, self.confirm_verify)
            else:
                self.result_label.config(text=f"❌ 验证失败  相似度：{avg_sim:.4f}", fg="#c62828")

    def confirm_collect(self):
        self.result = {
            'version': '1.0',
            'features': [f.tolist() for f in self.collected_features],
            'count': self.capture_count,
            'threshold': FACE_SIMILARITY_THRESHOLD,
            'created_at': time.time()
        }
        self.destroy()

    def confirm_verify(self):
        self.result = self.is_verified
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()

    def show(self):
        self.wait_window()
        return self.result, self.is_verified

    def destroy(self):
        self.running = False
        if hasattr(self, 'cap') and self.cap.isOpened():
            self.cap.release()
        cv2.destroyAllWindows()
        super().destroy()

# ====================== 声纹识别核心组件 ======================
class VoiceAuthManager:
    _encoder = None

    @classmethod
    def get_encoder(cls):
        if cls._encoder is None:
            cls._encoder = VoiceEncoder()
        return cls._encoder

    @staticmethod
    def record_audio(duration=VOICE_DURATION, sample_rate=VOICE_SAMPLE_RATE):
        recording = sd.rec(int(duration * sample_rate), samplerate=sample_rate, channels=1, dtype='float32')
        sd.wait()
        return recording.flatten()

    @staticmethod
    def extract_embedding(audio, sample_rate=VOICE_SAMPLE_RATE):
        wav = preprocess_wav(audio, source_sr=sample_rate)
        encoder = VoiceAuthManager.get_encoder()
        embed = encoder.embed_utterance(wav)
        return embed

    @staticmethod
    def calc_similarity(embed1, embed2):
        embed1 = embed1 / np.linalg.norm(embed1)
        embed2 = embed2 / np.linalg.norm(embed2)
        return float(np.dot(embed1, embed2))

class VoiceAuthDialog(tk.Toplevel):
    def __init__(self, parent, mode="collect", reference_embeddings=None, title="声纹验证"):
        super().__init__(parent)
        self.title(title)
        self.parent = parent
        self.mode = mode
        self.reference_embeddings = reference_embeddings
        self.result = None
        self.is_verified = False
        self.collected_embeddings = []
        self.capture_count = 0

        self.configure(bg="#e0e0e0")
        self.attributes('-alpha', 0.9)
        self.attributes('-topmost', True)
        self.transient(parent)
        self.grab_set()

        self.setup_ui()

        self.after(10, self._center_window)

    def _center_window(self):
        self.update_idletasks()
        width = self.winfo_reqwidth() + 20
        height = self.winfo_reqheight() + 10
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def setup_ui(self):
        prompt = "请点击按钮录制声音（每次3秒，共3次）" if self.mode == "collect" else "请点击按钮录制声音以验证身份"
        self.status_label = tk.Label(self, text=prompt, font=("微软雅黑", 11), bg="#e0e0e0")
        self.status_label.pack(pady=20)

        self.progress_label = tk.Label(self, text="", font=("微软雅黑", 10), bg="#e0e0e0", fg="#333")
        self.progress_label.pack(pady=10)

        btn_frame = tk.Frame(self, bg="#e0e0e0")
        btn_frame.pack(pady=20)

        self.record_btn = tk.Button(
            btn_frame, text="开始录音", command=self.on_record, width=12,
            bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00"
        )
        self.record_btn.pack(side=tk.LEFT, padx=10)

        tk.Button(
            btn_frame, text="取消", command=self.cancel, width=10,
            bg="#ff4444", fg="white", relief=tk.FLAT, activebackground="#dd2222"
        ).pack(side=tk.LEFT, padx=10)

    def on_record(self):
        self.record_btn.config(state=tk.DISABLED, text="录音中...")
        self.progress_label.config(text="正在录音... 请说话")
        self.update()

        def task():
            try:
                audio = VoiceAuthManager.record_audio(duration=VOICE_DURATION)
                embed = VoiceAuthManager.extract_embedding(audio)
                self.after(0, lambda emb=embed: self._safe_process_recording(emb))
            except Exception as e:
                err_msg = str(e)
                self.after(0, lambda msg=err_msg: self._safe_record_error(msg))
        threading.Thread(target=task, daemon=True).start()

    def _safe_process_recording(self, embed):
        try:
            if not self.winfo_exists():
                return
            self.process_recording(embed)
        except Exception:
            pass

    def _safe_record_error(self, error_msg):
        try:
            if not self.winfo_exists():
                return
            self.record_btn.config(state=tk.NORMAL, text="开始录音")
            self.progress_label.config(text="")
            messagebox.showerror("错误", f"录音失败：{error_msg}", parent=self)
        except Exception:
            pass

    def process_recording(self, embed):
        try:
            self.record_btn.config(state=tk.NORMAL, text="开始录音")
        except tk.TclError:
            return

        if self.mode == "collect":
            self.collected_embeddings.append(embed)
            self.capture_count += 1
            self.progress_label.config(text=f"✅ 第 {self.capture_count} 次录音成功")
            if self.capture_count < 3:
                self.status_label.config(text=f"继续录制第 {self.capture_count + 1} 次声音（共3次）")
            else:
                self.status_label.config(text="3次声音录制完成！")
                try:
                    self.record_btn.config(text="确认使用", command=self.confirm_collect)
                except tk.TclError:
                    pass
        else:
            sim_list = [VoiceAuthManager.calc_similarity(embed, ref) for ref in self.reference_embeddings]
            avg_sim = float(np.mean(sim_list))
            self.is_verified = avg_sim >= VOICE_EMBEDDING_THRESHOLD
            if self.is_verified:
                self.progress_label.config(text=f"✅ 验证通过  相似度：{avg_sim:.4f}", fg="#2e7d32")
                try:
                    self.record_btn.config(state=tk.DISABLED)
                except tk.TclError:
                    pass
                self.after(800, self.confirm_verify)
            else:
                self.progress_label.config(text=f"❌ 验证失败  相似度：{avg_sim:.4f}", fg="#c62828")

    def confirm_collect(self):
        self.result = {
            'version': '1.0',
            'embeddings': [emb.tolist() for emb in self.collected_embeddings],
            'count': self.capture_count,
            'threshold': VOICE_EMBEDDING_THRESHOLD,
            'created_at': time.time()
        }
        self.destroy()

    def confirm_verify(self):
        self.result = self.is_verified
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()

    def show(self):
        self.wait_window()
        return self.result, self.is_verified

# ====================== 主程序 ======================
class GuifeiCryptoTool(tkinterdnd2.Tk):
    def __init__(self):
        super().__init__()
        self.title("GuìFē! :) 超级加密工具 v16.11.4")
        self.geometry("1370x770")
        self.configure(bg="#f0f0f0")
        self.attributes('-alpha', 0.97)
        self.center_window()

        self.current_mode = "main"
        self.selected_path = None
        self.encryption_mode = tk.StringVar(value="aes_only")
        self.use_grid_signature = tk.BooleanVar(value=False)
        self.use_face_verification = tk.BooleanVar(value=False)
        self.use_voice_verification = tk.BooleanVar(value=False)

        self.show_loading()
        self.setup_main_ui()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def show_about(self):
        AboutDialog(self)

    def show_loading(self):
        loading = LoadingWindow(self)
        self.update()
        time.sleep(1.5)
        loading.destroy()

    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def setup_main_ui(self):
        self.current_mode = "main"
        for widget in self.winfo_children():
            widget.destroy()

        title_label = tk.Label(self, text="GuìFē! :) 超级加密工具 v16.11.4", font=("微软雅黑", 16, "bold"), bg="#f0f0f0")
        title_label.pack(pady=30)

        func_frame = tk.Frame(self, bg="#f0f0f0")
        func_frame.pack(fill=tk.X, padx=120, pady=10)

        buttons = [
            ("文件加密", self.show_file_encrypt_ui),
            ("文件夹加密", self.show_folder_encrypt_ui),
            ("文档加密", self.show_doc_encrypt_ui),
            ("一键解密", self.show_auto_decrypt_ui),
            ("关于", self.show_about)
        ]

        for text, cmd in buttons:
            btn_frame = tk.Frame(func_frame, bg="#cccccc", height=70, relief=tk.RAISED, bd=2)
            btn_frame.pack_propagate(False)
            btn_frame.pack(fill=tk.X, pady=8)

            def on_enter(e):
                e.widget.configure(bg="#dddddd")
            def on_leave(e):
                e.widget.configure(bg="#cccccc")

            btn_frame.bind("<Enter>", on_enter)
            btn_frame.bind("<Leave>", on_leave)

            btn_label = tk.Label(btn_frame, text=text, font=("微软雅黑", 14), bg="#cccccc")
            btn_label.pack(expand=True)

            btn_frame.bind("<Button-1>", lambda e, c=cmd: c())
            btn_label.bind("<Button-1>", lambda e, c=cmd: c())

        self.enable_drag_and_drop()

        self.status_bar = tk.Label(self, text="就绪 | 支持拖拽文件/文件夹到对应功能界面",
                                   bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)

    def enable_drag_and_drop(self):
        self.drop_target_register(tkinterdnd2.DND_FILES)
        self.dnd_bind('<<Drop>>', self.on_drop)
        self.dnd_bind('<<DragEnter>>', self.on_drag_enter)
        self.dnd_bind('<<DragLeave>>', self.on_drag_leave)

    def on_drag_enter(self, event):
        self.configure(bg="#e8f0fe")

    def on_drag_leave(self, event):
        self.configure(bg="#f0f0f0")

    def on_drop(self, event):
        self.configure(bg="#f0f0f0")
        files = self.tk.splitlist(event.data)
        if not files:
            return
        dropped_path = files[0]
        self.selected_path = dropped_path

        if self.current_mode == "file":
            self.file_path_var.set(dropped_path)
            self.update_status(f"已加载文件：{os.path.basename(dropped_path)}")
        elif self.current_mode == "folder":
            if os.path.isdir(dropped_path):
                self.folder_path_var.set(dropped_path)
                self.update_status(f"已加载文件夹：{os.path.basename(dropped_path)}\n⚠️提示：解密地址应为单独空文件夹\n因为解密后将释放原文件夹内文件")
            else:
                messagebox.showwarning("提示", "当前为文件夹加密界面，请拖拽文件夹！")
        elif self.current_mode == "decrypt":
            self.decrypt_path_var.set(dropped_path)
            self.update_status(f"已加载待解密文件：{os.path.basename(dropped_path)}")
        elif self.current_mode == "main":
            if os.path.isdir(dropped_path):
                self.show_folder_encrypt_ui()
                self.folder_path_var.set(dropped_path)
            else:
                self.show_file_encrypt_ui()
                self.file_path_var.set(dropped_path)
        elif self.current_mode == "doc":
            messagebox.showinfo("提示", "文档加密界面不支持文件拖拽，请直接编辑文本！")

    def show_back_button(self, parent):
        back_btn = tk.Button(parent, text="← 返回主界面", command=self.setup_main_ui,
                             bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777")
        back_btn.pack(anchor=tk.NW, padx=10, pady=10)
        return back_btn

    def _add_verification_options(self, parent_frame):
        frame = tk.Frame(parent_frame, bg="white" if parent_frame.cget('bg') == 'white' else "#f0f0f0")
        frame.pack(fill=tk.X, padx=10, pady=10)
        bg_color = frame.cget('bg')
        tk.Label(frame, text="附加验证方式（可多选）：", bg=bg_color, font=("微软雅黑", 10)).pack(anchor=tk.W)
        opts = tk.Frame(frame, bg=bg_color)
        opts.pack(anchor=tk.W, pady=5)
        tk.Checkbutton(opts, text="宫格加密", variable=self.use_grid_signature, bg=bg_color).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(opts, text="人脸验证", variable=self.use_face_verification, bg=bg_color).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(opts, text="声纹验证", variable=self.use_voice_verification, bg=bg_color).pack(side=tk.LEFT, padx=5)
        return frame

    def show_file_encrypt_ui(self):
        self.current_mode = "file"
        for widget in self.winfo_children():
            widget.destroy()

        self.show_back_button(self)
        tk.Label(self, text="文件加密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0").pack(pady=10)

        main_frame = tk.Frame(self, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        left_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)
        left_frame.pack_propagate(False)

        tk.Label(left_frame, text="选择文件", font=("微软雅黑", 12), bg="white").pack(pady=10)

        self.file_path_var = tk.StringVar(value=self.selected_path or "未选择文件")
        path_label = tk.Label(left_frame, textvariable=self.file_path_var, bg="white",
                              font=("微软雅黑", 10), wraplength=450, fg="#666666")
        path_label.pack(pady=5, padx=10)

        tk.Button(left_frame, text="浏览文件", command=self.select_file,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(pady=10)

        self._add_verification_options(left_frame)

        right_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10)
        right_frame.pack_propagate(False)

        tk.Label(right_frame, text="保存设置", font=("微软雅黑", 12), bg="white").pack(pady=10)

        self.save_path_var = tk.StringVar(value="")
        tk.Label(right_frame, text="保存路径：", bg="white", font=("微软雅黑", 10)).pack(anchor=tk.W, padx=10)
        tk.Entry(right_frame, textvariable=self.save_path_var, bg="#f5f5f5", relief=tk.FLAT).pack(fill=tk.X, padx=10, pady=5)
        tk.Button(right_frame, text="选择保存位置", command=self.select_file_save_path,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(pady=5)

        tk.Button(right_frame, text="开始加密", command=self.start_file_encryption,
                  bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00",
                  font=("微软雅黑", 12)).pack(side=tk.BOTTOM, pady=20, ipady=5)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=10)

        style = ttk.Style()
        style.configure("grey.Horizontal.TProgressbar", troughcolor='#e0e0e0', background='#44dd00')
        self.progress_bar.config(style="grey.Horizontal.TProgressbar")

        self.enable_drag_and_drop()

        self.status_bar = tk.Label(self, text="文件加密界面 | 支持拖拽文件到此处 | 加密后默认使用原文件名",
                                   bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)

    def show_folder_encrypt_ui(self):
        self.current_mode = "folder"
        for widget in self.winfo_children():
            widget.destroy()

        self.show_back_button(self)
        tk.Label(self, text="文件夹加密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0").pack(pady=10)

        main_frame = tk.Frame(self, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        left_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)
        left_frame.pack_propagate(False)

        tk.Label(left_frame, text="选择文件夹", font=("微软雅黑", 12), bg="white").pack(pady=10)

        self.folder_path_var = tk.StringVar(value=self.selected_path or "未选择文件夹")
        path_label = tk.Label(left_frame, textvariable=self.folder_path_var, bg="white",
                              font=("微软雅黑", 10), wraplength=450, fg="#666666")
        path_label.pack(pady=5, padx=10)

        tk.Button(left_frame, text="浏览文件夹", command=self.select_folder,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(pady=10)

        self._add_verification_options(left_frame)

        right_frame = tk.Frame(main_frame, bg="white", width=500, relief=tk.RAISED, bd=1)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10)
        right_frame.pack_propagate(False)

        tk.Label(right_frame, text="保存设置", font=("微软雅黑", 12), bg="white").pack(pady=10)

        self.folder_save_var = tk.StringVar(value="")
        tk.Label(right_frame, text="保存路径：", bg="white", font=("微软雅黑", 10)).pack(anchor=tk.W, padx=10)
        tk.Entry(right_frame, textvariable=self.folder_save_var, bg="#f5f5f5", relief=tk.FLAT).pack(fill=tk.X, padx=10, pady=5)
        tk.Button(right_frame, text="选择保存位置", command=self.select_folder_save_path,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777").pack(pady=5)

        tk.Button(right_frame, text="开始加密", command=self.start_folder_encryption,
                  bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00",
                  font=("微软雅黑", 12)).pack(side=tk.BOTTOM, pady=20, ipady=5)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=10)

        self.enable_drag_and_drop()

        self.status_bar = tk.Label(self, text="文件夹加密界面 | 支持拖拽文件夹到此处 | 加密后默认使用原文件夹名",
                                   bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)

    def show_doc_encrypt_ui(self):
        self.current_mode = "doc"
        for widget in self.winfo_children():
            widget.destroy()

        self.show_back_button(self)
        tk.Label(self, text="文档加密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0").pack(pady=10)

        text_frame = tk.Frame(self, bg="#f0f0f0")
        text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.doc_text = scrolledtext.ScrolledText(text_frame, font=("Consolas", 10), wrap=tk.WORD,
                                                  bg="#f5f5f5", relief=tk.FLAT, bd=1, height=25)
        self.doc_text.pack(fill=tk.BOTH, expand=True, pady=5)

        ver_frame = tk.Frame(self, bg="#f0f0f0")
        ver_frame.pack(fill=tk.X, padx=20, pady=5)
        self._add_verification_options(ver_frame)

        btn_frame = tk.Frame(self, bg="#f0f0f0")
        btn_frame.pack(fill=tk.X, padx=20, pady=10)

        tk.Button(btn_frame, text="保存加密文档", command=self.save_encrypted_doc,
                  bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00",
                  font=("微软雅黑", 10)).pack(side=tk.RIGHT, padx=5)
        tk.Button(btn_frame, text="打开加密文档", command=self.open_encrypted_doc,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777",
                  font=("微软雅黑", 10)).pack(side=tk.RIGHT, padx=5)
        tk.Button(btn_frame, text="清空内容", command=lambda: self.doc_text.delete(1.0, tk.END),
                  bg="#ff4444", fg="white", relief=tk.FLAT, activebackground="#dd2222",
                  font=("微软雅黑", 10)).pack(side=tk.RIGHT, padx=5)

        self.status_bar = tk.Label(self, text="文档加密界面 | 直接编辑文本内容",
                                   bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)

    def show_auto_decrypt_ui(self):
        self.current_mode = "decrypt"
        for widget in self.winfo_children():
            widget.destroy()

        self.show_back_button(self)
        tk.Label(self, text="自动解密", font=("微软雅黑", 14, "bold"), bg="#f0f0f0").pack(pady=10)

        self.decrypt_path_var = tk.StringVar(value=self.selected_path or "未选择加密文件")
        tk.Label(self, textvariable=self.decrypt_path_var, bg="#f0f0f0", font=("微软雅黑", 10), fg="#666666").pack(pady=10)

        btn_frame = tk.Frame(self, bg="#f0f0f0")
        btn_frame.pack(pady=20)

        tk.Button(btn_frame, text="选择加密文件", command=self.select_encrypted_file,
                  bg="#999999", fg="white", relief=tk.FLAT, activebackground="#777777",
                  font=("微软雅黑", 10)).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="开始解密", command=self.start_auto_decryption,
                  bg="#44dd00", fg="white", relief=tk.FLAT, activebackground="#33bb00",
                  font=("微软雅黑", 10)).pack(side=tk.LEFT, padx=10)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=10)

        self.enable_drag_and_drop()

        self.status_bar = tk.Label(self, text="自动解密界面 | 支持拖拽加密文件到此处 | 解密后默认显示原文件名",
                                   bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)

    # ====================== 核心加密解密逻辑 ======================
    def _derive_keys(self, password, salt):
        key_material = hashlib.pbkdf2_hmac(
            KDF_HASH_ALG,
            password.encode('utf-8'),
            salt,
            KDF_ITERATIONS,
            dklen=AES_KEY_LENGTH * 2
        )
        return key_material[:AES_KEY_LENGTH], key_material[AES_KEY_LENGTH:]

    def _encrypt_single_layer(self, data, password):
        salt = get_random_bytes(SALT_LENGTH)
        nonce = get_random_bytes(GCM_NONCE_LENGTH)
        encryption_key, hmac_key = self._derive_keys(password, salt)

        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(pad(data, AES.block_size))

        packet = ENCRYPTION_MAGIC + VERSION + salt + nonce + tag + ciphertext
        hmac_digest = hmac.new(hmac_key, packet, SIGNATURE_HASH_ALG).digest()

        return hmac_digest + packet

    def _decrypt_single_layer(self, encrypted_data, password):
        if len(encrypted_data) < HMAC_LENGTH + len(ENCRYPTION_MAGIC) + len(VERSION) + SALT_LENGTH + GCM_NONCE_LENGTH + 16:
            raise ValueError("无效的加密数据")

        hmac_digest = encrypted_data[:HMAC_LENGTH]
        packet = encrypted_data[HMAC_LENGTH:]

        if packet[:len(ENCRYPTION_MAGIC)] != ENCRYPTION_MAGIC:
            raise ValueError("无效的加密文件")

        salt = packet[len(ENCRYPTION_MAGIC)+len(VERSION):len(ENCRYPTION_MAGIC)+len(VERSION)+SALT_LENGTH]
        nonce = packet[len(ENCRYPTION_MAGIC)+len(VERSION)+SALT_LENGTH:len(ENCRYPTION_MAGIC)+len(VERSION)+SALT_LENGTH+GCM_NONCE_LENGTH]
        tag = packet[len(ENCRYPTION_MAGIC)+len(VERSION)+SALT_LENGTH+GCM_NONCE_LENGTH:len(ENCRYPTION_MAGIC)+len(VERSION)+SALT_LENGTH+GCM_NONCE_LENGTH+16]
        ciphertext = packet[len(ENCRYPTION_MAGIC)+len(VERSION)+SALT_LENGTH+GCM_NONCE_LENGTH+16:]

        encryption_key, hmac_key = self._derive_keys(password, salt)

        calculated_hmac = hmac.new(hmac_key, packet, SIGNATURE_HASH_ALG).digest()
        if not hmac.compare_digest(hmac_digest, calculated_hmac):
            raise ValueError("密码错误或文件已被篡改")

        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
        plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)

        return plaintext

    def _convert_grid_signature(self, signature):
        if not signature:
            return b''
        signature_str = signature.get('signature_string', '')
        return base64.b64encode(signature_str.encode('utf-8'))

    def _restore_grid_signature(self, special_data):
        if not special_data:
            return {}
        signature_str = base64.b64decode(special_data).decode('utf-8')
        grid_pad = GridSignaturePad(self)
        point_sequence = grid_pad.parse_signature_string(signature_str)
        return {
            'version': '1.0',
            'grid_size': GRID_SIZE,
            'signature_string': signature_str,
            'point_sequence': point_sequence,
            'sequence_length': len(point_sequence),
            'hash': hashlib.sha256(signature_str.encode()).hexdigest()
        }

    def _convert_face_signature(self, face_data):
        if not face_data:
            return b''
        return pickle.dumps(face_data)

    def _restore_face_signature(self, face_bytes):
        if not face_bytes:
            return {}
        return pickle.loads(face_bytes)

    def _convert_voice_signature(self, voice_data):
        if not voice_data:
            return b''
        return pickle.dumps(voice_data)

    def _restore_voice_signature(self, voice_bytes):
        if not voice_bytes:
            return {}
        return pickle.loads(voice_bytes)

    def encrypt_multi_layer(self, data, password, file_type, signature=None, face_signature=None, voice_signature=None,
                            verifications=None, original_filename="", grid_password=None, use_grid_outer=False):
        try:
            self.update_progress(10)

            layer1 = self._encrypt_single_layer(data, password)
            self.update_progress(30)

            encrypted_signature = b''
            if signature and not use_grid_outer:
                special_signature = self._convert_grid_signature(signature)
                encrypted_signature = self._encrypt_single_layer(special_signature, password)

            encrypted_face = b''
            if face_signature:
                face_bytes = self._convert_face_signature(face_signature)
                encrypted_face = self._encrypt_single_layer(face_bytes, password)

            encrypted_voice = b''
            if voice_signature:
                voice_bytes = self._convert_voice_signature(voice_signature)
                encrypted_voice = self._encrypt_single_layer(voice_bytes, password)

            folder_data = {
                'content': layer1,
                'signature': encrypted_signature,
                'face_signature': encrypted_face,
                'voice_signature': encrypted_voice,
                'type': file_type,
                'verifications': verifications if verifications else [],
                'mode': self.encryption_mode.get().encode('utf-8'),
                'timestamp': time.time(),
                'original_filename': original_filename.encode('utf-8'),
                'original_basename': os.path.basename(original_filename).encode('utf-8'),
                'use_grid_outer': use_grid_outer
            }
            folder_bytes = pickle.dumps(folder_data)
            self.update_progress(50)

            if use_grid_outer and grid_password:
                inner_encrypted = self._encrypt_single_layer(folder_bytes, password)
                self.update_progress(70)
                outer_encrypted = self._encrypt_single_layer(inner_encrypted, grid_password)
                final_encrypted = GRID_FLAG_BYTE + outer_encrypted
            else:
                final_encrypted = self._encrypt_single_layer(folder_bytes, password)
                final_encrypted = NO_GRID_FLAG_BYTE + final_encrypted

            self.update_progress(100)
            return final_encrypted

        except Exception as e:
            self.update_progress(0)
            raise Exception(f"加密失败: {str(e)}")

    def decrypt_multi_layer(self, encrypted_data, password, verify_signature=True, verify_face=True, verify_voice=True):
        try:
            self.update_progress(10)

            if len(encrypted_data) < 1:
                raise ValueError("无效的加密数据")

            flag_byte = encrypted_data[:1]
            data_without_flag = encrypted_data[1:]
            use_grid_outer = (flag_byte == GRID_FLAG_BYTE)

            if use_grid_outer:
                grid_pad = GridSignaturePad(self, "请输入加密时绘制的宫格密码（顺序需完全一致）")
                grid_result, _ = grid_pad.show()
                if not grid_result:
                    raise ValueError("宫格密码输入取消")
                grid_password = grid_result['signature_string']
                inner_encrypted = self._decrypt_single_layer(data_without_flag, grid_password)
                folder_bytes = self._decrypt_single_layer(inner_encrypted, password)
            else:
                if flag_byte != NO_GRID_FLAG_BYTE:
                    raise ValueError("无效的加密文件标志")
                folder_bytes = self._decrypt_single_layer(data_without_flag, password)

            self.update_progress(50)

            folder_data = pickle.loads(folder_bytes)
            content_data = folder_data['content']
            signature_data = folder_data.get('signature', b'')
            face_signature_data = folder_data.get('face_signature', b'')
            voice_signature_data = folder_data.get('voice_signature', b'')
            file_type = folder_data.get('type', FILE_TYPE_TEXT)
            verifications = folder_data.get('verifications', [])
            original_filename = folder_data.get('original_filename', b'').decode('utf-8')
            original_basename = folder_data.get('original_basename', b'').decode('utf-8')
            use_grid_outer_stored = folder_data.get('use_grid_outer', False)

            is_verified_all = True

            if verify_signature and 'grid' in verifications and signature_data and not use_grid_outer_stored:
                special_signature = self._decrypt_single_layer(signature_data, password)
                ref_signature = self._restore_grid_signature(special_signature)
                grid_pad = GridSignaturePad(self, "宫格验证", ref_signature)
                _, is_verified = grid_pad.show()
                if not is_verified:
                    raise ValueError("宫格验证失败：连接顺序不匹配")
                is_verified_all = is_verified_all and is_verified

            if verify_face and 'face' in verifications and face_signature_data:
                face_bytes = self._decrypt_single_layer(face_signature_data, password)
                ref_face_data = self._restore_face_signature(face_bytes)
                ref_features = [np.array(feat) for feat in ref_face_data['features']]
                face_dialog = FaceAuthDialog(self, mode="verify", reference_features=ref_features, title="人脸验证")
                _, face_verified = face_dialog.show()
                if not face_verified:
                    raise ValueError("人脸验证失败：身份不匹配")
                is_verified_all = is_verified_all and face_verified

            if verify_voice and 'voice' in verifications and voice_signature_data:
                voice_bytes = self._decrypt_single_layer(voice_signature_data, password)
                ref_voice_data = self._restore_voice_signature(voice_bytes)
                ref_embeddings = [np.array(emb) for emb in ref_voice_data['embeddings']]
                voice_dialog = VoiceAuthDialog(self, mode="verify", reference_embeddings=ref_embeddings, title="声纹验证")
                _, voice_verified = voice_dialog.show()
                if not voice_verified:
                    raise ValueError("声纹验证失败：身份不匹配")
                is_verified_all = is_verified_all and voice_verified

            self.update_progress(70)

            plain_data = self._decrypt_single_layer(content_data, password)
            self.update_progress(100)

            return plain_data, file_type, is_verified_all, original_filename, original_basename

        except Exception as e:
            self.update_progress(0)
            raise Exception(f"解密失败: {str(e)}")

    # ====================== 辅助方法 ======================
    def update_progress(self, value):
        self.after(0, lambda v=value: self._safe_update_progress(v))

    def _safe_update_progress(self, value):
        try:
            if hasattr(self, 'progress_var') and self.progress_var:
                self.progress_var.set(value)
                self.update_idletasks()
        except:
            pass

    def update_status(self, text):
        self.after(0, lambda t=text: self._safe_update_status(t))

    def _safe_update_status(self, text):
        try:
            if not hasattr(self, 'status_bar') or not self.status_bar.winfo_exists():
                self.status_bar = tk.Label(self, text=text, bg="#f0f0f0", anchor=tk.W, font=("微软雅黑", 9))
                self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)
            else:
                self.status_bar.config(text=text)
            self.update_idletasks()
        except:
            pass

    def select_file(self):
        path = filedialog.askopenfilename(title="选择要加密的文件")
        if path:
            self.selected_path = path
            self.file_path_var.set(path)

    def select_folder(self):
        path = filedialog.askdirectory(title="选择要加密的文件夹")
        if path:
            self.selected_path = path
            self.folder_path_var.set(path)

    def select_file_save_path(self):
        if not self.selected_path:
            messagebox.showwarning("警告", "请先选择要加密的文件！")
            return
        original_basename = os.path.basename(self.selected_path)
        default_filename = f"{original_basename}.guifei"
        path = filedialog.asksaveasfilename(
            defaultextension='.guifei',
            filetypes=[("加密文件", "*.guifei"), ("所有文件", "*.*")],
            title="保存",
            initialfile=default_filename
        )
        if path:
            self.save_path_var.set(path)

    def select_folder_save_path(self):
        if not self.selected_path:
            messagebox.showwarning("警告", "请先选择要加密的文件夹！")
            return
        original_basename = os.path.basename(self.selected_path)
        default_filename = f"{original_basename}.guifeinext"
        path = filedialog.asksaveasfilename(
            defaultextension='.guifeinext',
            filetypes=[("加密文件夹", "*.guifeinext"), ("所有文件", "*.*")],
            title="保存",
            initialfile=default_filename
        )
        if path:
            self.folder_save_var.set(path)

    def select_encrypted_file(self):
        path = filedialog.askopenfilename(
            filetypes=[
                ("所有支持的文件", "*.guifei *.guifeinext *.msc"),
                ("加密文件", "*.guifei"),
                ("加密文件夹", "*.guifeinext"),
                ("加密文本", "*.msc"),
                ("所有文件", "*.*")
            ],
            title="选择要解密的文件"
        )
        if path:
            self.decrypt_path_var.set(path)

    def _collect_verifications(self):
        verifications = []
        signature = None
        face_sig = None
        voice_sig = None
        grid_password = None
        use_grid_outer = False

        if self.use_grid_signature.get():
            grid_pad = GridSignaturePad(self, "设置宫格二次加密密码")
            sig, _ = grid_pad.show()
            if not sig:
                return None, None, None, None, None, None  # 用户取消时返回 None
            signature = sig
            verifications.append('grid')
            grid_password = sig['signature_string']
            use_grid_outer = True

        if self.use_face_verification.get():
            face_dialog = FaceAuthDialog(self, mode="collect", title="设置人脸验证")
            fs, _ = face_dialog.show()
            if not fs:
                return None, None, None, None, None, None
            face_sig = fs
            verifications.append('face')

        if self.use_voice_verification.get():
            voice_dialog = VoiceAuthDialog(self, mode="collect", title="设置声纹验证")
            vs, _ = voice_dialog.show()
            if not vs:
                return None, None, None, None, None, None
            voice_sig = vs
            verifications.append('voice')

        return signature, face_sig, voice_sig, verifications, grid_password, use_grid_outer

    def start_file_encryption(self):
        if not self.selected_path:
            messagebox.showwarning("警告", "请先选择要加密的文件！")
            return

        save_path = self.save_path_var.get()
        if not save_path:
            original_basename = os.path.basename(self.selected_path)
            default_filename = f"{original_basename}.guifei"
            save_path = filedialog.asksaveasfilename(
                defaultextension='.guifei',
                filetypes=[("加密文件", "*.guifei")],
                title="选择保存位置",
                initialfile=default_filename
            )
            if not save_path:
                return
            self.save_path_var.set(save_path)

        password = PasswordDialog(self, "加密密码", "请输入加密密码:").show()
        if not password:
            return

        result = self._collect_verifications()
        if result[0] is None and result[4] is None and result[5] is None:
            # 用户取消了所有验证，中止加密
            if self.use_grid_signature.get() or self.use_face_verification.get() or self.use_voice_verification.get():
                return
        # 如果没选任何验证，也允许继续
        signature, face_sig, voice_sig, verifications, grid_password, use_grid_outer = result

        def encrypt_task():
            try:
                self.update_progress(0)
                self.update_status("正在加密文件...")

                with open(self.selected_path, 'rb') as f:
                    file_data = f.read()
                self.update_progress(20)

                encrypted_data = self.encrypt_multi_layer(
                    file_data,
                    password,
                    FILE_TYPE_FILE,
                    signature=signature,
                    face_signature=face_sig,
                    voice_signature=voice_sig,
                    verifications=verifications,
                    original_filename=self.selected_path,
                    grid_password=grid_password,
                    use_grid_outer=use_grid_outer
                )
                self.update_progress(80)

                with open(save_path, 'wb') as f:
                    f.write(encrypted_data)
                self.update_progress(100)

                self.update_status(f"文件加密完成：{os.path.basename(save_path)}")
                self.after(0, lambda: messagebox.showinfo("成功", "文件加密完成！"))

            except Exception as e:
                error_msg = f"加密失败：{str(e)}"
                self.update_progress(0)
                self.update_status(error_msg)
                self.after(0, lambda msg=error_msg: messagebox.showerror("错误", msg))

        threading.Thread(target=encrypt_task, daemon=True).start()

    def start_folder_encryption(self):
        if not self.selected_path:
            messagebox.showwarning("警告", "请先选择要加密的文件夹！")
            return

        save_path = self.folder_save_var.get()
        if not save_path:
            original_basename = os.path.basename(self.selected_path)
            default_filename = f"{original_basename}.guifeinext"
            save_path = filedialog.asksaveasfilename(
                defaultextension='.guifeinext',
                filetypes=[("加密文件夹", "*.guifeinext")],
                title="选择保存位置",
                initialfile=default_filename
            )
            if not save_path:
                return
            self.folder_save_var.set(save_path)

        password = PasswordDialog(self, "加密密码", "请输入加密密码:").show()
        if not password:
            return

        result = self._collect_verifications()
        if result[0] is None and result[4] is None and result[5] is None:
            if self.use_grid_signature.get() or self.use_face_verification.get() or self.use_voice_verification.get():
                return
        signature, face_sig, voice_sig, verifications, grid_password, use_grid_outer = result

        def encrypt_task():
            try:
                self.update_progress(0)
                self.update_status("正在压缩并加密文件夹...")

                temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
                with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root, dirs, files in os.walk(self.selected_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, self.selected_path)
                            zipf.write(file_path, arcname)
                temp_zip.close()
                self.update_progress(30)

                with open(temp_zip.name, 'rb') as f:
                    zip_data = f.read()
                os.unlink(temp_zip.name)
                self.update_progress(50)

                encrypted_data = self.encrypt_multi_layer(
                    zip_data,
                    password,
                    FILE_TYPE_FOLDER,
                    signature=signature,
                    face_signature=face_sig,
                    voice_signature=voice_sig,
                    verifications=verifications,
                    original_filename=self.selected_path,
                    grid_password=grid_password,
                    use_grid_outer=use_grid_outer
                )
                self.update_progress(80)

                with open(save_path, 'wb') as f:
                    f.write(encrypted_data)
                self.update_progress(100)

                self.update_status(f"文件夹加密完成：{os.path.basename(save_path)}")
                self.after(0, lambda: messagebox.showinfo("成功", "文件夹加密完成！"))

            except Exception as e:
                error_msg = f"加密失败：{str(e)}"
                self.update_progress(0)
                self.update_status(error_msg)
                self.after(0, lambda msg=error_msg: messagebox.showerror("错误", msg))

        threading.Thread(target=encrypt_task, daemon=True).start()

    def save_encrypted_doc(self):
        content = self.doc_text.get(1.0, tk.END).encode('utf-8')
        if not content.strip():
            messagebox.showwarning("警告", "文档内容不能为空！")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension='.msc',
            filetypes=[("加密文档", "*.msc")],
            title="选择保存位置",
            initialfile="document.msc"
        )
        if not save_path:
            return

        password = PasswordDialog(self, "加密密码", "请输入加密密码:").show()
        if not password:
            return

        result = self._collect_verifications()
        if result[0] is None and result[4] is None and result[5] is None:
            if self.use_grid_signature.get() or self.use_face_verification.get() or self.use_voice_verification.get():
                return
        signature, face_sig, voice_sig, verifications, grid_password, use_grid_outer = result

        try:
            encrypted_data = self.encrypt_multi_layer(
                content,
                password,
                FILE_TYPE_TEXT,
                signature=signature,
                face_signature=face_sig,
                voice_signature=voice_sig,
                verifications=verifications,
                original_filename="document.msc",
                grid_password=grid_password,
                use_grid_outer=use_grid_outer
            )
            with open(save_path, 'wb') as f:
                f.write(encrypted_data)
            messagebox.showinfo("成功", "文档加密保存完成！")
        except Exception as e:
            messagebox.showerror("错误", f"保存失败：{str(e)}")

    def open_encrypted_doc(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("加密文档", "*.msc"), ("所有文件", "*.*")],
            title="打开加密文档"
        )
        if not file_path:
            return

        password = PasswordDialog(self, "解密密码", "请输入解密密码:", show_strength=False).show()
        if not password:
            return

        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            plain_data, _, _, _, original_basename = self.decrypt_multi_layer(encrypted_data, password)

            self.doc_text.delete(1.0, tk.END)
            self.doc_text.insert(tk.END, plain_data.decode('utf-8', errors='replace'))
            messagebox.showinfo("成功", f"文档解密完成！原文件名：{original_basename}")

        except Exception as e:
            messagebox.showerror("错误", f"解密失败：{str(e)}")

    def start_auto_decryption(self):
        file_path = self.decrypt_path_var.get()
        if file_path == "未选择加密文件":
            messagebox.showwarning("警告", "请先选择要解密的文件！")
            return

        password = PasswordDialog(self, "解密密码", "请输入解密密码:", show_strength=False).show()
        if not password:
            return

        def decrypt_task():
            try:
                self.update_progress(0)
                self.update_status("正在解密文件...")

                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                self.update_progress(20)

                plain_data, file_type, _, original_filename, original_basename = self.decrypt_multi_layer(encrypted_data, password)
                self.update_progress(60)

                if file_type == FILE_TYPE_TEXT:
                    self.after(0, lambda p=plain_data, b=original_basename: self._show_decrypted_text(p, b))

                elif file_type == FILE_TYPE_FILE:
                    def save_file():
                        save_path = filedialog.asksaveasfilename(
                            title="保存文件位置",
                            initialfile=original_basename or os.path.splitext(os.path.basename(file_path))[0]
                        )
                        if save_path:
                            with open(save_path, 'wb') as f:
                                f.write(plain_data)
                            self.update_status(f"文件解密完成：{os.path.basename(save_path)}")
                            messagebox.showinfo("成功", f"文件解密完成：{os.path.basename(save_path)}")
                    self.after(0, save_file)

                elif file_type == FILE_TYPE_FOLDER:
                    def extract_folder():
                        parent_dir = filedialog.askdirectory(title="选择文件夹保存位置")
                        if not parent_dir:
                            self.update_status("解密取消：未选择保存位置")
                            return

                        target_dir = os.path.join(parent_dir, original_basename)
                        counter = 1
                        base_name = original_basename
                        while os.path.exists(target_dir):
                            target_dir = os.path.join(parent_dir, f"{base_name}_{counter}")
                            counter += 1
                        os.makedirs(target_dir, exist_ok=True)

                        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
                        temp_zip.write(plain_data)
                        temp_zip.close()

                        with zipfile.ZipFile(temp_zip.name, 'r') as zipf:
                            total_files = len(zipf.namelist())
                            processed = 0
                            for file_info in zipf.infolist():
                                zipf.extract(file_info, target_dir)
                                processed += 1
                                self.update_progress(60 + int(30 * processed / total_files))

                        os.unlink(temp_zip.name)
                        self.update_progress(100)

                        self.update_status(f"文件夹解密完成：已解压到 {target_dir}")
                        self.after(0, lambda td=target_dir: messagebox.showinfo(
                            "成功",
                            f"文件夹解密完成！\n已解压到：{td}"
                        ))
                    self.after(0, extract_folder)

                self.update_progress(100)

            except Exception as e:
                error_msg = f"解密失败：{str(e)}"
                self.update_progress(0)
                self.update_status(error_msg)
                self.after(0, lambda msg=error_msg: messagebox.showerror("错误", msg))

        threading.Thread(target=decrypt_task, daemon=True).start()

    def _show_decrypted_text(self, plain_data, original_basename):
        if not hasattr(self, 'doc_text') or not self.doc_text.winfo_exists():
            self.show_doc_encrypt_ui()
        self.after(100, lambda pd=plain_data, ob=original_basename: self._safe_display_text(pd, ob))

    def _safe_display_text(self, plain_data, original_basename):
        try:
            self.doc_text.delete(1.0, tk.END)
            self.doc_text.insert(tk.END, plain_data.decode('utf-8', errors='replace'))
            self.update_status(f"文本解密完成：原文件名 {original_basename}")
            messagebox.showinfo(
                "成功",
                f"文本解密完成！\n原文件名：{original_basename}\n已加载到文档编辑区"
            )
        except Exception as e:
            self.update_status(f"文本显示失败：{str(e)}")
            messagebox.showwarning(
                "提示",
                f"文本解密成功但显示失败！\n原文件名：{original_basename}\n错误：{str(e)}\n请手动打开文档加密界面查看"
            )

    def on_close(self):
        if messagebox.askokcancel("退出", "确定要退出GuìFē! :)超级加密工具吗？"):
            self.destroy()
            sys.exit(0)

# ====================== 主程序入口 ======================

ICO_BASE64 = '''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xgfa2N4ANEBoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAx727AMa9ugTIwscTt7TFBMfDzQAREVoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA///////////////////B///DAf//AgD//gMAP/wDAB/4A4AP8AeAD+AQBAfgYAYH4GAHA8DgBwPA4AeDwOAHg8DgBwPA4AcDwPAPA+BxjgfgMAwH4AAQB/AAAA/4AYAf/ACAP/4AwH//gMH//4HH//+P//////////////////8='''

if __name__ == "__main__":
    def _global_exception_hook(exc_type, exc_value, exc_tb):
        err_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
        messagebox.showerror("未捕获的异常", err_msg[:800])
        with open("guifei_error.log", "a", encoding="utf-8") as f:
            f.write(err_msg)

    sys.excepthook = _global_exception_hook

    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    app = GuifeiCryptoTool()
    try:
        ico_bytes = base64.b64decode(ICO_BASE64.strip())
        ico_stream = io.BytesIO(ico_bytes)
        ico_image = Image.open(ico_stream)
        app_icon = ImageTk.PhotoImage(ico_image)
        app.iconphoto(True, app_icon)
        try:
            app.iconbitmap(default=app_icon)
        except Exception:
            pass
    except Exception as e:
        messagebox.showerror(title="错误", message=f"Error {e}")

    app.mainloop()