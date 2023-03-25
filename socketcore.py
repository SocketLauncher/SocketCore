import base64
import json
import socket
import threading
import time

from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

"""
{"head":"0","send_type":"0","recv_type":"0","pub_key":"","msg_mode":"0","from":"0","to":"0","msg_str":"0"，"msg":{},"time":"0", "spacer":""}

head:   0 - 申请链接
        1 - 消息
        2 - 退出
        3 - 查询响应

send_type:  0 - 明文
            1 - 密文

recv_type:  0 - 明文
            1 - 密文
            
pub_key:    公钥

msg_mode:   0 - 单播
            1 - 广播

from:       发送者

to:         接收者

msg:        消息(json)

time:       时间戳

spacer:     分隔符

"""


# 加密
def encryption(msg: str, pub_key: str, spacer: str):
    """
    :param msg: massage
    :param pub_key: public key
    :param spacer: spacer
    :return: encrypted message
    """
    token_list = [msg[i:i + 200] for i in range(0, len(msg), 200)]  # 切割,每份长度为200
    token_list_encrypted = []
    for i in token_list:
        i = i.encode('utf-8')
        cipher = PKCS1_v1_5.new(RSA.importKey(pub_key))
        cipher_text = cipher.encrypt(i)
        cipher_text = base64.b64encode(cipher_text)
        token_list_encrypted.append(cipher_text.decode('utf-8'))
    return spacer.join(token_list_encrypted)  # 拼接


# 解密
def decryption(msg: list, pri_key: str, spacer: str):
    """
    :param msg: cipher message
    :param pri_key: private key
    :param spacer: spacer
    :return: decrypted message
    """
    token_list = msg.split(spacer)
    token_list_decryption = []
    for i in token_list:
        i = i.encode('utf-8')
        cipher = PKCS1_v1_5.new(RSA.importKey(pri_key))
        text = cipher.decrypt(base64.b64decode(i), Random.new().read)
        token_list_decryption.append(text.decode('utf-8'))
    return ''.join(token_list_decryption)


class Server:
    def __init__(self, host, port):
        """

        :param host: IP address
        :param port: port number
        """
        self.host = host  # IP address
        self.port = port  # Port number

        # Create a socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen()

        # List of connected apps
        self.app_name_dict = {}
        self.app_socket_list = []

        # 生成公钥、私钥和分隔符
        self.rsa = RSA.generate(2048)
        self.pub_key = self.rsa.publickey().exportKey().decode()
        self.pri_key = self.rsa.exportKey().decode()
        self.spacer = Random.get_random_bytes(2).hex()

    def receive(self):
        ...

    def send(self):
        ...

    def start(self, recv=1024 * 4):
        """
        :param recv: receive buffer size
        """
        while True:
            # 收到新的连接申请
            conn, addr = self.socket.accept()
            self.app_socket_list.append(conn)
            msg = json.loads(conn.recv(recv).decode())

            # 判断含义
            if msg.get('head') == "0":
                self.app_name_dict.update(
                    {msg.get('from'): {"socket": conn, "pub_key": msg.get('pub_key'), "time": msg.get('time')}})
                time_stamp = str(int(time.time()))
                return_msg = {
                    "head": "0",
                    "send_type": "0",
                    "recv_type": "0",
                    "pub_key": self.pub_key,
                    "spacer": self.spacer,
                    "msg_mode": "0",
                    "from": "host",
                    "to": msg.get('from'),
                    "msg_str": "",
                    "msg": {},
                    "time": time_stamp
                }
                conn.send(json.dumps(return_msg).encode())
            print(f"New connection from {addr}")
            thread = threading.Thread(target=self.receive, args=(conn, addr))
            thread.start()


class Client:
    def __init__(self, host, port):
        """

        :param host: IP address
        :param port: port number
        """
        self.host = host  # IP address
        self.port = port  # Port number

        # Create a socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

        # 生成公钥、私钥、分隔符
        self.rsa = RSA.generate(2048)
        self.pub_key = self.rsa.publickey().exportKey().decode()
        self.pri_key = self.rsa.exportKey().decode()
        self.spacer = Random.get_random_bytes(2).hex()

        # 主机公钥
        self.host_pub_key = ""

        # 主机分隔符
        self.host_spacer = ""

    def receive(self, callback_func, spacer, recv=1024 * 4):
        while True:
            try:
                data = json.loads(self.socket.recv(recv).decode())
                if data.get('head') == "0":
                    self.host_pub_key = data.get('pub_key')
                data_unsecret = decryption(data)
                try:
                    eval(data_unsecret)
                except Exception as e:
                    print(e)
                print(f"收到消息\n{data_unsecret}\n")
            except:
                print("对方已断开连接")
                input()
                break
        return

    def send(self):
        ...

    def start(self, recv=1024 * 4):
        """
        :param recv: receive buffer size
        """
        msg = ''
        self.socket.send(msg.encode())
        print(self.socket.recv(recv).decode())
        while True:
            msg = input(">>>")
