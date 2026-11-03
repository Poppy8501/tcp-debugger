# -*- coding: utf-8 -*-
"""网络核心与编码逻辑的自动化验证（不涉及界面）"""
import socket
import sys
import threading
import time

sys.path.insert(0, r"D:\WorkBuddyProjects\WorkBuddy缓存\2026-11-03-15-45-46")
from tcp_debugger import TcpCore, parse_hex_text, hex_to_display, unescape_escapes, human_size

events = []
lock = threading.Lock()


def emit(kind, *args):
    with lock:
        events.append((kind,) + args)


def wait_for(pred, timeout=4.0):
    end = time.time() + timeout
    while time.time() < end:
        with lock:
            for e in events:
                if pred(e):
                    return e
        time.sleep(0.02)
    return None


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


ok = True


def check(name, cond, extra=""):
    global ok
    print(("  [PASS] " if cond else "  [FAIL] ") + name + ((" | " + extra) if extra else ""))
    if not cond:
        ok = False


# ---------- 1. 编码工具 ----------
print("1. 编码工具")
check("HEX 空格解析", parse_hex_text("48 65 6C 6C 6F") == b"Hello")
check("HEX 连续解析", parse_hex_text("48656c6c6f") == b"Hello")
check("HEX 0x 前缀", parse_hex_text("0x41,0x42") == b"AB")
check("HEX 反显", hex_to_display(b"\x01\xAB") == "01 AB")
check("转义还原", unescape_escapes("AT\\r\\n") == "AT\r\n")
check("反斜杠保留", unescape_escapes("a\\\\b") == "a\\b")
check("大小格式化", human_size(512) == "512 B" and human_size(2048) == "2.0 KB")
try:
    parse_hex_text("ABC")
    check("HEX 奇数长度报错", False)
except ValueError:
    check("HEX 奇数长度报错", True)

# ---------- 2. 服务端 + 客户端收发 ----------
print("2. 双端收发")
port = free_port()
srv = TcpCore(emit)
cli = TcpCore(emit)

srv_ok = srv.listen("127.0.0.1", port)
check("服务端监听成功", srv_ok)
check("监听态事件", wait_for(lambda e: e[0] == "state" and e[1] == "listening") is not None)

cli.connect("127.0.0.1", port)
check("客户端连接成功", wait_for(lambda e: e[0] == "state" and e[1] == "connected") is not None)
check("服务端发现客户端", wait_for(lambda e: e[0] == "peer_add") is not None)
check("服务端 ready", srv.ready)
check("客户端 ready", cli.ready)

# 客户端 -> 服务端
events.clear()
cli.send(b"hello-server")
got = wait_for(lambda e: e[0] == "rx" and e[2] == b"hello-server")
check("客户端发 / 服务端收", got is not None, str(got))

# 服务端 -> 客户端（广播）
events.clear()
cid = list(srv.conns.keys())[0]
srv.send(b"hello-client")
got = wait_for(lambda e: e[0] == "rx" and e[2] == b"hello-client")
check("服务端发 / 客户端收", got is not None, str(got))

# 服务端 -> 指定客户端
events.clear()
srv.send(b"direct", cid)
check("定向发送到指定客户端", wait_for(lambda e: e[0] == "rx" and e[2] == b"direct") is not None)

# 中文与 HEX 二进制
events.clear()
raw = "你好，TCP".encode("utf-8")
cli.send(raw)
check("UTF-8 中文收发", wait_for(lambda e: e[0] == "rx" and e[2] == raw) is not None)

events.clear()
bin_data = bytes([0x00, 0x01, 0xFF, 0x7F])
cli.send(bin_data)
check("二进制字节收发", wait_for(lambda e: e[0] == "rx" and e[2] == bin_data) is not None)

# 分片发送（服务端应能拼接成两次独立事件）
events.clear()
cli.send(b"A" * 1000)
check("大数据包发送", wait_for(lambda e: e[0] == "rx" and len(e[2]) == 1000) is not None)

# 统计
check("RX 计数正确", cli.rx_bytes >= len(raw) and srv.rx_bytes >= 1000,
      "cli=%d srv=%d" % (cli.rx_bytes, srv.rx_bytes))
check("TX 计数正确", cli.tx_bytes > 0 and srv.tx_bytes > 0)

# ---------- 3. 断开与清理 ----------
print("3. 断开清理")
events.clear()
cli.shutdown()
check("客户端收到断开事件", wait_for(lambda e: e[0] == "state" and e[1] == "idle") is not None)
check("服务端察觉客户端离开", wait_for(lambda e: e[0] == "peer_del") is not None)
check("服务端连接表已清空", len(srv.conns) == 0)
check("断开后发送返回 -1", cli.send(b"x") == -1)

srv.shutdown()
check("服务端停止监听", srv.server is None and not srv.running)

# 释放后能否立刻重新占用同一端口（TIME_WAIT 场景）
srv2 = TcpCore(emit)
check("释放后可立刻重新监听同一端口", srv2.listen("127.0.0.1", port))
srv2.shutdown()

# ---------- 4. 端口占用错误处理 ----------
print("4. 异常处理")
a = TcpCore(emit)
b = TcpCore(emit)
events.clear()
r1 = a.listen("127.0.0.1", port)
r2 = b.listen("127.0.0.1", port)
check("首端口监听成功", r1)
check("端口冲突被捕获", r2 is False)
check("端口冲突有错误事件", wait_for(lambda e: e[0] == "err") is not None)

events.clear()
c = TcpCore(emit)
c.connect("127.0.0.1", free_port() if False else 1)  # 无服务端口
check("连接失败有错误事件", wait_for(lambda e: e[0] == "err", 8) is not None)
check("连接失败后状态归零", not c.ready)

a.shutdown()
b.shutdown()
c.shutdown()

# ---------- 5. 会话竞态 ----------
# 曾经的真实 bug：一个挂起的连接在超时后把 running 置 False，
# 把同实例上已经跑起来的服务端一起关掉。
print("5. 会话竞态")
d = TcpCore(emit)
d.connect("10.255.255.1", 9, timeout=2.0)      # 黑洞地址，2 秒后才失败
time.sleep(0.15)
p3 = free_port()
check("挂起连接期间切换为监听成功", d.listen("127.0.0.1", p3))
check("切换后处于监听态", d.running and d.server is not None)

time.sleep(2.7)                                 # 让那次过期的连接超时返回
check("旧连接超时后仍处于监听态", d.running and d.server is not None,
      "running=%s server=%s" % (d.running, d.server is not None))

sk = socket.create_connection(("127.0.0.1", p3))
sk.settimeout(3)
events.clear()
sk.sendall(b"still-alive")
check("旧连接超时后仍能正常收数据",
      wait_for(lambda e: e[0] == "rx" and e[2] == b"still-alive") is not None)
sk.close()
d.shutdown()

# 过期会话的收尾动作必须被忽略
d2 = TcpCore(emit)
d2.listen("127.0.0.1", free_port())
stale_gen = d2._gen
d2.shutdown()
d2.listen("127.0.0.1", free_port())
d2._drop("server", "stale", stale_gen)
check("过期会话收尾不影响新会话", d2.running and d2.server is not None)
d2.shutdown()

print()
print("RESULT:", "ALL PASS" if ok else "HAS FAILURE")
sys.exit(0 if ok else 1)
