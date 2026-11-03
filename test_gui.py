# -*- coding: utf-8 -*-
"""界面交互自动化验证：真实 Tk 窗口 + 真实 socket 对端"""
import socket
import sys
import threading
import time
import tkinter as tk

sys.path.insert(0, r"D:\WorkBuddyProjects\WorkBuddy缓存\2026-11-03-15-45-46")
from tcp_debugger import App

ok = True


def check(name, cond, extra=""):
    global ok
    print(("  [PASS] " if cond else "  [FAIL] ") + name + ((" | " + extra) if extra else ""))
    if not cond:
        ok = False


def pump(root, seconds):
    end = time.time() + seconds
    while time.time() < end:
        root.update()
        time.sleep(0.01)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def log_text(app):
    return app.log.get("1.0", "end-1c")


root = tk.Tk()
app = App(root)
pump(root, 0.3)

# ==================== A. 客户端模式 ====================
print("A. 客户端模式")
port = free_port()
peer = socket.socket()
peer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
peer.bind(("127.0.0.1", port))
peer.listen(1)

app.mode_var.set("客户端")
app.on_mode_change()
app.host_var.set("127.0.0.1")
app.port_var.set(str(port))
app.toggle_connection()
pump(root, 0.4)

conn, _ = peer.accept()
conn.settimeout(3)
pump(root, 0.4)
check("连接后状态为已连接", "已连接" in app.conn_label.cget("text"),
      app.conn_label.cget("text"))
check("按钮变为断开", app.btn_conn.cget("text") == "断开")

# 收数据
conn.sendall(b"PING-FROM-PEER")
pump(root, 0.5)
check("接收对端数据写入日志", "PING-FROM-PEER" in log_text(app))
check("接收方向标记存在", "←" in log_text(app))
check("RX 字节数更新", app.core.rx_bytes == 14, str(app.core.rx_bytes))

# 发数据（文本 + 转义）
app.input.delete("1.0", "end")
app.input.insert("1.0", "AT\\r\\n")
app.do_send()
pump(root, 0.3)
got = conn.recv(1024)
check("文本发送并还原转义", got == b"AT\r\n", repr(got))
check("发送方向标记存在", "→" in log_text(app))

# HEX 发送
app.hex_send.set(True)
app.input.delete("1.0", "end")
app.input.insert("1.0", "48 45 4C 4C 4F")
app.do_send()
pump(root, 0.3)
got = conn.recv(1024)
check("HEX 发送", got == b"HELLO", repr(got))
app.hex_send.set(False)

# HEX 显示
app.hex_view.set(True)
conn.sendall(b"\x01\x02\xAB")
pump(root, 0.5)
check("HEX 显示模式", "01 02 AB" in log_text(app))
app.hex_view.set(False)

# 自动追加 \r\n
app.auto_crlf.set(True)
app.input.delete("1.0", "end")
app.input.insert("1.0", "CMD")
app.do_send()
pump(root, 0.3)
check("自动追加 CRLF", conn.recv(1024) == b"CMD\r\n")
app.auto_crlf.set(False)

# 定时发送
app.input.delete("1.0", "end")
app.input.insert("1.0", "TICK")
app.interval_var.set("100")
app.toggle_auto()
pump(root, 0.55)
app.stop_auto()
pump(root, 0.2)
buf = b""
conn.settimeout(0.4)
try:
    while True:
        d = conn.recv(4096)
        if not d:
            break
        buf += d
except socket.timeout:
    pass
check("定时发送多次触发", buf.count(b"TICK") >= 2, "count=%d" % buf.count(b"TICK"))

# 断开
app.toggle_connection()
pump(root, 0.4)
check("断开后状态归零", "未连接" in app.conn_label.cget("text"))
app.mode_var.set("服务端")
app.on_mode_change()
root.update()
check("服务端模式显示客户端面板", app.peer_card.winfo_manager() == "pack",
      repr(app.peer_card.winfo_manager()))
check("地址标签切换", app.host_label.cget("text") == "监听地址")
app.mode_var.set("客户端")
app.on_mode_change()
root.update()
check("客户端模式隐藏客户端面板", app.peer_card.winfo_manager() == "",
      repr(app.peer_card.winfo_manager()))
conn.close()
peer.close()

# ==================== B. 服务端模式 ====================
print("B. 服务端模式")
port2 = free_port()
app.mode_var.set("服务端")
app.on_mode_change()
app.host_var.set("127.0.0.1")
app.port_var.set(str(port2))
app.toggle_connection()
pump(root, 0.4)
check("监听中状态", "监听中" in app.conn_label.cget("text"),
      app.conn_label.cget("text"))

c1 = socket.create_connection(("127.0.0.1", port2))
c1.settimeout(3)
pump(root, 0.4)
c2 = socket.create_connection(("127.0.0.1", port2))
c2.settimeout(3)
pump(root, 0.4)
check("客户端列表含两个连接", app.peer_list.size() == 3,
      "size=%d" % app.peer_list.size())
check("客户端计数为 2", app.peer_count.cget("text") == "2")

c1.sendall(b"FROM-C1")
pump(root, 0.5)
check("服务端接收客户端数据", "FROM-C1" in log_text(app))

# 广播
app.input.delete("1.0", "end")
app.input.insert("1.0", "BROADCAST")
app.do_send()
pump(root, 0.3)
check("广播到客户端1", c1.recv(1024) == b"BROADCAST")
check("广播到客户端2", c2.recv(1024) == b"BROADCAST")

# 定向发送给单个客户端
app.peer_list.selection_clear(0, "end")
app.peer_list.selection_set(1)
app.input.delete("1.0", "end")
app.input.insert("1.0", "ONLY-ONE")
app.do_send()
pump(root, 0.3)
r1 = c1.recv(1024)
check("定向发送只到选中客户端", r1 == b"ONLY-ONE", repr(r1))
c2.settimeout(0.4)
try:
    leak = c2.recv(1024)
except socket.timeout:
    leak = b""
check("其他客户端未收到定向消息", leak == b"", repr(leak))
c2.settimeout(3)

# 客户端断开后列表更新
c2.close()
pump(root, 0.6)
check("客户端离开后列表更新", app.peer_list.size() == 2,
      "size=%d" % app.peer_list.size())

# 暂停 / 清空
app.toggle_pause()
check("暂停按钮切换", app.btn_pause.cget("text") == "继续")
c1.sendall(b"WHILE-PAUSED")
pump(root, 0.5)
check("暂停时不渲染数据", "WHILE-PAUSED" not in log_text(app))
app.toggle_pause()
c1.sendall(b"AFTER-RESUME")
pump(root, 0.5)
check("恢复后继续渲染", "AFTER-RESUME" in log_text(app))

app.clear_log()
pump(root, 0.2)
check("清空日志", log_text(app).strip() == "")

# 统计
check("统计栏有收发计数", "RX" in app.stat_right.cget("text"))

app.toggle_connection()
pump(root, 0.3)
check("停止监听", "未连接" in app.conn_label.cget("text"))
c1.close()

# ==================== C. 异常输入 ====================
print("C. 异常输入")
app.mode_var.set("客户端")
app.on_mode_change()
app.port_var.set("abc")
app.clear_log()
app.toggle_connection()
pump(root, 0.3)
check("非法端口给出提示", "端口无效" in log_text(app))

app.port_var.set("8080")
app.hex_send.set(True)
app.input.delete("1.0", "end")
app.input.insert("1.0", "ZZZ")
app.clear_log()
app.do_send()
pump(root, 0.3)
check("非法 HEX 给出提示", "HEX 格式错误" in log_text(app))
app.hex_send.set(False)

app.clear_log()
app.input.delete("1.0", "end")
app.input.insert("1.0", "no-server")
app.do_send()
pump(root, 0.3)
check("未连接发送给出提示", "没有可用" in log_text(app))

app._on_close()
print()
print("RESULT:", "ALL PASS" if ok else "HAS FAILURE")
sys.exit(0 if ok else 1)
