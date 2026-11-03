#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TCP 调试助手 v1.0
--------------------------------------------------
单文件、零第三方依赖的 TCP 客户端 / 服务端调试工具。
支持：文本 / HEX 收发、定时发送、多客户端管理、日志保存。

运行：python tcp_debugger.py
"""

import json
import os
import queue
import re
import socket
import sys
import threading
from datetime import datetime

# --------------------------------------------------------------------------
# 缺少 tkinter 时给出可读提示，而不是静默退出
# --------------------------------------------------------------------------
try:
    import tkinter as tk
    from tkinter import filedialog
except ImportError:  # pragma: no cover
    tk = None
    _msg = (
        "当前 Python 解释器没有安装 tkinter，无法显示界面。\n\n"
        "请安装官方 Python（python.org）并勾选 tcl/tk 组件，\n"
        "或直接使用目录下的启动脚本（会自动挑选可用的解释器）。"
    )
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, _msg, "TCP 调试助手", 0x10)
        except Exception:
            sys.stderr.write(_msg + "\n")
    else:
        sys.stderr.write(_msg + "\n")
    sys.exit(1)


APP_NAME = "TCP 调试助手"
APP_VER = "1.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
QUICK_FILE = os.path.join(BASE_DIR, "quick_cmds.json")
MAX_LOG_LINES = 4000

# --------------------------------------------------------------------------
# 配色 / 字体
# --------------------------------------------------------------------------
BG        = "#15171c"
PANEL     = "#1c1f27"
PANEL2    = "#232733"
PANEL3    = "#2a2f3d"
BORDER    = "#2e3340"
FG        = "#e6e9f0"
MUTED     = "#8b93a6"
ACCENT    = "#4c8dff"
ACCENT_D  = "#3a7bec"
RX_C      = "#4ade80"
TX_C      = "#5aa2ff"
SYS_C     = "#7c8598"
ERR_C     = "#f87171"
INPUT_BG  = "#12141a"
OK_C      = "#22c55e"
WARN_C    = "#f59e0b"

UI     = ("Microsoft YaHei UI", 10)
UI_S   = ("Microsoft YaHei UI", 9)
UI_M   = ("Microsoft YaHei UI", 9)
UI_B   = ("Microsoft YaHei UI", 11, "bold")
UI_T   = ("Microsoft YaHei UI", 13, "bold")
MONO   = ("Consolas", 10)

DEFAULT_QUICK = [
    "AT\\r\\n",
    "ping\\r\\n",
    "{\\\"cmd\\\":\\\"status\\\"}\\r\\n",
]


# --------------------------------------------------------------------------
# 编解码工具
# --------------------------------------------------------------------------
def parse_hex_text(text):
    """把 '48 65 6C 6C 6F' / '48656C6C6F' / '0x48,0x65' 解析为 bytes。"""
    cleaned = re.sub(r"0[xX]", "", text)
    cleaned = re.sub(r"[^0-9a-fA-F]", "", cleaned)
    if not cleaned:
        raise ValueError("没有可解析的十六进制内容")
    if len(cleaned) % 2 != 0:
        raise ValueError("十六进制字符个数必须为偶数")
    return bytes.fromhex(cleaned)


def hex_to_display(raw):
    return " ".join("%02X" % b for b in raw)


def human_size(n):
    if n < 1024:
        return "%d B" % n
    if n < 1024 * 1024:
        return "%.1f KB" % (n / 1024.0)
    return "%.1f MB" % (n / (1024.0 * 1024.0))


def unescape_escapes(text):
    """把用户输入的 \\r \\n \\t \\\\0 等转义还原成真实字符。"""
    def repl(m):
        c = m.group(1)
        return {"r": "\r", "n": "\n", "t": "\t", "0": "\x00", "\\": "\\"}.get(c, "\\" + c)
    return re.sub(r"\\([rnt0\\])", repl, text)


# --------------------------------------------------------------------------
# 网络核心：与界面完全解耦，所有回调通过 emit 投递到队列
# --------------------------------------------------------------------------
class TcpCore:
    def __init__(self, emit):
        self.emit = emit                     # emit(kind, *args)
        self._lock = threading.RLock()
        self.mode = None                     # 'client' | 'server' | None
        self.sock = None                     # 客户端连接
        self.server = None                   # 监听套接字
        self.conns = {}                      # cid -> {'sock':s, 'label':str}
        self.peer_label = "server"           # 客户端模式下对端地址，用于日志标注
        self._seq = 0
        # 会话代际：每次 connect/listen/shutdown 自增。旧线程凭自己的 gen 判断是否已过期，
        # 避免"上一个连接的超时/失败"把新会话的 running 标志关掉。
        self._gen = 0
        self.running = False
        self.rx_bytes = 0
        self.tx_bytes = 0

    # ------------------------- 状态 -------------------------
    @property
    def ready(self):
        with self._lock:
            if self.mode == "client":
                return self.sock is not None
            if self.mode == "server":
                return bool(self.conns)
            return False

    # ------------------------- 客户端 -------------------------
    def connect(self, host, port, timeout=6.0):
        self.shutdown(quiet=True)
        with self._lock:
            gen = self._gen
            self.mode = "client"
            self.running = True
        self.emit("sys", "正在连接 %s:%s ..." % (host, port))

        def worker():
            try:
                s = socket.create_connection((host, port), timeout=timeout)
            except Exception as exc:
                with self._lock:
                    if self._gen != gen:
                        return           # 会话已切换，丢弃这次失败
                    self.running = False
                self.emit("err", "连接失败：%s" % exc)
                self.emit("state", "idle", "")
                return

            try:
                s.settimeout(0.3)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                peer = "%s:%s" % (host, port)
                with self._lock:
                    if self._gen != gen:
                        s.close()
                        return       # 连接期间用户已切走
                    self.sock = s
                    self.peer_label = peer
                self.emit("sys", "已连接到 %s" % peer)
                self.emit("state", "connected", peer)
                self._recv_loop(s, "server", peer, gen)
            except Exception as exc:
                with self._lock:
                    if self._gen != gen:
                        return
                    self.running = False
                self.emit("err", "连接异常：%s" % exc)
                self.emit("state", "idle", "")

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------- 服务端 -------------------------
    def listen(self, host, port):
        self.shutdown(quiet=True)
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Windows 的 SO_REUSEADDR 允许重复绑定同一端口（端口劫持），
            # 这里改用独占绑定，端口被占用时能如实报错；其他平台沿用 REUSEADDR
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((host, port))
            srv.listen(16)
            srv.settimeout(0.5)
        except Exception as exc:
            self.emit("err", "监听失败：%s" % exc)
            self.emit("state", "idle", "")
            return False

        with self._lock:
            self.server = srv
            self.mode = "server"
            self.running = True
            gen = self._gen
        self.emit("sys", "已开始监听 %s:%s，等待客户端接入" % (host, port))
        self.emit("state", "listening", "%s:%s" % (host, port))
        threading.Thread(target=self._accept_loop, args=(srv, gen),
                         daemon=True).start()
        return True

    def _accept_loop(self, srv, gen):
        while True:
            with self._lock:
                if self._gen != gen or not self.running or self.server is not srv:
                    break
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(0.3)
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            with self._lock:
                if self._gen != gen:
                    conn.close()
                    break
                self._seq += 1
                cid = "c%d" % self._seq
                label = "%s:%s" % (addr[0], addr[1])
                self.conns[cid] = {"sock": conn, "label": label}
            self.emit("peer_add", cid, label)
            self.emit("sys", "客户端接入：%s" % label)
            threading.Thread(target=self._recv_loop,
                             args=(conn, cid, label, gen), daemon=True).start()

    # ------------------------- 接收 -------------------------
    def _recv_loop(self, sock, key, label, gen):
        while True:
            with self._lock:
                if self._gen != gen or not self.running:
                    break
            try:
                data = sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            with self._lock:
                self.rx_bytes += len(data)
            self.emit("rx", label, data)
        self._drop(key, label, gen)

    def _drop(self, key, label, gen):
        with self._lock:
            if self._gen != gen:
                return                      # 旧会话的收尾，不影响当前状态
            if key == "server":
                sock, self.sock = self.sock, None
                was = self.running
                self.running = False
            else:
                sock = None
                item = self.conns.pop(key, None)
                was = False
        if key == "server":
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
            if was:
                self.emit("sys", "与服务器的连接已断开")
            self.emit("state", "idle", "")
        else:
            if item:
                try:
                    item["sock"].close()
                except OSError:
                    pass
                self.emit("peer_del", key, label)
                self.emit("sys", "客户端断开：%s" % label)

    # ------------------------- 发送 -------------------------
    def send(self, data, target="all"):
        """返回成功发送的字节数，失败返回 -1。"""
        if not data:
            return 0
        targets = []
        with self._lock:
            if self.mode == "client":
                if not self.sock:
                    return -1
                targets = [("server", self.sock)]
            elif self.mode == "server":
                if target == "all":
                    targets = [(cid, it["sock"]) for cid, it in self.conns.items()]
                elif target in self.conns:
                    targets = [(target, self.conns[target]["sock"])]
                if not targets:
                    return -1
            else:
                return -1

        total = 0
        ok_labels = []
        for key, s in targets:
            try:
                s.sendall(data)
                total += len(data)
                if key == "server":
                    with self._lock:
                        ok_labels.append(self.peer_label)
                else:
                    with self._lock:
                        lbl = self.conns.get(key, {}).get("label", key)
                    ok_labels.append(lbl)
            except OSError as exc:
                self.emit("err", "发送失败(%s)：%s" % (key, exc))
        if total:
            with self._lock:
                self.tx_bytes += total
            self.emit("tx", "、".join(ok_labels) or "—", data)
        return total if total else -1

    # ------------------------- 关闭 -------------------------
    def shutdown(self, quiet=False):
        with self._lock:
            self._gen += 1        # 让所有在途线程立即失效
            self.running = False
            self.mode = None
            socks = [it["sock"] for it in self.conns.values()]
            socks += [self.sock] if self.sock else []
            srv = self.server
            self.conns.clear()
            self.sock = None
            self.server = None
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
        if srv:
            try:
                srv.close()
            except OSError:
                pass
        if not quiet:
            self.emit("peers_clear")
            self.emit("sys", "已断开")
            self.emit("state", "idle", "")


# --------------------------------------------------------------------------
# 分段选择控件
# --------------------------------------------------------------------------
class Segmented(tk.Frame):
    def __init__(self, master, options, variable, command=None, bg=PANEL, **kw):
        super().__init__(master, bg=bg, **kw)
        self.var = variable
        self.command = command
        self.buttons = {}
        for opt in options:
            b = tk.Label(self, text=opt, font=UI_S, padx=13, pady=5,
                         cursor="hand2", bd=0)
            b.pack(side="left", padx=(0, 4))
            b.bind("<Button-1>", lambda e, o=opt: self.select(o))
            self.buttons[opt] = b
        self.refresh()

    def select(self, opt):
        self.var.set(opt)
        self.refresh()
        if self.command:
            self.command()

    def refresh(self):
        cur = self.var.get()
        for opt, b in self.buttons.items():
            if opt == cur:
                b.configure(bg=ACCENT, fg="#ffffff")
            else:
                b.configure(bg=PANEL2, fg=MUTED)


# --------------------------------------------------------------------------
# 主界面
# --------------------------------------------------------------------------
class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.core = TcpCore(self._emit)
        self.pending = []
        self.paused = False
        self.auto_job = None
        self._last_flush = 0.0
        self._peer_packed = False     # 客户端面板当前是否已 pack
        self.quick = self._load_quick()

        # ---- 状态变量（必须在建界面前定义）----
        self.mode_var = tk.StringVar(value="客户端")
        self.enc_var = tk.StringVar(value="UTF-8")
        self.hex_view = tk.BooleanVar(value=False)
        self.hex_send = tk.BooleanVar(value=False)
        self.auto_crlf = tk.BooleanVar(value=False)
        self.esc_var = tk.BooleanVar(value=True)
        self.ts_on = tk.BooleanVar(value=True)
        self.auto_scroll = tk.BooleanVar(value=True)
        self.host_var = tk.StringVar(value="127.0.0.1")
        self.port_var = tk.StringVar(value="8080")
        self.interval_var = tk.StringVar(value="1000")
        self.status_var = tk.StringVar(value="未连接")

        self._setup_window()
        self._build_ui()
        self._bind_keys()
        self.root.after(40, self._poll)
        self.root.after(80, self._flush)
        self._push_sys("就绪 · 填写地址端口后点击连接")

    # ================= 窗口 =================
    def _setup_window(self):
        r = self.root
        r.title("%s v%s" % (APP_NAME, APP_VER))
        r.geometry("1140x760")
        r.minsize(960, 640)
        r.configure(bg=BG)
        try:
            r.iconphoto(True, self._make_icon())
        except Exception:
            pass
        r.protocol("WM_DELETE_WINDOW", self._on_close)

    def _make_icon(self):
        img = tk.PhotoImage(width=32, height=32)
        img.put(BG, to=(0, 0, 32, 32))
        img.put(ACCENT, to=(3, 6, 29, 12))
        img.put(ACCENT, to=(3, 20, 29, 26))
        img.put(BG, to=(0, 13, 32, 19))
        return img

    def _bind_keys(self):
        self.root.bind("<Control-Return>", lambda e: (self.do_send(), "break")[1])
        self.root.bind("<Control-l>", lambda e: self.clear_log())
        self.root.bind("<Control-s>", lambda e: self.save_log())
        self.root.bind("<F5>", lambda e: self.toggle_connection())

    # ================= 事件投递 =================
    def _emit(self, kind, *args):
        self.q.put((kind, args))

    def _push_sys(self, text, err=False):
        self.q.put(("err" if err else "sys", (text,)))

    # ================= 布局 =================
    def _build_ui(self):
        self._build_header()
        self._build_statusbar()      # 先占住底部，否则会被放大的 body 挤掉

        body = tk.Frame(self.root, bg=BG)
        body.pack(side="top", fill="both", expand=True, padx=12, pady=10)
        body.columnconfigure(0, weight=0)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        left = tk.Frame(body, bg=BG, width=300)
        left.grid(row=0, column=0, sticky="nsw", padx=(0, 12))
        left.pack_propagate(False)

        main = tk.Frame(body, bg=BG)
        main.grid(row=0, column=1, sticky="nsew")
        main.rowconfigure(1, weight=1)
        main.columnconfigure(0, weight=1)

        self._build_left(left)
        self._build_main(main)
        self.on_mode_change()   # 同步初始模式的布局与文案

    # ---------------- 顶部 ----------------
    def _build_header(self):
        h = tk.Frame(self.root, bg=PANEL, height=58)
        h.pack(side="top", fill="x")
        h.pack_propagate(False)
        tk.Frame(h, bg=BORDER, height=1).pack(side="bottom", fill="x")

        left = tk.Frame(h, bg=PANEL)
        left.pack(side="left", padx=16, pady=10)
        tk.Label(left, text="TCP 调试助手", bg=PANEL, fg=FG, font=UI_T).pack(side="left")
        tk.Label(left, text="v%s" % APP_VER, bg=PANEL, fg=MUTED, font=UI_S).pack(
            side="left", padx=(8, 0), pady=(4, 0))

        right = tk.Frame(h, bg=PANEL)
        right.pack(side="right", padx=16)
        self.dot = tk.Canvas(right, width=12, height=12, bg=PANEL,
                             highlightthickness=0)
        self.dot_id = self.dot.create_oval(2, 2, 10, 10, fill=MUTED, outline="")
        self.dot.pack(side="left", padx=(0, 7))
        self.conn_label = tk.Label(right, text="未连接", bg=PANEL, fg=MUTED, font=UI)
        self.conn_label.pack(side="left")

    # ---------------- 左栏 ----------------
    def _build_left(self, parent):
        # 卡片1：连接设置
        card = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER,
                        highlightthickness=1)
        card.pack(fill="x")
        box = tk.Frame(card, bg=PANEL)
        box.pack(fill="x", padx=14, pady=12)

        tk.Label(box, text="连接设置", bg=PANEL, fg=MUTED, font=UI_S).pack(anchor="w")
        self.mode_seg = Segmented(box, ["客户端", "服务端"], self.mode_var,
                                  command=self.on_mode_change, bg=PANEL)
        self.mode_seg.pack(anchor="w", pady=(8, 12))

        self.host_label = tk.Label(box, text="远程地址", bg=PANEL, fg=MUTED, font=UI_S)
        self.host_label.pack(anchor="w")
        tk.Entry(box, textvariable=self.host_var, bg=INPUT_BG, fg=FG, font=UI,
                 insertbackground=FG, relief="flat", bd=0,
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT).pack(fill="x", ipady=5, pady=(4, 9))

        tk.Label(box, text="端口", bg=PANEL, fg=MUTED, font=UI_S).pack(anchor="w")
        tk.Entry(box, textvariable=self.port_var, bg=INPUT_BG, fg=FG, font=UI,
                 insertbackground=FG, relief="flat", bd=0,
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT).pack(fill="x", ipady=5, pady=(4, 12))

        self.btn_conn = tk.Button(box, text="连接", bg=ACCENT, fg="#ffffff",
                                  activebackground=ACCENT_D, activeforeground="#ffffff",
                                  font=UI, relief="flat", bd=0, cursor="hand2",
                                  command=self.toggle_connection)
        self.btn_conn.pack(fill="x", ipady=4)

        # 卡片2：客户端列表
        self.peer_card = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER,
                                  highlightthickness=1)
        box2 = tk.Frame(self.peer_card, bg=PANEL)
        box2.pack(fill="both", expand=True, padx=14, pady=12)
        head = tk.Frame(box2, bg=PANEL)
        head.pack(fill="x")
        tk.Label(head, text="客户端", bg=PANEL, fg=MUTED, font=UI_S).pack(side="left")
        self.peer_count = tk.Label(head, text="0", bg=PANEL, fg=MUTED, font=UI_S)
        self.peer_count.pack(side="right")

        self.peer_list = tk.Listbox(box2, bg=INPUT_BG, fg=FG, font=MONO,
                                    relief="flat", bd=0, highlightthickness=1,
                                    highlightbackground=BORDER, height=3,
                                    selectbackground=PANEL3, selectforeground=ACCENT,
                                    activestyle="none")
        self.peer_list.pack(fill="both", expand=True, pady=(8, 0))
        self.peer_list.insert("end", "全部客户端")
        self.peer_list.selection_set(0)

        # 卡片3：快捷指令
        card3 = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER,
                         highlightthickness=1)
        card3.pack(fill="both", expand=True, pady=(10, 0))
        self.quick_card = card3
        box3 = tk.Frame(card3, bg=PANEL)
        box3.pack(fill="both", expand=True, padx=14, pady=12)
        head3 = tk.Frame(box3, bg=PANEL)
        head3.pack(fill="x")
        tk.Label(head3, text="快捷指令", bg=PANEL, fg=MUTED, font=UI_S).pack(side="left")
        tk.Label(head3, text="双击填入 · 右键发送", bg=PANEL, fg="#495066",
                 font=UI_S).pack(side="right")

        # 按钮行先固定在底部，避免被可伸缩的列表挤出可视区域
        row = tk.Frame(box3, bg=PANEL)
        row.pack(side="bottom", fill="x", pady=(0, 0))
        for text, cmd in (("添加", self._quick_add), ("删除", self._quick_del)):
            tk.Button(row, text=text, bg=PANEL2, fg=MUTED, activebackground=PANEL3,
                      activeforeground=FG, font=UI_S, relief="flat", bd=0,
                      cursor="hand2", command=cmd).pack(side="left", padx=(0, 6),
                                                        ipadx=10, ipady=3)

        self.quick_list = tk.Listbox(box3, bg=INPUT_BG, fg=FG, font=MONO,
                                     relief="flat", bd=0, highlightthickness=1,
                                     highlightbackground=BORDER,
                                     selectbackground=PANEL3, selectforeground=ACCENT,
                                     activestyle="none", height=5)
        self.quick_list.pack(fill="both", expand=True, pady=(8, 8))
        self.quick_list.bind("<Double-Button-1>", self._quick_fill)
        self.quick_list.bind("<Button-3>", self._quick_menu)

        self._refresh_quick()

    # ---------------- 主区 ----------------
    def _build_main(self, parent):
        # 工具栏
        bar = tk.Frame(parent, bg=BG)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        tk.Label(bar, text="显示", bg=BG, fg=MUTED, font=UI_S).pack(side="left",
                                                                   padx=(0, 6))
        Segmented(bar, ["UTF-8", "GBK"], self.enc_var, bg=BG).pack(side="left")

        self._check(bar, "HEX 显示", self.hex_view).pack(side="left", padx=(14, 0))
        self._check(bar, "时间戳", self.ts_on).pack(side="left", padx=(10, 0))
        self._check(bar, "自动滚动", self.auto_scroll).pack(side="left", padx=(10, 0))

        tk.Button(bar, text="保存", bg=PANEL2, fg=MUTED, activebackground=PANEL3,
                  activeforeground=FG, font=UI_S, relief="flat", bd=0, cursor="hand2",
                  command=self.save_log).pack(side="right", padx=(6, 0), ipadx=10, ipady=3)
        self.btn_pause = tk.Button(bar, text="暂停", bg=PANEL2, fg=MUTED,
                                   activebackground=PANEL3, activeforeground=FG,
                                   font=UI_S, relief="flat", bd=0, cursor="hand2",
                                   command=self.toggle_pause)
        self.btn_pause.pack(side="right", padx=(6, 0), ipadx=10, ipady=3)
        tk.Button(bar, text="清空", bg=PANEL2, fg=MUTED, activebackground=PANEL3,
                  activeforeground=FG, font=UI_S, relief="flat", bd=0, cursor="hand2",
                  command=self.clear_log).pack(side="right", ipadx=10, ipady=3)

        # 日志区
        logwrap = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER,
                           highlightthickness=1)
        logwrap.grid(row=1, column=0, sticky="nsew")
        logwrap.rowconfigure(0, weight=1)
        logwrap.columnconfigure(0, weight=1)

        self.log = tk.Text(logwrap, bg=INPUT_BG, fg=FG, font=MONO, relief="flat",
                           bd=0, padx=10, pady=8, wrap="char",
                           insertbackground=FG, state="disabled",
                           selectbackground=PANEL3, spacing1=1, spacing3=1)
        self.log.grid(row=0, column=0, sticky="nsew")
        sb = tk.Scrollbar(logwrap, orient="vertical", command=self.log.yview,
                          bg=PANEL, troughcolor=INPUT_BG, relief="flat", bd=0,
                          width=12, activebackground=PANEL3)
        sb.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=sb.set)

        self.log.tag_configure("ts", foreground=MUTED)
        self.log.tag_configure("rx", foreground=RX_C)
        self.log.tag_configure("tx", foreground=TX_C)
        self.log.tag_configure("sys", foreground=SYS_C)
        self.log.tag_configure("err", foreground=ERR_C)
        self.log.tag_configure("meta", foreground="#5d6478")
        self.log.tag_configure("body", foreground=FG)

        # 发送区
        self._build_sender(parent)

    def _build_sender(self, parent):
        wrap = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER,
                        highlightthickness=1)
        wrap.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        box = tk.Frame(wrap, bg=PANEL)
        box.pack(fill="x", padx=14, pady=12)

        head = tk.Frame(box, bg=PANEL)
        head.pack(fill="x")
        tk.Label(head, text="发送", bg=PANEL, fg=MUTED, font=UI_S).pack(side="left")
        tk.Label(head, text="Ctrl+Enter 发送", bg=PANEL, fg="#495066",
                 font=UI_S).pack(side="right")

        holder = tk.Frame(box, bg=INPUT_BG, highlightbackground=BORDER,
                          highlightthickness=1)
        holder.pack(fill="x", pady=(8, 10))
        self.input = tk.Text(holder, bg=INPUT_BG, fg=FG, font=MONO, relief="flat",
                             bd=0, height=4, padx=10, pady=8, wrap="char",
                             insertbackground=FG, selectbackground=PANEL3)
        self.input.pack(fill="both", expand=True)
        self.input.insert("1.0", "hello tcp")

        foot = tk.Frame(box, bg=PANEL)
        foot.pack(fill="x")

        self._check(foot, "HEX 发送", self.hex_send, bg=PANEL).pack(side="left")
        self._check(foot, "自动追加 \\r\\n", self.auto_crlf, bg=PANEL).pack(
            side="left", padx=(10, 0))
        self._check(foot, "转义字符生效", self.esc_var, bg=PANEL).pack(
            side="left", padx=(10, 0))

        self.btn_send = tk.Button(foot, text="发送", bg=ACCENT, fg="#ffffff",
                                  activebackground=ACCENT_D, activeforeground="#ffffff",
                                  font=UI, relief="flat", bd=0, cursor="hand2",
                                  command=self.do_send)
        self.btn_send.pack(side="right", ipadx=26, ipady=4)

        sep = tk.Frame(foot, bg=PANEL)
        sep.pack(side="right", padx=12)
        tk.Label(sep, text="间隔(ms)", bg=PANEL, fg=MUTED, font=UI_S).pack(side="left",
                                                                          padx=(0, 6))
        tk.Entry(sep, textvariable=self.interval_var, width=6, bg=INPUT_BG, fg=FG,
                 font=UI_S, justify="center", insertbackground=FG, relief="flat", bd=0,
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT).pack(side="left", ipady=3)
        self.btn_auto = tk.Button(sep, text="定时发送", bg=PANEL2, fg=MUTED,
                                  activebackground=PANEL3, activeforeground=FG,
                                  font=UI_S, relief="flat", bd=0, cursor="hand2",
                                  command=self.toggle_auto)
        self.btn_auto.pack(side="left", padx=(8, 0), ipadx=10, ipady=3)

    def _check(self, parent, text, var, bg=BG):
        return tk.Checkbutton(parent, text=text, variable=var, bg=bg, fg=MUTED,
                              activebackground=bg, activeforeground=FG,
                              selectcolor=INPUT_BG, font=UI_S, bd=0,
                              highlightthickness=0, cursor="hand2")

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=PANEL, height=28)
        bar.pack(side="bottom", fill="x")
        bar.pack_propagate(False)
        tk.Frame(bar, bg=BORDER, height=1).pack(side="top", fill="x")
        self.stat_left = tk.Label(bar, text="就绪", bg=PANEL, fg=MUTED, font=UI_S)
        self.stat_left.pack(side="left", padx=14)
        self.stat_right = tk.Label(bar, text="RX 0 B    TX 0 B", bg=PANEL, fg=MUTED,
                                   font=UI_S)
        self.stat_right.pack(side="right", padx=14)

    # ================= 交互：模式与连接 =================
    def on_mode_change(self):
        is_server = self.mode_var.get() == "服务端"
        self.mode_seg.refresh()      # 变量可能被程序改动，同步高亮
        # 切换模式时若仍在工作，先释放旧连接，避免端口/连接混淆
        if self.core.running or self.core.server:
            self.disconnect()
        self.host_label.configure(text="监听地址" if is_server else "远程地址")
        self.btn_conn.configure(text="开始监听" if is_server else "连接")
        if is_server:
            if self.host_var.get().strip() in ("", "127.0.0.1"):
                self.host_var.set("0.0.0.0")
            if not self._peer_packed:
                self.peer_card.pack(fill="x", pady=(10, 0), before=self.quick_card)
                self._peer_packed = True
        else:
            if self.host_var.get().strip() == "0.0.0.0":
                self.host_var.set("127.0.0.1")
            if self._peer_packed:
                self.peer_card.pack_forget()
                self._peer_packed = False

    def toggle_connection(self):
        # 只有在真正处于活动状态时才当作“断开”，避免停止监听后无法再次启动
        if self.core.running or self.core.server is not None:
            self.disconnect()
            return
        host = self.host_var.get().strip() or "127.0.0.1"
        try:
            port = int(self.port_var.get().strip())
            if not (0 < port < 65536):
                raise ValueError
        except ValueError:
            self._set_state("idle", "")
            self._push_sys("端口无效，请输入 1-65535 之间的数字", err=True)
            return

        if self.mode_var.get() == "服务端":
            self.core.listen(host, port)
        else:
            self.core.connect(host, port)

    def disconnect(self):
        self.stop_auto()
        self.core.shutdown()

    def _set_state(self, kind, info):
        colors = {"connected": OK_C, "listening": WARN_C, "idle": MUTED}
        texts = {"connected": "已连接", "listening": "监听中", "idle": "未连接"}
        c = colors.get(kind, MUTED)
        self.dot.itemconfig(self.dot_id, fill=c)
        self.conn_label.configure(text="%s %s" % (texts.get(kind, ""), info),
                                  fg=c)
        if kind == "idle":
            self.btn_conn.configure(
                text="开始监听" if self.mode_var.get() == "服务端" else "连接",
                bg=ACCENT, fg="#ffffff",
                activebackground=ACCENT_D, activeforeground="#ffffff")
        else:
            self.btn_conn.configure(
                text="断开", bg=PANEL2, fg=FG,
                activebackground=PANEL3, activeforeground=FG)

    # ================= 交互：发送 =================
    def _current_target(self):
        if self.mode_var.get() != "服务端":
            return "all"
        sel = self.peer_list.curselection()
        if not sel or sel[0] == 0:
            return "all"
        try:
            label = self.peer_list.get(sel[0])
        except tk.TclError:
            return "all"
        for cid, item in list(self.core.conns.items()):
            if item["label"] == label:
                return cid
        return "all"

    def do_send(self, text=None):
        if text is None:
            text = self.input.get("1.0", "end-1c")
        if not text.strip():
            return
        try:
            if self.hex_send.get():
                data = parse_hex_text(text)
            else:
                body = unescape_escapes(text) if self.esc_var.get() else text
                if self.auto_crlf.get():
                    body += "\r\n"
                data = body.encode(self.enc_var.get().lower().replace("-", ""))
        except ValueError as exc:
            self._push_sys("HEX 格式错误：%s" % exc, err=True)
            return
        except Exception as exc:
            self._push_sys("编码失败：%s" % exc, err=True)
            return

        n = self.core.send(data, self._current_target())
        if n < 0:
            self._push_sys("发送失败：当前没有可用的连接", err=True)

    def toggle_auto(self):
        if self.auto_job:
            self.stop_auto()
        else:
            try:
                iv = int(float(self.interval_var.get()))
                if iv < 50:
                    raise ValueError
            except ValueError:
                self._push_sys("间隔需为 >=50 的整数（毫秒）", err=True)
                return
            self.btn_auto.configure(text="停止定时", bg=ERR_C, fg="#ffffff")
            self._auto_tick(iv)

    def _auto_tick(self, iv):
        self.do_send()
        self.auto_job = self.root.after(iv, lambda: self._auto_tick(iv))

    def stop_auto(self):
        if self.auto_job:
            try:
                self.root.after_cancel(self.auto_job)
            except Exception:
                pass
            self.auto_job = None
        self.btn_auto.configure(text="定时发送", bg=PANEL2, fg=MUTED)

    # ================= 日志 =================
    def _poll(self):
        batch = 0
        while batch < 400:
            try:
                kind, args = self.q.get_nowait()
            except queue.Empty:
                break
            batch += 1
            try:
                self._handle(kind, args)
            except Exception as exc:      # 保证事件循环不被打断
                sys.stderr.write("handle error: %r\n" % (exc,))
        self.root.after(30, self._poll)

    def _handle(self, kind, args):
        if kind == "sys":
            self._queue_line("sys", "·", "", args[0], None)
        elif kind == "err":
            self._queue_line("err", "!", "", args[0], None)
        elif kind == "rx":
            label, data = args
            self._queue_line("rx", "←", label, self._fmt_data(data), len(data))
        elif kind == "tx":
            label, data = args
            self._queue_line("tx", "→", label, self._fmt_data(data), len(data))
        elif kind == "state":
            self._set_state(args[0], args[1])
        elif kind == "peer_add":
            self.peer_list.insert("end", args[1])
            self._sync_peer_count()
        elif kind == "peer_del":
            label = args[1]
            try:
                idx = self.peer_list.get(0, "end").index(label)
                self.peer_list.delete(idx)
            except ValueError:
                pass
            self._sync_peer_count()
        elif kind == "peers_clear":
            self.peer_list.delete(1, "end")
            self.peer_list.selection_set(0)
            self._sync_peer_count()

    def _sync_peer_count(self):
        n = max(0, self.peer_list.size() - 1)
        self.peer_count.configure(text=str(n))

    def _fmt_data(self, data):
        if self.hex_view.get():
            return hex_to_display(data)
        enc = self.enc_var.get().lower().replace("-", "")
        data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        out = []
        chunk = bytearray()

        def flush_chunk():
            if not chunk:
                return
            raw = bytes(chunk)
            del chunk[:]
            try:
                out.append(raw.decode(enc))
            except (UnicodeDecodeError, LookupError):
                out.append("".join("\\x%02X" % b for b in raw))

        for b in data:
            if b in (0x0A, 0x09) or 0x20 <= b <= 0x7E:
                flush_chunk()
                out.append(chr(b))
            elif b >= 0x80:
                chunk.append(b)          # 可能是多字节字符，攒起来整体解码
            else:
                flush_chunk()
                out.append("\\x%02X" % b)
        flush_chunk()
        return "".join(out)

    def _queue_line(self, tag, arrow, label, body, size):
        if self.paused and tag in ("rx", "tx"):
            return
        self.pending.append((tag, arrow, label, body, size))

    def _flush(self):
        if self.pending:
            items, self.pending = self.pending, []
            self.log.configure(state="normal")
            for tag, arrow, label, body, size in items:
                if self.ts_on.get():
                    self.log.insert("end", "[%s] " % datetime.now().strftime("%H:%M:%S.%f")[:-3],
                                    "ts")
                self.log.insert("end", arrow + " ", tag if tag in ("rx", "tx", "err", "sys") else "body")
                if label or size is not None:
                    meta = ""
                    if label:
                        meta += label + "  "
                    if size is not None:
                        meta += human_size(size)
                    self.log.insert("end", meta + "  ", "meta")
                # 多行数据续行缩进，避免和下一行时间戳混在一起
                text = ("\n" + " " * 10).join(body.rstrip("\n").split("\n")) + "\n"
                self.log.insert("end", text, "body")
            self.log.configure(state="disabled")
            self._trim()
            if self.auto_scroll.get():
                self.log.see("end-1c")
            self._update_stats()
        self.root.after(80, self._flush)

    def _trim(self):
        try:
            lines = int(self.log.index("end-1c").split(".")[0])
        except Exception:
            return
        if lines > MAX_LOG_LINES:
            self.log.configure(state="normal")
            self.log.delete("1.0", "%d.0" % (lines - MAX_LOG_LINES + 1000))
            self.log.configure(state="disabled")

    def _update_stats(self):
        self.stat_right.configure(
            text="RX %s    TX %s" % (human_size(self.core.rx_bytes),
                                     human_size(self.core.tx_bytes)))

    def clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        self.pending = []

    def toggle_pause(self):
        self.paused = not self.paused
        if self.paused:
            self.btn_pause.configure(text="继续", fg=WARN_C)
        else:
            self.btn_pause.configure(text="暂停", fg=MUTED)

    def save_log(self):
        content = self.log.get("1.0", "end-1c")
        if not content.strip():
            return
        path = filedialog.asksaveasfilename(
            title="保存日志", defaultextension=".log",
            initialfile="tcp_%s.log" % datetime.now().strftime("%Y%m%d_%H%M%S"),
            filetypes=[("日志文件", "*.log"), ("文本文件", "*.txt"), ("全部文件", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            self.stat_left.configure(text="日志已保存到 %s" % os.path.basename(path))
        except Exception as exc:
            self._push_sys("保存失败：%s" % exc, err=True)

    # ================= 快捷指令 =================
    def _load_quick(self):
        try:
            if os.path.exists(QUICK_FILE):
                with open(QUICK_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list) and data:
                    return [str(x) for x in data]
        except Exception:
            pass
        return list(DEFAULT_QUICK)

    def _save_quick(self):
        try:
            with open(QUICK_FILE, "w", encoding="utf-8") as f:
                json.dump(self.quick, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _refresh_quick(self):
        self.quick_list.delete(0, "end")
        for item in self.quick:
            self.quick_list.insert("end", item)

    def _quick_fill(self, _=None):
        sel = self.quick_list.curselection()
        if not sel:
            return
        self.input.delete("1.0", "end")
        self.input.insert("1.0", self.quick[sel[0]])

    def _quick_send(self, _=None):
        sel = self.quick_list.curselection()
        if not sel:
            return
        self.do_send(self.quick[sel[0]])

    def _quick_menu(self, event):
        idx = self.quick_list.nearest(event.y)
        if idx < 0 or idx >= len(self.quick):
            return
        self.quick_list.selection_clear(0, "end")
        self.quick_list.selection_set(idx)
        menu = tk.Menu(self.root, tearoff=0, bg=PANEL, fg=FG,
                       activebackground=ACCENT, activeforeground="#ffffff",
                       bd=0, font=UI_S)
        menu.add_command(label="填入输入框", command=self._quick_fill)
        menu.add_command(label="立即发送", command=self._quick_send)
        menu.add_separator()
        menu.add_command(label="删除", command=self._quick_del)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _quick_add(self):
        win = tk.Toplevel(self.root)
        win.title("添加快捷指令")
        win.configure(bg=PANEL)
        win.transient(self.root)
        win.resizable(False, False)
        tk.Label(win, text="内容（支持 \\r \\n 转义）", bg=PANEL, fg=MUTED,
                 font=UI_S).pack(anchor="w", padx=16, pady=(14, 6))
        ent = tk.Entry(win, width=42, bg=INPUT_BG, fg=FG, font=MONO,
                       insertbackground=FG, relief="flat", bd=0,
                       highlightthickness=1, highlightbackground=BORDER,
                       highlightcolor=ACCENT)
        ent.pack(padx=16, ipady=6)
        ent.focus_set()

        def ok(_=None):
            val = ent.get().strip()
            if val:
                self.quick.append(val)
                self._save_quick()
                self._refresh_quick()
            win.destroy()

        ent.bind("<Return>", ok)
        tk.Button(win, text="添加", bg=ACCENT, fg="#ffffff",
                  activebackground=ACCENT_D, font=UI_S, relief="flat", bd=0,
                  cursor="hand2", command=ok).pack(pady=14, ipadx=24, ipady=4)
        win.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - win.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - win.winfo_height()) // 3
        win.geometry("+%d+%d" % (x, y))
        win.grab_set()

    def _quick_del(self):
        sel = self.quick_list.curselection()
        if not sel:
            return
        del self.quick[sel[0]]
        self._save_quick()
        self._refresh_quick()

    # ================= 退出 =================
    def _on_close(self):
        self.stop_auto()
        try:
            self.core.shutdown(quiet=True)
        except Exception:
            pass
        self.root.destroy()


def main():
    if "--selftest" in sys.argv:
        root = tk.Tk()
        app = App(root)
        root.update_idletasks()
        root.update()
        print("SELFTEST OK size=%dx%d" % (root.winfo_width(), root.winfo_height()))
        root.after(300, root.destroy)
        root.mainloop()
        return

    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
