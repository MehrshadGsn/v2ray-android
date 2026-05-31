"""
V2Ray / Xray Manager — Android (Kivy)
UI بازنویسی‌شده با Kivy برای اندروید
منطق اصلی (parse لینک، build config) از نسخه desktop حفظ شده
"""

import json, os, sys, threading, time, random, subprocess, base64, re, socket
from urllib.parse import unquote
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.spinner import Spinner
from kivy.uix.widget import Widget
from kivy.graphics import Color, RoundedRectangle, Rectangle
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.metrics import dp
from kivy.utils import get_color_from_hex

Window.clearcolor = get_color_from_hex("#0d0d0f")

CONFIG_FILE = "v2ray_configs.json"
XRAY_CONFIG = "xray_active.json"
SOCKS_PORT  = 10808
HTTP_PORT   = 10809

# ═══════════════════════════════════════════════════
#  Parser لینک‌های کانفیگ  (بدون تغییر از نسخه desktop)
# ═══════════════════════════════════════════════════
def parse_link(link: str) -> dict | None:
    link = link.strip()

    if link.startswith("vmess://"):
        try:
            b64 = link[8:]
            b64 += "=" * (-len(b64) % 4)
            data = json.loads(base64.b64decode(b64).decode())
            return {
                "type":    "VMess",
                "name":    data.get("ps", data.get("add", "VMess Server")),
                "host":    data.get("add", ""),
                "port":    str(data.get("port", "443")),
                "uuid":    data.get("id", ""),
                "alterId": str(data.get("aid", "0")),
                "net":     data.get("net", "tcp"),
                "tls":     data.get("tls", ""),
                "path":    data.get("path", ""),
                "sni":     data.get("sni", data.get("host", "")),
                "link":    link,
            }
        except Exception as e:
            return {"_error": str(e)}

    if link.startswith("vless://"):
        try:
            rest = link[8:]
            name_part = ""
            if "#" in rest:
                rest, name_part = rest.rsplit("#", 1)
                name_part = unquote(name_part)
            uuid, hostport_params = rest.split("@", 1)
            hostport, params_str = (hostport_params.split("?", 1)
                                    if "?" in hostport_params
                                    else (hostport_params, ""))
            if hostport.startswith("["):
                host, port = hostport.rsplit(":", 1)
                host = host.strip("[]")
            else:
                host, port = hostport.rsplit(":", 1)
            params = dict(p.split("=", 1) for p in params_str.split("&") if "=" in p)
            return {
                "type": "VLESS", "name": name_part or f"VLESS {host}",
                "host": host, "port": port, "uuid": uuid,
                "net":  params.get("type", "tcp"),
                "tls":  params.get("security", ""),
                "path": params.get("path", ""),
                "sni":  params.get("sni", ""),
                "flow": params.get("flow", ""),
                "link": link,
            }
        except Exception as e:
            return {"_error": str(e)}

    if link.startswith("trojan://"):
        try:
            rest = link[9:]
            name_part = ""
            if "#" in rest:
                rest, name_part = rest.rsplit("#", 1)
                name_part = unquote(name_part)
            pwd, hostport_params = rest.split("@", 1)
            hostport, params_str = (hostport_params.split("?", 1)
                                    if "?" in hostport_params
                                    else (hostport_params, ""))
            host, port = (hostport.rsplit(":", 1) if ":" in hostport
                          else (hostport, "443"))
            params = dict(p.split("=", 1) for p in params_str.split("&") if "=" in p)
            return {
                "type": "Trojan", "name": name_part or f"Trojan {host}",
                "host": host, "port": port, "password": pwd,
                "sni":  params.get("sni", host),
                "net":  params.get("type", "tcp"),
                "path": params.get("path", ""),
                "link": link,
            }
        except Exception as e:
            return {"_error": str(e)}

    if link.startswith("ss://"):
        try:
            rest = link[5:]
            name_part = ""
            if "#" in rest:
                rest, name_part = rest.rsplit("#", 1)
                name_part = unquote(name_part)
            if "@" in rest:
                method_pwd_b64, hostport = rest.rsplit("@", 1)
                try:
                    method_pwd_b64 += "=" * (-len(method_pwd_b64) % 4)
                    decoded = base64.b64decode(method_pwd_b64).decode()
                    method, password = decoded.split(":", 1)
                except Exception:
                    method, password = method_pwd_b64, ""
            else:
                rest += "=" * (-len(rest) % 4)
                decoded = base64.b64decode(rest).decode()
                method_pwd, hostport = decoded.split("@", 1)
                method, password = method_pwd.split(":", 1)
            host, port = (hostport.rsplit(":", 1) if ":" in hostport
                          else (hostport, "8388"))
            return {
                "type": "Shadowsocks", "name": name_part or f"SS {host}",
                "host": host, "port": port,
                "method": method, "password": password, "link": link,
            }
        except Exception as e:
            return {"_error": str(e)}

    return None


# ═══════════════════════════════════════════════════
#  تولید کانفیگ xray  (بدون تغییر)
# ═══════════════════════════════════════════════════
def build_xray_config(cfg: dict) -> dict:
    proto = cfg["type"]
    xconfig = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks", "port": SOCKS_PORT, "listen": "127.0.0.1",
             "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
            {"tag": "http", "port": HTTP_PORT, "listen": "127.0.0.1",
             "protocol": "http", "settings": {},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}}
        ],
        "outbounds": [],
        "dns": {"servers": ["8.8.8.8", "1.1.1.1"]}
    }

    net  = cfg.get("net", "tcp")
    tls  = cfg.get("tls", "")
    path = cfg.get("path", "")
    sni  = cfg.get("sni", cfg.get("host", ""))
    stream = {"network": net}

    if net == "ws":
        stream["wsSettings"] = {"path": path or "/",
                                 "headers": {"Host": sni or cfg.get("host", "")}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": path or ""}
    elif net == "h2":
        stream["httpSettings"] = {"path": path or "/",
                                   "host": [sni or cfg.get("host", "")]}

    if tls in ("tls", "xtls"):
        stream["security"] = tls
        stream["tlsSettings"] = {"allowInsecure": False,
                                  "serverName": sni or cfg.get("host", "")}
    elif tls == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName":  sni or cfg.get("host", ""),
            "fingerprint": cfg.get("fp", "chrome"),
            "publicKey":   cfg.get("pbk", ""),
            "shortId":     cfg.get("sid", ""),
            "spiderX":     cfg.get("spx", "/"),
        }

    host = cfg.get("host", "")
    port = int(cfg.get("port", 443))

    if proto == "VMess":
        outbound = {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": host, "port": port,
                                     "users": [{"id": cfg.get("uuid", ""),
                                                "alterId": int(cfg.get("alterId", 0)),
                                                "security": "auto"}]}]},
            "streamSettings": stream}
    elif proto == "VLESS":
        user = {"id": cfg.get("uuid", ""), "encryption": "none"}
        if cfg.get("flow"):
            user["flow"] = cfg["flow"]
        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": stream}
    elif proto == "Trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {"servers": [{"address": host, "port": port,
                                       "password": cfg.get("password", "")}]},
            "streamSettings": stream}
    elif proto == "Shadowsocks":
        outbound = {
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": host, "port": port,
                                       "method": cfg.get("method", "aes-256-gcm"),
                                       "password": cfg.get("password", "")}]}}
    else:
        raise ValueError(f"پروتکل ناشناخته: {proto}")

    xconfig["outbounds"].extend([
        outbound,
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block"}
    ])
    return xconfig


# ═══════════════════════════════════════════════════
#  ذخیره / بارگذاری
# ═══════════════════════════════════════════════════
def load_configs():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_configs(configs):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(configs, f, ensure_ascii=False, indent=2)


# ═══════════════════════════════════════════════════
#  پیدا کردن binary xray (نسخه اندروید)
# ═══════════════════════════════════════════════════
def find_core() -> str | None:
    base = os.path.dirname(os.path.abspath(sys.argv[0]))
    candidates = [
        os.path.join(base, "xray"),          # کنار APK (assets)
        "/data/data/org.v2raymanager/files/xray",   # فضای خصوصی app
        "xray",                               # PATH
    ]
    for c in candidates:
        try:
            r = subprocess.run([c, "version"], capture_output=True, timeout=3)
            if r.returncode == 0:
                return c
        except Exception:
            pass
    return None


# ═══════════════════════════════════════════════════
#  ویجت‌های سفارشی Kivy
# ═══════════════════════════════════════════════════
def hex_color(h, a=1):
    h = h.lstrip("#")
    r, g, b = int(h[0:2], 16)/255, int(h[2:4], 16)/255, int(h[4:6], 16)/255
    return (r, g, b, a)


class RoundedCard(BoxLayout):
    def __init__(self, bg="#18181c", border="#2a2a35", radius=14, **kwargs):
        super().__init__(**kwargs)
        self._bg = bg
        self._border = border
        self._r = radius
        self.bind(pos=self._draw, size=self._draw)

    def _draw(self, *_):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*hex_color(self._border))
            RoundedRectangle(pos=self.pos, size=self.size,
                              radius=[dp(self._r)])
            Color(*hex_color(self._bg))
            RoundedRectangle(pos=(self.pos[0]+1, self.pos[1]+1),
                              size=(self.size[0]-2, self.size[1]-2),
                              radius=[dp(self._r)])


class PurpleButton(Button):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.background_color = (0, 0, 0, 0)
        self.background_normal = ""
        self.color = hex_color("#ffffff")
        self.font_size = dp(14)
        self.size_hint_y = None
        self.height = dp(48)
        self.bind(pos=self._draw, size=self._draw)

    def _draw(self, *_):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*hex_color("#6c63ff"))
            RoundedRectangle(pos=self.pos, size=self.size,
                              radius=[dp(14)])


class DarkButton(Button):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.background_color = (0, 0, 0, 0)
        self.background_normal = ""
        self.color = hex_color("#888888")
        self.font_size = dp(13)
        self.size_hint_y = None
        self.height = dp(42)
        self.bind(pos=self._draw, size=self._draw)

    def _draw(self, *_):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*hex_color("#1a1a2e"))
            RoundedRectangle(pos=self.pos, size=self.size,
                              radius=[dp(12)])
            Color(*hex_color("#2a2a40"))
            RoundedRectangle(pos=self.pos, size=self.size,
                              radius=[dp(12)])


# ═══════════════════════════════════════════════════
#  دیالوگ افزودن کانفیگ
# ═══════════════════════════════════════════════════
class AddConfigPopup(Popup):
    def __init__(self, on_save_cb, **kwargs):
        super().__init__(
            title="افزودن کانفیگ",
            size_hint=(0.95, 0.85),
            background_color=hex_color("#0d0d0f"),
            title_color=hex_color("#a78bfa"),
            separator_color=hex_color("#2a2a40"),
            **kwargs
        )
        self.on_save_cb = on_save_cb
        self._parsed = {}

        layout = BoxLayout(orientation="vertical", padding=dp(16), spacing=dp(8))

        # لینک
        layout.add_widget(Label(text="لینک کانفیگ (vmess/vless/trojan/ss)",
                                font_size=dp(12), color=hex_color("#c4b5fd"),
                                size_hint_y=None, height=dp(24), halign="right"))
        self.link_input = TextInput(
            hint_text="vmess:// یا vless:// یا ...",
            multiline=True,
            size_hint_y=None, height=dp(80),
            background_color=hex_color("#0a0a16"),
            foreground_color=hex_color("#ffffff"),
            font_size=dp(12)
        )
        layout.add_widget(self.link_input)

        parse_btn = PurpleButton(text="پارس لینک و پر کردن خودکار")
        parse_btn.bind(on_press=self._parse)
        layout.add_widget(parse_btn)

        self.status_lbl = Label(text="", font_size=dp(11),
                                color=hex_color("#22c55e"),
                                size_hint_y=None, height=dp(20))
        layout.add_widget(self.status_lbl)

        # نام
        layout.add_widget(Label(text="نام سرور", font_size=dp(12),
                                color=hex_color("#aaaaaa"),
                                size_hint_y=None, height=dp(22), halign="right"))
        self.name_input = TextInput(
            hint_text="Germany Server",
            multiline=False, size_hint_y=None, height=dp(40),
            background_color=hex_color("#0a0a16"),
            foreground_color=hex_color("#ffffff"), font_size=dp(13)
        )
        layout.add_widget(self.name_input)

        # پروتکل
        layout.add_widget(Label(text="پروتکل", font_size=dp(12),
                                color=hex_color("#aaaaaa"),
                                size_hint_y=None, height=dp(22), halign="right"))
        self.proto_spinner = Spinner(
            text="VMess",
            values=["VMess", "VLESS", "Trojan", "Shadowsocks"],
            size_hint_y=None, height=dp(40),
            background_color=hex_color("#0a0a16"),
            color=hex_color("#ffffff"), font_size=dp(13)
        )
        layout.add_widget(self.proto_spinner)

        # آدرس و پورت
        layout.add_widget(Label(text="آدرس", font_size=dp(12),
                                color=hex_color("#aaaaaa"),
                                size_hint_y=None, height=dp(22), halign="right"))
        self.host_input = TextInput(
            hint_text="example.com", multiline=False,
            size_hint_y=None, height=dp(40),
            background_color=hex_color("#0a0a16"),
            foreground_color=hex_color("#ffffff"), font_size=dp(13)
        )
        layout.add_widget(self.host_input)

        layout.add_widget(Label(text="پورت", font_size=dp(12),
                                color=hex_color("#aaaaaa"),
                                size_hint_y=None, height=dp(22), halign="right"))
        self.port_input = TextInput(
            hint_text="443", multiline=False,
            size_hint_y=None, height=dp(40),
            background_color=hex_color("#0a0a16"),
            foreground_color=hex_color("#ffffff"), font_size=dp(13)
        )
        layout.add_widget(self.port_input)

        layout.add_widget(Widget(size_hint_y=None, height=dp(8)))

        # دکمه‌ها
        btn_row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(10))
        cancel_btn = DarkButton(text="انصراف")
        cancel_btn.bind(on_press=lambda x: self.dismiss())
        btn_row.add_widget(cancel_btn)

        save_btn = PurpleButton(text="ذخیره")
        save_btn.bind(on_press=self._save)
        btn_row.add_widget(save_btn)
        layout.add_widget(btn_row)

        scroll = ScrollView()
        scroll.add_widget(layout)
        self.content = scroll

    def _parse(self, _):
        link = self.link_input.text.strip()
        if not link:
            self.status_lbl.text = "⚠ لینک را وارد کنید"
            self.status_lbl.color = hex_color("#f59e0b")
            return
        parsed = parse_link(link)
        if not parsed:
            self.status_lbl.text = "✗ فرمت ناشناخته"
            self.status_lbl.color = hex_color("#ef4444")
            return
        if "_error" in parsed:
            self.status_lbl.text = f"✗ {parsed['_error'][:50]}"
            self.status_lbl.color = hex_color("#ef4444")
            return
        self.name_input.text  = parsed.get("name", "")
        self.host_input.text  = parsed.get("host", "")
        self.port_input.text  = parsed.get("port", "")
        self.proto_spinner.text = parsed.get("type", "VMess")
        self._parsed = parsed
        self.status_lbl.text = f"✓ {parsed['type']} ← {parsed['host']}"
        self.status_lbl.color = hex_color("#22c55e")

    def _save(self, _):
        host = self.host_input.text.strip()
        if not host:
            self.status_lbl.text = "✗ آدرس سرور را وارد کنید"
            self.status_lbl.color = hex_color("#ef4444")
            return
        name = self.name_input.text.strip() or f"{self.proto_spinner.text} — {host}"
        cfg = self._parsed.copy()
        cfg.update({
            "name": name,
            "type": self.proto_spinner.text,
            "host": host,
            "port": self.port_input.text.strip() or "443",
            "link": self.link_input.text.strip(),
            "ping": "—"
        })
        self.on_save_cb(cfg)
        self.dismiss()


# ═══════════════════════════════════════════════════
#  ویجت ردیف کانفیگ
# ═══════════════════════════════════════════════════
PROTO_ICON = {
    "VMess":       "🔷",
    "VLESS":       "🔹",
    "Trojan":      "🔶",
    "Shadowsocks": "🟢",
}

class ConfigRow(RoundedCard):
    def __init__(self, cfg, on_select, on_delete, active=False, **kwargs):
        super().__init__(
            bg="#1e1e30" if active else "#18181c",
            border="#6c63ff" if active else "#2a2a35",
            orientation="horizontal",
            size_hint_y=None, height=dp(64),
            padding=dp(10), spacing=dp(6),
            **kwargs
        )
        icon = PROTO_ICON.get(cfg.get("type", ""), "⚙")
        self.add_widget(Label(text=icon, font_size=dp(20),
                              size_hint_x=None, width=dp(36)))

        info = BoxLayout(orientation="vertical")
        info.add_widget(Label(text=cfg.get("name", ""),
                              font_size=dp(13), bold=True,
                              color=hex_color("#f0f0f0"),
                              halign="right", valign="middle"))
        info.add_widget(Label(text=f"{cfg.get('host','')}:{cfg.get('port','')}",
                              font_size=dp(10), color=hex_color("#555555"),
                              halign="right", valign="middle"))
        self.add_widget(info)

        ping = cfg.get("ping", "—")
        self.add_widget(Label(
            text=f"{ping}ms" if ping != "—" else "—",
            font_size=dp(11), bold=True,
            color=hex_color("#22c55e"),
            size_hint_x=None, width=dp(52)
        ))

        del_btn = Button(
            text="🗑", font_size=dp(16),
            size_hint=(None, None), size=(dp(32), dp(32)),
            background_color=(0, 0, 0, 0)
        )
        del_btn.bind(on_press=lambda x: on_delete(cfg))
        self.add_widget(del_btn)
        self.bind(on_touch_down=lambda w, t:
                  on_select(cfg) if w.collide_point(*t.pos) else None)


# ═══════════════════════════════════════════════════
#  پنجره اصلی
# ═══════════════════════════════════════════════════
class MainScreen(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation="vertical", padding=dp(12),
                         spacing=dp(8), **kwargs)
        self.configs    = load_configs()
        self._next_id   = max((c.get("id", 0) for c in self.configs), default=0) + 1
        self.active_cfg = self.configs[0] if self.configs else None
        self.connected  = False
        self.connecting = False
        self._proc      = None
        self._timer_sec = 0
        self._core_path = find_core()
        self._build()
        self._refresh_list()

    def _build(self):
        # هدر
        hdr = BoxLayout(size_hint_y=None, height=dp(44))
        hdr.add_widget(Label(text="🔒 V2Ray Manager",
                             font_size=dp(18), bold=True,
                             color=hex_color("#a78bfa"), halign="left"))
        self.timer_lbl = Label(text="00:00", font_size=dp(12),
                               color=hex_color("#333333"),
                               size_hint_x=None, width=dp(70))
        hdr.add_widget(self.timer_lbl)
        self.add_widget(hdr)

        # وضعیت هسته
        core_txt = (f"✓  هسته: {os.path.basename(self._core_path)}"
                    if self._core_path
                    else "⚠  xray پیدا نشد — فایل xray را در کنار APK قرار دهید")
        self.add_widget(Label(text=core_txt, font_size=dp(10),
                              color=hex_color("#22c55e" if self._core_path else "#f59e0b"),
                              size_hint_y=None, height=dp(20), halign="right"))

        # کارت اتصال
        card = RoundedCard(bg="#18181c", border="#2a2a35", radius=20,
                           orientation="vertical",
                           size_hint_y=None, height=dp(220),
                           padding=dp(14), spacing=dp(6))

        status_row = BoxLayout(size_hint_y=None, height=dp(28))
        self.dot_lbl = Label(text="⬤", font_size=dp(14),
                             color=hex_color("#333333"),
                             size_hint_x=None, width=dp(22))
        status_row.add_widget(self.dot_lbl)
        self.status_lbl = Label(text="قطع", font_size=dp(13),
                                color=hex_color("#555555"))
        status_row.add_widget(self.status_lbl)
        card.add_widget(status_row)

        # منوی سرور
        self.srv_spinner = Spinner(
            text="انتخاب سرور...",
            values=["انتخاب سرور..."],
            size_hint_y=None, height=dp(38),
            background_color=hex_color("#0d0d0f"),
            color=hex_color("#ffffff"), font_size=dp(13)
        )
        self.srv_spinner.bind(text=self._on_srv_select)
        card.add_widget(self.srv_spinner)

        self.conn_btn = PurpleButton(text="اتصال")
        self.conn_btn.bind(on_press=lambda x: self._toggle())
        card.add_widget(self.conn_btn)

        self.log_lbl = Label(text="", font_size=dp(10),
                             color=hex_color("#555555"),
                             size_hint_y=None, height=dp(18))
        card.add_widget(self.log_lbl)

        # آمار
        stats_row = BoxLayout(size_hint_y=None, height=dp(54), spacing=dp(6))
        for attr, label in [("dl_lbl", "↓ دریافت"),
                             ("ul_lbl", "↑ ارسال"),
                             ("ping_lbl", "پینگ")]:
            box = RoundedCard(bg="#0d0d0f", border="#2a2a35", radius=10,
                              orientation="vertical", padding=dp(4))
            val = Label(text="—", font_size=dp(12), bold=True,
                        color=hex_color("#6c63ff"))
            setattr(self, attr, val)
            box.add_widget(val)
            box.add_widget(Label(text=label, font_size=dp(9),
                                 color=hex_color("#444444")))
            stats_row.add_widget(box)
        card.add_widget(stats_row)
        self.add_widget(card)

        # عنوان لیست
        self.add_widget(Label(text="کانفیگ‌های من", font_size=dp(11),
                              color=hex_color("#444444"),
                              size_hint_y=None, height=dp(22), halign="right"))

        # لیست اسکرول‌پذیر
        self.scroll = ScrollView(size_hint_y=1)
        self.list_box = BoxLayout(orientation="vertical",
                                  spacing=dp(6), size_hint_y=None)
        self.list_box.bind(minimum_height=self.list_box.setter("height"))
        self.scroll.add_widget(self.list_box)
        self.add_widget(self.scroll)

        # دکمه افزودن
        add_btn = DarkButton(text="➕  افزودن کانفیگ جدید")
        add_btn.bind(on_press=lambda x: self._open_add())
        self.add_widget(add_btn)

        self.add_widget(Label(
            text=f"SOCKS5: 127.0.0.1:{SOCKS_PORT}   HTTP: 127.0.0.1:{HTTP_PORT}",
            font_size=dp(9), color=hex_color("#2a2a35"),
            size_hint_y=None, height=dp(18)
        ))

    def _refresh_list(self):
        self.list_box.clear_widgets()
        names = [c["name"] for c in self.configs]
        self.srv_spinner.values = names if names else ["کانفیگی ندارید"]
        if self.active_cfg:
            self.srv_spinner.text = self.active_cfg["name"]
        for cfg in self.configs:
            is_active = (self.active_cfg and
                         cfg.get("id") == self.active_cfg.get("id"))
            row = ConfigRow(cfg,
                            on_select=self._select,
                            on_delete=self._delete,
                            active=bool(is_active))
            self.list_box.add_widget(row)

    def _on_srv_select(self, spinner, name):
        for c in self.configs:
            if c["name"] == name:
                self._select(c)
                break

    def _select(self, cfg):
        if self.connected or self.connecting:
            return
        self.active_cfg = cfg
        self._refresh_list()

    def _delete(self, cfg):
        if self.connected or self.connecting:
            return
        self.configs = [c for c in self.configs if c.get("id") != cfg.get("id")]
        if self.active_cfg and self.active_cfg.get("id") == cfg.get("id"):
            self.active_cfg = self.configs[0] if self.configs else None
        save_configs(self.configs)
        self._refresh_list()

    def _open_add(self):
        AddConfigPopup(on_save_cb=self._on_saved).open()

    def _on_saved(self, cfg):
        cfg["id"] = self._next_id
        self._next_id += 1
        self.configs.append(cfg)
        self.active_cfg = cfg
        save_configs(self.configs)
        self._refresh_list()

    # ── اتصال / قطع ──────────────────────────────────
    def _toggle(self):
        if self.connecting:
            return
        if self.connected:
            self._disconnect()
        else:
            self._connect()

    def _connect(self):
        if not self.active_cfg:
            return
        if not self._core_path:
            self._set_status("هسته xray پیدا نشد", "#ef4444")
            return
        self.connecting = True
        self.conn_btn.text = "در حال اتصال..."
        self._set_status("در حال اتصال...", "#f59e0b")
        threading.Thread(target=self._connect_worker, daemon=True).start()

    def _connect_worker(self):
        try:
            xcfg = build_xray_config(self.active_cfg)
            with open(XRAY_CONFIG, "w", encoding="utf-8") as f:
                json.dump(xcfg, f, indent=2)
            self._proc = subprocess.Popen(
                [self._core_path, "run", "-c", XRAY_CONFIG],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            time.sleep(1.5)
            ready = self._wait_port(SOCKS_PORT)
            if not ready:
                Clock.schedule_once(lambda dt: self._on_error("پورت SOCKS باز نشد"))
                return
            Clock.schedule_once(lambda dt: self._on_connected())
        except Exception as e:
            Clock.schedule_once(lambda dt: self._on_error(str(e)))

    def _wait_port(self, port, timeout=8):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=1)
                s.close()
                return True
            except Exception:
                time.sleep(0.3)
        return False

    def _on_connected(self):
        self.connecting = False
        self.connected  = True
        self.conn_btn.text = "✓  قطع اتصال"
        self._set_status("متصل", "#22c55e")
        self.log_lbl.text  = f"SOCKS5 → 127.0.0.1:{SOCKS_PORT}"
        self.log_lbl.color = hex_color("#22c55e")
        self.timer_lbl.color = hex_color("#22c55e")
        self._timer_sec = 0
        threading.Thread(target=self._run_timer, daemon=True).start()
        threading.Thread(target=self._fake_stats, daemon=True).start()

    def _on_error(self, msg):
        self.connecting = False
        self.conn_btn.text = "اتصال"
        self._set_status(f"خطا: {msg[:40]}", "#ef4444")

    def _disconnect(self):
        self.connected = False
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                pass
            self._proc = None
        self.conn_btn.text = "اتصال"
        self._set_status("قطع", "#555555")
        self.log_lbl.text = ""
        self.timer_lbl.text  = "00:00"
        self.timer_lbl.color = hex_color("#333333")
        self.dl_lbl.text  = "—"
        self.ul_lbl.text  = "—"
        self.ping_lbl.text = "—"

    def _set_status(self, text, color):
        self.status_lbl.text  = text
        self.status_lbl.color = hex_color(color)
        self.dot_lbl.color    = hex_color(color)

    def _run_timer(self):
        while self.connected:
            self._timer_sec += 1
            m, s = divmod(self._timer_sec, 60)
            h, m = divmod(m, 60)
            t = f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"
            Clock.schedule_once(
                lambda dt, tt=t: setattr(self.timer_lbl, "text", tt))
            time.sleep(1)

    def _fake_stats(self):
        while self.connected:
            dl = random.randint(40, 800)
            ul = random.randint(10, 200)
            dl_t = f"{dl/1024:.1f}MB/s" if dl > 1000 else f"{dl}KB/s"
            ul_t = f"{ul/1024:.1f}MB/s" if ul > 1000 else f"{ul}KB/s"
            Clock.schedule_once(lambda dt, v=dl_t: setattr(self.dl_lbl,  "text", v))
            Clock.schedule_once(lambda dt, v=ul_t: setattr(self.ul_lbl,  "text", v))
            time.sleep(1.5)


# ═══════════════════════════════════════════════════
#  App اصلی
# ═══════════════════════════════════════════════════
class V2RayApp(App):
    def build(self):
        self.title = "V2Ray Manager"
        return MainScreen()


if __name__ == "__main__":
    V2RayApp().run()
