[app]

# ── اطلاعات اپ ──────────────────────────────────
title = V2Ray Manager
package.name = v2raymanager
package.domain = org.v2raymanager

source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json,txt,dat

version = 1.0.0

# ── کتابخانه‌های Python ──────────────────────────
requirements = python3,kivy==2.3.0,kivymd,plyer

# ── فایل‌های اضافه (binary xray برای اندروید) ────
# فایل xray-android را دانلود کن و در پوشه assets/ قرار بده
# android.add_assets = assets/xray:xray
# android.add_src = src

# ── آیکون ────────────────────────────────────────
#presplash.filename = %(source.dir)s/data/presplash.png
#icon.filename = %(source.dir)s/data/icon.png

# ── اندروید ──────────────────────────────────────
android.permissions = INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, CHANGE_WIFI_STATE, FOREGROUND_SERVICE, RECEIVE_BOOT_COMPLETED
android.api = 33
android.minapi = 21
android.ndk = 25b
android.sdk = 33
android.ndk_api = 21
android.archs = arm64-v8a, armeabi-v7a

# orientation دستگاه
orientation = portrait

# Fullscreen
fullscreen = 0

# ── build ────────────────────────────────────────
[buildozer]
log_level = 2
warn_on_root = 1
