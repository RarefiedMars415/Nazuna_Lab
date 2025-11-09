#!/usr/bin/env python3
"""
Nazuna-Lab — multi-tool

Features:
 - Notes (add/view)
 - Password generator (optional clipboard copy)
 - File encryptor/decrypt (AES-256-GCM + PBKDF2; password NOT stored)
 - Metadata tool: remove/edit JPEG EXIF; strip video metadata via ffmpeg
 - QR code generator (PNG)
 - Hash & encoding tools (MD5, SHA1, SHA256, base64, hex)
 - Text steganography (PNG LSB hide/recover)
 - Secure file shredder (overwrite + delete)
 - Local hosting (dev HTTP server)
 - PCAP analyzer (offline only; requires scapy)
 - Network interface listing (read-only; prints tshark/wireshark examples)

Install suggestions (in venv):
    pip install pyfiglet colorama cryptography Pillow piexif scapy qrcode pyperclip

System deps:
    sudo apt update && sudo apt install -y ffmpeg

Run:
    python3 nazuna_lab.py
"""

import os
import sys
import time
import platform
import subprocess
import threading
import http.server
import socketserver
import hashlib
import base64
import secrets
import getpass
import shutil
from pathlib import Path
from typing import List

try:
    from pyfiglet import Figlet
except Exception:
    Figlet = None

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except Exception:
    class Fore:
        CYAN = GREEN = MAGENTA = YELLOW = BLUE = RED = RESET = ""
    class Style:
        BRIGHT = NORMAL = RESET_ALL = ""

# Optional feature libs (lazy-check)
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

try:
    from PIL import Image
    _HAS_PIL = True
except Exception:
    _HAS_PIL = False

try:
    import piexif
    _HAS_PIEXIF = True
except Exception:
    _HAS_PIEXIF = False

try:
    import qrcode
    _HAS_QR = True
except Exception:
    _HAS_QR = False

try:
    import pyperclip
    _HAS_PYPERCLIP = True
except Exception:
    _HAS_PYPERCLIP = False

try:
    from scapy.all import rdpcap, IP, TCP, UDP
    _HAS_SCAPY = True
except Exception:
    _HAS_SCAPY = False

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def typewriter(text: str, delay: float = 0.004, newline: bool = True):
    for ch in text:
        print(ch, end="", flush=True)
        time.sleep(delay)
    if newline:
        print()

def spinner(seconds: float = 0.7, msg: str = "Working"):
    chars = "|/-\\"
    end = time.time() + seconds
    i = 0
    while time.time() < end:
        print(f"\r{msg} {chars[i % len(chars)]}", end="", flush=True)
        time.sleep(0.07)
        i += 1
    print("\r" + " " * (len(msg) + 3), end="\r")

def banner():
    clear()
    if Figlet:
        f = Figlet(font="slant")
        print(Fore.CYAN + Style.BRIGHT + f.renderText("Nazuna-Lab"))
    else:
        print(Fore.CYAN + Style.BRIGHT + "=== Nazuna-Lab ===\n")
    print(Fore.MAGENTA + "Safe demo multi-tool — (i have nightmares from making this...)\n")
    print(Fore.YELLOW + "No live sniffing. Encrypt files you own; remove metadata for privacy.\n")

def pause(msg="\nPress Enter to return to menu..."):
    input(msg)

def intro_animation():
    clear()
    msgs = [
        "[SYSTEM] Initializing...",
        "[OK] UI Engine ready",
        "[OK] Crypto engine ready",
        "[OK] Metadata engine ready",
        "[OK] Utilities loaded",
        "[READY] booting Nazuna-Lab"
    ]
    for m in msgs:
        print(Fore.MAGENTA + m)
        time.sleep(0.45)
    time.sleep(0.3)

NOTES_FILE = "nazuna_notes.txt"

def notes_add():
    banner()
    print(Fore.GREEN + "Note taker — append a short line.")
    note = input("Note> ").strip()
    if not note:
        print("Nothing saved.")
    else:
        with open(NOTES_FILE, "a", encoding="utf-8") as f:
            f.write(f"{time.ctime()}: {note}\n")
        print("Saved.")
    pause()

def notes_view():
    banner()
    print(Fore.GREEN + "Saved notes:\n")
    if os.path.exists(NOTES_FILE):
        with open(NOTES_FILE, "r", encoding="utf-8") as f:
            print(f.read())
    else:
        print("(No notes yet.)")
    pause()

def pwgen():
    import string
    banner()
    print(Fore.GREEN + "Password generator")
    try:
        length = int(input("Length (default 20): ").strip() or "20")
    except Exception:
        length = 20
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}"
    pwd = "".join(secrets.choice(alphabet) for _ in range(length))
    print("\nGenerated password:\n")
    print(Fore.YELLOW + pwd)
    if _HAS_PYPERCLIP:
        try:
            if input("\nCopy to clipboard? (y/N): ").strip().lower() in ("y","yes"):
                pyperclip.copy(pwd)
                print("Copied to clipboard.")
        except Exception:
            print("Clipboard copy failed.")
    if input("Save to generated_passwords.txt? (y/N): ").strip().lower() == "y":
        with open("generated_passwords.txt", "a", encoding="utf-8") as f:
            f.write(f"{time.ctime()}: {pwd}\n")
        print("Saved.")
    pause()

SYSTEM_PATHS = [
    "/", "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin", "/etc", "/proc", "/sys", "/boot", "/dev"
]
if os.name == "nt":
    SYSTEM_PATHS += [r"C:\Windows", r"C:\Program Files", r"C:\Program Files (x86)"]

def is_forbidden_path(p: Path) -> bool:
    try:
        rp = str(p.resolve())
    except Exception:
        rp = str(p)
    for s in SYSTEM_PATHS:
        try:
            ss = str(Path(s))
            if rp.lower() == ss.lower() or rp.lower().startswith(ss.lower() + os.sep):
                return True
        except Exception:
            continue
    return False

def derive_key(password: bytes, salt: bytes, iterations: int = 200_000) -> bytes:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography missing")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_single_file(path: Path, password: str) -> Path:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography missing")
    data = path.read_bytes()
    salt = secrets.token_bytes(16)
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, data, None)
    out_path = path.with_suffix(path.suffix + ".enc")
    header = b"NAZUNA01"  # magic
    version = b"\x01"
    out_path.write_bytes(header + version + salt + nonce + ct)
    return out_path

def decrypt_single_file(path: Path, password: str) -> Path:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography missing")
    raw = path.read_bytes()
    if raw[:8] != b"NAZUNA01":
        raise ValueError("Unrecognized file format (missing magic).")
    salt = raw[9:25]
    nonce = raw[25:37]
    ct = raw[37:]
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    data = aesgcm.decrypt(nonce, ct, None)
    if path.name.endswith(".enc"):
        out_path = path.with_name(path.name[:-4])
    else:
        out_path = path.with_suffix(path.suffix + ".dec")
    out_path.write_bytes(data)
    return out_path

def encryptor_ui():
    banner()
    print(Fore.GREEN + "File Encryptor — single file (AES-256-GCM). Password is NOT saved.")
    print("Options:\n  1) Encrypt file\n  2) Decrypt file\n  (Enter to return)\n")
    opt = input("> ").strip()
    if opt == "1":
        p = input("Path to file to encrypt: ").strip()
        if not p:
            return
        path = Path(p).expanduser()
        if not path.exists() or not path.is_file():
            print("File not found.")
            pause(); return
        if is_forbidden_path(path):
            print("Refusing to operate on system or protected path.")
            pause(); return
        gen = input("Generate a strong random password for this file? (Y/n): ").strip().lower()
        if gen in ("", "y", "yes"):
            password = secrets.token_urlsafe(18)
            print("\nGenerated password (SAVE THIS, it will NOT be stored):\n")
            print(Fore.YELLOW + password)
            if _HAS_PYPERCLIP and input("\nCopy password to clipboard? (y/N): ").strip().lower() in ("y","yes"):
                try:
                    pyperclip.copy(password); print("Copied.")
                except: print("Clipboard copy failed.")
            print("\nCopy it now and send via secure channel (Signal, Bitwarden, etc.).")
        else:
            password = getpass.getpass("Enter password (will NOT be saved): ")
            pw2 = getpass.getpass("Repeat password: ")
            if not password or password != pw2:
                print("Passwords empty or do not match.")
                pause(); return
        try:
            out = encrypt_single_file(path, password)
            print(f"\nEncrypted -> {out}")
            print("Reminder: password not stored by tool.")
        except Exception as e:
            print("Encryption failed:", e)
        pause()
    elif opt == "2":
        p = input("Path to .enc file to decrypt: ").strip()
        if not p:
            return
        path = Path(p).expanduser()
        if not path.exists() or not path.is_file():
            print("File not found.")
            pause(); return
        if is_forbidden_path(path):
            print("Refusing to operate on system or protected path.")
            pause(); return
        password = getpass.getpass("Enter password: ")
        if not password:
            print("Empty password.")
            pause(); return
        try:
            out = decrypt_single_file(path, password)
            print(f"\nDecrypted -> {out}")
        except Exception as e:
            print("Decryption failed (wrong password or corrupt):", e)
        pause()
    else:
        return

def remove_image_exif(path: Path):
    if not _HAS_PIL:
        print("Pillow not installed. pip install Pillow")
        return
    if not path.exists() or not path.is_file():
        print("File not found.")
        return
    try:
        img = Image.open(path)
        out = path.with_name(path.stem + "_noexif" + path.suffix)
        if _HAS_PIEXIF and path.suffix.lower() in (".jpg", ".jpeg"):
            blank = {"0th":{}, "Exif":{}, "GPS":{}, "1st":{}, "thumbnail": None}
            exif_bytes = piexif.dump(blank)
            img.save(out, exif=exif_bytes)
        else:
            data = list(img.getdata())
            new = Image.new(img.mode, img.size)
            new.putdata(data)
            new.save(out)
        print("Saved without metadata:", out)
    except Exception as e:
        print("Failed to remove EXIF:", e)

def edit_jpeg_exif(path: Path):
    if not _HAS_PIEXIF or not _HAS_PIL:
        print("piexif and Pillow required. pip install piexif Pillow")
        return
    if not path.exists() or not path.is_file():
        print("File not found.")
        return
    if path.suffix.lower() not in (".jpg", ".jpeg"):
        print("JPEG files only for EXIF editing.")
        return
    try:
        exif = piexif.load(str(path))
        print("Leave blank to keep existing values.")
        make = input("  Make: ").strip()
        model = input("  Model: ").strip()
        desc = input("  ImageDescription: ").strip()
        if make:
            exif["0th"][piexif.ImageIFD.Make] = make.encode("utf-8")
        if model:
            exif["0th"][piexif.ImageIFD.Model] = model.encode("utf-8")
        if desc:
            exif["0th"][piexif.ImageIFD.ImageDescription] = desc.encode("utf-8")
        out = path.with_name(path.stem + "_edited" + path.suffix)
        img = Image.open(path)
        exif_bytes = piexif.dump(exif)
        img.save(out, exif=exif_bytes)
        print("Saved edited image:", out)
    except Exception as e:
        print("Failed to edit EXIF:", e)

def strip_video_metadata(path: Path):
    if shutil.which("ffmpeg") is None:
        print("ffmpeg not installed. Install: sudo apt install ffmpeg")
        return
    if not path.exists() or not path.is_file():
        print("File not found.")
        return
    out = path.with_name(path.stem + "_nometa" + path.suffix)
    cmd = ["ffmpeg", "-y", "-i", str(path), "-map_metadata", "-1", "-c", "copy", str(out)]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Saved video without metadata:", out)
    except subprocess.CalledProcessError:
        print("ffmpeg failed to strip metadata. Try re-encoding or check ffmpeg output.")
    except Exception as e:
        print("Error:", e)

def metadata_ui():
    banner()
    print(Fore.GREEN + "Metadata Tool — images & video (privacy)")
    print("Options:\n  1) Remove image metadata (single file)\n  2) Edit JPEG EXIF fields\n  3) Strip video metadata (ffmpeg)\n  4) Batch remove images in directory (creates *_noexif files)\n  (Enter to return)\n")
    opt = input("> ").strip()
    if opt == "1":
        p = input("Image path: ").strip()
        if p:
            remove_image_exif(Path(p).expanduser())
        pause()
    elif opt == "2":
        p = input("JPEG path: ").strip()
        if p:
            edit_jpeg_exif(Path(p).expanduser())
        pause()
    elif opt == "3":
        p = input("Video path: ").strip()
        if p:
            strip_video_metadata(Path(p).expanduser())
        pause()
    elif opt == "4":
        d = input("Directory path: ").strip()
        if not d:
            return
        dp = Path(d).expanduser()
        if not dp.is_dir():
            print("Directory not found.")
            pause(); return
        confirm = input(f"Process images in {dp}? This will create *_noexif copies. Type 'yes' to confirm: ").strip().lower()
        if confirm != "yes":
            print("Cancelled.")
            pause(); return
        for f in dp.iterdir():
            if f.suffix.lower() in (".jpg", ".jpeg", ".png", ".tiff", ".webp"):
                try:
                    remove_image_exif(f)
                except Exception as e:
                    print("Failed for", f, ":", e)
        print("Batch finished.")
        pause()
    else:
        return

def qr_code_ui():
    banner()
    print(Fore.GREEN + "QR Code Generator")
    text = input("Text / URL to encode (Enter to cancel): ").strip()
    if not text:
        return
    fname = input("Output filename (default qr.png): ").strip() or "qr.png"
    if not _HAS_QR:
        print("qrcode package not installed. pip install qrcode[pil]")
        pause(); return
    try:
        img = qrcode.make(text)
        img.save(fname)
        print(f"Saved QR image: {fname}")
        if _HAS_PYPERCLIP and input("Copy text to clipboard? (y/N): ").strip().lower() in ("y","yes"):
            try:
                pyperclip.copy(text); print("Copied.")
            except: print("Clipboard copy failed.")
    except Exception as e:
        print("Failed to create QR:", e)
    pause()

def hash_encode_ui():
    banner()
    print(Fore.GREEN + "Hash & Encode Tools")
    print("1) Hash a file/text (MD5, SHA1, SHA256)\n2) Base64 encode/decode\n3) Hex encode/decode\n(Enter to return)")
    c = input("> ").strip()
    if c == "1":
        t = input("Enter text (or path to file, prefix with @): ").strip()
        data = b""
        if t.startswith("@"):
            p = Path(t[1:]).expanduser()
            if not p.exists(): print("File not found."); pause(); return
            data = p.read_bytes()
        else:
            data = t.encode("utf-8")
        print("MD5:   ", hashlib.md5(data).hexdigest())
        print("SHA1:  ", hashlib.sha1(data).hexdigest())
        print("SHA256:", hashlib.sha256(data).hexdigest())
        pause()
    elif c == "2":
        s = input("Text to encode/decode: ").strip()
        mode = input("Encode or Decode? (e/d): ").strip().lower()
        if mode == "e":
            out = base64.b64encode(s.encode()).decode()
            print("Base64:", out)
        else:
            try:
                out = base64.b64decode(s.encode()).decode()
                print("Decoded:", out)
            except Exception as e:
                print("Decode failed:", e)
        pause()
    elif c == "3":
        s = input("Text to encode/decode: ").strip()
        mode = input("Encode or Decode? (e/d): ").strip().lower()
        if mode == "e":
            print("Hex:", s.encode().hex())
        else:
            try:
                print("Decoded:", bytes.fromhex(s).decode())
            except Exception as e:
                print("Decode failed:", e)
        pause()
    else:
        return

def _msg_to_bits(msg: str) -> List[int]:
    data = msg.encode("utf-8")
    bits = []
    for b in data:
        for i in range(8):
            bits.append((b >> (7 - i)) & 1)
    bits += [0]*64
    return bits

def _bits_to_msg(bits: List[int]) -> str:
    bytes_out = []
    cur = 0
    zero_run = 0
    for i, bit in enumerate(bits):
        cur = (cur << 1) | bit
        if (i+1) % 8 == 0:
            if cur == 0:
                zero_run += 1
                if zero_run >= 8:
                    break
            else:
                zero_run = 0
                bytes_out.append(cur)
            cur = 0
    try:
        return bytes(bytes_out).decode("utf-8", errors="ignore")
    except:
        return ""

def stego_ui():
    banner()
    print(Fore.GREEN + "Text Steganography (PNG LSB)")
    print("1) Hide message in PNG\n2) Recover message from PNG\n(Enter to return)")
    c = input("> ").strip()
    if c == "1":
        p = input("PNG path: ").strip()
        if not p: return
        path = Path(p).expanduser()
        if not path.exists(): print("File not found."); pause(); return
        if not _HAS_PIL:
            print("Pillow required. pip install Pillow")
            pause(); return
        msg = input("Message to hide: ").strip()
        if not msg: print("Empty message."); pause(); return
        img = Image.open(path).convert("RGBA")
        pixels = img.load()
        w, h = img.size
        bits = _msg_to_bits(msg)
        if len(bits) > w*h*3:
            print("Message too big for image.")
            pause(); return
        idx = 0
        for y in range(h):
            for x in range(w):
                if idx >= len(bits): break
                r,g,b,a = pixels[x,y]
                if idx < len(bits):
                    r = (r & ~1) | bits[idx]; idx += 1
                if idx < len(bits):
                    g = (g & ~1) | bits[idx]; idx += 1
                if idx < len(bits):
                    b = (b & ~1) | bits[idx]; idx += 1
                pixels[x,y] = (r,g,b,a)
            if idx >= len(bits): break
        out = path.with_name(path.stem + "_stego.png")
        img.save(out)
        print("Saved stego image:", out)
        pause()
    elif c == "2":
        p = input("PNG path: ").strip()
        if not p: return
        path = Path(p).expanduser()
        if not path.exists(): print("File not found."); pause(); return
        if not _HAS_PIL:
            print("Pillow required. pip install Pillow")
            pause(); return
        img = Image.open(path).convert("RGBA")
        w,h = img.size
        pixels = img.load()
        bits = []
        for y in range(h):
            for x in range(w):
                r,g,b,a = pixels[x,y]
                bits.append(r & 1); bits.append(g & 1); bits.append(b & 1)
        msg = _bits_to_msg(bits)
        print("Recovered message:")
        print(msg or "(no message or failed to decode)")
        pause()
    else:
        return

def shredder_ui():
    banner()
    print(Fore.RED + "Secure File Shredder — IRREVERSIBLE (you WILL destroy files)")
    p = input("Path to file to shred (Enter to cancel): ").strip()
    if not p:
        return
    path = Path(p).expanduser()
    if not path.exists() or not path.is_file():
        print("File not found.")
        pause(); return
    confirm = input(f"Are you sure you want to securely overwrite and delete {path}? Type 'SHRED' to confirm: ").strip()
    if confirm != "SHRED":
        print("Cancelled.")
        pause(); return
    try:
        size = path.stat().st_size
        passes = input("Number of overwrite passes (default 1): ").strip()
        try:
            passes = int(passes or "1")
        except:
            passes = 1
        with open(path, "r+b") as f:
            for pnum in range(passes):
                f.seek(0)
                remaining = size
                block = 64*1024
                while remaining > 0:
                    chunk = os.urandom(min(block, remaining))
                    f.write(chunk)
                    remaining -= len(chunk)
                f.flush()
                os.fsync(f.fileno())
                f.seek(0)
        path.unlink()
        print("File shredded.")
    except Exception as e:
        print("Shred failed:", e)
    pause()

_server_thread = None
_server_obj = None

def start_local_host(directory: str, port: int = 8000):
    global _server_thread, _server_obj
    if _server_thread and _server_thread.is_alive():
        print("Server already running.")
        return
    Handler = http.server.SimpleHTTPRequestHandler
    try:
        os.chdir(directory)
    except Exception:
        pass
    _server_obj = socketserver.TCPServer(("0.0.0.0", port), Handler)

    def get_lan_ip():
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("1.1.1.1", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "localhost"
        finally:
            s.close()
        return ip

    def serve():
        try:
            _server_obj.serve_forever()
        except Exception:
            pass

    _server_thread = threading.Thread(target=serve, daemon=True)
    _server_thread.start()
    ip = get_lan_ip()
    print(f"Serving {directory} at:")
    print(f"  • Localhost: http://localhost:{port}/")
    print(f"  • LAN:       http://{ip}:{port}/ (same Wi-Fi only)")

def stop_local_host():
    global _server_obj
    if _server_obj:
        _server_obj.shutdown()
        _server_obj.server_close()
        _server_obj = None
        print("Server stopped.")
    else:
        print("No server running.")

def local_host_ui():
    banner()
    print(Fore.GREEN + "Local Hosting (dev server, safe)")
    print("1) Start server\n2) Stop server\n(Enter to return)")
    c = input("> ").strip()
    if c == "1":
        d = input("Directory to serve (default current dir): ").strip() or "."
        port = input("Port (default 8000): ").strip() or "8000"
        try:
            port = int(port)
        except:
            port = 8000
        start_local_host(d, port)
        pause()
    elif c == "2":
        stop_local_host()
        pause()
    else:
        return

def analyze_pcap(path: Path):
    banner()
    print(Fore.GREEN + f"PCAP analyzer — offline: {path}")
    if not _HAS_SCAPY:
        print("scapy not installed. Install with: pip install scapy")
        pause(); return
    if not path.exists() or not path.is_file():
        print("File not found.")
        pause(); return
    try:
        pkts = rdpcap(str(path))
    except Exception as e:
        print("Failed to read pcap:", e)
        pause(); return

    total = len(pkts)
    proto = {}
    src = {}
    dst = {}
    tcp_ports = {}
    udp_ports = {}

    for p in pkts:
        try:
            if p.haslayer(TCP):
                proto["TCP"] = proto.get("TCP", 0) + 1
            elif p.haslayer(UDP):
                proto["UDP"] = proto.get("UDP", 0) + 1
            elif p.haslayer("ICMP") or p.haslayer("ICMPv6"):
                proto["ICMP"] = proto.get("ICMP", 0) + 1
            elif p.haslayer("IP") or p.haslayer("IPv6"):
                proto["IP"] = proto.get("IP", 0) + 1
            else:
                proto["Other"] = proto.get("Other", 0) + 1
        except Exception:
            proto["Other"] = proto.get("Other", 0) + 1
        try:
            if p.haslayer(IP):
                s = p[IP].src
                d = p[IP].dst
                src[s] = src.get(s, 0) + 1
                dst[d] = dst.get(d, 0) + 1
        except Exception:
            pass
        try:
            if p.haslayer(TCP):
                tcp_ports[int(p[TCP].sport)] = tcp_ports.get(int(p[TCP].sport), 0) + 1
                tcp_ports[int(p[TCP].dport)] = tcp_ports.get(int(p[TCP].dport), 0) + 1
            if p.haslayer(UDP):
                udp_ports[int(p[UDP].sport)] = udp_ports.get(int(p[UDP].sport), 0) + 1
                udp_ports[int(p[UDP].dport)] = udp_ports.get(int(p[UDP].dport), 0) + 1
        except Exception:
            pass

    def top(d, n=6):
        return sorted(d.items(), key=lambda x: x[1], reverse=True)[:n]

    print(f"Total packets: {total}\n")
    print("Protocol counts:")
    for k, v in sorted(proto.items(), key=lambda x: x[1], reverse=True):
        print(f"  {k}: {v}")
    print("\nTop source IPs:")
    for ip, c in top(src, 6):
        print(" ", ip, c)
    print("\nTop dest IPs:")
    for ip, c in top(dst, 6):
        print(" ", ip, c)
    if tcp_ports:
        print("\nTop TCP ports (combined src+dst):")
        for p, c in top(tcp_ports, 8):
            print(" ", p, c)
    if udp_ports:
        print("\nTop UDP ports (combined src+dst):")
        for p, c in top(udp_ports, 8):
            print(" ", p, c)
    pause()

def pcap_ui():
    banner()
    print(Fore.GREEN + "PCAP Analyzer (offline) — provide a .pcap file you own")
    path = input("Path to .pcap (Enter to cancel): ").strip()
    if not path:
        return
    analyze_pcap(Path(path).expanduser())

def run_cmd_captureless(cmd: List[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return out.decode(errors="ignore")
    except Exception:
        return ""

def list_interfaces() -> List[str]:
    syst = platform.system().lower()
    if syst == "linux":
        out = run_cmd_captureless(["ip", "-o", "link", "show"])
        if out:
            names = []
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 2:
                    names.append(parts[1].strip())
            return names
        try:
            return sorted(os.listdir("/sys/class/net"))
        except Exception:
            return []
    if syst == "windows":
        out = run_cmd_captureless(["ipconfig", "/all"])
        names = []
        for line in out.splitlines():
            line = line.strip()
            if line.endswith(":") and ("adapter" in line.lower()):
                names.append(line.rstrip(":"))
        return names
    out = run_cmd_captureless(["ifconfig", "-a"])
    names = []
    for line in out.splitlines():
        if line and not line.startswith("\t") and not line.startswith(" "):
            if ":" in line:
                names.append(line.split(":")[0].strip())
    return names

def interfaces_ui():
    banner()
    print(Fore.GREEN + "Network Interfaces (read-only):\n")
    ifaces = list_interfaces()
    if not ifaces:
        print("No interfaces found or cannot enumerate. Some details require privileges.")
        pause(); return
    for i, n in enumerate(ifaces, 1):
        print(f"  {i}) {n}")
    print("\nSelect a number to see example tshark/wireshark commands (tool will NOT run captures).")
    choice = input("\nEnter number or Enter to return: ").strip()
    if not choice:
        return
    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(ifaces):
            print("Invalid selection.")
            pause(); return
        sel = ifaces[idx]
    except Exception:
        print("Invalid input.")
        pause(); return
    banner()
    print(Fore.YELLOW + f"Selected interface: {sel}\n")
    print("Example commands (run manually if you have permission):\n")
    print(Fore.CYAN + f"  # show stats (read-only):\n    ip -s link show {sel}\n")
    print(Fore.CYAN + f"  # tshark basic (manual):\n    sudo tshark -i {sel} -c 50\n")
    print(Fore.CYAN + f"  # tshark with BPF (manual):\n    sudo tshark -i {sel} -f \"tcp port 80\" -c 100\n")
    print("\nEthics: only capture on networks you own or have explicit consent to analyze.")
    pause()

def main_menu():
    intro_animation()
    while True:
        banner()
        print(Fore.BLUE + "Select an option:")
        print("  1) Notes (add/view)")
        print("  2) Password generator")
        print("  3) File encryptor / decryptor (single-file, secure)")
        print("  4) Metadata tool (images & video)")
        print("  5) QR code generator")
        print("  6) Hash & encoding tools")
        print("  7) Text steganography (PNG LSB)")
        print("  8) Secure file shredder")
        print("  9) Local hosting (dev server)")
        print(" 10) PCAP analyzer (offline)")
        print(" 11) Network interfaces (read-only, example commands)")
        print("  0) Exit")
        choice = input("\n> ").strip()
        if choice == "1":
            banner()
            print("Notes:\n  1) Add note\n  2) View notes\n  (Enter to return)\n")
            c = input("> ").strip()
            if c == "1":
                notes_add()
            elif c == "2":
                notes_view()
            else:
                continue
        elif choice == "2":
            pwgen()
        elif choice == "3":
            encryptor_ui()
        elif choice == "4":
            metadata_ui()
        elif choice == "5":
            qr_code_ui()
        elif choice == "6":
            hash_encode_ui()
        elif choice == "7":
            stego_ui()
        elif choice == "8":
            shredder_ui()
        elif choice == "9":
            local_host_ui()
        elif choice == "10":
            pcap_ui()
        elif choice == "11":
            interfaces_ui()
        elif choice == "0":
            typewriter("Goodbye from Nazuna-Lab!", 0.01)
            spinner(0.6, "Exiting")
            break
        else:
            print("Unknown option.")
            time.sleep(0.5)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nInterrupted. Bye.")
