import os
import re
import csv
import sys
import socket
import queue
import threading
import subprocess
import multiprocessing
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from dataclasses import dataclass, asdict

import tkinter as tk
from tkinter import ttk, filedialog, messagebox


COMMON_PORTS = [80, 443, 22, 3389, 445, 135, 139, 53, 502, 4000, 8080, 8443]
DEFAULT_TIMEOUT_MS = 1200
DEFAULT_THREADS = 64


# -----------------------------
# Modern bright color palette
# -----------------------------
COLOR_BG = "#f3f7fb"
COLOR_SURFACE = "#ffffff"
COLOR_SURFACE_SOFT = "#f8fafc"
COLOR_PANEL = "#eef4ff"
COLOR_BORDER = "#dbe4f0"
COLOR_BORDER_STRONG = "#c7d3e3"

COLOR_TEXT = "#0f172a"
COLOR_TEXT_SUB = "#475569"
COLOR_TEXT_MUTED = "#64748b"
COLOR_PLACEHOLDER = "#94a3b8"

COLOR_PRIMARY = "#2563eb"
COLOR_PRIMARY_HOVER = "#1d4ed8"
COLOR_SUCCESS = "#16a34a"
COLOR_SUCCESS_HOVER = "#15803d"
COLOR_INFO = "#0ea5e9"
COLOR_INFO_HOVER = "#0284c7"
COLOR_DANGER = "#ef4444"
COLOR_DANGER_HOVER = "#dc2626"
COLOR_PURPLE = "#7c3aed"
COLOR_PURPLE_HOVER = "#6d28d9"
COLOR_NEUTRAL = "#475569"
COLOR_NEUTRAL_HOVER = "#334155"

COLOR_TABLE_BG = "#ffffff"
COLOR_TABLE_ALT = "#f8fbff"
COLOR_TABLE_HEAD = "#eaf1fb"
COLOR_TABLE_SELECTED = "#2563eb"

COLOR_UP = "#15803d"
COLOR_DOWN = "#dc2626"


@dataclass
class DeviceRow:
    ip: str
    alias: str = ""
    name: str = ""
    comment: str = ""
    status: str = "unknown"
    has_http: str = "0"
    expanded: str = "0"


@dataclass
class ScanResult:
    ip: str
    alias: str
    ping: str = "미확인"
    latency_ms: str = ""
    open_ports: str = ""
    web: str = ""
    last_checked: str = ""
    error: str = ""


class DeviceDialog(tk.Toplevel):
    def __init__(self, parent, title="장비 추가", ip="", alias=""):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.result = None
        self.transient(parent)
        self.grab_set()
        self.configure(bg=COLOR_BG)

        container = tk.Frame(
            self,
            bg=COLOR_SURFACE,
            padx=22,
            pady=20,
            highlightthickness=1,
            highlightbackground=COLOR_BORDER,
        )
        container.pack(fill="both", expand=True, padx=10, pady=10)

        title_label = tk.Label(
            container,
            text=title,
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT,
            font=("Segoe UI", 12, "bold")
        )
        title_label.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 16))

        tk.Label(
            container,
            text="IP",
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_SUB,
            font=("Segoe UI", 10, "bold")
        ).grid(row=1, column=0, sticky="w", padx=(0, 10), pady=6)

        self.ip_var = tk.StringVar(value=ip)
        self.ip_entry = tk.Entry(
            container,
            textvariable=self.ip_var,
            width=26,
            bg=COLOR_SURFACE_SOFT,
            fg=COLOR_TEXT,
            insertbackground=COLOR_TEXT,
            relief="flat",
            highlightthickness=1,
            highlightbackground=COLOR_BORDER_STRONG,
            highlightcolor=COLOR_PRIMARY,
            font=("Segoe UI", 10),
        )
        self.ip_entry.grid(row=1, column=1, sticky="ew", pady=6, ipady=8)

        tk.Label(
            container,
            text="Hostname / Alias",
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_SUB,
            font=("Segoe UI", 10, "bold")
        ).grid(row=2, column=0, sticky="w", padx=(0, 10), pady=6)

        self.alias_var = tk.StringVar(value=alias)
        self.alias_entry = tk.Entry(
            container,
            textvariable=self.alias_var,
            width=42,
            bg=COLOR_SURFACE_SOFT,
            fg=COLOR_TEXT,
            insertbackground=COLOR_TEXT,
            relief="flat",
            highlightthickness=1,
            highlightbackground=COLOR_BORDER_STRONG,
            highlightcolor=COLOR_PRIMARY,
            font=("Segoe UI", 10),
        )
        self.alias_entry.grid(row=2, column=1, sticky="ew", pady=6, ipady=8)

        btns = tk.Frame(container, bg=COLOR_SURFACE)
        btns.grid(row=3, column=0, columnspan=2, sticky="e", pady=(18, 0))

        self._make_button(btns, "저장", COLOR_PRIMARY, COLOR_PRIMARY_HOVER, self.on_ok).pack(side="left", padx=4)
        self._make_button(btns, "취소", COLOR_NEUTRAL, COLOR_NEUTRAL_HOVER, self.on_cancel).pack(side="left", padx=4)

        container.columnconfigure(1, weight=1)

        self.bind("<Return>", lambda e: self.on_ok())
        self.bind("<Escape>", lambda e: self.on_cancel())
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

        self.update_idletasks()
        self.geometry(f"+{parent.winfo_rootx()+100}+{parent.winfo_rooty()+100}")
        self.ip_entry.focus_set()

    def _make_button(self, parent, text, bg, active, command):
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            activebackground=active,
            activeforeground="#ffffff",
            fg="#ffffff",
            relief="flat",
            bd=0,
            padx=14,
            pady=9,
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
        )

    def on_ok(self):
        ip = self.ip_var.get().strip()
        alias = self.alias_var.get().strip()
        if not ip:
            messagebox.showwarning("입력 필요", "IP를 입력하세요.", parent=self)
            return
        if not self._is_valid_ip(ip):
            messagebox.showwarning("형식 오류", "올바른 IPv4 주소를 입력하세요.", parent=self)
            return
        self.result = {"ip": ip, "alias": alias}
        self.destroy()

    def on_cancel(self):
        self.result = None
        self.destroy()

    @staticmethod
    def _is_valid_ip(value: str) -> bool:
        parts = value.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except Exception:
            return False


class XMLScannerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("XML Network Scanner")
        self.root.geometry("1450x900")
        self.root.minsize(1220, 760)
        self.root.configure(bg=COLOR_BG)

        self.devices: list[DeviceRow] = []
        self.results: dict[str, ScanResult] = {}
        self.filtered_ips: list[str] = []
        self.scan_queue: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.is_scanning = False
        self.current_xml_path = ""

        self._apply_theme()
        self._build_ui()
        self._load_default_xml_if_exists()
        self._poll_result_queue()

    def _apply_theme(self):
        style = ttk.Style(self.root)
        try:
            if "vista" in style.theme_names():
                style.theme_use("vista")
            else:
                style.theme_use("clam")
        except Exception:
            pass

        style.configure(".", font=("Segoe UI", 10))
        style.configure("Card.TFrame", background=COLOR_SURFACE)
        style.configure("Panel.TFrame", background=COLOR_PANEL)
        style.configure("Inner.TFrame", background=COLOR_SURFACE)
        style.configure("Header.TLabel", background=COLOR_BG, foreground=COLOR_TEXT, font=("Segoe UI", 19, "bold"))
        style.configure("SubHeader.TLabel", background=COLOR_BG, foreground=COLOR_TEXT_MUTED, font=("Segoe UI", 10))
        style.configure("PanelTitle.TLabel", background=COLOR_SURFACE, foreground=COLOR_TEXT, font=("Segoe UI", 10, "bold"))
        style.configure("Info.TLabel", background=COLOR_SURFACE, foreground=COLOR_TEXT_MUTED, font=("Segoe UI", 9))
        style.configure("Status.TLabel", background=COLOR_BG, foreground=COLOR_TEXT_SUB, font=("Segoe UI", 10, "bold"))

        style.configure(
            "Scanner.Horizontal.TProgressbar",
            troughcolor="#e2e8f0",
            background=COLOR_SUCCESS,
            bordercolor="#e2e8f0",
            lightcolor=COLOR_SUCCESS,
            darkcolor=COLOR_SUCCESS,
        )

        style.configure(
            "Treeview",
            background=COLOR_TABLE_BG,
            fieldbackground=COLOR_TABLE_BG,
            foreground=COLOR_TEXT,
            rowheight=32,
            borderwidth=0,
            relief="flat",
            font=("Segoe UI", 10),
        )
        style.map(
            "Treeview",
            background=[("selected", COLOR_TABLE_SELECTED)],
            foreground=[("selected", "#ffffff")],
        )
        style.configure(
            "Treeview.Heading",
            background=COLOR_TABLE_HEAD,
            foreground=COLOR_TEXT,
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padding=(10, 9),
        )
        style.map(
            "Treeview.Heading",
            background=[("active", "#dbeafe")],
            foreground=[("active", COLOR_TEXT)],
        )

        style.configure(
            "Vertical.TScrollbar",
            background="#dbeafe",
            troughcolor="#eff6ff",
            bordercolor="#eff6ff",
            arrowcolor=COLOR_TEXT_SUB,
        )
        style.configure(
            "Horizontal.TScrollbar",
            background="#dbeafe",
            troughcolor="#eff6ff",
            bordercolor="#eff6ff",
            arrowcolor=COLOR_TEXT_SUB,
        )

    def _make_action_button(self, parent, text, bg, active, command, width=10):
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            activebackground=active,
            activeforeground="#ffffff",
            fg="#ffffff",
            relief="flat",
            bd=0,
            padx=12,
            pady=9,
            width=width,
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
        )

    def _make_entry(self, parent, textvariable=None, width=14):
        return tk.Entry(
            parent,
            textvariable=textvariable,
            width=width,
            bg=COLOR_SURFACE_SOFT,
            fg=COLOR_TEXT,
            insertbackground=COLOR_TEXT,
            relief="flat",
            highlightthickness=1,
            highlightbackground=COLOR_BORDER_STRONG,
            highlightcolor=COLOR_PRIMARY,
            font=("Segoe UI", 10),
        )

    def _build_ui(self):
        outer = tk.Frame(self.root, bg=COLOR_BG, padx=18, pady=16)
        outer.pack(fill="both", expand=True)

        header = tk.Frame(outer, bg=COLOR_BG)
        header.pack(fill="x", pady=(0, 12))

        ttk.Label(header, text="XML Network Scanner", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="GMP-IT 파트 네트워크 점검 툴(Ping, 포트 스캔, Arp 캐시 확인)",
            style="SubHeader.TLabel",
        ).pack(anchor="w", pady=(4, 0))

        toolbar_card = ttk.Frame(outer, style="Card.TFrame", padding=14)
        toolbar_card.pack(fill="x", pady=(0, 12))

        row1 = tk.Frame(toolbar_card, bg=COLOR_SURFACE)
        row1.pack(fill="x", pady=(0, 10))

        self._make_action_button(row1, "XML 열기", COLOR_PRIMARY, COLOR_PRIMARY_HOVER, self.open_xml).pack(side="left", padx=4)
        self._make_action_button(row1, "전체 스캔", COLOR_SUCCESS, COLOR_SUCCESS_HOVER, self.scan_all).pack(side="left", padx=4)
        self._make_action_button(row1, "선택 스캔", COLOR_INFO, COLOR_INFO_HOVER, self.scan_selected).pack(side="left", padx=4)
        self._make_action_button(row1, "중지", COLOR_DANGER, COLOR_DANGER_HOVER, self.stop_scan).pack(side="left", padx=4)
        self._make_action_button(row1, "CSV 내보내기", COLOR_PURPLE, COLOR_PURPLE_HOVER, self.export_csv).pack(side="left", padx=4)

        tk.Frame(row1, bg=COLOR_BORDER, width=1, height=30).pack(side="left", padx=10)

        self._make_action_button(row1, "장비 추가", COLOR_PRIMARY, COLOR_PRIMARY_HOVER, self.add_device).pack(side="left", padx=4)
        self._make_action_button(row1, "장비 수정", COLOR_NEUTRAL, COLOR_NEUTRAL_HOVER, self.edit_selected_device).pack(side="left", padx=4)
        self._make_action_button(row1, "장비 삭제", COLOR_DANGER, COLOR_DANGER_HOVER, self.delete_selected_devices).pack(side="left", padx=4)
        self._make_action_button(row1, "XML 저장", COLOR_NEUTRAL, COLOR_NEUTRAL_HOVER, self.save_xml).pack(side="left", padx=4)
        self._make_action_button(row1, "다른 이름 저장", COLOR_NEUTRAL, COLOR_NEUTRAL_HOVER, self.save_xml_as, width=12).pack(side="left", padx=4)

        row2 = tk.Frame(toolbar_card, bg=COLOR_SURFACE)
        row2.pack(fill="x")

        tk.Label(row2, text="검색", bg=COLOR_SURFACE, fg=COLOR_TEXT_SUB, font=("Segoe UI", 9, "bold")).pack(side="left", padx=(4, 8))
        self.search_var = tk.StringVar()
        search_entry = self._make_entry(row2, self.search_var, width=30)
        search_entry.pack(side="left", padx=(0, 18), ipady=6)
        search_entry.bind("<KeyRelease>", lambda e: self.apply_filter())

        tk.Label(row2, text="스레드", bg=COLOR_SURFACE, fg=COLOR_TEXT_SUB, font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 8))
        self.thread_var = tk.StringVar(value=str(DEFAULT_THREADS))
        self._make_entry(row2, self.thread_var, width=7).pack(side="left", padx=(0, 18), ipady=6)

        tk.Label(row2, text="타임아웃(ms)", bg=COLOR_SURFACE, fg=COLOR_TEXT_SUB, font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 8))
        self.timeout_var = tk.StringVar(value=str(DEFAULT_TIMEOUT_MS))
        self._make_entry(row2, self.timeout_var, width=9).pack(side="left", padx=(0, 18), ipady=6)

        self.http_check_var = tk.BooleanVar(value=True)
        self.http_check = tk.Checkbutton(
            row2,
            text="HTTP/HTTPS 확인",
            variable=self.http_check_var,
            bg=COLOR_SURFACE,
            activebackground=COLOR_SURFACE,
            fg=COLOR_TEXT_SUB,
            activeforeground=COLOR_TEXT,
            selectcolor=COLOR_SURFACE_SOFT,
            font=("Segoe UI", 9, "bold"),
        )
        self.http_check.pack(side="left")

        status_row = tk.Frame(outer, bg=COLOR_BG)
        status_row.pack(fill="x", pady=(0, 10))

        ttk.Label(status_row, text="상태", style="Status.TLabel").pack(side="left")
        self.status_var = tk.StringVar(value="준비")
        self.status_text = tk.Label(
            status_row,
            textvariable=self.status_var,
            bg=COLOR_BG,
            fg=COLOR_PRIMARY,
            font=("Segoe UI", 10, "bold"),
        )
        self.status_text.pack(side="left", padx=(10, 0))

        self.summary_label = tk.Label(
            status_row,
            text="UP 0 / DOWN 0",
            bg=COLOR_BG,
            fg=COLOR_TEXT_MUTED,
            font=("Segoe UI", 10),
        )
        self.summary_label.pack(side="right")

        progress_card = ttk.Frame(outer, style="Card.TFrame", padding=12)
        progress_card.pack(fill="x", pady=(0, 12))
        ttk.Label(progress_card, text="스캔 진행률", style="PanelTitle.TLabel").pack(anchor="w", pady=(0, 8))
        self.progress = ttk.Progressbar(progress_card, mode="determinate", style="Scanner.Horizontal.TProgressbar")
        self.progress.pack(fill="x")

        table_card = ttk.Frame(outer, style="Card.TFrame", padding=12)
        table_card.pack(fill="both", expand=True)

        table_top = tk.Frame(table_card, bg=COLOR_SURFACE)
        table_top.pack(fill="x", pady=(0, 8))

        ttk.Label(table_top, text="장비 목록", style="PanelTitle.TLabel").pack(side="left")
        tk.Label(
            table_top,
            text="UP=초록 / DOWN=빨강",
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_MUTED,
            font=("Segoe UI", 9),
        ).pack(side="right")

        table_frame = tk.Frame(
            table_card,
            bg=COLOR_SURFACE,
            highlightthickness=1,
            highlightbackground=COLOR_BORDER,
        )
        table_frame.pack(fill="both", expand=True)

        columns = (
            "ip", "alias", "ping", "latency",
            "ports", "web", "last_checked", "error"
        )
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="extended")
        self.tree.tag_configure("up", foreground=COLOR_UP, background=COLOR_TABLE_BG)
        self.tree.tag_configure("down", foreground=COLOR_DOWN, background=COLOR_TABLE_BG)
        self.tree.tag_configure("oddrow", background=COLOR_TABLE_BG, foreground=COLOR_TEXT)
        self.tree.tag_configure("evenrow", background=COLOR_TABLE_ALT, foreground=COLOR_TEXT)
        self.tree.tag_configure("oddrow_up", background=COLOR_TABLE_BG, foreground=COLOR_UP)
        self.tree.tag_configure("evenrow_up", background=COLOR_TABLE_ALT, foreground=COLOR_UP)
        self.tree.tag_configure("oddrow_down", background=COLOR_TABLE_BG, foreground=COLOR_DOWN)
        self.tree.tag_configure("evenrow_down", background=COLOR_TABLE_ALT, foreground=COLOR_DOWN)

        self.tree.bind("<Double-1>", self.edit_selected_device)

        headers = {
            "ip": "IP",
            "alias": "Hostname / Alias",
            "ping": "Status",
            "latency": "Latency (ms)",
            "ports": "Open Ports",
            "web": "Web",
            "last_checked": "Last Checked",
            "error": "Error",
        }

        widths = {
            "ip": 120,
            "alias": 300,
            "ping": 90,
            "latency": 100,
            "ports": 180,
            "web": 90,
            "last_checked": 160,
            "error": 240,
        }

        for col in columns:
            self.tree.heading(col, text=headers[col], command=lambda c=col: self.sort_by_column(c, False))
            self.tree.column(col, width=widths[col], anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        footer = ttk.Frame(outer, style="Card.TFrame", padding=12)
        footer.pack(fill="x", pady=(12, 0))

        ttk.Label(footer, text="PS", style="PanelTitle.TLabel").pack(anchor="w")
        ttk.Label(
            footer,
            text="대리님 추가 반영사항 있으시면 말씀해주십시오",
            style="Info.TLabel",
        ).pack(anchor="w", pady=(4, 0))

    def _load_default_xml_if_exists(self):
        default_name = "advanced_ip_scanner_final.xml"
        if os.path.exists(default_name):
            try:
                self.load_xml(default_name)
            except Exception as e:
                self.status_var.set(f"기본 XML 자동 로드 실패: {e}")

    def open_xml(self):
        path = filedialog.askopenfilename(
            title="XML 파일 선택",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
        )
        if not path:
            return
        self.load_xml(path)

    def load_xml(self, path: str):
        tree = ET.parse(path)
        root = tree.getroot()
        devices: list[DeviceRow] = []

        for row in root.findall(".//row"):
            ip = (row.get("ip") or "").strip()
            if not ip:
                continue
            devices.append(
                DeviceRow(
                    ip=ip,
                    alias=(row.get("alias") or "").replace("\n", " ").strip(),
                    name=(row.get("name") or "").replace("\n", " ").strip(),
                    comment=(row.get("comment") or "").replace("\n", " ").strip(),
                    status=(row.get("status") or "unknown").strip(),
                    has_http=(row.get("has_http") or "0").strip(),
                    expanded=(row.get("expanded") or "0").strip(),
                )
            )

        self.devices = self._deduplicate_devices(devices)
        self.results = {}
        self.current_xml_path = path
        self.apply_filter()
        self.status_var.set(f"XML 로드 완료: {os.path.basename(path)} / {len(self.devices)}개 장비")

    def _deduplicate_devices(self, devices: list[DeviceRow]) -> list[DeviceRow]:
        seen: dict[str, DeviceRow] = {}
        for dev in devices:
            if dev.ip not in seen:
                seen[dev.ip] = dev
            else:
                prev = seen[dev.ip]
                prev_len = len(prev.alias + prev.name + prev.comment)
                cur_len = len(dev.alias + dev.name + dev.comment)
                if cur_len > prev_len:
                    seen[dev.ip] = dev
        return sorted(list(seen.values()), key=lambda d: self.ip_sort_key(d.ip))

    def apply_filter(self):
        keyword = self.search_var.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        self.filtered_ips = []

        for dev in self.devices:
            hay = f"{dev.ip} {dev.alias} {dev.name} {dev.comment}".lower()
            if keyword and keyword not in hay:
                continue

            self.filtered_ips.append(dev.ip)
            result = self.results.get(dev.ip) or ScanResult(ip=dev.ip, alias=dev.alias)
            self._upsert_tree_row(result)

        self._update_summary()
        self.status_var.set(f"표시 중: {len(self.filtered_ips)} / 전체: {len(self.devices)}")

    def _get_row_tag(self, result: ScanResult):
        try:
            children = self.tree.get_children("")
            row_index = len(children)
        except Exception:
            row_index = 0

        base = "evenrow" if row_index % 2 else "oddrow"
        status = str(result.ping).upper()

        if status == "UP":
            return f"{base}_up"
        if status == "DOWN":
            return f"{base}_down"
        return base

    def _upsert_tree_row(self, result: ScanResult):
        values = (
            result.ip,
            result.alias,
            result.ping,
            result.latency_ms,
            result.open_ports,
            result.web,
            result.last_checked,
            result.error,
        )

        if self.tree.exists(result.ip):
            children = list(self.tree.get_children(""))
            row_index = children.index(result.ip) if result.ip in children else 0
            base = "evenrow" if row_index % 2 else "oddrow"
            status = str(result.ping).upper()
            if status == "UP":
                tag = f"{base}_up"
            elif status == "DOWN":
                tag = f"{base}_down"
            else:
                tag = base
            self.tree.item(result.ip, values=values, tags=(tag,))
        else:
            tag = self._get_row_tag(result)
            self.tree.insert("", "end", iid=result.ip, values=values, tags=(tag,))

    def _refresh_row_colors(self):
        children = self.tree.get_children("")
        for idx, item_id in enumerate(children):
            values = self.tree.item(item_id, "values")
            ping = str(values[2]).upper() if len(values) > 2 else ""
            base = "evenrow" if idx % 2 else "oddrow"

            if ping == "UP":
                tag = f"{base}_up"
            elif ping == "DOWN":
                tag = f"{base}_down"
            else:
                tag = base

            self.tree.item(item_id, tags=(tag,))

    def _update_summary(self):
        up_count = sum(1 for r in self.results.values() if r.ping.upper() == "UP")
        down_count = sum(1 for r in self.results.values() if r.ping.upper() == "DOWN")
        self.summary_label.config(text=f"UP {up_count} / DOWN {down_count}")

    def _get_timeout(self) -> int:
        try:
            value = int(self.timeout_var.get().strip())
            return max(200, min(value, 10000))
        except Exception:
            return DEFAULT_TIMEOUT_MS

    def _get_thread_count(self) -> int:
        try:
            value = int(self.thread_var.get().strip())
            return max(1, min(value, 256))
        except Exception:
            return DEFAULT_THREADS

    def scan_all(self):
        targets = [d for d in self.devices if d.ip in self.filtered_ips] if self.search_var.get().strip() else list(self.devices)
        self._start_scan(targets)

    def scan_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("선택 필요", "스캔할 대상을 선택하세요.")
            return
        ip_set = set(selected)
        targets = [d for d in self.devices if d.ip in ip_set]
        self._start_scan(targets)

    def _start_scan(self, targets: list[DeviceRow]):
        if self.is_scanning:
            messagebox.showinfo("진행 중", "이미 스캔이 진행 중입니다.")
            return
        if not targets:
            messagebox.showwarning("대상 없음", "스캔할 장비가 없습니다.")
            return

        self.is_scanning = True
        self.stop_event.clear()
        self.progress["maximum"] = len(targets)
        self.progress["value"] = 0
        self.status_var.set(f"스캔 시작: {len(targets)}개")

        thread = threading.Thread(target=self._run_scan_batch, args=(targets,), daemon=True)
        thread.start()

    def stop_scan(self):
        if self.is_scanning:
            self.stop_event.set()
            self.status_var.set("중지 요청됨...")

    def _run_scan_batch(self, targets: list[DeviceRow]):
        completed = 0
        total = len(targets)
        timeout = self._get_timeout()
        max_workers = self._get_thread_count()

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_map = {executor.submit(self.scan_device, dev, timeout): dev.ip for dev in targets}
                for future in as_completed(future_map):
                    if self.stop_event.is_set():
                        break
                    try:
                        result = future.result()
                    except Exception as e:
                        dev_ip = future_map[future]
                        result = ScanResult(ip=dev_ip, alias="", error=str(e))
                    self.scan_queue.put(("result", result))
                    completed += 1
                    self.scan_queue.put(("progress", completed, total))
        finally:
            self.scan_queue.put(("done",))

    def scan_device(self, dev: DeviceRow, timeout_ms: int) -> ScanResult:
        if self.stop_event.is_set():
            return ScanResult(ip=dev.ip, alias=dev.alias, error="사용자 중지")

        ping_ok, latency = self.ping_host(dev.ip, timeout_ms)
        open_ports = self.check_ports(dev.ip, timeout_ms)
        web = self.check_web_hint(dev.ip, timeout_ms) if self.http_check_var.get() else ""
        arp_seen = self.arp_cache_contains(dev.ip)

        is_up = ping_ok or bool(open_ports) or arp_seen


        return ScanResult(
            ip=dev.ip,
            alias=dev.alias,
            ping="UP" if is_up else "DOWN",
            latency_ms=str(latency) if latency is not None else "",
            open_ports=", ".join(map(str, open_ports)),
            web=web,
            last_checked=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            error="" if is_up else "응답 없음",
        )

    def _subprocess_kwargs(self, timeout: int | float):
        kwargs = {
            "capture_output": True,
            "timeout": timeout,
        }

        if sys.platform.startswith("win"):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            kwargs["startupinfo"] = startupinfo
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        return kwargs

    def ping_host(self, ip: str, timeout_ms: int):
        try:
            if sys.platform.startswith("win"):
                cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
                encoding_candidates = ["cp949", "utf-8", "euc-kr"]
            else:
                timeout_sec = max(1, int(round(timeout_ms / 1000)))
                cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]
                encoding_candidates = ["utf-8"]

            completed = subprocess.run(
                cmd,
                **self._subprocess_kwargs(max(3, int(timeout_ms / 1000) + 2))
            )
            raw = (completed.stdout or b"") + b"\n" + (completed.stderr or b"")
            out = ""
            for enc in encoding_candidates:
                try:
                    out = raw.decode(enc, errors="ignore")
                    if out:
                        break
                except Exception:
                    pass
            if not out:
                out = raw.decode(errors="ignore")

            ttl_success = re.search(r"ttl[=:\s]+\d+", out, re.IGNORECASE) is not None
            reply_success = any(
                token in out.lower()
                for token in ["reply from", "bytes from", "time=", "time<", "시간=", "시간<"]
            )
            success = completed.returncode == 0 or ttl_success or reply_success
            if not success:
                return False, None

            patterns = [
                r"time[=<]\s*(\d+)\s*ms",
                r"time=(\d+(?:\.\d+)?)\s*ms",
                r"시간[=<]\s*(\d+)\s*ms",
                r"시간[=<]\s*(\d+)ms",
            ]
            for pattern in patterns:
                match = re.search(pattern, out, re.IGNORECASE)
                if match:
                    try:
                        return True, int(float(match.group(1)))
                    except Exception:
                        pass

            if "time<" in out.lower() or "시간<" in out:
                return True, 1

            return True, None
        except Exception:
            return False, None

    def reverse_dns(self, ip: str) -> str:
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host
        except Exception:
            return ""

    def arp_cache_contains(self, ip: str) -> bool:
        try:
            if sys.platform.startswith("win"):
                output = subprocess.run(
                    ["arp", "-a", ip],
                    **self._subprocess_kwargs(3)
                )
                raw = (output.stdout or b"") + b"\n" + (output.stderr or b"")
                text = raw.decode("cp949", errors="ignore")
            else:
                output = subprocess.run(
                    ["arp", "-n", ip],
                    capture_output=True,
                    timeout=3,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                )
                text = (output.stdout or "") + "\n" + (output.stderr or "")

            lowered = text.lower()
            return ip in text and (
                "동적" in text or "정적" in text or "dynamic" in lowered or "static" in lowered
            )
        except Exception:
            return False

    def check_ports(self, ip: str, timeout_ms: int) -> list[int]:
        timeout_sec = max(0.2, timeout_ms / 1000.0)
        opened = []
        for port in COMMON_PORTS:
            if self.stop_event.is_set():
                break
            try:
                with socket.create_connection((ip, port), timeout=timeout_sec):
                    opened.append(port)
            except Exception:
                continue
        return opened

    def check_web_hint(self, ip: str, timeout_ms: int) -> str:
        timeout_sec = max(0.2, timeout_ms / 1000.0)
        try:
            with socket.create_connection((ip, 443), timeout=timeout_sec):
                return "HTTPS"
        except Exception:
            pass
        try:
            with socket.create_connection((ip, 80), timeout=timeout_sec):
                return "HTTP"
        except Exception:
            return ""

    def add_device(self):
        dialog = DeviceDialog(self.root, title="장비 추가")
        self.root.wait_window(dialog)
        if not dialog.result:
            return

        ip = dialog.result["ip"]
        alias = dialog.result["alias"]

        if any(d.ip == ip for d in self.devices):
            messagebox.showwarning("중복 IP", f"{ip} 는 이미 등록되어 있습니다.")
            return

        self.devices.append(DeviceRow(ip=ip, alias=alias))
        self.devices = sorted(self.devices, key=lambda d: self.ip_sort_key(d.ip))
        self.apply_filter()
        self.status_var.set(f"장비 추가 완료: {ip}")

    def edit_selected_device(self, event=None):
        selected = self.tree.selection()
        if len(selected) != 1:
            if event is None:
                messagebox.showwarning("선택 필요", "수정할 장비 1개를 선택하세요.")
            return

        target_ip = selected[0]
        dev = next((d for d in self.devices if d.ip == target_ip), None)
        if not dev:
            return

        dialog = DeviceDialog(self.root, title="장비 수정", ip=dev.ip, alias=dev.alias)
        self.root.wait_window(dialog)
        if not dialog.result:
            return

        new_ip = dialog.result["ip"]
        new_alias = dialog.result["alias"]

        if new_ip != dev.ip and any(d.ip == new_ip for d in self.devices):
            messagebox.showwarning("중복 IP", f"{new_ip} 는 이미 등록되어 있습니다.")
            return

        old_ip = dev.ip
        dev.ip = new_ip
        dev.alias = new_alias

        if old_ip != new_ip and old_ip in self.results:
            self.results[new_ip] = self.results.pop(old_ip)
            self.results[new_ip].ip = new_ip

        self.devices = sorted(self.devices, key=lambda d: self.ip_sort_key(d.ip))
        self.apply_filter()
        self.status_var.set(f"장비 수정 완료: {old_ip} -> {new_ip}")

    def delete_selected_devices(self):
        selected = list(self.tree.selection())
        if not selected:
            messagebox.showwarning("선택 필요", "삭제할 장비를 선택하세요.")
            return

        if not messagebox.askyesno("삭제 확인", f"{len(selected)}개 장비를 삭제하시겠습니까?"):
            return

        selected_set = set(selected)
        self.devices = [d for d in self.devices if d.ip not in selected_set]
        for ip in selected:
            self.results.pop(ip, None)

        self.apply_filter()
        self.status_var.set(f"장비 삭제 완료: {len(selected)}개")

    def save_xml(self):
        if not self.current_xml_path:
            return self.save_xml_as()
        self._write_xml(self.current_xml_path)
        messagebox.showinfo("저장 완료", f"XML 저장 완료\n{self.current_xml_path}")

    def save_xml_as(self):
        path = filedialog.asksaveasfilename(
            title="XML 저장",
            defaultextension=".xml",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
            initialfile=os.path.basename(self.current_xml_path) if self.current_xml_path else "advanced_ip_scanner_custom.xml",
        )
        if not path:
            return
        self._write_xml(path)
        self.current_xml_path = path
        messagebox.showinfo("저장 완료", f"XML 저장 완료\n{path}")

    def _write_xml(self, path: str):
        root = ET.Element("rows")
        for dev in sorted(self.devices, key=lambda d: self.ip_sort_key(d.ip)):
            ET.SubElement(
                root,
                "row",
                {
                    "ip": dev.ip,
                    "alias": dev.alias or "",
                    "name": dev.name or "",
                    "comment": dev.comment or "",
                    "status": dev.status or "unknown",
                    "has_http": dev.has_http or "0",
                    "expanded": dev.expanded or "0",
                },
            )

        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        tree.write(path, encoding="utf-8", xml_declaration=True)

    def _poll_result_queue(self):
        try:
            while True:
                item = self.scan_queue.get_nowait()
                kind = item[0]

                if kind == "result":
                    result = item[1]
                    if result.ip:
                        self.results[result.ip] = result
                        if not self.search_var.get().strip() or result.ip in self.filtered_ips:
                            self._upsert_tree_row(result)
                            self._refresh_row_colors()
                        self._update_summary()

                elif kind == "progress":
                    completed, total = item[1], item[2]
                    self.progress["maximum"] = total
                    self.progress["value"] = completed
                    self.status_var.set(f"스캔 중... {completed}/{total}")

                elif kind == "done":
                    self.is_scanning = False
                    self._update_summary()
                    self._refresh_row_colors()
                    self.status_var.set("스캔 중지됨" if self.stop_event.is_set() else "스캔 완료")

        except queue.Empty:
            pass

        self.root.after(120, self._poll_result_queue)

    def export_csv(self):
        if not self.results:
            messagebox.showwarning("데이터 없음", "내보낼 스캔 결과가 없습니다.")
            return

        path = filedialog.asksaveasfilename(
            title="CSV 저장",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile=f"scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        )
        if not path:
            return

        rows = [asdict(r) for r in sorted(self.results.values(), key=lambda r: self.ip_sort_key(r.ip))]
        fieldnames = ["ip", "alias", "ping", "latency_ms", "open_ports", "web", "last_checked", "error"]

        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        messagebox.showinfo("완료", f"CSV 저장 완료\n{path}")

    def sort_by_column(self, col: str, descending: bool):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]

        def generic_key(value: str):
            value = value or ""
            if col == "ip":
                return self.ip_sort_key(value)
            if value.isdigit():
                return int(value)
            return value.lower()

        items.sort(key=lambda t: generic_key(t[0]), reverse=descending)

        for index, (_, k) in enumerate(items):
            self.tree.move(k, "", index)

        self._refresh_row_colors()
        self.tree.heading(col, command=lambda: self.sort_by_column(col, not descending))

    @staticmethod
    def ip_sort_key(value: str):
        try:
            return tuple(int(x) for x in value.split("."))
        except Exception:
            return (999, 999, 999, 999)


def main():
    root = tk.Tk()
    XMLScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()