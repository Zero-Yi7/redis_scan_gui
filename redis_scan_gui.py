#!/usr/bin/env python
# coding=utf-8
# author: Rabbit
# GUI modification by AI Assistant (Version 4 - TSV Output)

import socket
import sys
import time
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import threading


# --- 原脚本的核心逻辑 (修改版，返回简洁状态描述) ---
def check_redis_unauth_detailed_v4(ip, port, timeout=5):
    """
    检查单个Redis实例是否存在未授权访问。
    返回: (status_code, display_message, short_status_message, raw_response)
    status_code: "VULNERABLE_REDIS", "VULNERABLE_SENTINEL", "SECURED", "TIMEOUT", "ERROR", "CHECK_MANUALLY", "CONN_REFUSED"
    display_message: 用于GUI显示的主消息
    short_status_message: 用于文件记录的简洁状态描述
    raw_response: 服务器返回的原始响应片段 (如果适用)
    """
    raw_response_snippet = ""
    target_str = f"{ip}:{port}"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, int(port)))
        payload = "INFO\r\n"
        s.send(payload.encode())
        result_bytes = s.recv(4096)
        s.close()

        try:
            result_decoded = result_bytes.decode("utf-8", errors="ignore")
            raw_response_snippet = (
                result_decoded[:250] + "..."
                if len(result_decoded) > 250
                else result_decoded
            )
        except UnicodeDecodeError:
            try:
                result_decoded = result_bytes.decode("gbk", errors="ignore")
                raw_response_snippet = (
                    result_decoded[:250] + "..."
                    if len(result_decoded) > 250
                    else result_decoded
                )
            except UnicodeDecodeError:
                result_decoded = str(result_bytes[:250]) + "..."
                raw_response_snippet = result_decoded

        if (
            "NOAUTH" in result_decoded.upper()
            or "WRONGPASS" in result_decoded.upper()
            or "DENIED" in result_decoded.upper()
            or (
                result_decoded.strip().startswith("-ERR operation not permitted")
                and "AUTH" not in result_decoded.upper()
            )
            or (result_decoded.strip().startswith("-NOPERM"))
        ):
            return (
                "SECURED",
                f"[-] {target_str} 需要认证或访问被拒",
                "需要认证/访问被拒",
                raw_response_snippet,
            )

        if "redis_mode:sentinel" in result_decoded:
            if "redis_version" in result_decoded:
                return (
                    "VULNERABLE_SENTINEL",
                    f"[+] {target_str} (Sentinel) 存在未授权访问漏洞 (可INFO)",
                    "存在未授权访问 (Sentinel, INFO)",
                    raw_response_snippet,
                )
            else:
                return (
                    "CHECK_MANUALLY",
                    f"[?] {target_str} (Sentinel) 响应异常",
                    "响应异常 (Sentinel)",
                    raw_response_snippet,
                )
        elif "redis_version" in result_decoded and (
            "loading_total_bytes" in result_decoded
            or "mem_fragmentation_ratio" in result_decoded
        ):
            return (
                "VULNERABLE_REDIS",
                f"[+] {target_str} (Redis) 存在未授权访问漏洞",
                "存在未授权访问 (Redis)",
                raw_response_snippet,
            )
        elif result_decoded.strip() == "" or len(result_decoded) < 10:
            return (
                "CHECK_MANUALLY",
                f"[?] {target_str} 响应不明确",
                "响应不明确",
                raw_response_snippet,
            )
        else:
            return (
                "CHECK_MANUALLY",
                f"[?] {target_str} 响应异常",
                "响应异常",
                raw_response_snippet,
            )

    except socket.timeout:
        return "TIMEOUT", f"[-] {target_str} 请求超时", "请求超时", "N/A (超时)"
    except socket.error as e:
        if (
            "actively refused it" in str(e).lower()
            or "connection refused" in str(e).lower()
        ):
            return (
                "CONN_REFUSED",
                f"[!] {target_str} 连接被拒绝",
                "连接被拒绝",
                f"Error: {e}",
            )
        return "ERROR", f"[-] {target_str} 连接错误", "连接错误", f"Error: {e}"
    except Exception as e:
        return "ERROR", f"[-] {target_str} 未知错误", "未知错误", f"Error: {e}"


# --- GUI 部分 ---
class RedisScanAppGUIV4:
    def __init__(self, master):
        self.master = master
        master.title("Redis 未授权访问扫描器 (GUI v4 - TSV Output)")
        master.geometry("850x700")

        self.targets_to_scan = []
        self.results_file_path = ""
        self.scanning_thread = None
        self.stop_scan_flag = False
        self.file_header_written = False  # 标志文件头是否已写入

        # --- 主布局 ---
        main_paned_window = ttk.PanedWindow(master, orient=tk.VERTICAL)
        main_paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- 目标输入区域 ---
        target_input_frame = ttk.LabelFrame(
            main_paned_window, text="扫描目标 (每行一个 ip:port)"
        )
        main_paned_window.add(target_input_frame, weight=2)

        self.targets_text_area = scrolledtext.ScrolledText(
            target_input_frame,
            wrap=tk.WORD,
            width=70,
            height=12,
            font=("TkDefaultFont", 10),
        )
        self.targets_text_area.pack(padx=5, pady=5, fill="both", expand=True)
        self.targets_text_area.insert(
            tk.END,
            "在此粘贴目标列表",
        )

        # --- 控制区域 ---
        control_frame_outer = ttk.Frame(main_paned_window)
        main_paned_window.add(control_frame_outer, weight=0)

        control_frame = ttk.LabelFrame(control_frame_outer, text="控制与设置")
        control_frame.pack(padx=0, pady=5, fill="x")

        ttk.Label(control_frame, text="超时(秒):").grid(
            row=0, column=0, padx=5, pady=3, sticky="w"
        )
        self.timeout_var = tk.StringVar(value="3")
        self.timeout_entry = ttk.Entry(
            control_frame, width=5, textvariable=self.timeout_var
        )
        self.timeout_entry.grid(row=0, column=1, padx=5, pady=3, sticky="w")

        self.start_button = ttk.Button(
            control_frame, text="▶ 开始扫描", command=self.start_scan_thread
        )
        self.start_button.grid(row=0, column=2, padx=(10, 5), pady=3)
        self.stop_button = ttk.Button(
            control_frame, text="■ 停止扫描", command=self.stop_scan, state=tk.DISABLED
        )
        self.stop_button.grid(row=0, column=3, padx=5, pady=3)
        ttk.Button(
            control_frame, text="清空目标", command=self.clear_target_input
        ).grid(row=0, column=4, padx=5, pady=3)
        ttk.Button(
            control_frame, text="清空结果", command=self.clear_results_display
        ).grid(row=0, column=5, padx=5, pady=3)
        ttk.Button(
            control_frame, text="复制结果", command=self.copy_results_to_clipboard
        ).grid(row=0, column=6, padx=5, pady=3)

        control_frame.columnconfigure(6, weight=1)

        # --- 结果显示区域 ---
        results_display_frame = ttk.LabelFrame(main_paned_window, text="扫描结果")
        main_paned_window.add(results_display_frame, weight=5)

        self.results_text_display = scrolledtext.ScrolledText(
            results_display_frame,
            wrap=tk.WORD,
            width=80,
            height=25,
            font=("Consolas", 11),
        )
        self.results_text_display.pack(padx=5, pady=5, fill="both", expand=True)
        self.results_text_display.tag_config(
            "VULNERABLE_REDIS", foreground="#E60000", font=("Consolas", 11, "bold")
        )
        self.results_text_display.tag_config(
            "VULNERABLE_SENTINEL", foreground="#FF4500", font=("Consolas", 11, "bold")
        )
        self.results_text_display.tag_config("SECURED", foreground="#006400")
        self.results_text_display.tag_config("TIMEOUT", foreground="#FF8C00")
        self.results_text_display.tag_config("ERROR", foreground="#8A2BE2")
        self.results_text_display.tag_config("CHECK_MANUALLY", foreground="#1E90FF")
        self.results_text_display.tag_config("CONN_REFUSED", foreground="#A0522D")
        self.results_text_display.tag_config("INFO", foreground="#696969")
        self.results_text_display.tag_config(
            "RAW_RESPONSE_LABEL", foreground="#4682B4", font=("Consolas", 10, "italic")
        )
        self.results_text_display.tag_config(
            "RAW_RESPONSE_DATA", foreground="#2F4F4F", font=("Consolas", 10)
        )

        self.status_bar_text = tk.StringVar()
        self.status_bar = ttk.Label(
            master, textvariable=self.status_bar_text, relief=tk.SUNKEN, anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=2, pady=2)
        self.status_bar_text.set("就绪")

    def clear_target_input(self):
        self.targets_text_area.delete("1.0", tk.END)
        self.targets_to_scan = []
        self.status_bar_text.set("目标列表已清空")

    def clear_results_display(self):
        self.results_text_display.config(state=tk.NORMAL)
        self.results_text_display.delete("1.0", tk.END)
        self.results_text_display.config(state=tk.DISABLED)
        self.status_bar_text.set("扫描结果已清空")

    def copy_results_to_clipboard(self):
        try:
            all_results = self.results_text_display.get("1.0", tk.END)
            self.master.clipboard_clear()
            self.master.clipboard_append(all_results)
            self.status_bar_text.set("结果已复制到剪贴板")
        except tk.TclError:
            self.status_bar_text.set("复制失败 (剪贴板不可用)")
        except Exception as e:
            self.status_bar_text.set(f"复制时发生错误: {e}")

    def parse_targets_from_text_area(self):
        self.targets_to_scan = []
        content = self.targets_text_area.get("1.0", tk.END)
        lines = content.splitlines()
        for line in lines:
            target = line.strip()
            if target and ":" in target and not target.startswith("#"):
                self.targets_to_scan.append(target)
        if not self.targets_to_scan:
            messagebox.showwarning(
                "提示", "目标输入区为空或格式不正确 (ip:port 每行一个)。"
            )
            return False
        self.log_to_results_display(
            f"已从输入区加载 {len(self.targets_to_scan)} 个有效目标。", "INFO"
        )
        return True

    def write_to_results_file(self, ip, port, short_status, raw_response=""):
        if self.results_file_path:
            try:
                # 确保只写入一次文件头
                if not self.file_header_written:
                    with open(
                        self.results_file_path, "a", encoding="utf-8", newline=""
                    ) as file:
                        file.write("IP\tPort\tStatus\tRawResponse\n")
                    self.file_header_written = True

                with open(
                    self.results_file_path, "a", encoding="utf-8", newline=""
                ) as file:
                    # 清理原始响应中的换行符，使其适合TSV
                    cleaned_raw_response = (
                        raw_response.replace("\n", " ").replace("\r", " ")
                        if raw_response
                        else ""
                    )
                    file.write(
                        f"{ip}\t{port}\t{short_status}\t{cleaned_raw_response}\n"
                    )
            except Exception as e:
                self.log_to_results_display(f"写入结果文件失败: {e}", "ERROR")

    def log_to_results_display(
        self,
        message,
        tag=None,
        raw_response=None,
        target_ip=None,
        target_port=None,
        short_status=None,
    ):
        self.results_text_display.config(state=tk.NORMAL)
        timestamp = time.strftime("%H:%M:%S", time.localtime())

        if tag:
            self.results_text_display.insert(tk.END, f"[{timestamp}] ", "INFO")
            self.results_text_display.insert(tk.END, message + "\n", tag)
        else:
            self.results_text_display.insert(tk.END, f"[{timestamp}] {message}\n")

        if raw_response:
            self.results_text_display.insert(
                tk.END, "  响应详情: ", "RAW_RESPONSE_LABEL"
            )
            self.results_text_display.insert(
                tk.END, f"{raw_response}\n\n", "RAW_RESPONSE_DATA"
            )

        self.results_text_display.see(tk.END)
        self.results_text_display.config(state=tk.DISABLED)

        # 写入文件逻辑 - 现在所有结果都写入
        if target_ip and target_port and short_status:
            self.write_to_results_file(
                target_ip,
                target_port,
                short_status,
                raw_response if raw_response else "",
            )

    def perform_scan(self):
        if not self.targets_to_scan:
            if not self.parse_targets_from_text_area():
                self.scan_finished()
                return

        self.results_file_path = (
            "result_redis_gui_v4_tsv_" + str(int(time.time())) + ".txt"
        )
        self.file_header_written = False  # 重置文件头写入标志
        self.log_to_results_display(
            f"扫描开始，所有结果将以TSV格式保存到: {self.results_file_path}", "INFO"
        )
        self.stop_scan_flag = False
        self.status_bar_text.set("扫描中...")

        try:
            timeout = int(self.timeout_var.get())
            if timeout <= 0:
                raise ValueError("Timeout must be positive")
        except ValueError:
            messagebox.showerror("错误", "超时时间必须是正整数。")
            self.scan_finished()
            self.status_bar_text.set("扫描错误：无效超时")
            return

        processed_count = 0
        total_targets = len(self.targets_to_scan)

        for target_str in self.targets_to_scan:
            if self.stop_scan_flag:
                self.log_to_results_display("扫描已手动停止。", "INFO")
                break
            try:
                ip, port_str = target_str.split(":", 1)
                port = int(port_str)
                status_code, display_msg, short_status_msg, raw_resp = (
                    check_redis_unauth_detailed_v4(ip, port, timeout)
                )
                self.log_to_results_display(
                    display_msg, status_code, raw_resp, ip, str(port), short_status_msg
                )
            except ValueError:
                error_msg = f"[ERROR] 目标格式错误: {target_str} (应为 ip:port)"
                self.log_to_results_display(
                    error_msg,
                    "ERROR",
                    target_ip=(
                        target_str.split(":")[0] if ":" in target_str else target_str
                    ),
                    target_port=(
                        target_str.split(":")[1] if ":" in target_str else "N/A"
                    ),
                    short_status="格式错误",
                )
            except Exception as e:
                error_msg = f"[ERROR] 处理 {target_str} 时发生未知错误: {e}"
                self.log_to_results_display(
                    error_msg,
                    "ERROR",
                    target_ip=(
                        target_str.split(":")[0] if ":" in target_str else target_str
                    ),
                    target_port=(
                        target_str.split(":")[1] if ":" in target_str else "N/A"
                    ),
                    short_status="未知错误",
                )

            processed_count += 1
            self.status_bar_text.set(f"扫描中... ({processed_count}/{total_targets})")
            self.master.update_idletasks()

        if not self.stop_scan_flag:
            self.log_to_results_display("扫描完成。", "INFO")
            self.status_bar_text.set(f"扫描完成. 共处理 {processed_count} 个目标.")
        else:
            self.status_bar_text.set(
                f"扫描已停止. 已处理 {processed_count}/{total_targets} 个目标."
            )
        self.scan_finished()

    def start_scan_thread(self):
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.results_text_display.config(state=tk.NORMAL)
        self.results_text_display.delete("1.0", tk.END)
        self.results_text_display.config(state=tk.DISABLED)

        self.scanning_thread = threading.Thread(target=self.perform_scan, daemon=True)
        self.scanning_thread.start()

    def stop_scan(self):
        if self.scanning_thread and self.scanning_thread.is_alive():
            self.stop_scan_flag = True
            self.status_bar_text.set("正在停止扫描...")

    def scan_finished(self):
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.scanning_thread = None


if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style(root)
    try:
        current_os = sys.platform
        if current_os == "win32":
            if "vista" in style.theme_names():
                style.theme_use("vista")
            elif "xpnative" in style.theme_names():
                style.theme_use("xpnative")
        elif current_os == "darwin":
            if "aqua" in style.theme_names():
                style.theme_use("aqua")
        else:
            if "clam" in style.theme_names():
                style.theme_use("clam")
            elif "alt" in style.theme_names():
                style.theme_use("alt")
            elif "default" in style.theme_names():
                style.theme_use("default")
    except tk.TclError:
        print("当前系统不支持选定的ttk主题或主题不存在，将使用Tk默认主题。")

    app = RedisScanAppGUIV4(root)
    root.mainloop()
