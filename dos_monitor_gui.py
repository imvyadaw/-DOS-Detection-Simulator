"""
dos_monitor_gui.py
Real-time network traffic monitor with DoS-style flood detection.

Unlike a simulation, this reads ACTUAL network I/O counters from your OS
(via psutil) every second, computes real throughput, and raises an alert
when it crosses your threshold. Works on Linux (Kali) and Windows.

Install requirements:
    pip install psutil --break-system-packages   # Linux
    pip install psutil                            # Windows

Run:
    python3 dos_monitor_gui.py
"""

import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox

try:
    import psutil
except ImportError:
    raise SystemExit("psutil is required. Install it with: pip install psutil")


class DosMonitorGUI:
    MAX_POINTS = 60

    def __init__(self, root):
        self.root = root
        self.root.title("Network Flood / DoS Monitor")
        self.root.geometry("780x560")
        self.root.configure(bg="#060a0f")

        self.running = False
        self.alert_active = False
        self.data_points = []
        self.last_counters = psutil.net_io_counters()
        self.last_time = time.time()

        self._build_ui()

    # ---------- UI ----------
    def _build_ui(self):
        FG = "#9ca3af"
        ACCENT = "#00f2ff"
        BG = "#0f1620"

        top = tk.Frame(self.root, bg="#060a0f")
        top.pack(fill="x", padx=20, pady=15)

        tk.Label(top, text="NETWORK FLOOD / DoS MONITOR", fg=ACCENT, bg="#060a0f",
                 font=("Courier New", 16, "bold")).pack(anchor="w")
        tk.Label(top, text="Reads real system network throughput (psutil) every second.",
                 fg=FG, bg="#060a0f", font=("Courier New", 10)).pack(anchor="w", pady=(4, 0))

        stats = tk.Frame(self.root, bg="#060a0f")
        stats.pack(fill="x", padx=20, pady=10)

        self.current_lbl = self._stat_box(stats, "CURRENT KB/s", "0")
        self.peak_lbl = self._stat_box(stats, "PEAK KB/s", "0")
        self.status_lbl = self._stat_box(stats, "STATUS", "IDLE")

        controls = tk.Frame(self.root, bg="#060a0f")
        controls.pack(fill="x", padx=20, pady=(0, 10))

        tk.Label(controls, text="Threshold (KB/s):", fg=FG, bg="#060a0f",
                 font=("Courier New", 10)).pack(side="left")
        self.threshold_var = tk.StringVar(value="500")
        tk.Entry(controls, textvariable=self.threshold_var, width=8,
                 bg="black", fg=ACCENT, insertbackground=ACCENT).pack(side="left", padx=8)

        self.start_btn = tk.Button(controls, text="START MONITORING", command=self.start,
                                    bg="#060a0f", fg=ACCENT, activebackground=ACCENT,
                                    relief="solid", bd=1)
        self.start_btn.pack(side="left", padx=10)

        self.stop_btn = tk.Button(controls, text="STOP", command=self.stop,
                                   bg="#060a0f", fg="#f87171", activebackground="#f87171",
                                   relief="solid", bd=1, state="disabled")
        self.stop_btn.pack(side="left")

        self.canvas = tk.Canvas(self.root, bg="black", height=220,
                                 highlightthickness=1, highlightbackground="#00f2ff33")
        self.canvas.pack(fill="both", expand=False, padx=20, pady=10)

        tk.Label(self.root, text="DETECTION LOG", fg="#6b7280", bg="#060a0f",
                 font=("Courier New", 9)).pack(anchor="w", padx=20)

        self.log_box = tk.Text(self.root, height=10, bg="black", fg=FG,
                                font=("Courier New", 9), bd=1, relief="solid")
        self.log_box.pack(fill="both", expand=True, padx=20, pady=(4, 20))
        self.log_box.tag_config("alert", foreground="#f87171")
        self.log_box.tag_config("ok", foreground="#4ade80")
        self._log("// monitoring stopped. click START to begin.")

    def _stat_box(self, parent, title, value):
        box = tk.Frame(parent, bg="black", highlightbackground="#00f2ff33",
                        highlightthickness=1)
        box.pack(side="left", expand=True, fill="both", padx=5)
        tk.Label(box, text=title, fg="#6b7280", bg="black",
                 font=("Courier New", 9)).pack(anchor="w", padx=10, pady=(8, 0))
        val_lbl = tk.Label(box, text=value, fg="white", bg="black",
                            font=("Arial", 18, "bold"))
        val_lbl.pack(anchor="w", padx=10, pady=(0, 8))
        return val_lbl

    def _log(self, text, tag=None):
        self.log_box.insert("end", text + "\n", tag)
        self.log_box.see("end")

    # ---------- monitoring logic ----------
    def start(self):
        try:
            self.threshold = float(self.threshold_var.get())
        except ValueError:
            messagebox.showerror("Invalid threshold", "Enter a numeric threshold in KB/s.")
            return

        self.running = True
        self.alert_active = False
        self.data_points = []
        self.peak = 0
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_lbl.config(text="MONITORING", fg="#00f2ff")
        self._log("> monitoring started, sampling real network I/O every second...")

        self.last_counters = psutil.net_io_counters()
        self.last_time = time.time()
        self._sample()

    def stop(self):
        self.running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_lbl.config(text="IDLE", fg="white")
        self._log("> monitoring stopped.")

    def _sample(self):
        if not self.running:
            return

        now = time.time()
        counters = psutil.net_io_counters()
        elapsed = max(now - self.last_time, 0.001)

        bytes_delta = (counters.bytes_sent + counters.bytes_recv) - \
                      (self.last_counters.bytes_sent + self.last_counters.bytes_recv)
        kbps = (bytes_delta / 1024.0) / elapsed

        self.last_counters = counters
        self.last_time = now

        self.data_points.append(kbps)
        if len(self.data_points) > self.MAX_POINTS:
            self.data_points.pop(0)

        self.peak = max(self.peak, kbps)
        self.current_lbl.config(text=f"{kbps:.1f}")
        self.peak_lbl.config(text=f"{self.peak:.1f}")

        if kbps > self.threshold and not self.alert_active:
            self.alert_active = True
            self.status_lbl.config(text="FLOOD DETECTED", fg="#f87171")
            self._log(f"[ALERT] throughput {kbps:.1f} KB/s exceeded threshold "
                       f"({self.threshold:.1f} KB/s) — possible flood/DoS", "alert")
        elif kbps <= self.threshold and self.alert_active:
            self.alert_active = False
            self.status_lbl.config(text="MONITORING", fg="#00f2ff")
            self._log("> throughput back under threshold.", "ok")

        self._draw()
        self.root.after(1000, self._sample)

    def _draw(self):
        self.canvas.delete("all")
        w = self.canvas.winfo_width() or 700
        h = self.canvas.winfo_height() or 220
        if not self.data_points:
            return

        max_val = max(max(self.data_points), self.threshold * 1.5, 10)
        step_x = w / self.MAX_POINTS

        thresh_y = h - (self.threshold / max_val) * h
        self.canvas.create_line(0, thresh_y, w, thresh_y, fill="#f87171", dash=(4, 3))
        self.canvas.create_text(40, thresh_y - 10, text="THRESHOLD", fill="#f87171",
                                 font=("Courier New", 8))

        points = []
        for i, v in enumerate(self.data_points):
            x = i * step_x
            y = h - (v / max_val) * h
            points.extend([x, y])
        if len(points) >= 4:
            self.canvas.create_line(*points, fill="#00f2ff", width=2, smooth=True)


if __name__ == "__main__":
    root = tk.Tk()
    app = DosMonitorGUI(root)
    root.mainloop()
