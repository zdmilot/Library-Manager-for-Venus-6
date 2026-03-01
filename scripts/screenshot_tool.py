#!/usr/bin/env python3
"""
CHM Documentation Screenshot Tool
===================================
Interactive tool that guides you through capturing screenshots for
CHM help documentation placeholders.

Features:
  - Reads chm-image-map.json to know exactly which screenshots are needed
  - Shows which images are missing vs already captured
  - Displays setup instructions for each screenshot
  - Transparent overlay with click-and-drag bounding box selection
  - Auto-saves screenshots with the correct filename
  - Supports retaking screenshots
  - Countdown timer so you can set up the target window

Requirements:
  pip install Pillow mss

Usage:
  python scripts/screenshot_tool.py
"""

import json
import os
import sys
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont, ImageTk
except ImportError:
    print("ERROR: Pillow is required.  Install with:  pip install Pillow")
    sys.exit(1)

try:
    import mss
    import mss.tools
except ImportError:
    print("ERROR: mss is required.  Install with:  pip install mss")
    sys.exit(1)


# ── Paths ──────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
CHM_DIR = PROJECT_DIR / "CHM Help Source Files"
IMAGES_DIR = CHM_DIR / "images"
MAP_FILE = IMAGES_DIR / "chm-image-map.json"


# ── Setup hints for each screenshot ───────────────────────────────────────
# These tell the user what to display on screen before capturing.

SETUP_HINTS = {
    "packager-main.png": (
        "Open the Library Packager window.\n"
        "Make sure it is in its default/empty state.\n"
        "Capture the full packager window."
    ),
    "packager-filled.png": (
        "Open the Library Packager and fill in:\n"
        "  - Metadata fields (name, version, author)\n"
        "  - Add some files to the file list\n"
        "Capture the full packager window."
    ),
    "db-folder-structure.png": (
        "Open Windows Explorer to the 'db/' folder\n"
        "in the project directory. Show the folder\n"
        "with all JSON files visible.\n"
        "Capture the Explorer window or tree view."
    ),
    "delete-confirmation-dialog.png": (
        "Trigger a library deletion so the\n"
        "confirmation dialog appears.\n"
        "Capture just the dialog."
    ),
    "export-choice-modal.png": (
        "Click Export on a library to open the\n"
        "export choice modal.\n"
        "Capture just the modal dialog."
    ),
    "export-button-detail-modal.png": (
        "Open a library's detail modal and\n"
        "make sure the Export button is visible.\n"
        "Capture the detail modal showing the button."
    ),
    "export-choice-with-deps.png": (
        "Open the export modal for a library that\n"
        "has dependencies listed.\n"
        "Capture the modal showing dependency list."
    ),
    "archive-export-modal.png": (
        "Open the archive export modal showing\n"
        "library checkboxes for bulk export.\n"
        "Capture the full modal."
    ),
    "main-window.png": (
        "Show the Venus Library Manager main window\n"
        "in its normal state with some libraries visible.\n"
        "Capture the entire application window."
    ),
    "main-window-labeled.png": (
        "Show the main window. You'll annotate this\n"
        "later with labels for Sidebar, Card Area, Tabs.\n"
        "Capture the entire application window."
    ),
    "navigation-tabs.png": (
        "Focus on the navigation tabs at the top\n"
        "of the main window.\n"
        "Capture just the tab bar area."
    ),
    "library-card-annotated.png": (
        "Show a single library card clearly.\n"
        "You'll annotate parts later.\n"
        "Capture one library card with some padding."
    ),
    "library-detail-modal.png": (
        "Click on a library to open its detail modal.\n"
        "Make sure all info is visible.\n"
        "Capture the full modal."
    ),
    "import-preview-modal.png": (
        "Start importing a .hslpkg file.\n"
        "The preview modal should show metadata\n"
        "and signature status.\n"
        "Capture the full preview modal."
    ),
    "settings-panel.png": (
        "Open the Settings panel.\n"
        "Make sure all settings sections are visible.\n"
        "Capture the full settings view."
    ),
    "overflow-menu.png": (
        "Click the overflow menu (⋯ or ☰) button.\n"
        "Make sure all menu items are visible.\n"
        "Capture the dropdown menu."
    ),
    "event-history-modal.png": (
        "Open the Event History modal.\n"
        "Make sure filters and event list are visible.\n"
        "Capture the full modal."
    ),
    "import-success-modal.png": (
        "Complete a library import so the success\n"
        "modal appears.\n"
        "Capture the success dialog."
    ),
    "group-create.png": (
        "Open Settings → Groups section.\n"
        "Show the group creation interface.\n"
        "Capture the group creation area."
    ),
    "group-drag-drop.png": (
        "Open Settings → Groups and show the\n"
        "drag-and-drop interface for assigning\n"
        "libraries to groups.\n"
        "Capture the drag-drop area."
    ),
    "venus-shortcuts-sidebar.png": (
        "Show the VENUS application with the\n"
        "tool shortcuts visible in the sidebar.\n"
        "Capture the sidebar area."
    ),
    "integrity-error-card.png": (
        "Show a library card that has an integrity\n"
        "error (red/warning styling).\n"
        "Capture the affected library card."
    ),
    "verify-repair-modal.png": (
        "Open the Verify & Repair modal showing\n"
        "library status list.\n"
        "Capture the full modal."
    ),
    "audit-verify-result.png": (
        "Run a library audit and show the\n"
        "verification result dialog.\n"
        "Capture the result dialog."
    ),
    "search-bar-chips.png": (
        "Click in the search bar and add some\n"
        "tag and author filter chips.\n"
        "Capture the search bar with chips visible."
    ),
    "search-autocomplete.png": (
        "Start typing in the search bar so the\n"
        "autocomplete dropdown appears with suggestions.\n"
        "Capture the search bar + dropdown."
    ),
    "splash-screen.png": (
        "Launch the application to show the splash screen\n"
        "with the animated logo and status text.\n"
        "Capture the splash screen."
    ),
    "success-dialog.png": (
        "Trigger any action that shows a success dialog\n"
        "(green checkmark with details).\n"
        "Capture the success dialog."
    ),
    "unsigned-settings.png": (
        "Open Settings and scroll to the unsigned\n"
        "libraries section showing checkboxes\n"
        "and the Scan button.\n"
        "Capture that settings section."
    ),
    "unsigned-library-cards.png": (
        "Show the main screen with unsigned library\n"
        "cards visible (different styling).\n"
        "Capture the card area."
    ),
    "unsigned-detail-modal.png": (
        "Open an unsigned library's detail/edit modal.\n"
        "Capture the full modal."
    ),
    "cached-versions-list.png": (
        "Open a library detail modal and scroll to\n"
        "the cached versions list.\n"
        "Capture the versions section."
    ),
    "rollback-confirmation.png": (
        "Click rollback on a version to show the\n"
        "rollback confirmation dialog.\n"
        "Capture the confirmation dialog."
    ),
    "composited-icon-example.png": (
        "Show an example of a composited package icon\n"
        "with the logo overlay.\n"
        "Capture the icon area or a clear view of it."
    ),
}


# ── Region Selector Overlay ───────────────────────────────────────────────

class RegionSelector:
    """Full-screen transparent overlay for selecting a screen region."""

    def __init__(self, on_complete, on_cancel):
        self.on_complete = on_complete
        self.on_cancel = on_cancel
        self.start_x = 0
        self.start_y = 0
        self.rect_id = None

        # Get full virtual screen geometry using mss
        with mss.mss() as sct:
            monitors = sct.monitors
            # monitors[0] is the combined virtual screen
            self.vscreen = monitors[0]

        self.root = tk.Toplevel()
        self.root.title("Select Region")
        self.root.attributes("-fullscreen", True)
        self.root.attributes("-topmost", True)
        self.root.attributes("-alpha", 0.3)
        self.root.configure(bg="black")

        # Position to cover virtual screen
        self.root.geometry(
            f"{self.vscreen['width']}x{self.vscreen['height']}"
            f"+{self.vscreen['left']}+{self.vscreen['top']}"
        )

        self.canvas = tk.Canvas(
            self.root,
            cursor="crosshair",
            bg="black",
            highlightthickness=0,
        )
        self.canvas.pack(fill=tk.BOTH, expand=True)

        # Instructions
        self.canvas.create_text(
            self.vscreen["width"] // 2,
            40,
            text="Click and drag to select the screenshot region  •  Press Escape to cancel",
            fill="white",
            font=("Segoe UI", 16, "bold"),
        )

        self.canvas.bind("<ButtonPress-1>", self._on_press)
        self.canvas.bind("<B1-Motion>", self._on_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)
        self.root.bind("<Escape>", self._on_escape)

    def _on_press(self, event):
        self.start_x = event.x + self.vscreen["left"]
        self.start_y = event.y + self.vscreen["top"]
        if self.rect_id:
            self.canvas.delete(self.rect_id)
        self.rect_id = self.canvas.create_rectangle(
            event.x, event.y, event.x, event.y,
            outline="red", width=2
        )

    def _on_drag(self, event):
        if self.rect_id:
            sx = self.start_x - self.vscreen["left"]
            sy = self.start_y - self.vscreen["top"]
            self.canvas.coords(self.rect_id, sx, sy, event.x, event.y)

    def _on_release(self, event):
        end_x = event.x + self.vscreen["left"]
        end_y = event.y + self.vscreen["top"]

        x1 = min(self.start_x, end_x)
        y1 = min(self.start_y, end_y)
        x2 = max(self.start_x, end_x)
        y2 = max(self.start_y, end_y)

        width = x2 - x1
        height = y2 - y1

        self.root.destroy()

        if width < 10 or height < 10:
            self.on_cancel()
            return

        # Capture the region
        region = {"left": x1, "top": y1, "width": width, "height": height}
        with mss.mss() as sct:
            screenshot = sct.grab(region)
            img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")

        self.on_complete(img)

    def _on_escape(self, event):
        self.root.destroy()
        self.on_cancel()


# ── Main Application ──────────────────────────────────────────────────────

class ScreenshotApp:
    """Main GUI for guided screenshot capture."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CHM Documentation Screenshot Tool")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        self.root.configure(bg="#1e1e1e")

        # Load image map
        if not MAP_FILE.exists():
            messagebox.showerror(
                "Missing Map",
                f"Cannot find:\n{MAP_FILE}\n\nRun 'node scripts/chm-image-placeholders.js scan' first.",
            )
            sys.exit(1)

        with open(MAP_FILE, "r", encoding="utf-8") as f:
            self.image_map = json.load(f)

        # Build task list: list of (placeholder_text, image_filename, html_file)
        self.tasks = []
        for text, info in self.image_map.items():
            img_name = info.get("image", "")
            html_file = info.get("file", "")
            if img_name:
                self.tasks.append((text, img_name, html_file))

        # Deduplicate by image filename (some placeholders share images)
        seen = set()
        unique_tasks = []
        for text, img, html in self.tasks:
            if img not in seen:
                seen.add(img)
                unique_tasks.append((text, img, html))
        self.tasks = unique_tasks

        self.current_index = 0
        self.preview_photo = None  # keep reference for Tk

        self._build_ui()
        self._refresh_list()
        self._select_task(0)

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Dark theme colors
        BG = "#1e1e1e"
        FG = "#d4d4d4"
        ACCENT = "#0078d4"
        CARD_BG = "#2d2d2d"
        SUCCESS = "#4ec9b0"
        WARNING = "#ce9178"

        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
        style.configure("Header.TLabel", background=BG, foreground=FG, font=("Segoe UI", 14, "bold"))
        style.configure("Status.TLabel", background=BG, foreground=ACCENT, font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10))
        style.configure("Capture.TButton", font=("Segoe UI", 12, "bold"))
        style.configure("Treeview", background=CARD_BG, foreground=FG, fieldbackground=CARD_BG,
                         font=("Segoe UI", 9), rowheight=28)
        style.configure("Treeview.Heading", background="#333", foreground=FG,
                         font=("Segoe UI", 9, "bold"))

        # ── Left panel: task list ──
        left = ttk.Frame(self.root, width=340)
        left.pack(side=tk.LEFT, fill=tk.BOTH, padx=(8, 4), pady=8)
        left.pack_propagate(False)

        ttk.Label(left, text="Screenshots To Capture", style="Header.TLabel").pack(anchor="w", pady=(0, 4))

        self.status_label = ttk.Label(left, text="", style="Status.TLabel")
        self.status_label.pack(anchor="w", pady=(0, 6))

        # Filter buttons
        filter_frame = ttk.Frame(left)
        filter_frame.pack(fill=tk.X, pady=(0, 4))

        self.filter_var = tk.StringVar(value="all")
        for val, label in [("all", "All"), ("missing", "Missing"), ("done", "Done")]:
            rb = ttk.Radiobutton(filter_frame, text=label, variable=self.filter_var,
                                  value=val, command=self._refresh_list)
            rb.pack(side=tk.LEFT, padx=(0, 8))

        # Treeview
        tree_frame = ttk.Frame(left)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(tree_frame, columns=("status", "file"), show="headings",
                                  selectmode="browse")
        self.tree.heading("status", text="Status")
        self.tree.heading("file", text="Image File")
        self.tree.column("status", width=70, minwidth=50)
        self.tree.column("file", width=220, minwidth=150)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        # Jump-to-next-missing button
        ttk.Button(left, text="▶  Next Missing", command=self._jump_next_missing).pack(
            fill=tk.X, pady=(6, 0)
        )

        # ── Right panel: details + capture ──
        right = ttk.Frame(self.root)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 8), pady=8)

        # Title
        self.title_label = ttk.Label(right, text="Select a screenshot", style="Header.TLabel",
                                      wraplength=500)
        self.title_label.pack(anchor="w", pady=(0, 2))

        # HTML file
        self.file_label = ttk.Label(right, text="", foreground="#808080")
        self.file_label.pack(anchor="w", pady=(0, 8))

        # Instructions card
        instr_frame = tk.Frame(right, bg=CARD_BG, bd=1, relief="solid", padx=12, pady=10)
        instr_frame.pack(fill=tk.X, pady=(0, 8))

        tk.Label(instr_frame, text="📋  Setup Instructions", bg=CARD_BG, fg=ACCENT,
                 font=("Segoe UI", 11, "bold"), anchor="w").pack(anchor="w")

        self.instructions_text = tk.Text(
            instr_frame, bg=CARD_BG, fg=FG, font=("Segoe UI", 10),
            wrap=tk.WORD, height=6, bd=0, highlightthickness=0,
            padx=4, pady=4, state=tk.DISABLED
        )
        self.instructions_text.pack(fill=tk.X, pady=(4, 0))

        # Capture controls
        ctrl_frame = ttk.Frame(right)
        ctrl_frame.pack(fill=tk.X, pady=(0, 8))

        # Delay selector
        delay_frame = ttk.Frame(ctrl_frame)
        delay_frame.pack(side=tk.LEFT)

        ttk.Label(delay_frame, text="Delay:").pack(side=tk.LEFT, padx=(0, 4))
        self.delay_var = tk.IntVar(value=3)
        delay_spin = ttk.Spinbox(delay_frame, from_=0, to=15, textvariable=self.delay_var,
                                  width=3, font=("Segoe UI", 10))
        delay_spin.pack(side=tk.LEFT)
        ttk.Label(delay_frame, text="sec").pack(side=tk.LEFT, padx=(2, 0))

        # Capture button
        self.capture_btn = ttk.Button(
            ctrl_frame, text="📸  Capture Region", style="Capture.TButton",
            command=self._start_capture
        )
        self.capture_btn.pack(side=tk.RIGHT)

        # Full-window capture button
        self.fullscreen_btn = ttk.Button(
            ctrl_frame, text="🖥  Capture Full Screen",
            command=self._capture_fullscreen
        )
        self.fullscreen_btn.pack(side=tk.RIGHT, padx=(0, 6))

        # Countdown label
        self.countdown_label = ttk.Label(right, text="", font=("Segoe UI", 24, "bold"),
                                          foreground=WARNING)
        self.countdown_label.pack(pady=(0, 4))

        # Preview area
        preview_frame = tk.Frame(right, bg=CARD_BG, bd=1, relief="solid")
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        tk.Label(preview_frame, text="Preview", bg=CARD_BG, fg="#808080",
                 font=("Segoe UI", 9)).pack(anchor="w", padx=8, pady=(4, 0))

        self.preview_label = tk.Label(preview_frame, bg=CARD_BG, text="No preview yet",
                                       fg="#555", font=("Segoe UI", 10))
        self.preview_label.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Bottom buttons
        bottom = ttk.Frame(right)
        bottom.pack(fill=tk.X)

        self.save_status = ttk.Label(bottom, text="", foreground=SUCCESS)
        self.save_status.pack(side=tk.LEFT)

        ttk.Button(bottom, text="Open Images Folder",
                    command=lambda: os.startfile(str(IMAGES_DIR))).pack(side=tk.RIGHT)

    # ── List management ──

    def _get_status(self, img_name):
        img_path = IMAGES_DIR / img_name
        return "✅ Done" if img_path.exists() else "❌ Missing"

    def _refresh_list(self):
        self.tree.delete(*self.tree.get_children())

        total = len(self.tasks)
        done = sum(1 for _, img, _ in self.tasks if (IMAGES_DIR / img).exists())
        missing = total - done

        self.status_label.config(
            text=f"{done}/{total} captured  •  {missing} remaining"
        )

        filter_val = self.filter_var.get()
        for i, (text, img, html) in enumerate(self.tasks):
            status = self._get_status(img)
            if filter_val == "missing" and "Done" in status:
                continue
            if filter_val == "done" and "Missing" in status:
                continue
            self.tree.insert("", tk.END, iid=str(i), values=(status, img))

    def _on_tree_select(self, event):
        sel = self.tree.selection()
        if sel:
            idx = int(sel[0])
            self._select_task(idx)

    def _select_task(self, index):
        if index < 0 or index >= len(self.tasks):
            return
        self.current_index = index
        text, img, html = self.tasks[index]

        # Clean up placeholder text for display
        display_text = text.replace("PLACE IMAGE OF ", "").replace(" HERE", "")
        self.title_label.config(text=display_text)
        self.file_label.config(text=f"📄 {html}  →  images/{img}")

        # Instructions
        hint = SETUP_HINTS.get(img, f"Set up the application to show:\n{display_text}\nThen capture the relevant region.")
        self.instructions_text.config(state=tk.NORMAL)
        self.instructions_text.delete("1.0", tk.END)
        self.instructions_text.insert(tk.END, hint)
        self.instructions_text.config(state=tk.DISABLED)

        # Preview existing image
        self._load_preview(img)

        # Update save status
        if (IMAGES_DIR / img).exists():
            self.save_status.config(text=f"✅ {img} exists (capture again to replace)")
        else:
            self.save_status.config(text="")

        # Clear countdown
        self.countdown_label.config(text="")

    def _load_preview(self, img_name):
        img_path = IMAGES_DIR / img_name
        if img_path.exists():
            try:
                img = Image.open(img_path)
                # Scale to fit preview area
                max_w, max_h = 500, 300
                img.thumbnail((max_w, max_h), Image.LANCZOS)
                self.preview_photo = ImageTk.PhotoImage(img)
                self.preview_label.config(image=self.preview_photo, text="")
            except Exception:
                self.preview_label.config(image="", text="Could not load preview")
                self.preview_photo = None
        else:
            self.preview_label.config(image="", text="No image captured yet")
            self.preview_photo = None

    def _jump_next_missing(self):
        # Find next missing starting from current
        for offset in range(len(self.tasks)):
            idx = (self.current_index + offset) % len(self.tasks)
            _, img, _ = self.tasks[idx]
            if not (IMAGES_DIR / img).exists():
                self._select_task(idx)
                # Select in tree
                iid = str(idx)
                if self.tree.exists(iid):
                    self.tree.selection_set(iid)
                    self.tree.see(iid)
                return
        messagebox.showinfo("All Done!", "All screenshots have been captured! 🎉")

    # ── Capture ──

    def _start_capture(self):
        delay = self.delay_var.get()
        if delay > 0:
            self.capture_btn.config(state=tk.DISABLED)
            self.fullscreen_btn.config(state=tk.DISABLED)
            self._countdown(delay)
        else:
            self._do_region_capture()

    def _countdown(self, remaining):
        if remaining > 0:
            self.countdown_label.config(text=f"Capturing in {remaining}...")
            self.root.after(1000, self._countdown, remaining - 1)
        else:
            self.countdown_label.config(text="Select region now!")
            self.root.after(200, self._do_region_capture)

    def _do_region_capture(self):
        # Minimize main window so it's not in the way
        self.root.withdraw()
        self.root.after(400, self._show_overlay)

    def _show_overlay(self):
        RegionSelector(
            on_complete=self._on_capture_complete,
            on_cancel=self._on_capture_cancel,
        )

    def _on_capture_complete(self, img: Image.Image):
        self.root.deiconify()
        self.capture_btn.config(state=tk.NORMAL)
        self.fullscreen_btn.config(state=tk.NORMAL)
        self.countdown_label.config(text="")

        _, img_name, _ = self.tasks[self.current_index]
        save_path = IMAGES_DIR / img_name

        # Ensure directory exists
        IMAGES_DIR.mkdir(parents=True, exist_ok=True)

        # Save
        img.save(str(save_path), "PNG", optimize=True)

        self.save_status.config(text=f"✅ Saved: {img_name}")
        self._load_preview(img_name)
        self._refresh_list()

        # Re-select current in tree
        iid = str(self.current_index)
        if self.tree.exists(iid):
            self.tree.selection_set(iid)

    def _on_capture_cancel(self):
        self.root.deiconify()
        self.capture_btn.config(state=tk.NORMAL)
        self.fullscreen_btn.config(state=tk.NORMAL)
        self.countdown_label.config(text="")

    def _capture_fullscreen(self):
        delay = self.delay_var.get()
        if delay > 0:
            self.capture_btn.config(state=tk.DISABLED)
            self.fullscreen_btn.config(state=tk.DISABLED)
            self._countdown_fullscreen(delay)
        else:
            self._do_fullscreen_capture()

    def _countdown_fullscreen(self, remaining):
        if remaining > 0:
            self.countdown_label.config(text=f"Full-screen in {remaining}...")
            self.root.after(1000, self._countdown_fullscreen, remaining - 1)
        else:
            self.countdown_label.config(text="Capturing...")
            self.root.after(200, self._do_fullscreen_capture)

    def _do_fullscreen_capture(self):
        self.root.withdraw()
        self.root.after(500, self._grab_fullscreen)

    def _grab_fullscreen(self):
        with mss.mss() as sct:
            # Capture primary monitor (monitors[1])
            monitor = sct.monitors[1]
            screenshot = sct.grab(monitor)
            img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")

        self._on_capture_complete(img)

    # ── Run ──

    def run(self):
        # Jump to first missing on startup
        self.root.after(100, self._jump_next_missing)
        self.root.mainloop()


# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = ScreenshotApp()
    app.run()
