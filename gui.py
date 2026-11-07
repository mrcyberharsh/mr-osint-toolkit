#!/usr/bin/env python3
"""Cross-platform desktop interface for the MR OSINT Toolkit.

Uses Python's standard-library Tkinter and runs the existing CLI commands locally.
"""
from __future__ import annotations

import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_DIR = Path(__file__).resolve().parent
CLI_PATH = APP_DIR / "mr_osint_toolkit.py"


class ToolkitGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("MR OSINT Toolkit")
        self.geometry("850x650")
        self.minsize(680, 500)
        self._running = False
        self._outputs: dict[str, tk.Text] = {}
        self._run_buttons: list[ttk.Button] = []
        self._save_buttons: dict[str, ttk.Button] = {}

        header = ttk.Frame(self, padding=(16, 14, 16, 8))
        header.pack(fill="x")
        ttk.Label(header, text="MR OSINT Toolkit", font=("TkDefaultFont", 18, "bold")).pack(anchor="w")
        ttk.Label(
            header,
            text="Local, passive checks only. Results depend on public services and are not proof of identity or wrongdoing.",
            wraplength=800,
        ).pack(anchor="w", pady=(4, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        self._add_simple_tab("Username", "username", [("Username", "username")])
        self._add_simple_tab("IP metadata", "ip", [("IP address", "ip")])
        self._add_simple_tab("Email", "email", [("Email address", "email")])
        self._add_simple_tab("Phone", "phone", [("Phone number (include country code)", "number")])
        self._add_simple_tab("Website red flags", "scamcheck", [("Domain or URL", "target")])
        self._add_candidate_tab()
        self._add_simple_tab("Health", "health", [])

        self.status = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w", padding=(8, 4)).pack(fill="x", side="bottom")

    def _add_output(self, parent: ttk.Frame, name: str) -> tk.Text:
        output_frame = ttk.LabelFrame(parent, text="Output", padding=8)
        output_frame.pack(fill="both", expand=True, pady=(12, 0))
        output = tk.Text(output_frame, height=12, wrap="word", state="disabled", undo=False)
        scrollbar = ttk.Scrollbar(output_frame, orient="vertical", command=output.yview)
        output.configure(yscrollcommand=scrollbar.set)
        output.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self._outputs[name] = output
        return output

    def _add_simple_tab(self, title: str, command: str, fields: list[tuple[str, str]]) -> None:
        frame = ttk.Frame(self.notebook, padding=14)
        self.notebook.add(frame, text=title)
        entries: dict[str, ttk.Entry] = {}
        for row, (label, key) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=4, padx=(0, 10))
            entry = ttk.Entry(frame)
            entry.grid(row=row, column=1, sticky="ew", pady=4)
            entries[key] = entry
        frame.columnconfigure(1, weight=1)

        controls = ttk.Frame(frame)
        controls.grid(row=len(fields), column=0, columnspan=2, sticky="ew", pady=(10, 0))
        run_button = ttk.Button(controls, text="Run check", command=lambda: self._run(command, [entries[k].get().strip() for _, k in fields], title))
        run_button.pack(side="left")
        self._run_buttons.append(run_button)
        save_button = ttk.Button(controls, text="Save output…", command=lambda: self._save(title), state="disabled")
        save_button.pack(side="left", padx=(8, 0))
        self._save_buttons[title] = save_button

        if command == "health":
            run_button.configure(text="Run health check")
            ttk.Label(frame, text="Checks optional dependencies and public provider connectivity.", wraplength=700).grid(row=0, column=0, columnspan=2, sticky="w")
        self._add_output(frame, title)

    def _add_candidate_tab(self) -> None:
        title = "Candidate report"
        frame = ttk.Frame(self.notebook, padding=14)
        self.notebook.add(frame, text=title)
        fields: dict[str, ttk.Entry] = {}
        for row, (label, key) in enumerate([
            ("Candidate name", "name"),
            ("GitHub username (optional)", "github"),
            ("Portfolio URL (optional)", "portfolio"),
        ]):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=4, padx=(0, 10))
            entry = ttk.Entry(frame)
            entry.grid(row=row, column=1, sticky="ew", pady=4)
            fields[key] = entry

        ttk.Label(frame, text="Candidate-supplied certificate URLs (one per line)").grid(row=3, column=0, sticky="nw", pady=4, padx=(0, 10))
        certs = tk.Text(frame, height=3, wrap="word")
        certs.grid(row=3, column=1, sticky="ew", pady=4)
        consent = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            frame,
            text="I have permission to verify links voluntarily supplied for this application.",
            variable=consent,
            wraplength=600,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(6, 2))
        frame.columnconfigure(1, weight=1)

        controls = ttk.Frame(frame)
        controls.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(8, 0))

        def run_candidate() -> None:
            name = fields["name"].get().strip()
            if not name:
                messagebox.showerror("Missing candidate name", "Enter a candidate name to create the report.", parent=self)
                return
            if not consent.get():
                messagebox.showwarning("Permission required", "Only verify candidate-provided links with permission.", parent=self)
                return
            args = ["--name", name]
            for key in ("github", "portfolio"):
                value = fields[key].get().strip()
                if value:
                    args.extend([f"--{key}", value])
            for value in certs.get("1.0", "end").splitlines():
                value = value.strip()
                if value:
                    args.extend(["--cert", value])
            self._run("candidate", args, title)

        run_button = ttk.Button(controls, text="Generate report", command=run_candidate)
        run_button.pack(side="left")
        self._run_buttons.append(run_button)
        save_button = ttk.Button(controls, text="Save output…", command=lambda: self._save(title), state="disabled")
        save_button.pack(side="left", padx=(8, 0))
        self._save_buttons[title] = save_button
        ttk.Label(frame, text="A local HTML report is created by the CLI. This tab displays its command output.", wraplength=700).grid(row=6, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self._add_output(frame, title)

    def _run(self, command: str, args: list[str], title: str) -> None:
        if command != "health" and any(not value for value in args):
            messagebox.showerror("Missing input", "Fill in the required field before running this check.", parent=self)
            return
        if self._running:
            return
        self._running = True
        for button in self._run_buttons:
            button.configure(state="disabled")
        self.status.set(f"Running {title}…")
        output = self._outputs[title]
        output.configure(state="normal")
        output.delete("1.0", "end")
        output.insert("end", "Running locally…\n")
        output.configure(state="disabled")
        threading.Thread(target=self._worker, args=(command, args, title), daemon=True).start()

    def _worker(self, command: str, args: list[str], title: str) -> None:
        try:
            completed = subprocess.run(
                [sys.executable, str(CLI_PATH), command, *args],
                cwd=APP_DIR,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
            text = (completed.stdout or "") + (completed.stderr or "")
            if not text.strip():
                text = f"Command finished with exit code {completed.returncode}; no output was produced."
            if completed.returncode:
                text += f"\n\nExit code: {completed.returncode}"
            status = "Finished" if completed.returncode == 0 else f"Finished with exit code {completed.returncode}"
        except subprocess.TimeoutExpired:
            text, status = "The check exceeded the 5-minute time limit and was stopped.", "Timed out"
        except OSError as exc:
            text, status = f"Could not start the toolkit: {exc}", "Could not start"
        self.after(0, self._finish, title, text, status)

    def _finish(self, title: str, text: str, status: str) -> None:
        output = self._outputs[title]
        output.configure(state="normal")
        output.delete("1.0", "end")
        output.insert("end", text)
        output.configure(state="disabled")
        self._save_buttons[title].configure(state="normal")
        self._running = False
        for button in self._run_buttons:
            button.configure(state="normal")
        self.status.set(status)

    def _save(self, title: str) -> None:
        text = self._outputs[title].get("1.0", "end-1c")
        if not text.strip():
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Save check output",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="mr-osint-output.txt",
        )
        if not path:
            return
        try:
            Path(path).write_text(text, encoding="utf-8")
            self.status.set(f"Output saved to {path}")
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc), parent=self)


if __name__ == "__main__":
    if not CLI_PATH.is_file():
        raise SystemExit("mr_osint_toolkit.py must be in the same directory as gui.py")
    ToolkitGUI().mainloop()
