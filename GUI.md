# Desktop GUI

MR OSINT Toolkit includes a lightweight desktop interface built with Python's standard-library Tkinter. It works on Windows, macOS, and Linux and runs the existing command-line checks locally; it does not add a web server or additional OSINT providers.

## Start the GUI

From the repository directory, install the toolkit requirements and launch:

```bash
python -m pip install -r requirements.txt
python gui.py
```

On some Linux distributions, Tkinter is packaged separately from Python. If the GUI reports that `tkinter` is missing, install your distribution's Python Tk package (for example, `python3-tk` on Debian/Ubuntu), then retry. Python installers for Windows and macOS generally offer Tkinter as an included component.

The GUI provides tabs for all current CLI commands: username, IP, email, phone, website red-flag checks, candidate reports, and dependency/provider health. It runs checks in the background so the window remains responsive. Candidate report generation requires confirming that you have permission to verify the candidate-provided links.

## New feature: save check output

After a check completes, select **Save output…** to save its displayed CLI output to a local `.txt` file. Saving is opt-in; results are not uploaded or stored by the GUI. Candidate checks also create the existing HTML report in the repository directory, as described by the CLI.

The GUI is an interface to the existing toolkit, not a guarantee of accuracy. Use it for passive, authorized checks only. Third-party services may rate-limit requests, and results should be independently reviewed.
