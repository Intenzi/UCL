import os
import tkinter as tk
import traceback
from tkinter import filedialog, scrolledtext, messagebox, ttk

from threading import Thread

from Server.ucl import UCLGenerator


class UCLGeneratorGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Unified Code Language Generator")
        self.geometry("900x700")

        self.create_widgets()

        # Initialize UCL Generator
        self.generator = None
        self.init_generator_thread = Thread(target=self.init_generator)
        self.init_generator_thread.daemon = True
        self.init_generator_thread.start()

    def init_generator(self):
        """Initialize the UCL generator in a background thread."""
        try:
            self.log_message("Initializing parsers and queries, please wait...")
            self.generator = UCLGenerator(logger=self.log_message)
            self.log_message("Initialization complete. Ready to analyze code.")
            self.toggle_buttons(True)
        except Exception as e:
            self.log_message(f"Error initializing UCL generator: {e}")
            self.log_message(traceback.format_exc())

    def create_widgets(self):
        """Create GUI widgets."""
        # Main frame
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Input")
        input_frame.pack(fill=tk.X, pady=5)

        # Repository URL
        ttk.Label(input_frame, text="GitHub Repository URL:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.repo_url = ttk.Entry(input_frame, width=60)
        self.repo_url.grid(row=0, column=1, sticky=tk.W + tk.E, padx=5, pady=5)

        # OR label
        ttk.Label(input_frame, text="OR").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)

        # Local directory
        ttk.Label(input_frame, text="Local Directory:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.local_dir = ttk.Entry(input_frame, width=60)
        self.local_dir.grid(row=2, column=1, sticky=tk.W + tk.E, padx=5, pady=5)
        ttk.Button(input_frame, text="Browse...", command=self.browse_directory).grid(row=2, column=2, padx=5, pady=5)

        # Output file
        ttk.Label(input_frame, text="Output File:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.output_file = ttk.Entry(input_frame, width=60)
        self.output_file.grid(row=3, column=1, sticky=tk.W + tk.E, padx=5, pady=5)
        ttk.Button(input_frame, text="Browse...", command=self.browse_output).grid(row=3, column=2, padx=5, pady=5)

        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)

        self.github_button = ttk.Button(button_frame, text="Analyze GitHub Repo", command=self.analyze_github)
        self.github_button.pack(side=tk.LEFT, padx=5)

        self.local_button = ttk.Button(button_frame, text="Analyze Local Directory", command=self.analyze_local)
        self.local_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(button_frame, text="Clear", command=self.clear_output)
        self.clear_button.pack(side=tk.RIGHT, padx=5)

        self.save_button = ttk.Button(button_frame, text="Save Output", command=self.save_output)
        self.save_button.pack(side=tk.RIGHT, padx=5)

        self.copy_button = ttk.Button(button_frame, text="Copy UCL", command=self.copy_ucl)
        self.copy_button.pack(side=tk.LEFT, padx=5)

        # Disable buttons until initialization completes
        self.toggle_buttons(False)

        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)

        # Output section
        output_frame = ttk.LabelFrame(main_frame, text="Output")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Log and output tabs
        self.tabs = ttk.Notebook(output_frame)
        self.tabs.pack(fill=tk.BOTH, expand=True)

        # Log tab
        log_frame = ttk.Frame(self.tabs)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.tabs.add(log_frame, text="Log")

        # Output tab
        output_frame = ttk.Frame(self.tabs)
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.tabs.add(output_frame, text="UCL Output")

        # Status bar
        self.status = ttk.Label(self, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def toggle_buttons(self, enabled):
        """Enable or disable action buttons."""
        state = tk.NORMAL if enabled else tk.DISABLED
        self.github_button['state'] = state
        self.local_button['state'] = state

    def browse_directory(self):
        """Browse for a local directory."""
        directory = filedialog.askdirectory(title="Select Directory")
        if directory:
            self.local_dir.delete(0, tk.END)
            self.local_dir.insert(0, directory)

            # Set default output file based on directory name
            if not self.output_file.get():
                dir_name = os.path.basename(directory)
                self.output_file.delete(0, tk.END)
                self.output_file.insert(0, f"{dir_name}.ucl")

    def browse_output(self):
        """Browse for output file location."""
        filename = filedialog.asksaveasfilename(
            title="Save UCL File",
            defaultextension=".ucl",
            filetypes=[("UCL files", "*.ucl"), ("All files", "*.*")]
        )
        if filename:
            self.output_file.delete(0, tk.END)
            self.output_file.insert(0, filename)

    def log_message(self, message):
        """Add a message to the log."""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.update_idletasks()

    def set_status(self, message):
        """Set status bar message."""
        self.status['text'] = message
        self.update_idletasks()

    def copy_ucl(self):
        """Copy the UCL output to the clipboard."""
        ucl_text = self.output_text.get(1.0, tk.END).strip()
        if ucl_text:
            self.clipboard_clear()
            self.clipboard_append(ucl_text)
            self.log_message("UCL output copied to clipboard")
        else:
            messagebox.showerror("Error", "No UCL output to copy")

    def clear_output(self):
        """Clear the output text."""
        self.output_text.delete(1.0, tk.END)

    def save_output(self):
        """Save the current output to a file."""
        if not self.output_text.get(1.0, tk.END).strip():
            messagebox.showerror("Error", "No output to save")
            return

        filename = filedialog.asksaveasfilename(
            title="Save UCL File",
            defaultextension=".ucl",
            filetypes=[("UCL files", "*.ucl"), ("All files", "*.*")]
        )

        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.output_text.get(1.0, tk.END))
            self.log_message(f"Output saved to {filename}")

    def analyze_github(self):
        """Analyze a GitHub repository."""
        repo_url = self.repo_url.get().strip()
        if not repo_url:
            messagebox.showerror("Error", "Please enter a GitHub repository URL")
            return

        output_file = self.output_file.get().strip()

        # Start processing in a separate thread
        self.toggle_buttons(False)
        self.progress.start()
        self.set_status("Analyzing GitHub repository...")

        def process():
            try:
                ucl_output = self.generator.generate_ucl_from_github(repo_url, output_file)
                self.update_output(ucl_output)
                self.log_message("GitHub repository analysis complete")
                self.set_status("Ready")
            except Exception as e:
                self.log_message(f"Error analyzing repository: {e}")
                self.log_message(traceback.format_exc())
                self.set_status("Error")
                messagebox.showerror("Error", f"Failed to analyze repository: {e}")
            finally:
                self.toggle_buttons(True)
                self.progress.stop()

        thread = Thread(target=process)
        thread.daemon = True
        thread.start()

    def analyze_local(self):
        """Analyze a local directory."""
        local_dir = self.local_dir.get().strip()
        if not local_dir:
            messagebox.showerror("Error", "Please select a local directory")
            return

        if not os.path.isdir(local_dir):
            messagebox.showerror("Error", f"Directory '{local_dir}' does not exist")
            return

        output_file = self.output_file.get().strip()

        # Start processing in a separate thread
        self.toggle_buttons(False)
        self.progress.start()
        self.set_status("Analyzing local directory...")

        def process():
            try:
                ucl_output = self.generator.generate_ucl_from_local(local_dir, output_file)
                self.update_output(ucl_output)
                self.log_message("Local directory analysis complete")
                self.set_status("Ready")
            except Exception as e:
                self.log_message(f"Error analyzing directory: {e}")
                self.log_message(traceback.format_exc())
                self.set_status("Error")
                messagebox.showerror("Error", f"Failed to analyze directory: {e}")
            finally:
                self.toggle_buttons(True)
                self.progress.stop()

        thread = Thread(target=process)
        thread.daemon = True
        thread.start()

    def update_output(self, ucl_output):
        """Update the output text area with UCL output."""
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, ucl_output)
        self.tabs.select(1)  # Switch to UCL Output tab

    def on_closing(self):
        """Handle window closing."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.destroy()


if __name__ == "__main__":
    app = UCLGeneratorGUI()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
