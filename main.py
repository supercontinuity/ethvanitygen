import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import os
import sys
import threading
import json
from eth_account import Account
from eth_utils import is_checksum_address
from multiprocessing import Process, Value, Queue, Lock, cpu_count, set_start_method, freeze_support
import datetime

# ----------------- Worker Function (Top-Level) ----------------- #
def worker(prefix, suffix, found, queue, attempts, lock):
    """
    Worker function for generating and checking Ethereum addresses.

    Args:
        prefix (str): The desired prefix (e.g., '0xABC').
        suffix (str): The desired suffix (e.g., 'DEF').
        found (Value): Shared value indicating if a match is found.
        queue (Queue): Queue to communicate messages to the GUI.
        attempts (Value): Shared counter for the number of attempts.
        lock (Lock): Lock to synchronize access to shared variables.
    """
    try:
        # Notify that the worker has started
        queue.put(("status", "Worker process started.\n"))
        while not found.value:
            private_key = generate_private_key()
            address = private_key_to_address(private_key)
            
            # Check for prefix and suffix
            if prefix and suffix:
                if address.lower().startswith(prefix.lower()) and address.lower().endswith(suffix.lower()):
                    if is_checksum_address(address):
                        with lock:
                            if not found.value:
                                found.value = 1
                                queue.put(("match_found", (private_key.hex(), address)))
                                break
            elif prefix:
                if address.lower().startswith(prefix.lower()):
                    if is_checksum_address(address):
                        with lock:
                            if not found.value:
                                found.value = 1
                                queue.put(("match_found", (private_key.hex(), address)))
                                break
            elif suffix:
                if address.lower().endswith(suffix.lower()):
                    if is_checksum_address(address):
                        with lock:
                            if not found.value:
                                found.value = 1
                                queue.put(("match_found", (private_key.hex(), address)))
                                break

            with lock:
                attempts.value += 1
                if attempts.value % 10000 == 0:
                    # Send a status update every 10,000 attempts
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    queue.put(("status", f"{timestamp} - {attempts.value} attempts made without a match.\n"))
    except Exception as e:
        # Send exception message back to GUI
        error_message = f"Error in worker process: {str(e)}\n"
        queue.put(("error", error_message))

def generate_private_key():
    """
    Generates a random 256-bit (32-byte) private key.
    """
    return os.urandom(32)

def private_key_to_address(private_key_bytes):
    """
    Converts a private key to its corresponding Ethereum address.
    
    Args:
        private_key_bytes (bytes): The 32-byte private key.
    
    Returns:
        str: The corresponding Ethereum address in checksum format.
    """
    account = Account.from_key(private_key_bytes)
    return account.address

# ----------------- Task Window Class ----------------- #
class TaskWindow(tk.Toplevel):
    def __init__(self, master, task_id):
        super().__init__(master)
        self.title(f"Grind Task #{task_id}")
        self.geometry("800x600")
        self.minsize(700, 500)
        self.resizable(True, True)
        
        # Initialize variables specific to this task
        self.prefix_var = tk.StringVar()
        self.suffix_var = tk.StringVar()
        self.attempts_var = tk.StringVar(value="0")
        self.status_var = tk.StringVar(value="Idle")
        self.process = None
        self.found = None
        self.queue = None
        self.attempts = None
        self.lock = None
        self.log_file_path = None  # Path to log file
        
        # Build GUI
        self.build_gui()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
    def build_gui(self):
        """Construct the GUI layout for the task window."""
        pad_x = 20
        pad_y = 10
        
        # -------------- Input Frame --------------
        input_frame = tk.LabelFrame(self, text="Vanity Address Parameters", padx=20, pady=20)
        input_frame.pack(fill="both", expand="yes", padx=pad_x, pady=pad_y)
        
        # Prefix
        tk.Label(input_frame, text="Prefix (e.g., 0xABC):", font=("Arial", 12)).grid(row=0, column=0, sticky=tk.W, pady=5)
        tk.Entry(input_frame, textvariable=self.prefix_var, width=30, font=("Arial", 12)).grid(row=0, column=1, pady=5)
        
        # Suffix
        tk.Label(input_frame, text="Suffix (e.g., DEF):", font=("Arial", 12)).grid(row=1, column=0, sticky=tk.W, pady=5)
        tk.Entry(input_frame, textvariable=self.suffix_var, width=30, font=("Arial", 12)).grid(row=1, column=1, pady=5)
        
        # Attempts Label
        tk.Label(input_frame, text="Attempts:", font=("Arial", 12)).grid(row=2, column=0, sticky=tk.W, pady=5)
        tk.Label(input_frame, textvariable=self.attempts_var, font=("Arial", 12, "bold")).grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Status Label
        tk.Label(input_frame, text="Status:", font=("Arial", 12)).grid(row=3, column=0, sticky=tk.W, pady=5)
        tk.Label(input_frame, textvariable=self.status_var, font=("Arial", 12, "bold")).grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # -------------- Buttons Frame --------------
        buttons_frame = tk.Frame(self)
        buttons_frame.pack(pady=10)
        
        self.start_button = tk.Button(
            buttons_frame, 
            text="Start Grind", 
            command=self.start_grind, 
            bg="green", 
            fg="white",
            font=("Arial", 12, "bold"),
            width=15
        )
        self.start_button.grid(row=0, column=0, padx=10)
        
        self.stop_button = tk.Button(
            buttons_frame, 
            text="Stop Grinding", 
            command=self.stop_grind, 
            bg="red", 
            fg="white",
            font=("Arial", 12, "bold"),
            width=15,
            state=tk.DISABLED
        )
        self.stop_button.grid(row=0, column=1, padx=10)
        
        # -------------- Progress Bar --------------
        self.progress = ttk.Progressbar(self, mode='indeterminate')
        self.progress.pack(fill="x", padx=pad_x, pady=10)
        self.progress.pack_forget()  # Hide initially
        
        # -------------- Console Output --------------
        console_frame = tk.LabelFrame(self, text="Console Output", padx=20, pady=20)
        console_frame.pack(fill="both", expand="yes", padx=pad_x, pady=pad_y)
        
        self.console_text = tk.Text(console_frame, wrap=tk.WORD, height=10, font=("Courier", 10))
        self.console_text.pack(side=tk.LEFT, fill="both", expand=True)
        
        console_scrollbar = tk.Scrollbar(console_frame, command=self.console_text.yview)
        console_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.console_text['yscrollcommand'] = console_scrollbar.set
        
        # -------------- Wallet Details --------------
        wallet_frame = tk.LabelFrame(self, text="Generated Wallet Details", padx=20, pady=20)
        wallet_frame.pack(fill="both", expand="yes", padx=pad_x, pady=pad_y)
        
        # Private Key
        tk.Label(wallet_frame, text="Private Key:", font=("Arial", 12)).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.private_key_text = tk.Text(wallet_frame, wrap=tk.WORD, height=2, width=50, font=("Courier", 10))
        self.private_key_text.grid(row=0, column=1, pady=5)
        self.private_key_text.config(state=tk.DISABLED)
        
        # Ethereum Address
        tk.Label(wallet_frame, text="Ethereum Address:", font=("Arial", 12)).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.address_text = tk.Text(wallet_frame, wrap=tk.WORD, height=2, width=50, font=("Courier", 10))
        self.address_text.grid(row=1, column=1, pady=5)
        self.address_text.config(state=tk.DISABLED)
        
        # -------------- Logging Options --------------
        logging_frame = tk.LabelFrame(self, text="Logging Options", padx=20, pady=20)
        logging_frame.pack(fill="both", expand="yes", padx=pad_x, pady=pad_y)
        
        self.log_var = tk.BooleanVar()
        self.log_var.set(False)
        log_check = tk.Checkbutton(
            logging_frame, 
            text="Save Logs to File", 
            variable=self.log_var,
            command=self.toggle_log_file,
            font=("Arial", 12)
        )
        log_check.grid(row=0, column=0, sticky=tk.W, pady=5)
        
        self.log_button = tk.Button(
            logging_frame,
            text="Choose Log File",
            command=self.choose_log_file,
            state=tk.DISABLED,
            font=("Arial", 12),
            width=20
        )
        self.log_button.grid(row=0, column=1, padx=10, pady=5)
        
        self.log_file_label = tk.Label(logging_frame, text="", font=("Arial", 10), fg="blue")
        self.log_file_label.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=5)
    
    def toggle_log_file(self):
        """Enable or disable the log file selection button based on the checkbox."""
        if self.log_var.get():
            self.log_button.config(state=tk.NORMAL)
        else:
            self.log_button.config(state=tk.DISABLED)
            self.log_file_path = None
            self.log_file_label.config(text="")
    
    def choose_log_file(self):
        """Open a file dialog for the user to choose where to save logs."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log Files", "*.log"), ("All Files", "*.*")]
        )
        if file_path:
            self.log_file_path = file_path
            self.log_file_label.config(text=f"Logging to: {self.log_file_path}")
    
    def start_grind(self):
        """Start the vanity address grinding process."""
        prefix = self.prefix_var.get().strip()
        suffix = self.suffix_var.get().strip()
        
        # Input Validation: At least one of prefix or suffix must be provided
        if not prefix and not suffix:
            messagebox.showerror("Input Error", "Please enter at least a prefix or a suffix.")
            return
        
        # Further Validation for prefix
        if prefix:
            if not prefix.startswith("0x") or len(prefix) < 3:
                messagebox.showerror("Input Error", "Prefix must start with '0x' and have at least one hexadecimal character after '0x'.")
                return
            if not all(c in '0123456789abcdefABCDEF' for c in prefix[2:]):
                messagebox.showerror("Input Error", "Prefix contains invalid characters. Only hexadecimal characters are allowed after '0x'.")
                return
        
        # Further Validation for suffix
        if suffix:
            if not all(c in '0123456789abcdefABCDEF' for c in suffix):
                messagebox.showerror("Input Error", "Suffix contains invalid characters. Only hexadecimal characters are allowed.")
                return
        
        # Combined Length Validation
        total_length = len(prefix) + len(suffix)
        if total_length > 42:
            messagebox.showerror("Input Error", f"Combined length of prefix and suffix ({total_length} characters) exceeds the maximum allowed (42 characters).")
            return
        
        # Disable Start button and enable Stop button
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Reset attempts and status
        self.attempts_var.set("0")
        self.status_var.set("Grinding...")
        
        # Clear previous wallet details
        self.private_key_text.config(state=tk.NORMAL)
        self.private_key_text.delete("1.0", tk.END)
        self.private_key_text.config(state=tk.DISABLED)
        
        self.address_text.config(state=tk.NORMAL)
        self.address_text.delete("1.0", tk.END)
        self.address_text.config(state=tk.DISABLED)
        
        # Show and start the progress bar
        self.progress.pack(fill="x", padx=20, pady=10)
        self.progress.start(10)
        
        # Initialize shared variables
        self.found = Value('i', 0)
        self.attempts = Value('i', 0)
        self.lock = Lock()
        self.queue = Queue()
        
        # Start the grinding process in a separate process
        self.process = Process(target=worker, args=(prefix, suffix, self.found, self.queue, self.attempts, self.lock))
        self.process.start()
        
        # Start polling the queue
        self.after(100, self.poll_queue)
        
        # Initialize log file if logging is enabled
        if self.log_var.get() and self.log_file_path:
            try:
                self.log_file = open(self.log_file_path, "a")
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.log_file.write(f"{timestamp} - Grinding started with prefix: '{prefix}' and suffix: '{suffix}'\n")
            except Exception as e:
                messagebox.showerror("Logging Error", f"Failed to open log file: {e}")
                self.log_var.set(False)
                self.log_button.config(state=tk.DISABLED)
    
    def stop_grind(self):
        """Stop the vanity address grinding process."""
        if self.process and self.process.is_alive():
            self.found.value = 1  # Signal workers to stop
            self.process.terminate()
            self.process.join()
            self.append_console("Grinding process terminated by user.\n")
            if self.log_var.get() and self.log_file_path:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.log_file.write(f"{timestamp} - Grinding terminated by user.\n")
                self.log_file.close()
        
        # Update UI elements
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("Stopped")
        self.progress.stop()
        self.progress.pack_forget()
    
    def poll_queue(self):
        """Poll the queue for updates from worker processes."""
        while not self.queue.empty():
            msg_type, data = self.queue.get()
            if msg_type == "match_found":
                # Match found
                private_key, address = data
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.append_console(f"\n{timestamp} - Match found!\n")
                self.append_console(f"Private Key: {private_key}\n")
                self.append_console(f"Address: {address}\n\n")
                self.display_wallet_details(private_key, address)
                
                # Log to file if enabled
                if self.log_var.get() and self.log_file_path:
                    self.log_file.write(f"{timestamp} - Match found!\n")
                    self.log_file.write(f"Private Key: {private_key}\n")
                    self.log_file.write(f"Address: {address}\n\n")
                
                # Stop the grinding process
                self.stop_grind()
            elif msg_type == "status":
                # Status update
                self.append_console(data)
                # Update attempts counter if it's a status update about attempts
                if "attempts made without a match" in data.lower():
                    # Extract the number of attempts from the message
                    try:
                        parts = data.split()
                        attempts_made = int(parts[2])
                        self.attempts_var.set(str(attempts_made))
                    except:
                        pass  # Ignore parsing errors
                # Log to file if enabled
                if self.log_var.get() and self.log_file_path:
                    self.log_file.write(data)
            elif msg_type == "error":
                # Error message
                self.append_console(data)
                # Log to file if enabled
                if self.log_var.get() and self.log_file_path:
                    self.log_file.write(data)
                # Stop the grinding process due to error
                self.stop_grind()
        
        # Schedule the next poll
        if self.process and self.process.is_alive():
            self.after(100, self.poll_queue)
        else:
            # Update UI to idle state
            self.status_var.set("Idle")
            self.progress.stop()
            self.progress.pack_forget()
            self.stop_button.config(state=tk.DISABLED)
            self.start_button.config(state=tk.NORMAL)
            if self.log_var.get() and self.log_file_path and hasattr(self, 'log_file'):
                self.log_file.close()
    
    def append_console(self, text):
        """Append text to the console_output_text widget with timestamp."""
        formatted_text = f"{text}"
        self.console_text.config(state=tk.NORMAL)
        self.console_text.insert(tk.END, formatted_text)
        self.console_text.see(tk.END)
        self.console_text.config(state=tk.DISABLED)
        
        # Also write to log file if enabled
        if self.log_var.get() and self.log_file_path and hasattr(self, 'log_file'):
            try:
                self.log_file.write(formatted_text)
            except:
                pass  # Ignore logging errors
    
    def display_wallet_details(self, private_key, address):
        """Display the generated wallet's private key and address."""
        self.private_key_text.config(state=tk.NORMAL)
        self.private_key_text.delete("1.0", tk.END)
        self.private_key_text.insert(tk.END, private_key)
        self.private_key_text.config(state=tk.DISABLED)
        
        self.address_text.config(state=tk.NORMAL)
        self.address_text.delete("1.0", tk.END)
        self.address_text.insert(tk.END, address)
        self.address_text.config(state=tk.DISABLED)
        
        # Also write to log file if enabled
        if self.log_var.get() and self.log_file_path and hasattr(self, 'log_file'):
            try:
                self.log_file.write(f"Private Key: {private_key}\n")
                self.log_file.write(f"Address: {address}\n\n")
            except:
                pass  # Ignore logging errors
        
        # Save to JSON
        self.save_wallet_as_json(private_key, address)
    
    def save_wallet_as_json(self, private_key, address):
        """Save the wallet details to a JSON file."""
        wallet_data = {
            "address": address,
            "private_key": private_key
        }
        
        # Create 'wallets' directory if it doesn't exist
        wallets_dir = "wallets"
        os.makedirs(wallets_dir, exist_ok=True)
        
        # Sanitize the address to create a valid filename
        # Ethereum addresses are already in a safe format (0x followed by hex), but remove '0x' for filename
        sanitized_address = address[2:]
        filename = os.path.join(wallets_dir, f"{sanitized_address}.json")
        
        try:
            with open(filename, 'w') as json_file:
                json.dump(wallet_data, json_file, indent=4)
            self.append_console(f"Wallet details saved to {filename}\n")
        except Exception as e:
            self.append_console(f"Failed to save wallet details to JSON: {str(e)}\n")
            if self.log_var.get() and self.log_file_path:
                self.log_file.write(f"Failed to save wallet details to JSON: {str(e)}\n")
    
    def on_close(self):
        """Handle the window close event with confirmation."""
        if self.process and self.process.is_alive():
            if messagebox.askyesno("Exit Confirmation", "A grinding process is running. Do you want to terminate it and exit?"):
                self.stop_grind()
                self.destroy()
        else:
            if messagebox.askyesno("Exit Confirmation", "Are you sure you want to exit this task?"):
                self.destroy()

# ----------------- Main Application Class ----------------- #
class EthereumVanityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ethereum Vanity Address Generator")
        self.root.geometry("400x200")
        self.root.minsize(400, 200)
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.task_count = 0  # To keep track of the number of tasks
        
        # Build GUI
        self.build_gui()
    
    def build_gui(self):
        """Construct the main GUI layout."""
        pad_x = 20
        pad_y = 20
        
        # New Task Button
        new_task_button = tk.Button(
            self.root,
            text="New Grind Task",
            command=self.open_new_task,
            bg="blue",
            fg="white",
            font=("Arial", 14, "bold"),
            width=20
        )
        new_task_button.pack(padx=pad_x, pady=pad_y)
        
        # Instructions
        instructions = tk.Label(
            self.root,
            text="Click 'New Grind Task' to start a new vanity address generation task.",
            font=("Arial", 12),
            wraplength=350,
            justify=tk.CENTER
        )
        instructions.pack(padx=pad_x, pady=(0, pad_y))
    
    def open_new_task(self):
        """Open a new TaskWindow."""
        self.task_count += 1
        TaskWindow(self.root, self.task_count)
    
    def on_close(self):
        """Handle the main window close event with confirmation."""
        if messagebox.askyesno("Exit Confirmation", "Are you sure you want to exit the application?"):
            self.root.destroy()

# ----------------- Entry Point ----------------- #
def main():
    # Set multiprocessing start method appropriately
    # Important for macOS and Windows
    try:
        set_start_method('spawn')
    except RuntimeError:
        pass  # Start method has already been set
    
    # For Windows compatibility
    freeze_support()
    
    root = tk.Tk()
    app = EthereumVanityApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
