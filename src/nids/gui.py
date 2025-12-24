import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import psutil
from collections import deque
import os

from nids.main import Main
from nids.helper.other.constants import ROOT_DIR
from nids.anomaly_detector import DetectionResult


PATHS = {
    "Binary Model": os.path.join(ROOT_DIR, 'model/binary_classification/knn_binary.joblib'),
    "Multi-class Model": os.path.join(ROOT_DIR, "model/multi_class_classification/knn_multi_class.joblib"),
    "Scaler": os.path.join(ROOT_DIR, "model/binary_classification/robust_scaler.joblib"),
    "Output CSV": os.path.join(ROOT_DIR, "csv")
}

class gui:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CICFlowMeter - Network Flow Monitor")
        self.root.geometry("700x500")
        self.root.protocol("WM_DELETE_WINDOW", self.exit_app)
        
        self.main: Main = None
        self.capturing = False
        
        # Resource monitoring values
        self.throughput_value = 0
        self.cpu_usage_value = 0
        self.memory_usage_value = 0
        self.packet_count = 0
        self.flow_count = 0
        
        # Performance optimizations
        self.log_queue = deque(maxlen=1000)
        self.last_update_time = 0
        self.update_interval = 0.1  # 100ms for UI updates
        self.resource_update_interval = 1.0  # 1 second for resource updates

        # Model selection
        self.binary_models = {
            'KNN': os.path.join(ROOT_DIR, 'model/binary_classification/knn_binary.joblib'),
            'RF': os.path.join(ROOT_DIR, 'model/binary_classification/rf_binary.joblib'),
            'XGBoost': os.path.join(ROOT_DIR, 'model/binary_classification/xgb_binary.joblib')
        }
        self.multi_class_models = {
            'KNN': os.path.join(ROOT_DIR, 'model/multi_class_classification/knn_multi_class.joblib'),
            'RF': os.path.join(ROOT_DIR, 'model/multi_class_classification/rf_multi_class.joblib'),
            'XGBoost': os.path.join(ROOT_DIR, 'model/multi_class_classification/xgb_multi_class.joblib')
        }
        self.scaler_path = os.path.join(ROOT_DIR, 'model/binary_classification/robust_scaler.joblib')
        self.selected_binary = "KNN"
        self.selected_multi_class = "KNN"
        self.use_scaler = True  # Default to True

        self.setup_gui()
    
    def setup_gui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title and Control Buttons Frame
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Title
        title_label = ttk.Label(header_frame, text="Network Intrusion Detection System", 
                               font=("Segoe UI", 14, "bold"))
        title_label.pack(side=tk.LEFT)
        
        # Control Buttons - positioned at top right
        button_frame = ttk.Frame(header_frame)
        button_frame.pack(side=tk.RIGHT)
        
        # Start Capture Button
        self.start_btn = ttk.Button(
            button_frame,
            text="Start Capture",
            command=self.start_capture,
            width=12
        )
        self.start_btn.pack(side=tk.LEFT, padx=2)

        # Stop Capture Button
        self.stop_btn = ttk.Button(
            button_frame, 
            text="Stop Capture", 
            command=self.stop_capture,
            state="disabled",
            width=12
        )
        self.stop_btn.pack(side=tk.LEFT, padx=2)

        # Clear Log Button
        self.clear_btn = ttk.Button(
            button_frame,
            text="Clear Log",
            command=self.clear_log,
            width=10
        )
        self.clear_btn.pack(side=tk.LEFT, padx=2)
        
        config_frame = ttk.Frame(main_frame)
        config_frame.pack(fill=tk.X, pady=5)
        
        # Network Interface
        ttk.Label(config_frame, text="Interface:").grid(row=0, column=0, sticky="w", padx=(0, 2))
        self.interface_entry = ttk.Entry(config_frame, width=12)
        self.interface_entry.insert(0, "wlan0")
        self.interface_entry.grid(row=0, column=1, sticky="w", padx=(0, 10))

        # Binary Model Selection
        ttk.Label(config_frame, text="Binary Model:").grid(row=0, column=2, sticky="w", padx=(0, 2))
        self.binary_combo = ttk.Combobox(config_frame, values=list(self.binary_models.keys()), state="readonly", width=10)
        self.binary_combo.set(self.selected_binary)
        self.binary_combo.grid(row=0, column=3, sticky="w", padx=(0, 10))

        # Multi-class Model Selection
        ttk.Label(config_frame, text="Multi-class Model:").grid(row=0, column=4, sticky="w", padx=(0, 2))
        self.multi_class_combo = ttk.Combobox(config_frame, values=list(self.multi_class_models.keys()), state="readonly", width=10)
        self.multi_class_combo.set(self.selected_multi_class)
        self.multi_class_combo.grid(row=0, column=5, sticky="w", padx=(0, 10))

        # Scaler Checkbox
        self.scaler_var = tk.BooleanVar(value=self.use_scaler)
        ttk.Checkbutton(config_frame, text="Use Scaler", variable=self.scaler_var).grid(row=0, column=6, sticky="w", padx=(0, 10))
        
        # System Metrics
        metrics_frame = ttk.Frame(main_frame)
        metrics_frame.pack(fill=tk.X, pady=3)
        # CPU Usage
        self.cpu_label = ttk.Label(metrics_frame, text="CPU: --%", font=("Consolas", 9))
        self.cpu_label.pack(side=tk.LEFT, padx=8)
        # Memory Usage
        self.mem_label = ttk.Label(metrics_frame, text="Memory: --%", font=("Consolas", 9))
        self.mem_label.pack(side=tk.LEFT, padx=8)
        # Throughput
        self.throughput_label = ttk.Label(metrics_frame, text="Throughput: -- pkt/s", font=("Consolas", 9))
        self.throughput_label.pack(side=tk.LEFT, padx=8)
        # Packet Count
        self.packet_count_label = ttk.Label(metrics_frame, text="Packet Count: --", font=("Consolas", 9))
        self.packet_count_label.pack(side=tk.LEFT, padx=8)
        # Flow Count (ADD THIS)
        self.flow_count_label = ttk.Label(metrics_frame, text="Flow Count: --", font=("Consolas", 9))
        self.flow_count_label.pack(side=tk.LEFT, padx=8)



        # Log widget with optimized configuration - now gets more space
        log_frame = ttk.LabelFrame(main_frame, text="Detection Log", padding="3")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_widget = scrolledtext.ScrolledText(
            log_frame, 
            bg="black", 
            fg="lime", 
            insertbackground="white",
            font=("Consolas", 9),
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.log_widget.pack(fill=tk.BOTH, expand=True)

        # Quick Access Buttons at bottom
        quick_button_frame = ttk.Frame(main_frame)
        quick_button_frame.pack(fill=tk.X, pady=3)
    
        ttk.Button(
            quick_button_frame,
            text="Clear Log",
            command=self.clear_log,
            width=10
        ).pack(side=tk.RIGHT, padx=2)
        
        ttk.Button(
            quick_button_frame,
            text="Copy Log",
            command=self.copy_log,
            width=10
        ).pack(side=tk.RIGHT, padx=2)

    def copy_log(self):
        """Copy log contents to clipboard."""
        try:
            log_content = self.log_widget.get(1.0, tk.END)
            if log_content.strip():
                self.root.clipboard_clear()
                self.root.clipboard_append(log_content)
                self._update_log_widget("[*] Log copied to clipboard\n")
        except Exception as e:
            self._update_log_widget(f"[ERROR] Failed to copy log: {str(e)}\n")

    def validate_parameters(self):
        """Validate all parameters before starting capture."""
        interface = self.interface_entry.get().strip()
        selected_binary = self.binary_combo.get().strip()
        selected_multi_class = self.multi_class_combo.get().strip()
        
        if not interface:
            self._update_log_widget("[ERROR] Network interface is required\n")
            return False
        
        if not selected_binary or selected_binary not in self.binary_models:
            self._update_log_widget("[ERROR] Valid binary model selection is required\n")
            return False
            
        if not selected_multi_class or selected_multi_class not in self.multi_class_models:
            self._update_log_widget("[ERROR] Valid multi-class model selection is required\n")
            return False
            
        return True
   
    def start_capture(self):
        """Start the NIDS main."""
        if self.capturing:
            return
            
        if not self.validate_parameters():
            return
            
        interface = self.interface_entry.get().strip()
        selected_binary = self.binary_combo.get()
        selected_multi_class = self.multi_class_combo.get()
        use_scaler = self.scaler_var.get()
        
        binary_path = self.binary_models[selected_binary]
        multi_class_path = self.multi_class_models[selected_multi_class]
        scaler_path = self.scaler_path if use_scaler else None
        
        # Disable UI during startup
        self._set_ui_state(False)
            
        try:
            # Create the main with all 5 components
            self.main = Main(
                interface=interface,
                binary_model_path=binary_path,
                multi_class_model_path=multi_class_path,
                scaler_path=scaler_path,
                output_path=PATHS["Output CSV"],
                detection_callback=self._on_detection,
                log_callback=self._update_log_widget
            )
            
            # Start the main
            self.main.start()
            self.capturing = True
            
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            
            self._update_log_widget(f"[*] NIDS started on interface {interface}\n")
            self._update_log_widget(f"[*] Binary model: {selected_binary} ({binary_path})\n")
            self._update_log_widget(f"[*] Multi-class model: {selected_multi_class} ({multi_class_path})\n")
            if use_scaler:
                self._update_log_widget(f"[*] Scaler: {scaler_path}\n")
            else:
                self._update_log_widget("[*] Scaler: Not used\n")
            self._update_log_widget(f"[*] Flow is saved to: {PATHS['Output CSV']}\n")
            self._update_log_widget("[*] Components: Capturer → Parser → Extractor → Mapper → Detector\n")
            
            # Start monitoring thread
            threading.Thread(target=self._monitor_capture, daemon=True).start()
            
        except PermissionError:
            self._update_log_widget("[ERROR] Permission denied. Try running with sudo.\n")
            self._set_ui_state(True)
        except Exception as e:
            self._update_log_widget(f"[ERROR] Failed to start capture: {str(e)}\n")
            self._set_ui_state(True)    

    def _set_ui_state(self, enabled):
        """Enable/disable UI elements."""
        state = "normal" if enabled else "disabled"
        self.start_btn.config(state=state)
        self.interface_entry.config(state=state)
        self.binary_combo.config(state=state)
        self.multi_class_combo.config(state=state)
        # Note: Checkbox can remain enabled even when disabled, but we'll disable it too
        if enabled:
            self.scaler_var.set(self.use_scaler)  # Reset to default if re-enabling


    def _monitor_capture(self):
        """Monitor packet capture and update statistics."""
        last_packet_count = 0
        last_time = time.time()
        
        while self.capturing and self.main:
            try:
                current_time = time.time()
                elapsed = current_time - last_time
                
                if elapsed >= 1.0:
                    # Get current packet count from packet capturer component
                    current_packet_count = self.main.packet_capturer.packets_captured
                    
                    # Calculate throughput
                    packets_diff = current_packet_count - last_packet_count
                    self.throughput_value = int(packets_diff / elapsed)
                    self.packet_count = current_packet_count
                    self.flow_count = self.main.packet_parser.flows_completed
                    
                    # Update for next iteration
                    last_packet_count = current_packet_count
                    last_time = current_time
                    
                    # Update resource usage
                    process = psutil.Process()
                    self.cpu_usage_value = process.cpu_percent(interval=None)
                    self.memory_usage_value = process.memory_info().rss / 1024 / 1024
                
                time.sleep(0.5)
                
            except Exception as e:
                print(f"Error in monitor: {e}")
                break
    
    def _on_detection(self, result: DetectionResult):
        """Callback for detection results from the Anomaly Detector."""
        # Detection logging is handled in the pipeline
        pass

    def stop_capture(self):
        """Stop the NIDS main."""
        if not self.main or not self.capturing:
            return
        
        self.capturing = False
        
        try:
            # Give monitoring thread time to exit
            time.sleep(0.2)
            
            # Stop the main (this flushes all flows)
            self.main.stop()
            
            self._update_log_widget("[!] NIDS stopped\n")
                
        except Exception as e:
            self._update_log_widget(f"[ERROR] Error stopping capture: {str(e)}\n")
        finally:
            self.main = None
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self._set_ui_state(True)

    def _update_log_widget(self, message):
        """Update the log widget with a new message."""
        self.log_widget.config(state=tk.NORMAL)
        self.log_widget.insert(tk.END, message)
        self.log_widget.see(tk.END)
        self.log_widget.config(state=tk.DISABLED)

    def clear_log(self):
        """Clear the log widget."""
        self.log_queue.clear()
        self.log_widget.config(state=tk.NORMAL)
        self.log_widget.delete(1.0, tk.END)
        self.log_widget.config(state=tk.DISABLED)

    def update_system_metrics(self):
        """Update system resource usage displays."""
        try:
            self.cpu_label.config(text=f"CPU: {self.cpu_usage_value:.1f}%")
            self.mem_label.config(text=f"Memory: {self.memory_usage_value:.1f} MB")
            self.throughput_label.config(text=f"Throughput: {self.throughput_value} pkt/s")
            self.packet_count_label.config(text=f"Packets: {self.packet_count}")
            self.flow_count_label.config(text=f"Flows: {self.flow_count}")
            
        except Exception as e:
            print(f"Error updating system metrics: {e}")

    def exit_app(self):
        """Clean exit from application."""
        if self.capturing and self.main:
            self.stop_capture()
        
        if self.root:
            self.root.quit()
            self.root.destroy()

    def run(self):
        """Start the GUI application."""
        def periodic_updates():
            while True:
                try:
                    if not self.root.winfo_exists():
                        break
                    
                    self.root.after(0, self.update_system_metrics)
                    time.sleep(self.resource_update_interval)
                    
                except Exception as e:
                    print(f"Error in periodic updates: {e}")
                    break
        
        threading.Thread(target=periodic_updates, daemon=True).start()
        
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.exit_app()

if __name__ == "__main__":
    app = gui()
    app.run() 
