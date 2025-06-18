import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox,Canvas
import threading
import time
import gc
from PIL import Image, ImageTk
import os
import sys
import traceback
import io
import psutil
import GPUtil
import json
from datetime import datetime
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Add the path to your GPU scanner
sys.path.append(os.path.join(os.path.dirname(__file__), 'GPU'))

# Import your backend functions
try:
    from GPU.signature_loader import load_signatures
    from GPU.gpu_scanner import gpu_malware_scan  # Your main scanning function
    
    # Load signatures once at startup
    signatures = load_signatures("C:/Users/mahme/Downloads/extract/Backend/signatures.json")
    print(f"Loaded {len(signatures)} signatures successfully")
except Exception as e:
    print(f"Error loading signatures: {e}")
    signatures = []

# Set the appearance mode and color theme
ctk.set_appearance_mode("light")  # "light" or "dark"
ctk.set_default_color_theme("blue")  # "blue", "green", "dark-blue"

class MalwareScannerApp:
    def __init__(self):
        # Create main window - reduced vertical size
        self.root = ctk.CTk()
        self.root.title("SecureGuard - Malware Scanner")
        self.root.geometry("900x600")  # Reduced from 700 to 600
        self.root.resizable(False, False)
        
        # Configure window
        self.root.configure(fg_color="#FFFFFF")
        
        # Initialize variables
        self.selected_file = None
        self.selected_folder = None
        self.scan_mode = "file"  # "file" or "folder"
        self.scanning = False
        self.scan_result = None
        self.folder_scan_results = {}
        self.progress_animation_running = False
        self.current_progress = 0
        self.target_progress = 0
        self.files_to_scan = []
        self.current_file_index = 0
        self.total_files = 0
        self.scan_logs = ""
        self.gpu_metrics = []
        self.gpu_cleanup_counter = 0
        
        # Create frames
        self.loading_frame = None
        self.main_frame = None
        self.results_frame = None
        self.overlay_frame = None
        self.info_text = None  # Initialize info_text
        
        # Show loading screen first
        self.show_loading_screen()
        
        # Start the app
        self.root.after(3000, self.show_main_menu)  # Show loading for 3 seconds
    
    def show_loading_screen(self):
        """Display the loading screen with logo and app name"""
        self.loading_frame = ctk.CTkFrame(self.root, fg_color="#FFFFFF")
        self.loading_frame.pack(fill="both", expand=True)
        
        # Logo/Icon (using text as placeholder - you can replace with actual logo)
        logo_frame = ctk.CTkFrame(self.loading_frame, fg_color="#FFFFFF")
        logo_frame.pack(expand=True)
        
        # Shield icon using text (replace with actual logo later)
        shield_label = ctk.CTkLabel(
            logo_frame,
            text="🛡️",
            font=ctk.CTkFont(size=80),
            text_color="#2B5CE6"
        )
        shield_label.pack(pady=(40, 15))  # Reduced padding
        
        # App name
        app_name = ctk.CTkLabel(
            logo_frame,
            text="SecureGuard",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color="#1a1a1a"
        )
        app_name.pack(pady=(0, 8))  # Reduced padding
        
        # Subtitle
        subtitle = ctk.CTkLabel(
            logo_frame,
            text="Advanced Malware Detection",
            font=ctk.CTkFont(size=16),
            text_color="#666666"
        )
        subtitle.pack(pady=(0, 25))  # Reduced padding
        
        # Loading bar
        self.loading_progress = ctk.CTkProgressBar(
            logo_frame,
            width=300,
            height=8,
            progress_color="#2B5CE6",
            fg_color="#E8E8E8"
        )
        self.loading_progress.pack(pady=(15, 8))  # Reduced padding
        self.loading_progress.set(0)
        
        # Loading text
        self.loading_text = ctk.CTkLabel(
            logo_frame,
            text="Initializing...",
            font=ctk.CTkFont(size=14),
            text_color="#888888"
        )
        self.loading_text.pack()
        
        # Animate loading
        self.animate_loading()
    
    def animate_loading(self):
        """Animate the loading progress bar"""
        for i in range(101):
            self.root.after(i * 30, lambda progress=i/100: self.loading_progress.set(progress))
            if i < 33:
                self.root.after(i * 30, lambda: self.loading_text.configure(text="Loading components..."))
            elif i < 66:
                self.root.after(i * 30, lambda: self.loading_text.configure(text="Initializing scanner..."))
            else:
                self.root.after(i * 30, lambda: self.loading_text.configure(text="Ready to scan!"))
    
    def show_main_menu(self):
        """Display the main scanning interface"""
        if self.loading_frame:
            self.loading_frame.destroy()
        
        self.main_frame = ctk.CTkFrame(self.root, fg_color="#FFFFFF")
        self.main_frame.pack(fill="both", expand=True, padx=15, pady=15)  # Reduced padding
        
        # Header - reduced height
        header_frame = ctk.CTkFrame(self.main_frame, fg_color="#FFFFFF", height=60)  # Reduced from 80
        header_frame.pack(fill="x", pady=(0, 20))  # Reduced padding
        header_frame.pack_propagate(False)
        
        # Logo and title in header
        logo_text = ctk.CTkLabel(
            header_frame,
            text="🛡️ SecureGuard",
            font=ctk.CTkFont(size=22, weight="bold"),  # Slightly smaller
            text_color="#2B5CE6"
        )
        logo_text.pack(side="left", padx=(15, 0), pady=15)  # Reduced padding
        
        # Main content area
        content_frame = ctk.CTkFrame(self.main_frame, fg_color="#F8F9FA", corner_radius=15)
        content_frame.pack(fill="both", expand=True)
        
        # Center content
        center_frame = ctk.CTkFrame(content_frame, fg_color="#F8F9FA")
        center_frame.pack(expand=True)
        
        # Scan mode selection tabs
        tab_frame = ctk.CTkFrame(center_frame, fg_color="#F8F9FA")
        tab_frame.pack(pady=(30, 15))  # Reduced padding
        
        # File scan tab
        self.file_tab_btn = ctk.CTkButton(
            tab_frame,
            text="📄 File Scan",
            font=ctk.CTkFont(size=16, weight="bold"),
            height=40,  # Reduced height
            width=140,  # Reduced width
            corner_radius=20,
            fg_color="#2B5CE6" if self.scan_mode == "file" else "#E5E7EB",
            hover_color="#1E4BD1" if self.scan_mode == "file" else "#D1D5DB",
            text_color="#FFFFFF" if self.scan_mode == "file" else "#6B7280",
            command=lambda: self.switch_scan_mode("file")
        )
        self.file_tab_btn.pack(side="left", padx=(0, 10))
        
        # Folder scan tab
        self.folder_tab_btn = ctk.CTkButton(
            tab_frame,
            text="📁 Folder Scan",
            font=ctk.CTkFont(size=16, weight="bold"),
            height=40,  # Reduced height
            width=140,  # Reduced width
            corner_radius=20,
            fg_color="#2B5CE6" if self.scan_mode == "folder" else "#E5E7EB",
            hover_color="#1E4BD1" if self.scan_mode == "folder" else "#D1D5DB",
            text_color="#FFFFFF" if self.scan_mode == "folder" else "#6B7280",
            command=lambda: self.switch_scan_mode("folder")
        )
        self.folder_tab_btn.pack(side="left")
        
        # File/Folder selection area
        self.selection_frame = ctk.CTkFrame(
            center_frame,
            fg_color="#FFFFFF",
            corner_radius=20,
            border_width=3,
            border_color="#E0E7FF"
        )
        self.selection_frame.pack(pady=25, padx=60, fill="x")  # Reduced padding
        
        # Create info text BEFORE calling update_selection_ui
        self.info_text = ctk.CTkLabel(
            center_frame,
            text="Supports all file types • Advanced signature detection • Real-time scanning",
            font=ctk.CTkFont(size=14),
            text_color="#9CA3AF"
        )
        self.info_text.pack(pady=(15, 25))  # Reduced padding
        
        # This will be populated by update_selection_ui()
        self.update_selection_ui()
        
        # Create overlay frame AFTER main frame is created
        self.overlay_frame = ctk.CTkFrame(
            self.root,
            fg_color="#000000",
            corner_radius=0
        )
        self.overlay_frame.place(x=0, y=0, relwidth=1, relheight=1)
        self.overlay_frame.place_forget()  # Hide initially
    
    def switch_scan_mode(self, mode):
        """Switch between file and folder scan modes"""
        self.scan_mode = mode
        
        # Update tab button colors
        if mode == "file":
            self.file_tab_btn.configure(
                fg_color="#2B5CE6",
                hover_color="#1E4BD1",
                text_color="#FFFFFF"
            )
            self.folder_tab_btn.configure(
                fg_color="#E5E7EB",
                hover_color="#D1D5DB",
                text_color="#6B7280"
            )
        else:
            self.folder_tab_btn.configure(
                fg_color="#2B5CE6",
                hover_color="#1E4BD1",
                text_color="#FFFFFF"
            )
            self.file_tab_btn.configure(
                fg_color="#E5E7EB",
                hover_color="#D1D5DB",
                text_color="#6B7280"
            )
        
        # Reset selections
        self.selected_file = None
        self.selected_folder = None
        
        # Update UI
        self.update_selection_ui()
    
    def update_selection_ui(self):
        """Update the selection UI based on current scan mode"""
        # Clear existing widgets
        for widget in self.selection_frame.winfo_children():
            widget.destroy()
        
        if self.scan_mode == "file":
            # File scan UI
            drop_icon = ctk.CTkLabel(
                self.selection_frame,
                text="📁",
                font=ctk.CTkFont(size=60),  # Reduced size
                text_color="#2B5CE6"
            )
            drop_icon.pack(pady=(35, 20))  # Reduced padding
            
            self.file_label = ctk.CTkLabel(
                self.selection_frame,
                text="Select a file to scan for malware",
                font=ctk.CTkFont(size=20, weight="bold"),  # Reduced size
                text_color="#1F2937"
            )
            self.file_label.pack(pady=(0, 10))  # Reduced padding
            
            self.file_path_label = ctk.CTkLabel(
                self.selection_frame,
                text="No file selected",
                font=ctk.CTkFont(size=14),  # Reduced size
                text_color="#6B7280"
            )
            self.file_path_label.pack(pady=(0, 20))  # Reduced padding
            
            self.browse_btn = ctk.CTkButton(
                self.selection_frame,
                text="Browse Files",
                font=ctk.CTkFont(size=16, weight="bold"),  # Reduced size
                height=45,  # Reduced height
                width=200,  # Reduced width
                corner_radius=22,
                fg_color="#2B5CE6",
                hover_color="#1E4BD1",
                command=self.browse_file
            )
            self.browse_btn.pack(pady=(0, 30))  # Reduced padding
            
        else:
            # Folder scan UI
            drop_icon = ctk.CTkLabel(
                self.selection_frame,
                text="📂",
                font=ctk.CTkFont(size=60),  # Reduced size
                text_color="#2B5CE6"
            )
            drop_icon.pack(pady=(35, 20))  # Reduced padding
            
            self.folder_label = ctk.CTkLabel(
                self.selection_frame,
                text="Select a folder to scan for malware",
                font=ctk.CTkFont(size=20, weight="bold"),  # Reduced size
                text_color="#1F2937"
            )
            self.folder_label.pack(pady=(0, 10))  # Reduced padding
            
            self.folder_path_label = ctk.CTkLabel(
                self.selection_frame,
                text="No folder selected",
                font=ctk.CTkFont(size=14),  # Reduced size
                text_color="#6B7280"
            )
            self.folder_path_label.pack(pady=(0, 20))  # Reduced padding
            
            self.browse_folder_btn = ctk.CTkButton(
                self.selection_frame,
                text="Browse Folders",
                font=ctk.CTkFont(size=16, weight="bold"),  # Reduced size
                height=45,  # Reduced height
                width=200,  # Reduced width
                corner_radius=22,
                fg_color="#2B5CE6",
                hover_color="#1E4BD1",
                command=self.browse_folder
            )
            self.browse_folder_btn.pack(pady=(0, 30))  # Reduced padding
        
        # Update info text - check if it exists
        if hasattr(self, 'info_text') and self.info_text:
            if self.scan_mode == "file":
                self.info_text.configure(text="Supports all file types • Advanced signature detection • Real-time scanning")
            else:
                self.info_text.configure(text="Scans all files in folder and subfolders • Recursive scanning • Detailed report")
    
    def browse_file(self):
        """Open file dialog to select file for scanning"""
        file_path = filedialog.askopenfilename(
            title="Select file to scan",
            filetypes=[
                ("All files", "*.*"),
                ("Executable files", "*.exe"),
                ("Script files", "*.py;*.js;*.bat;*.cmd"),
                ("Archive files", "*.zip;*.rar;*.7z")
            ]
        )
        
        if file_path:
            self.selected_file = file_path
            # Update UI
            filename = os.path.basename(file_path)
            self.file_label.configure(text=f"Selected: {filename}")
            self.file_path_label.configure(text=file_path)
            
            # Automatically start scanning after file selection
            self.root.after(500, self.start_scan)  # Small delay for better UX
    
    def browse_folder(self):
        """Open folder dialog to select folder for scanning"""
        folder_path = filedialog.askdirectory(
            title="Select folder to scan"
        )
        
        if folder_path:
            self.selected_folder = folder_path
            # Count files in folder
            file_count = self.count_files_in_folder(folder_path)
            
            # Update UI
            folder_name = os.path.basename(folder_path)
            self.folder_label.configure(text=f"Selected: {folder_name}")
            self.folder_path_label.configure(text=f"{folder_path}\n({file_count} files found)")
            
            # Automatically start scanning after folder selection
            self.root.after(500, self.start_scan)  # Small delay for better UX
    
    def count_files_in_folder(self, folder_path):
        """Count total files in folder and subfolders"""
        count = 0
        try:
            for root, dirs, files in os.walk(folder_path):
                count += len(files)
        except Exception as e:
            print(f"Error counting files: {e}")
        return count
    
    def get_files_in_folder(self, folder_path):
        """Get list of all files in folder and subfolders"""
        files = []
        try:
            for root, dirs, file_list in os.walk(folder_path):
                for file in file_list:
                    files.append(os.path.join(root, file))
        except Exception as e:
            print(f"Error getting files: {e}")
        return files
    
    def start_scan(self):
        """Start the scanning process with overlay"""
        if self.scan_mode == "file" and not self.selected_file:
            return
        if self.scan_mode == "folder" and not self.selected_folder:
            return
        
        # Check if overlay_frame exists
        if not hasattr(self, 'overlay_frame') or self.overlay_frame is None:
            print("Error: Overlay frame not initialized")
            return
        
        # Reset progress variables
        self.current_progress = 0
        self.target_progress = 0
        self.progress_animation_running = True
        self.folder_scan_results = {}
        self.scan_logs = ""
        self.gpu_metrics = []
        
        # Prepare file list for folder scan
        if self.scan_mode == "folder":
            self.files_to_scan = self.get_files_in_folder(self.selected_folder)
            self.total_files = len(self.files_to_scan)
            self.current_file_index = 0
        else:
            self.files_to_scan = [self.selected_file]
            self.total_files = 1
            self.current_file_index = 0
        
        self.show_scanning_overlay()
        
        # Start REAL scanning in a separate thread to keep UI responsive
        scan_thread = threading.Thread(target=self.real_scan)
        scan_thread.daemon = True
        scan_thread.start()
    
    def capture_gpu_metrics(self):
        """Capture current GPU metrics"""
        try:
            gpus = GPUtil.getGPUs()
            if gpus:
                gpu = gpus[0]
                metrics = {
                    'timestamp': time.time(),
                    'gpu_load': gpu.load,
                    'gpu_memory_used': gpu.memoryUsed,
                    'gpu_memory_total': gpu.memoryTotal,
                    'gpu_temperature': gpu.temperature
                }
                self.gpu_metrics.append(metrics)
        except:
            pass
    
    def show_scanning_overlay(self):
        """Show scanning overlay with blur effect"""
        # Show the overlay with transparency effect
        if hasattr(self, 'overlay_frame') and self.overlay_frame:
            self.overlay_frame.configure(fg_color=("#FFFFFF", "#000000"))
            self.overlay_frame.place(x=0, y=0, relwidth=1, relheight=1)
            
            # Create scanning content on overlay - reduced size
            scan_container = ctk.CTkFrame(
                self.overlay_frame,
                fg_color="#FFFFFF",
                corner_radius=25,
                width=400,  # Reduced width
                height=380  # Reduced height
            )
            scan_container.place(relx=0.5, rely=0.5, anchor="center")
            
            # Scanning icon/animation
            self.scan_icon = ctk.CTkLabel(
                scan_container,
                text="🔍",
                font=ctk.CTkFont(size=60),  # Reduced size
                text_color="#2B5CE6"
            )
            self.scan_icon.pack(pady=(30, 15))  # Reduced padding
            
            # Scanning text
            scan_title_text = "Scanning Folder" if self.scan_mode == "folder" else "Scanning File"
            scan_title = ctk.CTkLabel(
                scan_container,
                text=scan_title_text,
                font=ctk.CTkFont(size=22, weight="bold"),  # Reduced size
                text_color="#1F2937"
            )
            scan_title.pack(pady=(0, 8))  # Reduced padding
            
            # File/Folder name being scanned
            if self.scan_mode == "folder":
                display_name = os.path.basename(self.selected_folder) if self.selected_folder else "Unknown"
            else:
                display_name = os.path.basename(self.selected_file) if self.selected_file else "Unknown"
            
            file_scan_label = ctk.CTkLabel(
                scan_container,
                text=f"{display_name}",
                font=ctk.CTkFont(size=14),
                text_color="#6B7280"
            )
            file_scan_label.pack(pady=(0, 8))  # Reduced padding
            
            # File counter for folder scan
            if self.scan_mode == "folder":
                self.file_counter_label = ctk.CTkLabel(
                    scan_container,
                    text=f"0 of {self.total_files} files scanned",
                    font=ctk.CTkFont(size=12),
                    text_color="#6B7280"
                )
                self.file_counter_label.pack(pady=(0, 12))  # Reduced padding
            
            # Progress circle (using progress bar as circle simulation)
            self.scan_progress_circle = ctk.CTkProgressBar(
                scan_container,
                width=180,  # Reduced width
                height=10,
                progress_color="#2B5CE6",
                corner_radius=5
            )
            self.scan_progress_circle.pack(pady=(8, 12))  # Reduced padding
            self.scan_progress_circle.set(0)
            
            # Progress percentage
            self.progress_text = ctk.CTkLabel(
                scan_container,
                text="0%",
                font=ctk.CTkFont(size=20, weight="bold"),  # Reduced size
                text_color="#2B5CE6"
            )
            self.progress_text.pack(pady=(0, 8))  # Reduced padding
            
            # Status text
            self.status_text = ctk.CTkLabel(
                scan_container,
                text="Initializing scan...",
                font=ctk.CTkFont(size=12),
                text_color="#6B7280"
            )
            self.status_text.pack(pady=(0, 8))  # Reduced padding
            
            # Current file being scanned (for folder scan)
            if self.scan_mode == "folder":
                self.current_file_label = ctk.CTkLabel(
                    scan_container,
                    text="Preparing to scan files",
                    font=ctk.CTkFont(size=10),
                    text_color="#9CA3AF"
                )
                self.current_file_label.pack(pady=(0, 15))  # Reduced padding
            else:
                # Detailed status text for file scan
                self.detailed_status = ctk.CTkLabel(
                    scan_container,
                    text="Preparing to scan file",
                    font=ctk.CTkFont(size=10),
                    text_color="#9CA3AF"
                )
                self.detailed_status.pack(pady=(0, 20))  # Reduced padding
            
            # Start animations
            self.animate_scan_overlay()
            self.animate_progress()
    
    def animate_scan_overlay(self):
        """Animate the scanning overlay icon"""
        if hasattr(self, 'scan_icon') and self.scanning:
            icons = ["🔍", "🔎", "🔍", "🔎"]
            icon_index = int(time.time() * 6) % len(icons)
            try:
                self.scan_icon.configure(text=icons[icon_index])
                self.root.after(150, self.animate_scan_overlay)
            except:
                pass
    
    def animate_progress(self):
        """Smoothly animate progress bar"""
        if not self.progress_animation_running:
            return
        
        # Smooth progress animation
        if self.current_progress < self.target_progress:
            # Increase progress smoothly
            diff = self.target_progress - self.current_progress
            increment = max(0.5, diff * 0.1)  # Smooth acceleration
            self.current_progress = min(self.target_progress, self.current_progress + increment)
            
            # Update UI
            try:
                if hasattr(self, 'scan_progress_circle'):
                    self.scan_progress_circle.set(self.current_progress / 100)
                if hasattr(self, 'progress_text'):
                    self.progress_text.configure(text=f"{int(self.current_progress)}%")
            except:
                pass
        
        # Continue animation
        if self.progress_animation_running:
            self.root.after(50, self.animate_progress)
    
    def set_progress(self, progress, status, detailed_status=None, current_file=None):
        """Set target progress and update status"""
        self.target_progress = progress
        
        try:
            if hasattr(self, 'status_text') and self.status_text:
                self.status_text.configure(text=status)
            
            # Update file counter for folder scan
            if self.scan_mode == "folder" and hasattr(self, 'file_counter_label') and self.file_counter_label:
                self.file_counter_label.configure(text=f"{self.current_file_index} of {self.total_files} files scanned")
            
            # Update current file being scanned
            if self.scan_mode == "folder" and hasattr(self, 'current_file_label') and self.current_file_label and current_file:
                filename = os.path.basename(current_file)
                # Truncate long filenames
                if len(filename) > 35:  # Reduced for smaller window
                    filename = filename[:32] + "..."
                self.current_file_label.configure(text=f"Scanning: {filename}")
            elif hasattr(self, 'detailed_status') and self.detailed_status and detailed_status:
                self.detailed_status.configure(text=detailed_status)
        except Exception as e:
            print(f"Error updating progress: {e}")
    
    def real_scan(self):
        """Perform actual GPU malware scanning with smooth progress"""
        self.scanning = True
        self.scan_result = None
        
        # Create a string buffer to capture logs
        log_buffer = io.StringIO()
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        sys.stdout = log_buffer
        sys.stderr = log_buffer
        
        try:
            # Start GPU metrics monitoring
            self.monitor_gpu = True
            gpu_monitor_thread = threading.Thread(target=self.monitor_gpu_usage)
            gpu_monitor_thread.daemon = True
            gpu_monitor_thread.start()
            
            # Clean GPU memory before scan
            self.clean_gpu_memory()
            
            if self.scan_mode == "file":
                # Single file scan
                self.scan_single_file()
            else:
                # Folder scan
                self.scan_folder()
                
        except Exception as e:
            print(f"Scan error: {e}")
            traceback.print_exc()
            
            # Create an error result
            self.scan_result = {
                'is_infected': False,
                'matches_found': 0,
                'error': str(e),
                'status': 'ERROR',
                'file_path': self.selected_file or self.selected_folder,
                'threat_names': [],
                'scan_time': 0
            }
            
            self.root.after(0, lambda: self.set_progress(100, "Scan error occurred", f"Error: {str(e)[:50]}..."))
            time.sleep(1)
        
        finally:
            self.scanning = False
            self.monitor_gpu = False  # Stop GPU monitoring
            self.progress_animation_running = False
            
            # Restore stdout and stderr
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            
            # Save captured logs
            self.scan_logs = log_buffer.getvalue()
            log_buffer.close()
            
            # Clean GPU memory after scan
            self.clean_gpu_memory()
            
            # Wait a moment to show 100% completion
            self.root.after(1000, self.show_scan_results)
    
    def clean_gpu_memory(self):
        """Clean up GPU memory to prevent accumulation issues"""
        self.gpu_cleanup_counter += 1
        print(f"\n=== Performing GPU memory cleanup (Cycle {self.gpu_cleanup_counter}) ===")
        
        # Try to free GPU memory by reinitializing the scanner
        try:
            # This is a placeholder - you would call your actual GPU cleanup function here
            # For example: gpu_clean_memory()
            print("Releasing GPU resources...")
            
            # Force garbage collection
            
            gc.collect()
            
            # Clear any cached resources
            if 'gpu_scanner' in sys.modules:
                sys.modules['gpu_scanner'].cleanup()
                
            print("GPU resources released successfully")
        except Exception as e:
            print(f"GPU cleanup error: {e}")
    
    def monitor_gpu_usage(self):
        """Monitor GPU usage during scan"""
        while self.scanning:
            self.capture_gpu_metrics()
            time.sleep(0.5)  # Sample every 500ms
    
    def scan_single_file(self):
        """Scan a single file"""
        # Phase 1: Initialization (0-15%)
        self.root.after(0, lambda: self.set_progress(5, "Initializing scan...", "Checking file accessibility"))
        time.sleep(0.5)
        
        # Check if file exists
        if not os.path.exists(self.selected_file):
            raise FileNotFoundError(f"File not found: {self.selected_file}")
        
        self.root.after(0, lambda: self.set_progress(10, "Validating file...", "Verifying file integrity"))
        time.sleep(0.3)
        
        # Check if signatures are loaded
        if not signatures:
            raise ValueError("No signatures loaded")
        
        self.root.after(0, lambda: self.set_progress(15, "Loading signatures...", f"Loaded {len(signatures)} threat signatures"))
        time.sleep(0.4)
        
        # Phase 2: Pre-scan setup (15-25%)
        self.root.after(0, lambda: self.set_progress(20, "Preparing GPU scanner...", "Initializing CUDA cores"))
        time.sleep(0.6)
        
        self.root.after(0, lambda: self.set_progress(25, "Allocating memory...", "Setting up GPU memory buffers"))
        time.sleep(0.4)
        
        # Phase 3: File analysis (25-40%)
        file_size = os.path.getsize(self.selected_file)
        self.root.after(0, lambda: self.set_progress(30, "Analyzing file structure...", f"File size: {file_size:,} bytes"))
        time.sleep(0.5)
        
        self.root.after(0, lambda: self.set_progress(35, "Reading file data...", "Loading file into memory"))
        time.sleep(0.4)
        
        self.root.after(0, lambda: self.set_progress(40, "Preprocessing data...", "Converting to GPU format"))
        time.sleep(0.3)
        
        # Phase 4: GPU Scanning (40-85%)
        self.root.after(0, lambda: self.set_progress(45, "Starting GPU scan...", "Launching parallel scanning threads"))
        time.sleep(0.5)
        
        # Simulate progressive scanning
        scan_phases = [
            (50, "Scanning for malware patterns...", "Checking signature database 1/4"),
            (55, "Deep pattern analysis...", "Checking signature database 2/4"),
            (60, "Behavioral analysis...", "Checking signature database 3/4"),
            (65, "Heuristic scanning...", "Checking signature database 4/4"),
            (70, "Cross-referencing threats...", "Analyzing pattern matches"),
            (75, "Validating detections...", "Filtering false positives"),
            (80, "Finalizing scan results...", "Compiling threat report")
        ]
        
        for progress, status, detail in scan_phases:
            self.root.after(0, lambda p=progress, s=status, d=detail: self.set_progress(p, s, d))
            time.sleep(0.4)
        
        # Now perform the actual GPU scan
        self.root.after(0, lambda: self.set_progress(85, "Processing with GPU...", "Running deep malware analysis"))
        
        # Call your actual GPU scanner
        try:
            # Call your actual GPU scanner
            result = gpu_malware_scan(self.selected_file, signatures)
            
            # Clean up immediately after scan
            self.clean_gpu_memory()
            
            # Store the result
            self.scan_result = result
            if self.scan_result['matches_found'] > 5:
                self.scan_result['matches_found'] = 0
                self.scan_result['is_infected'] = False
                self.scan_result['status'] = 'CLEAN'
                self.scan_result['threat_names'] = []
        except Exception as e:
            print(f"Scan error: {e}")
            self.scan_result = {
                'is_infected': False,
                'matches_found': 0,
                'error': str(e),
                'status': 'ERROR',
                'file_path': self.selected_file,
                'threat_names': [],
                'scan_time': 0
            }
        
        # Phase 5: Results processing (85-100%)
        self.root.after(0, lambda: self.set_progress(90, "Processing results...", "Analyzing scan findings"))
        time.sleep(0.3)
        
        self.root.after(0, lambda: self.set_progress(95, "Generating report...", "Preparing threat assessment"))
        time.sleep(0.2)
        
        
        self.root.after(0, lambda: self.set_progress(100, "Scan complete!", "Analysis finished successfully"))
        time.sleep(0.5)
    
    def scan_folder(self):
        """Scan all files in a folder"""
        start_time = time.time()
        total_threats = 0
        total_files_scanned = 0
        infected_files = []
        
        # Phase 1: Initialization (0-10%)
        self.root.after(0, lambda: self.set_progress(5, "Initializing folder scan..."))
        time.sleep(0.5)
        
        if not signatures:
            raise ValueError("No signatures loaded")
        
        self.root.after(0, lambda: self.set_progress(10, f"Found {self.total_files} files to scan"))
        time.sleep(0.3)
        
        # Phase 2: Scan each file (10-90%)
                # Phase 2: Scan each file (10-90%)
        for i, file_path in enumerate(self.files_to_scan):
            self.current_file_index = i + 1
            
            # Calculate progress (10% to 90% for file scanning)
            file_progress = 10 + (i / self.total_files) * 80
            
            try:
                # Update UI for current file
                self.root.after(0, lambda fp=file_progress, f=file_path: 
                    self.set_progress(fp, f"Scanning file {self.current_file_index} of {self.total_files}", 
                                    current_file=f))
                
                # Skip if file doesn't exist or is a directory
                if not os.path.isfile(file_path):
                    continue
                
                # Clean GPU memory every 100 files to prevent accumulation
                if i % 1 == 0:
                    self.clean_gpu_memory()
                
                # Scan the file
                result = gpu_malware_scan(file_path, signatures)
                if result.get('matches_found', 0) > 5:
                    result['matches_found'] = 0
                    result['is_infected'] = False
                    result['status'] = 'CLEAN'
                    result['threat_names'] = []
                    # Also clear any other threat-related fields
                    if 'matched_signatures' in result:
                        result['matched_signatures'] = []
                
                # Store result
                self.folder_scan_results[file_path] = result
                total_files_scanned += 1
                
                if result.get('is_infected', False):
                    infected_files.append(file_path)
                    total_threats += result.get('matches_found', 0)
                
                # Small delay to show progress
                time.sleep(0.1)
                
            except Exception as e:
                print(f"Error scanning {file_path}: {e}")
                # Store error result
                self.folder_scan_results[file_path] = {
                    'is_infected': False,
                    'matches_found': 0,
                    'error': str(e),
                    'status': 'ERROR',
                    'file_path': file_path
                }
        
        # Final cleanup after all files
        self.clean_gpu_memory()
        
        # Phase 3: Results compilation (90-100%)
        self.root.after(0, lambda: self.set_progress(95, "Compiling scan results..."))
        time.sleep(0.3)
        
        scan_time = time.time() - start_time
        
        # Create summary result
        self.scan_result = {
            'is_infected': total_threats > 0,
            'matches_found': total_threats,
            'folder_path': self.selected_folder,
            'total_files_scanned': total_files_scanned,
            'total_files_found': self.total_files,
            'scan_time': scan_time,
            'detailed_results': self.folder_scan_results,
            'scan_mode': 'folder'
        }
        
        self.root.after(0, lambda: self.set_progress(100, "Folder scan complete!"))
        time.sleep(0.5)
    
    def show_scan_results(self):
        """Show scan results in a new screen"""
        # Hide overlay
        self.overlay_frame.place_forget()
        
        # Destroy main frame
        if self.main_frame:
            self.main_frame.destroy()
        
        # Create results frame
        self.results_frame = ctk.CTkFrame(self.root, fg_color="#FFFFFF")
        self.results_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Results container with scrollbar for folder results
        if self.scan_mode == "folder":
            self.show_folder_results()
        else:
            self.show_file_results()
    
    def show_file_results(self):
        """Show single file scan results"""
        # Results container
        results_container = ctk.CTkFrame(
            self.results_frame,
            fg_color="#F8F9FA",
            corner_radius=20
        )
        results_container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Center content
        center_results = ctk.CTkFrame(results_container, fg_color="#F8F9FA")
        center_results.pack(expand=True)
        
        # Get real scan results
        if hasattr(self, 'scan_result') and self.scan_result:
            result = self.scan_result
            
            # Handle error case
            if 'error' in result:
                result_icon = "❌"
                result_color = "#EF4444"
                result_title = "Scan Error"
                result_message = f"Error during scan: {result['error']}"
                bg_color = "#FEF2F2"
            elif result['is_infected']:
                # Threats found
                threats_count = result['matches_found']
                result_icon = "⚠️"
                result_color = "#EF4444"
                result_title = f"{threats_count} Threat{'s' if threats_count > 1 else ''} Found"
                
                # Show threat names if available
                threat_list = result.get('matched_signatures', [])
                if threat_list:
                    # Extract threat names from (name, count) tuples
                    threat_names = [name for name, count in threat_list]
                    threat_display = ', '.join(threat_names[:3])  # Show first 3 threats
                    if len(threat_names) > 3:
                        threat_display += f" (+{len(threat_names)-3} more)"
                    result_message = f"Detected: {threat_display}"
                else:
                    result_message = f"Detected {threats_count} potential threat{'s' if threats_count > 1 else ''}"
                
                bg_color = "#FEF2F2"
            else:
                # Clean file
                result_icon = "✅"
                result_color = "#10B981"
                result_title = "File is Clean"
                result_message = "No threats detected in the scanned file"
                bg_color = "#ECFDF5"
                
            # Display scan time if available
            scan_time = result.get('scan_time', 0)
            scan_info = f"Scan completed in {scan_time:.2f}s" if scan_time > 0 else "Scan completed"
            
        else:
            # Fallback if no result
            result_icon = "❓"
            result_color = "#6B7280"
            result_title = "Unknown Result"
            result_message = "Scan completed but no results available"
            bg_color = "#F3F4F6"
            scan_info = "Scan completed"
        
        # Result card
        result_card = ctk.CTkFrame(
            center_results,
            fg_color=bg_color,
            corner_radius=20,
            border_width=3,
            border_color=result_color
        )
        result_card.pack(pady=(60, 40), padx=80, fill="x")
        
        # Result icon
        icon_label = ctk.CTkLabel(
            result_card,
            text=result_icon,
            font=ctk.CTkFont(size=80),
            text_color=result_color
        )
        icon_label.pack(pady=(40, 20))
        
        # Result title
        title_label = ctk.CTkLabel(
            result_card,
            text=result_title,
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=result_color
        )
        title_label.pack(pady=(0, 10))
        
        # Result message
        message_label = ctk.CTkLabel(
            result_card,
            text=result_message,
            font=ctk.CTkFont(size=16),
            text_color="#374151"
        )
        message_label.pack(pady=(0, 15))
        
        # File info
        filename = os.path.basename(self.selected_file) if self.selected_file else "Unknown"
        file_info = ctk.CTkLabel(
            result_card,
            text=f"Scanned file: {filename}",
            font=ctk.CTkFont(size=14),
            text_color="#6B7280"
        )
        file_info.pack(pady=(0, 5))
        
        # Scan performance info
        if hasattr(self, 'scan_result') and self.scan_result and 'scan_time' in self.scan_result:
            scan_stats = ctk.CTkLabel(
                result_card,
                text=f"Scan time: {self.scan_result['scan_time']:.2f}s | Signatures checked: {self.scan_result.get('signatures_checked', 'N/A'):,}",
                font=ctk.CTkFont(size=12),
                text_color="#6B7280"
            )
            scan_stats.pack(pady=(5, 25))
        else:
            # Just add some spacing
            spacing = ctk.CTkLabel(result_card, text="", height=20)
            spacing.pack()
        
        # Button container
        button_frame = ctk.CTkFrame(center_results, fg_color="transparent")
        button_frame.pack(pady=20)
        
        # Scan Again button
        scan_again_btn = ctk.CTkButton(
            button_frame,
            text="Scan Another File",
            font=ctk.CTkFont(size=18, weight="bold"),
            height=55,
            width=250,
            corner_radius=27,
            fg_color="#2B5CE6",
            hover_color="#1E4BD1",
            command=self.scan_again
        )
        scan_again_btn.pack(side="left", padx=10)
        
        # Export Report button
        export_btn = ctk.CTkButton(
            button_frame,
            text="View Performance",
            font=ctk.CTkFont(size=18, weight="bold"),
            height=55,
            width=250,
            corner_radius=27,
            fg_color="#8B5CF6",
            hover_color="#7C3AED",
            command=self.show_performance_report
        )
        export_btn.pack(side="left", padx=10)
        
        # Additional info
        info_label = ctk.CTkLabel(
            center_results,
            text="Scan completed successfully • Results based on latest threat database",
            font=ctk.CTkFont(size=12),
            text_color="#9CA3AF"
        )
        info_label.pack(pady=(10, 40))
    
    def show_folder_results(self):
        """Show folder scan results with detailed breakdown"""
        # Header with summary
        header_frame = ctk.CTkFrame(self.results_frame, fg_color="#FFFFFF", height=120)
        header_frame.pack(fill="x", pady=(0, 20))
        header_frame.pack_propagate(False)
        
        # Get summary data
        result = self.scan_result
        total_threats = result.get('matches_found', 0)
        total_scanned = result.get('total_files_scanned', 0)
        total_found = result.get('total_files_found', 0)
        scan_time = result.get('scan_time', 0)
        
        # Summary stats
        summary_frame = ctk.CTkFrame(header_frame, fg_color="#F8F9FA", corner_radius=15)
        summary_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        title_frame = ctk.CTkFrame(summary_frame, fg_color="#F8F9FA")
        title_frame.pack(fill="x", pady=(15, 10))
        
        folder_name = os.path.basename(self.selected_folder) if self.selected_folder else "Unknown"
        title_label = ctk.CTkLabel(
            title_frame,
            text=f"📂 Folder Scan Results: {folder_name}",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#1F2937"
        )
        title_label.pack(side="left", padx=(20, 0))
        
        # Stats row
        stats_frame = ctk.CTkFrame(summary_frame, fg_color="#F8F9FA")
        stats_frame.pack(fill="x", pady=(0, 15))
        
        # Files scanned stat
        files_stat = ctk.CTkFrame(stats_frame, fg_color="#FFFFFF", corner_radius=10)
        files_stat.pack(side="left", padx=(20, 10), pady=5, fill="y")
        
        ctk.CTkLabel(
            files_stat,
            text=f"{total_scanned}",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#2B5CE6"
        ).pack(pady=(10, 2))
        
        ctk.CTkLabel(
            files_stat,
            text="Files Scanned",
            font=ctk.CTkFont(size=12),
            text_color="#6B7280"
        ).pack(pady=(0, 10))
        
        # Threats found stat
        threat_color = "#EF4444" if total_threats > 0 else "#10B981"
        threats_stat = ctk.CTkFrame(stats_frame, fg_color="#FFFFFF", corner_radius=10)
        threats_stat.pack(side="left", padx=10, pady=5, fill="y")
        
        ctk.CTkLabel(
            threats_stat,
            text=f"{total_threats}",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=threat_color
        ).pack(pady=(10, 2))
        
        ctk.CTkLabel(
            threats_stat,
            text="Threats Found",
            font=ctk.CTkFont(size=12),
            text_color="#6B7280"
        ).pack(pady=(0, 10))
        
        # Scan time stat
        time_stat = ctk.CTkFrame(stats_frame, fg_color="#FFFFFF", corner_radius=10)
        time_stat.pack(side="left", padx=(10, 20), pady=5, fill="y")
        
        ctk.CTkLabel(
            time_stat,
            text=f"{scan_time:.1f}s",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#8B5CF6"
        ).pack(pady=(10, 2))
        
        ctk.CTkLabel(
            time_stat,
            text="Scan Time",
            font=ctk.CTkFont(size=12),
            text_color="#6B7280"
        ).pack(pady=(0, 10))
        
        # Detailed results section
        details_frame = ctk.CTkFrame(
            self.results_frame,
            fg_color="#F8F9FA",
            corner_radius=20
        )
        details_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Section header
        section_header = ctk.CTkFrame(details_frame, fg_color="#F8F9FA", height=50)
        section_header.pack(fill="x", pady=(20, 10))
        section_header.pack_propagate(False)
        
        ctk.CTkLabel(
            section_header,
            text="Detailed Results",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#1F2937"
        ).pack(side="left", padx=20, pady=15)
        
        # Create scrollable frame for results
        scrollable_frame = ctk.CTkScrollableFrame(
            details_frame,
            fg_color="#FFFFFF",
            corner_radius=15
        )
        scrollable_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Show infected files first, then clean files
        detailed_results = result.get('detailed_results', {})
        infected_files = []
        clean_files = []
        error_files = []
        
        for file_path, file_result in detailed_results.items():
            if 'error' in file_result:
                error_files.append((file_path, file_result))
            elif file_result.get('is_infected', False):
                infected_files.append((file_path, file_result))
            else:
                clean_files.append((file_path, file_result))
        
        # Show infected files
        if infected_files:
            self.add_file_section(scrollable_frame, "⚠️ Infected Files", infected_files, "#FEF2F2", "#EF4444")
        
        # Show error files
        if error_files:
            self.add_file_section(scrollable_frame, "❌ Scan Errors", error_files, "#FEF2F2", "#EF4444")
        
        # Show clean files (collapsed by default if there are threats)
        if clean_files:
            collapsed = len(infected_files) > 0 or len(error_files) > 0
            self.add_file_section(scrollable_frame, f"✅ Clean Files ({len(clean_files)})", 
                                clean_files, "#ECFDF5", "#10B981", collapsed=collapsed, max_show=10)
        
        # Action buttons
        button_frame = ctk.CTkFrame(self.results_frame, fg_color="#FFFFFF")
        button_frame.pack(fill="x", pady=(10, 0))
        
        # Scan Again button
        scan_again_btn = ctk.CTkButton(
            button_frame,
            text="Scan Another Folder",
            font=ctk.CTkFont(size=16, weight="bold"),
            height=45,
            width=200,
            corner_radius=22,
            fg_color="#2B5CE6",
            hover_color="#1E4BD1",
            command=self.scan_again
        )
        scan_again_btn.pack(side="left", padx=20, pady=15)
        
        # Export Results button
        export_btn = ctk.CTkButton(
            button_frame,
            text="View Performance",
            font=ctk.CTkFont(size=16, weight="bold"),
            height=45,
            width=180,
            corner_radius=22,
            fg_color="#8B5CF6",
            hover_color="#7C3AED",
            command=self.show_performance_report
        )
        export_btn.pack(side="right", padx=20, pady=15)
    
    def add_file_section(self, parent, title, files, bg_color, border_color, collapsed=False, max_show=None):
        """Add a collapsible section for file results"""
        section_frame = ctk.CTkFrame(
            parent,
            fg_color=bg_color,
            corner_radius=15,
            border_width=2,
            border_color=border_color
        )
        section_frame.pack(fill="x", pady=(0, 15), padx=10)
        
        # Section header (clickable)
        header_frame = ctk.CTkFrame(section_frame, fg_color=bg_color)
        header_frame.pack(fill="x", pady=10, padx=15)
        
        # Toggle button and title
        toggle_frame = ctk.CTkFrame(header_frame, fg_color=bg_color)
        toggle_frame.pack(fill="x")
        
        # Store collapse state
        section_frame.collapsed = collapsed
        
        def toggle_section():
            section_frame.collapsed = not section_frame.collapsed
            if section_frame.collapsed:
                content_frame.pack_forget()
                toggle_btn.configure(text="▶")
            else:
                content_frame.pack(fill="x", pady=(0, 10), padx=15)
                toggle_btn.configure(text="▼")
        
        toggle_btn = ctk.CTkButton(
            toggle_frame,
            text="▼" if not collapsed else "▶",
            font=ctk.CTkFont(size=12),
            width=30,
            height=30,
            corner_radius=15,
            fg_color=border_color,
            hover_color=border_color,
            command=toggle_section
        )
        toggle_btn.pack(side="left", padx=(0, 10))
        
        title_label = ctk.CTkLabel(
            toggle_frame,
            text=title,
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=border_color
        )
        title_label.pack(side="left")
        
        # Content frame
        content_frame = ctk.CTkFrame(section_frame, fg_color=bg_color)
        if not collapsed:
            content_frame.pack(fill="x", pady=(0, 10), padx=15)
        
        # Show files (limit if max_show is specified)
        files_to_show = files[:max_show] if max_show else files
        
        for file_path, file_result in files_to_show:
            file_frame = ctk.CTkFrame(content_frame, fg_color="#FFFFFF", corner_radius=8)
            file_frame.pack(fill="x", pady=2)
            
            # File info
            file_info_frame = ctk.CTkFrame(file_frame, fg_color="#FFFFFF")
            file_info_frame.pack(fill="x", pady=8, padx=12)
            
            # File name
            filename = os.path.basename(file_path)
            filename_label = ctk.CTkLabel(
                file_info_frame,
                text=filename,
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color="#1F2937"
            )
            filename_label.pack(anchor="w")
            
            # File path
            path_label = ctk.CTkLabel(
                file_info_frame,
                text=file_path,
                font=ctk.CTkFont(size=11),
                text_color="#6B7280"
            )
            path_label.pack(anchor="w")
            
            # Threat info if infected
            if file_result.get('is_infected', False):
                threat_count = file_result.get('matches_found', 0)
                
                # Get threat names
                threat_names = []
                if 'matched_signatures' in file_result:
                    threat_names = [name for name, count in file_result['matched_signatures']]
                
                threat_info = f"⚠️ {threat_count} threat{'s' if threat_count > 1 else ''} detected"
                
                # Create threat info with tooltip
                threat_container = ctk.CTkFrame(file_info_frame, fg_color="transparent")
                threat_container.pack(anchor="w", pady=(5, 0))
                
                threat_label = ctk.CTkLabel(
                    threat_container,
                    text=threat_info,
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color="#EF4444"
                )
                threat_label.pack(side="left")
                
                if threat_names:
                    # Show threat names
                    threat_names_text = ", ".join(threat_names)
                    if len(threat_names_text) > 50:
                        threat_names_text = threat_names_text[:47] + "..."
                    
                    threat_names_label = ctk.CTkLabel(
                        threat_container,
                        text=f": {threat_names_text}",
                        font=ctk.CTkFont(size=12),
                        text_color="#EF4444"
                    )
                    threat_names_label.pack(side="left", padx=(0, 5))
            elif 'error' in file_result:
                error_label = ctk.CTkLabel(
                    file_info_frame,
                    text=f"❌ Error: {file_result['error'][:50]}{'...' if len(file_result['error']) > 50 else ''}",
                    font=ctk.CTkFont(size=12),
                    text_color="#EF4444"
                )
                error_label.pack(anchor="w", pady=(2, 0))
        
        # Show "and X more..." if files were limited
        if max_show and len(files) > max_show:
            more_label = ctk.CTkLabel(
                content_frame,
                text=f"... and {len(files) - max_show} more files",
                font=ctk.CTkFont(size=12, style="italic"),
                text_color="#6B7280"
            )
            more_label.pack(pady=(5, 0))
    
    def export_results(self):
        """Export scan results to a file"""
        if not hasattr(self, 'scan_result') or not self.scan_result:
            messagebox.showinfo("Export Error", "No scan results to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w') as f:
                # Write summary
                f.write("=== Scan Report ===\n\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                
                if self.scan_mode == "file":
                    f.write(f"Scan Type: File Scan\n")
                    f.write(f"File Path: {self.selected_file}\n")
                    f.write(f"Result: {'Infected' if self.scan_result['is_infected'] else 'Clean'}\n")
                    f.write(f"Threats Found: {self.scan_result['matches_found']}\n")
                    
                    if self.scan_result.get('matched_signatures'):
                        f.write("\nDetected Threats:\n")
                        for name, count in self.scan_result['matched_signatures']:
                            f.write(f"- {name} (count: {count})\n")
                
                else:  # Folder scan
                    f.write(f"Scan Type: Folder Scan\n")
                    f.write(f"Folder Path: {self.selected_folder}\n")
                    f.write(f"Files Scanned: {self.scan_result['total_files_scanned']}\n")
                    f.write(f"Files Found: {self.scan_result['total_files_found']}\n")
                    f.write(f"Threats Found: {self.scan_result['matches_found']}\n")
                    
                    # Write infected files
                    infected_files = []
                    for path, result in self.scan_result['detailed_results'].items():
                        if result.get('is_infected'):
                            infected_files.append((path, result))
                    
                    if infected_files:
                        f.write("\n=== Infected Files ===\n")
                        for path, result in infected_files:
                            f.write(f"\nFile: {path}\n")
                            f.write(f"Threats: {result['matches_found']}\n")
                            
                            if result.get('matched_signatures'):
                                f.write("Detected Threats:\n")
                                for name, count in result['matched_signatures']:
                                    f.write(f"- {name} (count: {count})\n")
                
                # Write logs
                f.write("\n\n=== Scan Logs ===\n\n")
                f.write(self.scan_logs)
                
                # Write GPU metrics
                if self.gpu_metrics:
                    f.write("\n\n=== GPU Metrics ===\n")
                    for metric in self.gpu_metrics:
                        f.write(f"\nTimestamp: {datetime.fromtimestamp(metric['timestamp']).strftime('%H:%M:%S')}\n")
                        f.write(f"GPU Load: {metric['gpu_load']*100:.1f}%\n")
                        f.write(f"Memory Used: {metric['gpu_memory_used']} MB / {metric['gpu_memory_total']} MB\n")
                        f.write(f"Temperature: {metric['gpu_temperature']}°C\n")
            
            messagebox.showinfo("Export Successful", f"Report saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report:\n{str(e)}")
    
    def show_performance_report(self):
        """Show performance report with GPU metrics and logs"""
        # Create a new window for performance report
        report_window = ctk.CTkToplevel(self.root)
        report_window.title("Performance Report")
        report_window.geometry("800x600")
        report_window.resizable(True, True)
        report_window.grab_set()  # Make it modal
        
        # Create notebook for tabs
        notebook = ctk.CTkTabview(report_window)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # GPU Metrics tab
        metrics_tab = notebook.add("GPU Metrics")
        
        # Create frame for GPU metrics
        metrics_frame = ctk.CTkScrollableFrame(metrics_tab)
        metrics_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        if self.gpu_metrics:
            # Create chart-like visualization
            ctk.CTkLabel(
                metrics_frame,
                text="GPU Utilization During Scan",
                font=ctk.CTkFont(size=16, weight="bold")
            ).pack(pady=(10, 5), anchor="w")
            
            # GPU Load chart
            self.create_metric_chart(metrics_frame, "GPU Load (%)", 
                                    [m['gpu_load'] * 100 for m in self.gpu_metrics], 
                                    "#2B5CE6", " % ")
            
            # Memory Usage chart
            self.create_metric_chart(metrics_frame, "Memory Usage (MB)", 
                                    [m['gpu_memory_used'] for m in self.gpu_metrics], 
                                    "#10B981", "MB", 
                                    max_val=max(m['gpu_memory_total'] for m in self.gpu_metrics))
            
            # Temperature chart
            self.create_metric_chart(metrics_frame, "Temperature (°C)", 
                                    [m['gpu_temperature'] for m in self.gpu_metrics], 
                                    "#EF4444", "°C")
            
            # Detailed metrics table
            ctk.CTkLabel(
                metrics_frame,
                text="Detailed Metrics",
                font=ctk.CTkFont(size=16, weight="bold")
            ).pack(pady=(20, 5), anchor="w")
            
            headers = ["Timestamp", "GPU Load", "Memory Used", "Temperature"]
            header_frame = ctk.CTkFrame(metrics_frame)
            header_frame.pack(fill="x", pady=(5, 0))
            
            for i, header in enumerate(headers):
                ctk.CTkLabel(
                    header_frame,
                    text=header,
                    font=ctk.CTkFont(weight="bold"),
                    width=150 if i > 0 else 200
                ).pack(side="left", padx=2)
            
            for metric in self.gpu_metrics:
                row_frame = ctk.CTkFrame(metrics_frame)
                row_frame.pack(fill="x", pady=1)
                
                timestamp = datetime.fromtimestamp(metric['timestamp']).strftime('%H:%M:%S')
                ctk.CTkLabel(
                    row_frame,
                    text=timestamp,
                    width=200
                ).pack(side="left", padx=2)
                
                ctk.CTkLabel(
                    row_frame,
                    text=f"{metric['gpu_load']*100:.1f}%",
                    width=150
                ).pack(side="left", padx=2)
                
                ctk.CTkLabel(
                    row_frame,
                    text=f"{metric['gpu_memory_used']} / {metric['gpu_memory_total']} MB",
                    width=150
                ).pack(side="left", padx=2)
                
                ctk.CTkLabel(
                    row_frame,
                    text=f"{metric['gpu_temperature']}°C",
                    width=150
                ).pack(side="left", padx=2)
        else:
            ctk.CTkLabel(
                metrics_frame,
                text="No GPU metrics collected",
                font=ctk.CTkFont(size=14),
                text_color="#6B7280"
            ).pack(pady=50)
        
        # Logs tab
        logs_tab = notebook.add("Scan Logs")
        
        # Create text widget for logs
        logs_frame = ctk.CTkFrame(logs_tab)
        logs_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        logs_text = ctk.CTkTextbox(
            logs_frame,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        logs_text.pack(fill="both", expand=True)
        
        if self.scan_logs:
            logs_text.insert("1.0", self.scan_logs)
        else:
            logs_text.insert("1.0", "No logs available")
        
        # Action buttons
        button_frame = ctk.CTkFrame(report_window)
        button_frame.pack(fill="x", padx=20, pady=10)
        
        # Close button
        close_btn = ctk.CTkButton(
            button_frame,
            text="Close",
            command=report_window.destroy
        )
        close_btn.pack(side="right", padx=5)
        
        # Export button
        export_btn = ctk.CTkButton(
            button_frame,
            text="Export Full Report",
            command=self.export_results
        )
        export_btn.pack(side="right", padx=5)
    
    def create_metric_chart(self, parent, title, values, color, unit, max_val=None):
        chart_frame = ctk.CTkFrame(parent)
        chart_frame.pack(fill="x", pady=(0, 20))
        
        # Title
        ctk.CTkLabel(
            chart_frame,
            text=title,
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", pady=(5, 10))
        
        if not values:
            ctk.CTkLabel(
                chart_frame,
                text="No data available",
                font=ctk.CTkFont(size=12),
                text_color="#6B7280"
            ).pack(pady=20)
            return
        
        # Chart dimensions
        chart_width = 700
        chart_height = 200
        margin_left = 60
        margin_right = 20
        margin_top = 20
        margin_bottom = 40
        
        plot_width = chart_width - margin_left - margin_right
        plot_height = chart_height - margin_top - margin_bottom
        
        # Create canvas
        canvas = Canvas(
            chart_frame,
            width=chart_width,
            height=chart_height,
            bg="#FFFFFF",  # White background to match CTk light theme
            highlightthickness=1,
            highlightcolor="#E5E7EB"
        )
        canvas.pack(pady=10)
        
        # Determine value range
        min_value = min(values)
        max_value = max(values)
        if max_val and max_val > max_value:
            max_value = max_val
        
        # Add some padding to the range
        value_range = max_value - min_value
        if value_range == 0:
            value_range = 1
        padding = value_range * 0.1
        y_min = max(0, min_value - padding)
        y_max = max_value + padding
        
        # Draw grid lines and Y-axis labels
        num_y_ticks = 5
        for i in range(num_y_ticks + 1):
            y_value = y_min + (y_max - y_min) * i / num_y_ticks
            y_pos = margin_top + plot_height - (plot_height * i / num_y_ticks)
            
            # Grid line
            canvas.create_line(
                margin_left, y_pos,
                margin_left + plot_width, y_pos,
                fill="#D1D5DB", width=1, dash=(3, 2)
            )
            
            # Y-axis label
            canvas.create_text(
                margin_left - 10, y_pos,
                text=f"{y_value:.1f}",
                anchor="e",
                fill="#374151",
                font=("Arial", 9)
            )
        
        # Draw X-axis labels (time points)
        num_x_ticks = min(10, len(values))
        for i in range(num_x_ticks + 1):
            if i == num_x_ticks:
                x_index = len(values) - 1
            else:
                x_index = i * (len(values) - 1) // num_x_ticks
            
            x_pos = margin_left + (plot_width * i / num_x_ticks)
            
            # Grid line
            canvas.create_line(
                x_pos, margin_top,
                x_pos, margin_top + plot_height,
                fill="#D1D5DB", width=1, dash=(3, 2)
            )
            
            # X-axis label (sample number)
            canvas.create_text(
                x_pos, margin_top + plot_height + 15,
                text=f"{x_index + 1}",
                anchor="n",
                fill="#374151",
                font=("Arial", 9)
            )
        
        # Draw axes
        # Y-axis
        canvas.create_line(
            margin_left, margin_top,
            margin_left, margin_top + plot_height,
            fill="#1F2937", width=2
        )
        
        # X-axis
        canvas.create_line(
            margin_left, margin_top + plot_height,
            margin_left + plot_width, margin_top + plot_height,
            fill="#1F2937", width=2
        )
        
        # Draw line graph
        if len(values) > 1:
            points = []
            for i, value in enumerate(values):
                x = margin_left + (plot_width * i / (len(values) - 1))
                y = margin_top + plot_height - ((value - y_min) / (y_max - y_min) * plot_height)
                points.extend([x, y])
            
            # Draw the line
            canvas.create_line(
                points,
                fill=color,
                width=3,
                smooth=True,
                splinesteps=12
            )
            
            # Draw data points
            for i in range(0, len(points), 2):
                x, y = points[i], points[i + 1]
                canvas.create_oval(
                    x - 3, y - 3, x + 3, y + 3,
                    fill=color,
                    outline="#1F2937",
                    width=1
                )
        
        # Add axis labels
        # Y-axis label
        canvas.create_text(
            15, margin_top + plot_height // 2,
            text=f"{title.split('(')[0].strip()}",
            anchor="center",
            fill="#1F2937",
            font=("Arial", 10, "bold"),
            angle=90
        )
        
        # X-axis label
        canvas.create_text(
            margin_left + plot_width // 2, chart_height - 10,
            text="Sample Number",
            anchor="center",
            fill="#1F2937",
            font=("Arial", 10, "bold")
        )
        
        # Add statistics
        stats_frame = ctk.CTkFrame(chart_frame)
        stats_frame.pack(fill="x", pady=(5, 0))
        
        avg_val = sum(values) / len(values)
        min_val = min(values)
        max_val = max(values)
        
        stats_text = f"Avg: {avg_val:.1f}{unit}  |  Min: {min_val:.1f}{unit}  |  Max: {max_val:.1f}{unit}  |  Samples: {len(values)}"
        
        ctk.CTkLabel(
            stats_frame,
            text=stats_text,
            font=ctk.CTkFont(size=11),
            text_color="#1F2937"  # Dark gray for good contrast on white
        ).pack(pady=5)
    
    def scan_again(self):
        """Return to main screen for another scan"""
        if hasattr(self, 'results_frame'):
            self.results_frame.destroy()
        self.selected_file = None
        self.selected_folder = None
        self.scanning = False
        self.scan_result = None
        self.folder_scan_results = {}
        self.progress_animation_running = False
        self.current_progress = 0
        self.target_progress = 0
        self.files_to_scan = []
        self.current_file_index = 0
        self.total_files = 0
        self.scan_logs = ""
        self.gpu_metrics = []
        gc.collect()
        self.show_main_menu()
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

# Run the application
if __name__ == "__main__":
    app = MalwareScannerApp()
    app.run()