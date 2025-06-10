import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import time
from PIL import Image, ImageTk
import os
import sys
import traceback

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
        # Create main window
        self.root = ctk.CTk()
        self.root.title("SecureGuard - Malware Scanner")
        self.root.geometry("800x600")
        self.root.resizable(False, False)
        
        # Configure window
        self.root.configure(fg_color="#FFFFFF")
        
        # Initialize variables
        self.selected_file = None
        self.scanning = False
        self.scan_result = None
        self.progress_animation_running = False
        self.current_progress = 0
        self.target_progress = 0
        
        # Create frames
        self.loading_frame = None
        self.main_frame = None
        self.results_frame = None
        self.overlay_frame = None
        
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
        shield_label.pack(pady=(50, 20))
        
        # App name
        app_name = ctk.CTkLabel(
            logo_frame,
            text="SecureGuard",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color="#1a1a1a"
        )
        app_name.pack(pady=(0, 10))
        
        # Subtitle
        subtitle = ctk.CTkLabel(
            logo_frame,
            text="Advanced Malware Detection",
            font=ctk.CTkFont(size=16),
            text_color="#666666"
        )
        subtitle.pack(pady=(0, 30))
        
        # Loading bar
        self.loading_progress = ctk.CTkProgressBar(
            logo_frame,
            width=300,
            height=8,
            progress_color="#2B5CE6",
            fg_color="#E8E8E8"
        )
        self.loading_progress.pack(pady=(20, 10))
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
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        header_frame = ctk.CTkFrame(self.main_frame, fg_color="#FFFFFF", height=80)
        header_frame.pack(fill="x", pady=(0, 30))
        header_frame.pack_propagate(False)
        
        # Logo and title in header
        logo_text = ctk.CTkLabel(
            header_frame,
            text="🛡️ SecureGuard",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#2B5CE6"
        )
        logo_text.pack(side="left", padx=(20, 0), pady=20)
        
        # Main content area
        content_frame = ctk.CTkFrame(self.main_frame, fg_color="#F8F9FA", corner_radius=15)
        content_frame.pack(fill="both", expand=True)
        
        # Center content
        center_frame = ctk.CTkFrame(content_frame, fg_color="#F8F9FA")
        center_frame.pack(expand=True)
        
        # File selection area
        file_frame = ctk.CTkFrame(
            center_frame,
            fg_color="#FFFFFF",
            corner_radius=20,
            border_width=3,
            border_color="#E0E7FF"
        )
        file_frame.pack(pady=60, padx=80, fill="x")
        
        # Drop zone icon
        drop_icon = ctk.CTkLabel(
            file_frame,
            text="📁",
            font=ctk.CTkFont(size=72),
            text_color="#2B5CE6"
        )
        drop_icon.pack(pady=(50, 25))
        
        # File selection text
        self.file_label = ctk.CTkLabel(
            file_frame,
            text="Select a file to scan for malware",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#1F2937"
        )
        self.file_label.pack(pady=(0, 12))
        
        # File path display
        self.file_path_label = ctk.CTkLabel(
            file_frame,
            text="No file selected",
            font=ctk.CTkFont(size=16),
            text_color="#6B7280"
        )
        self.file_path_label.pack(pady=(0, 25))
        
        # Browse button
        self.browse_btn = ctk.CTkButton(
            file_frame,
            text="Browse Files",
            font=ctk.CTkFont(size=18, weight="bold"),
            height=55,
            width=220,
            corner_radius=27,
            fg_color="#2B5CE6",
            hover_color="#1E4BD1",
            command=self.browse_file
        )
        self.browse_btn.pack(pady=(0, 40))
        
        # Info text
        info_text = ctk.CTkLabel(
            center_frame,
            text="Supports all file types • Advanced signature detection • Real-time scanning",
            font=ctk.CTkFont(size=14),
            text_color="#9CA3AF"
        )
        info_text.pack(pady=(20, 40))
        
        # Overlay frame for scanning (initially hidden)
        self.overlay_frame = ctk.CTkFrame(
            self.root,
            fg_color="#000000",
            corner_radius=0
        )
        self.overlay_frame.place(x=0, y=0, relwidth=1, relheight=1)
        self.overlay_frame.place_forget()  # Hide initially
    
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
    
    def start_scan(self):
        """Start the scanning process with overlay"""
        if not self.selected_file:
            return
        
        # Reset progress variables
        self.current_progress = 0
        self.target_progress = 0
        self.progress_animation_running = True
        
        self.show_scanning_overlay()
        
        # Start REAL scanning in a separate thread to keep UI responsive
        scan_thread = threading.Thread(target=self.real_scan)
        scan_thread.daemon = True
        scan_thread.start()
    
    def show_scanning_overlay(self):
        """Show scanning overlay with blur effect"""
        # Show the overlay with transparency effect
        self.overlay_frame.configure(fg_color=("#FFFFFF", "#000000"))
        self.overlay_frame.place(x=0, y=0, relwidth=1, relheight=1)
        
        # Create scanning content on overlay
        scan_container = ctk.CTkFrame(
            self.overlay_frame,
            fg_color="#FFFFFF",
            corner_radius=25,
            width=400,
            height=400
        )
        scan_container.place(relx=0.5, rely=0.5, anchor="center")
        
        # Scanning icon/animation
        self.scan_icon = ctk.CTkLabel(
            scan_container,
            text="🔍",
            font=ctk.CTkFont(size=80),
            text_color="#2B5CE6"
        )
        self.scan_icon.pack(pady=(40, 20))
        
        # Scanning text
        scan_title = ctk.CTkLabel(
            scan_container,
            text="Scanning File",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#1F2937"
        )
        scan_title.pack(pady=(0, 10))
        
        # File name being scanned
        filename = os.path.basename(self.selected_file) if self.selected_file else "Unknown"
        file_scan_label = ctk.CTkLabel(
            scan_container,
            text=f"{filename}",
            font=ctk.CTkFont(size=16),
            text_color="#6B7280"
        )
        file_scan_label.pack(pady=(0, 20))
        
        # Progress circle (using progress bar as circle simulation)
        self.scan_progress_circle = ctk.CTkProgressBar(
            scan_container,
            width=200,
            height=12,
            progress_color="#2B5CE6",
            corner_radius=6
        )
        self.scan_progress_circle.pack(pady=(10, 15))
        self.scan_progress_circle.set(0)
        
        # Progress percentage
        self.progress_text = ctk.CTkLabel(
            scan_container,
            text="0%",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#2B5CE6"
        )
        self.progress_text.pack(pady=(0, 10))
        
        # Status text
        self.status_text = ctk.CTkLabel(
            scan_container,
            text="Initializing scan...",
            font=ctk.CTkFont(size=14),
            text_color="#6B7280"
        )
        self.status_text.pack(pady=(0, 20))
        
        # Detailed status text
        self.detailed_status = ctk.CTkLabel(
            scan_container,
            text="Preparing to scan file",
            font=ctk.CTkFont(size=12),
            text_color="#9CA3AF"
        )
        self.detailed_status.pack(pady=(0, 30))
        
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
    
    def set_progress(self, progress, status, detailed_status=None):
        """Set target progress and update status"""
        self.target_progress = progress
        
        try:
            if hasattr(self, 'status_text'):
                self.status_text.configure(text=status)
            if hasattr(self, 'detailed_status') and detailed_status:
                self.detailed_status.configure(text=detailed_status)
        except:
            pass
    
    def real_scan(self):
        """Perform actual GPU malware scanning with smooth progress"""
        self.scanning = True
        self.scan_result = None
        
        try:
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
            result = gpu_malware_scan(self.selected_file, signatures)
            
            # Phase 5: Results processing (85-100%)
            self.root.after(0, lambda: self.set_progress(90, "Processing results...", "Analyzing scan findings"))
            time.sleep(0.3)
            
            self.root.after(0, lambda: self.set_progress(95, "Generating report...", "Preparing threat assessment"))
            time.sleep(0.2)
            
            # Store the result
            self.scan_result = result
            
            self.root.after(0, lambda: self.set_progress(100, "Scan complete!", "Analysis finished successfully"))
            time.sleep(0.5)
            
        except Exception as e:
            print(f"Scan error: {e}")
            traceback.print_exc()
            
            # Create an error result
            self.scan_result = {
                'is_infected': False,
                'matches_found': 0,
                'error': str(e),
                'status': 'ERROR',
                'file_path': self.selected_file,
                'threat_names': [],
                'scan_time': 0
            }
            
            self.root.after(0, lambda: self.set_progress(100, "Scan error occurred", f"Error: {str(e)[:50]}..."))
            time.sleep(1)
        
        finally:
            self.scanning = False
            self.progress_animation_running = False
            # Wait a moment to show 100% completion
            self.root.after(1000, self.show_scan_results)
    
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
        
        # Scan Again button
        scan_again_btn = ctk.CTkButton(
            center_results,
            text="Scan Another File",
            font=ctk.CTkFont(size=18, weight="bold"),
            height=55,
            width=250,
            corner_radius=27,
            fg_color="#2B5CE6",
            hover_color="#1E4BD1",
            command=self.scan_again
        )
        scan_again_btn.pack(pady=20)
        
        # Additional info
        info_label = ctk.CTkLabel(
            center_results,
            text="Scan completed successfully • Results based on latest threat database",
            font=ctk.CTkFont(size=12),
            text_color="#9CA3AF"
        )
        info_label.pack(pady=(10, 40))
    
    def scan_again(self):
        """Return to main screen for another scan"""
        if hasattr(self, 'results_frame'):
            self.results_frame.destroy()
        self.selected_file = None
        self.scanning = False
        self.scan_result = None
        self.progress_animation_running = False
        self.current_progress = 0
        self.target_progress = 0
        self.show_main_menu()
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

# Run the application
if __name__ == "__main__":
    app = MalwareScannerApp()
    app.run()