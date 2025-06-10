import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import time
from PIL import Image, ImageTk
import os

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
        
        self.show_scanning_overlay()
        
        # Start scanning in a separate thread to keep UI responsive
        scan_thread = threading.Thread(target=self.simulate_scan)
        scan_thread.daemon = True
        scan_thread.start()
    
    def show_scanning_overlay(self):
        """Show scanning overlay with blur effect"""
        # Show the overlay with transparency effect
        self.overlay_frame.configure(fg_color=("#FFFFFF", "#000000"))
        self.overlay_frame.attributes = 0.85  # Semi-transparent
        self.overlay_frame.place(x=0, y=0, relwidth=1, relheight=1)
        
        # Create scanning content on overlay
        scan_container = ctk.CTkFrame(
            self.overlay_frame,
            fg_color="#FFFFFF",
            corner_radius=25,
            width=400,
            height=350
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
            width=120,
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
            font=ctk.CTkFont(size=20, weight="bold"),
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
        self.status_text.pack(pady=(0, 30))
        
        # Animate scanning icon
        self.animate_scan_overlay()
    
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
    

    
    def simulate_scan(self):
        """Simulate the scanning process with progress updates"""
        self.scanning = True
        
        # Faster scanning with more frequent updates
        for progress in range(0, 101, 2):  # Increment by 2 for faster progress
            if not self.scanning:
                break
                
            time.sleep(0.05)  # Much faster updates (50ms intervals)
            
            # Update status based on progress
            if progress < 20:
                status = "Analyzing file signature..."
            elif progress < 40:
                status = "Checking against malware database..."
            elif progress < 60:
                status = "Deep signature analysis..."
            elif progress < 80:
                status = "Behavioral pattern detection..."
            elif progress < 95:
                status = "Cross-referencing threat intelligence..."
            else:
                status = "Finalizing security assessment..."
            
            try:
                self.root.after(0, lambda p=progress, s=status: self.update_scan_progress(p, s))
            except:
                break
        
        # Final completion
        if self.scanning:
            self.root.after(0, lambda: self.update_scan_progress(100, "Scan complete!"))
            time.sleep(0.5)
            self.scanning = False
            self.root.after(0, self.show_scan_results)
    
    def update_scan_progress(self, progress, status):
        """Update the scanning progress display"""
        try:
            if hasattr(self, 'scan_progress_circle'):
                self.scan_progress_circle.set(progress / 100)
            if hasattr(self, 'progress_text'):
                self.progress_text.configure(text=f"{progress}%")
            if hasattr(self, 'status_text'):
                self.status_text.configure(text=status)
        except:
            pass
    
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
        
        # Simulate scan result (you'll replace this with your backend logic)
        import random
        threats_found = random.choice([0, 1, 2, 3])  # Random for demo
        
        if threats_found == 0:
            # Clean file
            result_icon = "✅"
            result_color = "#10B981"
            result_title = "File is Clean"
            result_message = "No threats detected in the scanned file"
            bg_color = "#ECFDF5"
        else:
            # Threats found
            result_icon = "⚠️"
            result_color = "#EF4444"
            result_title = f"{threats_found} Threat{'s' if threats_found > 1 else ''} Found"
            result_message = f"Detected {threats_found} potential threat{'s' if threats_found > 1 else ''} in the file"
            bg_color = "#FEF2F2"
        
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
        file_info.pack(pady=(0, 30))
        
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
        self.show_main_menu()
    

    
    def run(self):
        """Start the application"""
        self.root.mainloop()

# Run the application
if __name__ == "__main__":
    app = MalwareScannerApp()
    app.run()