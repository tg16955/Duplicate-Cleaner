import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import hashlib
import shutil
from PIL import Image, ImageTk
import cv2
import numpy as np
from pathlib import Path
import threading
import logging
from datetime import datetime
import json
from collections import defaultdict
try:
    import imagehash
    HAS_IMAGEHASH = True
except ImportError:
    HAS_IMAGEHASH = False

class DuplicateCleanerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Duplicate Cleaner Pro")
        self.root.geometry("1000x700")
        
        # Setup logging
        self.setup_logging()
        
        # Variables
        self.scan_path = tk.StringVar()
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Ready")
        self.duplicates = {}
        self.screenshots = []
        self.selected_files = []
        self.scanning = False
        self.total_files = 0
        self.current_file = 0
        
        # Create GUI
        self.create_widgets()
        
    def setup_logging(self):
        """Setup logging configuration"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"duplicate_cleaner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Duplicate Cleaner started")
        
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(6, weight=1)
        
        # Path selection
        ttk.Label(main_frame, text="Scan Directory:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(main_frame, textvariable=self.scan_path, width=50).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_directory).grid(row=0, column=2, padx=5)
        
        # Options frame
        options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding="5")
        options_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Checkboxes for file types
        self.scan_images = tk.BooleanVar(value=True)
        self.scan_videos = tk.BooleanVar(value=True)
        self.classify_screenshots = tk.BooleanVar(value=True)
        self.include_subfolders = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="Scan Images", variable=self.scan_images).grid(row=0, column=0, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Scan Videos", variable=self.scan_videos).grid(row=0, column=1, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Classify Screenshots", variable=self.classify_screenshots).grid(row=0, column=2, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Include Subfolders", variable=self.include_subfolders).grid(row=0, column=3, sticky=tk.W)
        
        # Auto-removal options
        auto_frame = ttk.LabelFrame(main_frame, text="Auto-Removal Options", padding="5")
        auto_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        self.auto_remove = tk.BooleanVar(value=False)
        self.create_backup = tk.BooleanVar(value=True)
        self.keep_preference = tk.StringVar(value="newest")
        
        ttk.Checkbutton(auto_frame, text="Auto-Remove Duplicates After Scan", variable=self.auto_remove).grid(row=0, column=0, sticky=tk.W)
        ttk.Checkbutton(auto_frame, text="Create Backup Before Removal", variable=self.create_backup).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(auto_frame, text="Keep:").grid(row=0, column=2, sticky=tk.W, padx=(20, 5))
        keep_combo = ttk.Combobox(auto_frame, textvariable=self.keep_preference, values=["newest", "oldest", "largest", "smallest"], state="readonly", width=10)
        keep_combo.grid(row=0, column=3, sticky=tk.W)
        
        # Similarity threshold
        ttk.Label(auto_frame, text="Similarity Threshold:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.similarity_threshold = tk.DoubleVar(value=0.95)
        similarity_scale = ttk.Scale(auto_frame, from_=0.8, to=1.0, orient=tk.HORIZONTAL, 
                                   variable=self.similarity_threshold, length=200)
        similarity_scale.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Threshold label
        self.threshold_label = ttk.Label(auto_frame, text="0.95")
        self.threshold_label.grid(row=1, column=3, sticky=tk.W, padx=5)
        similarity_scale.config(command=self.update_threshold_label)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=10)
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Status label
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.grid(row=5, column=0, columnspan=3, sticky=tk.W)
        
        # Results notebook
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        # Duplicates tab
        self.duplicates_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.duplicates_frame, text="Duplicates")
        
        # Create treeview for duplicates
        self.create_duplicates_tree()
        
        # Screenshots tab
        self.screenshots_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.screenshots_frame, text="Screenshots")
        
        # Create treeview for screenshots
        self.create_screenshots_tree()
        
        # Log tab
        self.log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.log_frame, text="Log")
        
        # Create log text widget
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Action buttons
        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=7, column=0, columnspan=3, pady=10)
        
        ttk.Button(action_frame, text="Move to Folder", command=self.move_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Delete Selected", command=self.delete_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Export Report", command=self.export_report).pack(side=tk.LEFT, padx=5)
        
    def update_threshold_label(self, value):
        """Update threshold label"""
        self.threshold_label.config(text=f"{float(value):.2f}")
        
    def create_duplicates_tree(self):
        """Create treeview for duplicates"""
        # Frame for treeview and scrollbars
        tree_frame = ttk.Frame(self.duplicates_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ('file', 'size', 'path', 'type', 'similarity')
        self.duplicates_tree = ttk.Treeview(tree_frame, columns=columns, show='tree headings')
        
        # Configure columns
        self.duplicates_tree.heading('#0', text='Group')
        self.duplicates_tree.heading('file', text='File')
        self.duplicates_tree.heading('size', text='Size')
        self.duplicates_tree.heading('path', text='Path')
        self.duplicates_tree.heading('type', text='Type')
        self.duplicates_tree.heading('similarity', text='Similarity')
        
        # Configure column widths
        self.duplicates_tree.column('#0', width=100)
        self.duplicates_tree.column('file', width=200)
        self.duplicates_tree.column('size', width=80)
        self.duplicates_tree.column('path', width=300)
        self.duplicates_tree.column('type', width=60)
        self.duplicates_tree.column('similarity', width=80)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.duplicates_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.duplicates_tree.xview)
        self.duplicates_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack widgets
        self.duplicates_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Configure grid weights
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Bind selection event
        self.duplicates_tree.bind('<<TreeviewSelect>>', self.on_tree_select)
        
    def create_screenshots_tree(self):
        """Create treeview for screenshots"""
        # Frame for treeview and scrollbars
        tree_frame = ttk.Frame(self.screenshots_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ('file', 'size', 'path', 'date')
        self.screenshots_tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        
        # Configure columns
        self.screenshots_tree.heading('file', text='File')
        self.screenshots_tree.heading('size', text='Size')
        self.screenshots_tree.heading('path', text='Path')
        self.screenshots_tree.heading('date', text='Date')
        
        # Configure column widths
        self.screenshots_tree.column('file', width=200)
        self.screenshots_tree.column('size', width=80)
        self.screenshots_tree.column('path', width=300)
        self.screenshots_tree.column('date', width=120)
        
        # Scrollbars
        v_scrollbar2 = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.screenshots_tree.yview)
        h_scrollbar2 = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.screenshots_tree.xview)
        self.screenshots_tree.configure(yscrollcommand=v_scrollbar2.set, xscrollcommand=h_scrollbar2.set)
        
        # Pack widgets
        self.screenshots_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar2.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar2.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Configure grid weights
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
    def browse_directory(self):
        """Browse for directory to scan"""
        directory = filedialog.askdirectory()
        if directory:
            self.scan_path.set(directory)
            
    def start_scan(self):
        """Start scanning for duplicates"""
        if not self.scan_path.get():
            messagebox.showerror("Error", "Please select a directory to scan")
            return
            
        if not os.path.exists(self.scan_path.get()):
            messagebox.showerror("Error", "Selected directory does not exist")
            return
            
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.clear_results()
        
        # Add to log
        self.log_text.insert(tk.END, f"Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.log_text.insert(tk.END, f"Scan path: {self.scan_path.get()}\n")
        self.log_text.insert(tk.END, f"Auto-remove: {self.auto_remove.get()}\n")
        self.log_text.insert(tk.END, f"Similarity threshold: {self.similarity_threshold.get():.2f}\n\n")
        self.log_text.see(tk.END)
        
        # Start scanning in a separate thread
        scan_thread = threading.Thread(target=self.scan_directory)
        scan_thread.daemon = True
        scan_thread.start()
        
    def stop_scan(self):
        """Stop the scanning process"""
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("Scan stopped")
        
    def clear_results(self):
        """Clear all results"""
        self.duplicates = {}
        self.screenshots = []
        self.selected_files = []
        
        # Clear treeviews
        for item in self.duplicates_tree.get_children():
            self.duplicates_tree.delete(item)
            
        for item in self.screenshots_tree.get_children():
            self.screenshots_tree.delete(item)
            
    def scan_directory(self):
        """Scan directory for duplicates"""
        try:
            path = Path(self.scan_path.get())
            files = []
            
            # Get all files
            self.root.after(0, lambda: self.status_var.set("Collecting files..."))
            
            # Define file extensions
            image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.ico'}
            video_extensions = {'.mp4', '.avi', '.mov', '.mkv', '.flv', '.wmv', '.m4v', '.mpg', '.mpeg', '.3gp', '.webm'}
            
            # Walk through directory
            if self.include_subfolders.get():
                for root, dirs, filenames in os.walk(path):
                    for filename in filenames:
                        if not self.scanning:
                            return
                        file_path = Path(root) / filename
                        ext = file_path.suffix.lower()
                        
                        # Filter by file type
                        if ((self.scan_images.get() and ext in image_extensions) or 
                            (self.scan_videos.get() and ext in video_extensions)):
                            files.append(file_path)
            else:
                for file_path in path.iterdir():
                    if not self.scanning:
                        return
                    if file_path.is_file():
                        ext = file_path.suffix.lower()
                        if ((self.scan_images.get() and ext in image_extensions) or 
                            (self.scan_videos.get() and ext in video_extensions)):
                            files.append(file_path)
                            
            self.total_files = len(files)
            self.logger.info(f"Found {self.total_files} files to process")
            
            if self.total_files == 0:
                self.root.after(0, lambda: messagebox.showinfo("Info", "No files found in the selected directory"))
                return
            
            # Process files
            image_files = []
            video_files = []
            screenshots = []
            
            self.root.after(0, lambda: self.status_var.set("Categorizing files..."))
            
            for i, file_path in enumerate(files):
                if not self.scanning:
                    return
                    
                self.current_file = i + 1
                progress = (i / self.total_files) * 20  # First 20% for categorization
                self.root.after(0, lambda p=progress: self.progress_var.set(p))
                self.root.after(0, lambda: self.status_var.set(f"Categorizing: {file_path.name} ({i+1}/{self.total_files})"))
                
                ext = file_path.suffix.lower()
                
                if ext in image_extensions:
                    if self.classify_screenshots.get() and self.is_screenshot(file_path):
                        screenshots.append(file_path)
                    else:
                        image_files.append(file_path)
                elif ext in video_extensions:
                    video_files.append(file_path)
                    
            self.screenshots = screenshots
            
            # Find duplicates
            self.duplicates = {}
            
            if image_files:
                self.root.after(0, lambda: self.status_var.set("Finding duplicate images..."))
                self.find_duplicate_images(image_files)
                
            if video_files:
                self.root.after(0, lambda: self.status_var.set("Finding duplicate videos..."))
                self.find_duplicate_videos(video_files)
                
            # Update GUI
            self.root.after(0, lambda: self.update_results())
            
            # Auto-remove duplicates if enabled
            if self.auto_remove.get() and self.duplicates:
                self.root.after(0, lambda: self.auto_remove_duplicates())
                
        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Scan failed: {str(e)}"))
        finally:
            self.root.after(0, lambda: self.scan_complete())
            
    def is_screenshot(self, file_path):
        """Check if file is likely a screenshot"""
        name = file_path.name.lower()
        screenshot_indicators = [
            'screenshot', 'screen shot', 'screen_shot', 'capture', 'snap',
            'shot_', 'screen_', 'scr_', 'img_', 'pic_', 'snip'
        ]
        
        return any(indicator in name for indicator in screenshot_indicators)
        
    def calculate_file_hash(self, file_path):
        """Calculate MD5 hash of file"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            self.logger.warning(f"Could not hash {file_path}: {str(e)}")
            return None
            
    def find_duplicate_images(self, image_files):
        """Find duplicate images using multiple methods"""
        if not image_files:
            return
            
        # Method 1: Exact duplicates using file hash
        self.root.after(0, lambda: self.status_var.set("Finding exact image duplicates..."))
        
        file_hashes = defaultdict(list)
        for i, file_path in enumerate(image_files):
            if not self.scanning:
                return
                
            file_hash = self.calculate_file_hash(file_path)
            if file_hash:
                file_hashes[file_hash].append(file_path)
                
            # Update progress
            progress = 20 + (i / len(image_files)) * 30  # 20-50% of total
            self.root.after(0, lambda p=progress: self.progress_var.set(p))
            
        # Add exact duplicates to results
        group_count = 0
        for file_hash, files in file_hashes.items():
            if len(files) > 1:
                group_key = f"exact_image_group_{group_count}"
                self.duplicates[group_key] = {
                    'files': files,
                    'type': 'image',
                    'similarity': 1.0
                }
                group_count += 1
                self.logger.info(f"Found exact image duplicate group: {len(files)} files")
                
        # Method 2: Similar images using perceptual hashing (if available)
        if HAS_IMAGEHASH:
            self.root.after(0, lambda: self.status_var.set("Finding similar images..."))
            
            perceptual_hashes = {}
            for i, file_path in enumerate(image_files):
                if not self.scanning:
                    return
                    
                try:
                    with Image.open(file_path) as img:
                        # Calculate perceptual hash
                        phash = imagehash.phash(img)
                        perceptual_hashes[file_path] = phash
                        
                except Exception as e:
                    self.logger.warning(f"Could not process image {file_path}: {str(e)}")
                    
                # Update progress
                progress = 50 + (i / len(image_files)) * 25  # 50-75% of total
                self.root.after(0, lambda p=progress: self.progress_var.set(p))
                
            # Compare perceptual hashes
            self.root.after(0, lambda: self.status_var.set("Comparing image similarities..."))
            
            processed_files = set()
            file_paths = list(perceptual_hashes.keys())
            
            for i, file1 in enumerate(file_paths):
                if file1 in processed_files or not self.scanning:
                    continue
                    
                similar_files = [file1]
                similarity_score = 1.0
                
                for j, file2 in enumerate(file_paths[i+1:], i+1):
                    if file2 in processed_files:
                        continue
                        
                    try:
                        hash1 = perceptual_hashes[file1]
                        hash2 = perceptual_hashes[file2]
                        
                        # Calculate similarity (lower hamming distance = more similar)
                        hamming_distance = hash1 - hash2
                        similarity = 1 - (hamming_distance / 64.0)
                        
                        if similarity >= self.similarity_threshold.get():
                            similar_files.append(file2)
                            processed_files.add(file2)
                            similarity_score = min(similarity_score, similarity)
                            
                    except Exception as e:
                        self.logger.warning(f"Could not compare {file1} and {file2}: {str(e)}")
                        
                if len(similar_files) > 1:
                    group_key = f"similar_image_group_{group_count}"
                    self.duplicates[group_key] = {
                        'files': similar_files,
                        'type': 'image',
                        'similarity': similarity_score
                    }
                    group_count += 1
                    self.logger.info(f"Found similar image group: {len(similar_files)} files (similarity: {similarity_score:.2f})")
                    
                processed_files.add(file1)
                
                # Update progress
                progress = 75 + (i / len(file_paths)) * 15  # 75-90% of total
                self.root.after(0, lambda p=progress: self.progress_var.set(p))
                
        else:
            self.logger.warning("imagehash library not available, skipping perceptual hash comparison")
            
    def find_duplicate_videos(self, video_files):
        """Find duplicate videos using file hash"""
        if not video_files:
            return
            
        self.root.after(0, lambda: self.status_var.set("Finding duplicate videos..."))
        
        file_hashes = defaultdict(list)
        for i, file_path in enumerate(video_files):
            if not self.scanning:
                return
                
            file_hash = self.calculate_file_hash(file_path)
            if file_hash:
                file_hashes[file_hash].append(file_path)
                
            # Update progress
            progress = 20 + (i / len(video_files)) * 70  # 20-90% of total
            self.root.after(0, lambda p=progress: self.progress_var.set(p))
            
        # Add exact duplicates to results
        group_count = len(self.duplicates)
        for file_hash, files in file_hashes.items():
            if len(files) > 1:
                group_key = f"exact_video_group_{group_count}"
                self.duplicates[group_key] = {
                    'files': files,
                    'type': 'video',
                    'similarity': 1.0
                }
                group_count += 1
                self.logger.info(f"Found exact video duplicate group: {len(files)} files")
                
    def update_results(self):
        """Update GUI with results"""
        # Clear existing items
        for item in self.duplicates_tree.get_children():
            self.duplicates_tree.delete(item)
            
        for item in self.screenshots_tree.get_children():
            self.screenshots_tree.delete(item)
            
        # Add duplicates
        total_duplicate_files = 0
        for group_key, group_data in self.duplicates.items():
            group_item = self.duplicates_tree.insert('', 'end', text=f"Group ({len(group_data['files'])} files)")
            total_duplicate_files += len(group_data['files'])
            
            for file_path in group_data['files']:
                try:
                    file_size = self.format_file_size(file_path.stat().st_size)
                    self.duplicates_tree.insert(group_item, 'end', values=(
                        file_path.name,
                        file_size,
                        str(file_path.parent),
                        group_data['type'],
                        f"{group_data['similarity']:.2f}"
                    ))
                except Exception as e:
                    self.logger.warning(f"Could not get info for {file_path}: {str(e)}")
                    
        # Add screenshots
        for file_path in self.screenshots:
            try:
                file_size = self.format_file_size(file_path.stat().st_size)
                file_date = datetime.fromtimestamp(file_path.stat().st_mtime).strftime('%Y-%m-%d %H:%M')
                
                self.screenshots_tree.insert('', 'end', values=(
                    file_path.name,
                    file_size,
                    str(file_path.parent),
                    file_date
                ))
            except Exception as e:
                self.logger.warning(f"Could not get info for screenshot {file_path}: {str(e)}")
                
        # Update log
        self.log_text.insert(tk.END, f"Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.log_text.insert(tk.END, f"Found {len(self.duplicates)} duplicate groups with {total_duplicate_files} files\n")
        self.log_text.insert(tk.END, f"Found {len(self.screenshots)} screenshots\n\n")
        self.log_text.see(tk.END)
        
    def format_file_size(self, size):
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
        
    def scan_complete(self):
        """Handle scan completion"""
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_var.set(100)
        self.status_var.set("Scan completed")
        
        # Show completion message
        total_duplicates = sum(len(group['files']) for group in self.duplicates.values())
        message = f"Scan completed!\n\nFound {len(self.duplicates)} duplicate groups with {total_duplicates} files\nFound {len(self.screenshots)} screenshots"
        messagebox.showinfo("Scan Complete", message)
        
    def auto_remove_duplicates(self):
        """Auto-remove duplicates based on user preferences"""
        if not self.duplicates:
            return
            
        try:
            # Create backup if requested
            if self.create_backup.get():
                self.create_backup_folder()
                
            removed_count = 0
            total_size_saved = 0
            
            for group_key, group_data in self.duplicates.items():
                files = group_data['files']
                if len(files) <= 1:
                    continue
                    
                # Sort files based on preference
                files_with_info = []
                for file_path in files:
                    try:
                        stat = file_path.stat()
                        files_with_info.append({
                            'path': file_path,
                            'size': stat.st_size,
                            'mtime': stat.st_mtime
                        })
                    except Exception as e:
                        self.logger.warning(f"Could not get file info for {file_path}: {str(e)}")
                        
                if len(files_with_info) <= 1:
                    continue
                    
                # Sort based on preference
                preference = self.keep_preference.get()
                if preference == "newest":
                    files_with_info.sort(key=lambda x: x['mtime'], reverse=True)
                elif preference == "oldest":
                    files_with_info.sort(key=lambda x: x['mtime'])
                elif preference == "largest":
                    files_with_info.sort(key=lambda x: x['size'], reverse=True)
                elif preference == "smallest":
                    files_with_info.sort(key=lambda x: x['size'])
                    
                # Keep the first file, remove the rest
                keep_file = files_with_info[0]
                remove_files = files_with_info[1:]
                
                self.logger.info(f"Keeping: {keep_file['path']}")
                
                for file_info in remove_files:
                    try:
                        file_path = file_info['path']
                        file_size = file_info['size']
                        
                        # Move to backup if enabled, otherwise delete
                        if self.create_backup.get():
                            self.move_to_backup(file_path)
                        else:
                            os.remove(file_path)
                            
                        removed_count += 1
                        total_size_saved += file_size
                        self.logger.info(f"Removed: {file_path}")
                        
                    except Exception as e:
                        self.logger.error(f"Could not remove {file_path}: {str(e)}")
                        
            # Update log
            size_saved_str = self.format_file_size(total_size_saved)
            self.log_text.insert(tk.END, f"Auto-removal completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.log_text.insert(tk.END, f"Removed {removed_count} duplicate files\n")
            self.log_text.insert(tk.END, f"Saved {size_saved_str} of disk space\n\n")
            self.log_text.see(tk.END)
            
            # Show completion message
            messagebox.showinfo("Auto-Remove Complete", 
                              f"Removed {removed_count} duplicate files\nSaved {size_saved_str} of disk space")
            
            # Refresh results
            self.update_results()
            
        except Exception as e:
            self.logger.error(f"Error during auto-removal: {str(e)}")
            messagebox.showerror("Error", f"Auto-removal failed: {str(e)}")
            
    def create_backup_folder(self):
        """Create backup folder for removed files"""
        try:
            backup_dir = Path(self.scan_path.get()) / "DuplicateBackup"
            backup_dir.mkdir(exist_ok=True)
            self.backup_dir = backup_dir
            self.logger.info(f"Created backup directory: {backup_dir}")
        except Exception as e:
            self.logger.error(f"Could not create backup directory: {str(e)}")
            raise
            
    def move_to_backup(self, file_path):
        """Move file to backup directory"""
        try:
            if not hasattr(self, 'backup_dir'):
                self.create_backup_folder()
                
            backup_path = self.backup_dir / file_path.name
            
            # If file with same name exists, add number suffix
            counter = 1
            while backup_path.exists():
                name_parts = file_path.name.rsplit('.', 1)
                if len(name_parts) == 2:
                    backup_path = self.backup_dir / f"{name_parts[0]}_{counter}.{name_parts[1]}"
                else:
                    backup_path = self.backup_dir / f"{file_path.name}_{counter}"
                counter += 1
                
            shutil.move(str(file_path), str(backup_path))
            self.logger.info(f"Moved to backup: {file_path} -> {backup_path}")
            
        except Exception as e:
            self.logger.error(f"Could not move {file_path} to backup: {str(e)}")
            raise
            
    def on_tree_select(self, event):
        """Handle tree selection"""
        tree = event.widget
        selection = tree.selection()
        
        self.selected_files = []
        for item in selection:
            values = tree.item(item, 'values')
            if values:  # This is a file item, not a group
                # Get the file path from the values
                file_name = values[0]
                file_dir = values[2]
                file_path = Path(file_dir) / file_name
                self.selected_files.append(file_path)
                
    def move_selected(self):
        """Move selected files to a folder"""
        if not self.selected_files:
            messagebox.showwarning("Warning", "No files selected")
            return
            
        # Ask for destination folder
        destination = filedialog.askdirectory(title="Select destination folder")
        if not destination:
            return
            
        destination_path = Path(destination)
        moved_count = 0
        
        for file_path in self.selected_files:
            try:
                if file_path.exists():
                    dest_file = destination_path / file_path.name
                    
                    # If file with same name exists, add number suffix
                    counter = 1
                    while dest_file.exists():
                        name_parts = file_path.name.rsplit('.', 1)
                        if len(name_parts) == 2:
                            dest_file = destination_path / f"{name_parts[0]}_{counter}.{name_parts[1]}"
                        else:
                            dest_file = destination_path / f"{file_path.name}_{counter}"
                        counter += 1
                        
                    shutil.move(str(file_path), str(dest_file))
                    moved_count += 1
                    self.logger.info(f"Moved: {file_path} -> {dest_file}")
                    
            except Exception as e:
                self.logger.error(f"Could not move {file_path}: {str(e)}")
                messagebox.showerror("Error", f"Could not move {file_path.name}: {str(e)}")
                
        if moved_count > 0:
            messagebox.showinfo("Success", f"Moved {moved_count} files to {destination}")
            self.update_results()
            
    def delete_selected(self):
        """Delete selected files"""
        if not self.selected_files:
            messagebox.showwarning("Warning", "No files selected")
            return
            
        # Confirm deletion
        file_names = [f.name for f in self.selected_files]
        if len(file_names) > 5:
            display_names = file_names[:5] + [f"... and {len(file_names) - 5} more"]
        else:
            display_names = file_names
            
        message = f"Are you sure you want to delete the following files?\n\n" + "\n".join(display_names)
        if messagebox.askyesno("Confirm Delete", message):
            deleted_count = 0
            
            for file_path in self.selected_files:
                try:
                    if file_path.exists():
                        os.remove(file_path)
                        deleted_count += 1
                        self.logger.info(f"Deleted: {file_path}")
                        
                except Exception as e:
                    self.logger.error(f"Could not delete {file_path}: {str(e)}")
                    messagebox.showerror("Error", f"Could not delete {file_path.name}: {str(e)}")
                    
            if deleted_count > 0:
                messagebox.showinfo("Success", f"Deleted {deleted_count} files")
                self.update_results()
                
    def export_report(self):
        """Export scan results to a text file"""
        if not self.duplicates and not self.screenshots:
            messagebox.showwarning("Warning", "No results to export")
            return
            
        # Ask for save location
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Export Report"
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("Duplicate Cleaner Report\n")
                f.write("=" * 50 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Scan Path: {self.scan_path.get()}\n")
                f.write(f"Similarity Threshold: {self.similarity_threshold.get():.2f}\n\n")
                
                # Write duplicates
                f.write("DUPLICATE FILES\n")
                f.write("-" * 30 + "\n")
                
                if self.duplicates:
                    for group_key, group_data in self.duplicates.items():
                        f.write(f"\nGroup: {group_key}\n")
                        f.write(f"Type: {group_data['type']}\n")
                        f.write(f"Similarity: {group_data['similarity']:.2f}\n")
                        f.write(f"Files ({len(group_data['files'])}):\n")
                        
                        for file_path in group_data['files']:
                            try:
                                file_size = self.format_file_size(file_path.stat().st_size)
                                f.write(f"  - {file_path} ({file_size})\n")
                            except Exception as e:
                                f.write(f"  - {file_path} (error getting size)\n")
                                
                else:
                    f.write("No duplicates found.\n")
                    
                # Write screenshots
                f.write("\n\nSCREENSHOTS\n")
                f.write("-" * 20 + "\n")
                
                if self.screenshots:
                    for file_path in self.screenshots:
                        try:
                            file_size = self.format_file_size(file_path.stat().st_size)
                            file_date = datetime.fromtimestamp(file_path.stat().st_mtime).strftime('%Y-%m-%d %H:%M')
                            f.write(f"- {file_path} ({file_size}, {file_date})\n")
                        except Exception as e:
                            f.write(f"- {file_path} (error getting info)\n")
                            
                else:
                    f.write("No screenshots found.\n")
                    
                # Write summary
                total_duplicates = sum(len(group['files']) for group in self.duplicates.values())
                f.write(f"\n\nSUMMARY\n")
                f.write("-" * 15 + "\n")
                f.write(f"Duplicate Groups: {len(self.duplicates)}\n")
                f.write(f"Duplicate Files: {total_duplicates}\n")
                f.write(f"Screenshots: {len(self.screenshots)}\n")
                
            messagebox.showinfo("Success", f"Report exported to {file_path}")
            
        except Exception as e:
            self.logger.error(f"Could not export report: {str(e)}")
            messagebox.showerror("Error", f"Could not export report: {str(e)}")


def main():
    """Main function to run the application"""
    root = tk.Tk()
    app = DuplicateCleanerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()