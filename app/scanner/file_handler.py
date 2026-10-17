"""Secure file upload and ZIP handling"""
import os
import zipfile
import tempfile
import shutil
from pathlib import Path
from flask import current_app


class FileHandler:
    """Handles secure file uploads and ZIP extraction"""
    
    SUPPORTED_EXTENSIONS = {'.py', '.js', '.java', '.php', '.zip'}
    
    def __init__(self):
        self.temp_dirs = []
    
    def validate_file(self, filename: str) -> tuple[bool, str]:
        """Validate uploaded file"""
        if not filename:
            return False, "Filename is empty"
        
        # Check extension
        file_ext = Path(filename).suffix.lower()
        if file_ext not in self.SUPPORTED_EXTENSIONS:
            return False, f"Unsupported file type. Supported: {', '.join(self.SUPPORTED_EXTENSIONS)}"
        
        return True, "File is valid"
    
    def validate_file_size(self, file_obj) -> tuple[bool, str]:
        """Validate file size"""
        # Get file size
        file_obj.seek(0, 2)
        size = file_obj.tell()
        file_obj.seek(0)
        
        max_size = current_app.config.get('MAX_FILE_SIZE', 10485760)
        
        if size > max_size:
            return False, f"File is too large. Max size: {max_size} bytes"
        
        if size == 0:
            return False, "File is empty"
        
        return True, "File size is valid"
    
    def extract_zip_safe(self, zip_path: str) -> tuple[bool, str, list]:
        """
        Safely extract a ZIP file
        
        Returns:
            (success, message, list_of_extracted_files)
        """
        try:
            # Validate ZIP file
            if not zipfile.is_zipfile(zip_path):
                return False, "Invalid ZIP file", []
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Check for ZIP-slip attacks (path traversal)
                file_list = zip_ref.namelist()
                
                if len(file_list) > current_app.config.get('MAX_FILES_IN_ZIP', 100):
                    return False, f"Too many files in ZIP archive", []
                
                # Check for path traversal
                for filename in file_list:
                    if '..' in filename or filename.startswith('/'):
                        return False, "Invalid path in ZIP file (path traversal detected)", []
                
                # Check total size after extraction
                total_size = sum(info.file_size for info in zip_ref.infolist())
                max_zip_size = current_app.config.get('MAX_ZIP_SIZE', 52428800)
                
                if total_size > max_zip_size:
                    return False, f"Extracted files too large", []
                
                # Extract to temporary directory
                temp_dir = tempfile.mkdtemp(prefix='audit_scan_')
                self.temp_dirs.append(temp_dir)
                
                extracted_files = []
                for filename in file_list:
                    if filename.endswith('/'):
                        continue  # Skip directories
                    
                    extracted_path = zip_ref.extract(filename, temp_dir)
                    extracted_files.append(extracted_path)
                
                return True, f"Extracted {len(extracted_files)} files", extracted_files
        
        except zipfile.BadZipFile:
            return False, "Corrupted or malformed ZIP file", []
        except Exception as e:
            return False, f"Error extracting ZIP: {str(e)}", []
    
    def cleanup_temp_dirs(self):
        """Clean up temporary directories"""
        for temp_dir in self.temp_dirs:
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except Exception as e:
                print(f"Error cleaning up {temp_dir}: {e}")
        self.temp_dirs = []
    
    @staticmethod
    def is_supported_file(filename: str) -> bool:
        """Check if file extension is supported"""
        file_ext = Path(filename).suffix.lower()
        return file_ext in FileHandler.SUPPORTED_EXTENSIONS
    
    @staticmethod
    def read_file_safe(filepath: str) -> tuple[bool, str]:
        """
        Safely read a file
        
        Returns:
            (success, content_or_error)
        """
        try:
            # Verify file exists and is readable
            if not os.path.exists(filepath):
                return False, "File not found"
            
            if not os.path.isfile(filepath):
                return False, "Path is not a file"
            
            # Check file size
            file_size = os.path.getsize(filepath)
            if file_size > 5242880:  # 5MB limit for reading
                return False, "File is too large to scan"
            
            # Read file
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            return True, content
        
        except Exception as e:
            return False, f"Error reading file: {str(e)}"
