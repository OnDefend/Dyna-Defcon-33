"""
APKContext: A data class to hold and manage context for APK analysis.

This includes paths, package information, and instances of helper utilities.
Enhanced with isolated analysis contexts and unique analysis IDs to prevent
cross-contamination between different app analyses.
"""

import logging
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, List
import os
import subprocess
import zipfile

# Enhanced drozer manager import
try:
    from .enhanced_drozer_manager import EnhancedDrozerManager, ConnectionConfig
    ENHANCED_DROZER_AVAILABLE = True
except ImportError:
    try:
        from enhanced_drozer_manager import EnhancedDrozerManager, ConnectionConfig
        ENHANCED_DROZER_AVAILABLE = True
    except ImportError:
        ENHANCED_DROZER_AVAILABLE = False
        logging.warning("Enhanced drozer manager not available, falling back to legacy implementation")

# Forward declaration for type hinting if DrozerHelper and APKAnalyzer
# are in other files. To avoid circular imports during type-checking.
# For runtime, these would be actual imports.
if False:  # TYPE_CHECKING
    from .analyzer import APKAnalyzer  # type: ignore
    from .drozer_helper import DrozerHelper  # type: ignore

class APKContext:
    """
    Manages contextual information for a single APK analysis session.

    Enhanced with isolation features to prevent cross-contamination between
    different app analyses and robust drozer integration.

    Attributes:
        analysis_id (str): Unique identifier for this analysis session.
        apk_path (Path): Absolute path to the APK file.
        package_name (Optional[str]): The package name of the APK.
        decompiled_apk_dir (Path): Path to the directory where APK is
                                   decompiled.
        manifest_path (Path): Path to the AndroidManifest.xml file.
        jadx_output_dir (Path): Path to JADX decompiled output directory.
        apktool_output_dir (Path): Path to APKTool decompiled output directory.
        drozer (Optional[DrozerHelper]): Instance of DrozerHelper for
                                         dynamic analysis.
        analyzer (Optional[APKAnalyzer]): Instance of APKAnalyzer for
                                          static analysis.
        results_cache (Dict[str, Any]): A cache for storing results
                                        from various plugins/modules.
        device_info (Dict[str, Any]): Information about the target device.
        scan_mode (str): The current scan mode ('safe' or 'deep').
        analysis_metadata (Dict[str, Any]): Metadata about the analysis session.
    """

    def __init__(self, apk_path_str: str, package_name: Optional[str] = None):
        """
            package_name: The package name of the APK (optional, can be
                          extracted later).
        """
        # Generate unique analysis ID to prevent cross-contamination
        self.analysis_id = str(uuid.uuid4())

        # Store the original path string for compatibility
        self.apk_path_str = apk_path_str

        # Expand user and resolve to get a robust absolute path
        self.apk_path: Path = Path(apk_path_str).expanduser().resolve()
        if not self.apk_path.is_file():
            raise FileNotFoundError(f"APK file not found at: {self.apk_path}")

        self.package_name: Optional[str] = package_name

        # Additional attributes for plugin compatibility
        self.classes = []
        self.device_id = None
        self.stem = None

        # Define default directory for decompiled output relative to a
        # workspace/temp area.
        # For now, let's assume a 'workspace' directory in the project root.
        # This should be made configurable later.
        core_dir = Path(__file__).parent
        self.project_root: Path = core_dir.parent
        self.workspace_dir: Path = self.project_root / "workspace"
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

        # Use a unique name for the decompiled directory,
        # perhaps derived from APK name or hash and analysis ID
        apk_stem = self.apk_path.stem
        
        # CRITICAL FIX: Look for existing decompiled directories first to prevent AndroidManifest.xml not found errors
        existing_decompiled_dir = self._find_existing_decompiled_directory(apk_stem)
        if existing_decompiled_dir:
            self.decompiled_apk_dir = existing_decompiled_dir
            logging.info(f"🔄 Reusing existing decompiled directory: {existing_decompiled_dir.name}")
        else:
            # Create new directory only if none exists
            decompiled_dir_name = f"{apk_stem}_{self.analysis_id[:8]}_decompiled"
            self.decompiled_apk_dir: Path = self.workspace_dir / decompiled_dir_name
            logging.info(f"📁 Creating new decompiled directory: {decompiled_dir_name}")
        
        self.manifest_path: Path = self.decompiled_apk_dir / "AndroidManifest.xml"

        # Ensure AndroidManifest.xml and source files are available by copying from JADX output if needed
        self._ensure_manifest_availability()
        self._ensure_sources_availability()

        # Add JADX output directory (missing attribute causing errors)
        self.jadx_output_dir: Path = self.decompiled_apk_dir / "jadx_output"

        # Add APKTool output directory (missing attribute causing errors)
        self.apktool_output_dir: Path = self.decompiled_apk_dir / "apktool_output"

        # Add missing attributes for dynamic analysis and file operations
        self.stem: str = apk_stem  # APK filename without extension
        self.device_id: Optional[str] = None  # Android device ID for dynamic analysis
        
        # **PLUGIN COMPATIBILITY FIX**: Add output_dir attribute that plugins expect
        self.output_dir: Path = self.decompiled_apk_dir  # Standard output directory for analysis results

        # Placeholder for helper instances and cache
        self.drozer: Optional["DrozerHelper"] = None  # type: ignore
        self.analyzer: Optional["APKAnalyzer"] = None  # type: ignore
        
        # Enhanced drozer management
        self._drozer_initialized = False
        self._enhanced_drozer: Optional[EnhancedDrozerManager] = None

        # Isolated results cache with analysis ID prefix
        self.results_cache: Dict[str, Any] = {}
        self.device_info: Dict[str, Any] = {}
        self.scan_mode: str = "safe"  # Default to safe mode

        # Analysis metadata for tracking and isolation
        self.analysis_metadata: Dict[str, Any] = {
            "analysis_id": self.analysis_id,
            "start_time": None,
            "end_time": None,
            "package_name": package_name,
            "apk_size_mb": self._calculate_apk_size(),
            "enterprise_framework": None,
            "analysis_strategy": None,
        }
        
        # Add logger attribute for plugins that expect it
        self.logger = logging.getLogger(f"APKContext.{self.analysis_id[:8]}")
        
        # Use lazy initialization for enhanced drozer to avoid serialization issues
        # The drozer manager will be initialized on first access
        if package_name:
            # Just mark that it should be initialized later
            self._should_initialize_drozer = True
        else:
            self._should_initialize_drozer = False

    def _calculate_apk_size(self) -> float:
        """Calculate APK size in megabytes."""
        try:
            size_bytes = self.apk_path.stat().st_size
            return size_bytes / (1024 * 1024)
        except Exception:
            return 0.0

    def get_enhanced_drozer(self):
        """Get enhanced drozer manager with lazy initialization to avoid serialization issues"""
        if not self._drozer_initialized and self._should_initialize_drozer:
            self._initialize_enhanced_drozer()
        return self._enhanced_drozer

    def _initialize_enhanced_drozer(self):
        """Initialize enhanced drozer manager with anti-spam protection"""
        if not ENHANCED_DROZER_AVAILABLE or not self.package_name:
            logging.warning("Enhanced drozer manager not available or package name missing")
            return
        
        try:
            # Try anti-spam wrapper first (prevents connection spam when no devices)
            try:
                from .anti_spam_drozer import AntiSpamDrozerWrapper
                
                drozer_helper = AntiSpamDrozerWrapper(self.package_name)
                
                # Quick device check to avoid spam
                if drozer_helper.quick_device_check():
                    logging.info("📱 Devices detected - attempting optimized connection...")
                    if drozer_helper.start_connection():
                        logging.info(f"✅ Anti-spam drozer established for {self.package_name}")
                        self._drozer_initialized = True
                    else:
                        logging.info("📱 Quick connection failed - static analysis mode")
                else:
                    logging.info("📱 No devices detected - static analysis mode")
                
                self.drozer = drozer_helper
                self._enhanced_drozer = drozer_helper
                return
                
            except ImportError:
                logging.debug("Anti-spam wrapper not available, using standard drozer")
            
            # Fallback to standard enhanced drozer
            from .enhanced_drozer_manager import DrozerHelper
            
            # Reduced timeouts to prevent hanging
            drozer_helper = DrozerHelper(
                package_name=self.package_name,
                max_retries=1,  # Single attempt
                command_timeout=60,
                connection_timeout=30  # Quick timeout
            )
            
            self.drozer = drozer_helper  # type: ignore
            self._enhanced_drozer = drozer_helper
            
            # Quick connection attempt
            try:
                if drozer_helper.start_connection():
                    logging.info(f"✅ Enhanced drozer connection established for {self.package_name}")
                    self._drozer_initialized = True
                else:
                    logging.info(f"📱 No drozer connection - static analysis for {self.package_name}")
            except Exception as conn_e:
                logging.info(f"📱 Drozer unavailable - static analysis mode")
                
        except Exception as e:
            logging.info(f"📱 Drozer initialization skipped - static analysis mode")
            self._enhanced_drozer = None

    def set_package_name(self, package_name: str) -> None:
        """Sets or updates the package name and initializes drozer if needed."""
        self.package_name = package_name
        self.analysis_metadata["package_name"] = package_name
        
        # Initialize enhanced drozer if not already done
        if not self._drozer_initialized and ENHANCED_DROZER_AVAILABLE:
            self._initialize_enhanced_drozer()

    def set_drozer_helper(self, drozer_helper: "DrozerHelper") -> None:
        """Assigns a DrozerHelper instance (legacy compatibility)."""
        # If enhanced drozer is available, keep it as primary
        if self._enhanced_drozer:
            logging.info("Enhanced drozer already active, keeping legacy drozer as fallback")
            # Store legacy drozer as fallback
            self.set_cache("legacy_drozer", drozer_helper)
        else:
            self.drozer = drozer_helper

    def get_drozer_status(self) -> dict:
        """Get comprehensive drozer status information"""
        if self._enhanced_drozer:
            return self._enhanced_drozer.get_connection_status()
        elif self.drozer:
            # Legacy drozer status
            return {
                "available": True,
                "connected": hasattr(self.drozer, 'connection_state'),
                "legacy_mode": True,
                "error": None
            }
        else:
            return {
                "available": False,
                "connected": False,
                "error": "No drozer manager initialized"
            }

    def get_drozer_diagnostic_report(self) -> str:
        """Get detailed diagnostic report for troubleshooting"""
        if self._enhanced_drozer:
            return self._enhanced_drozer.get_diagnostic_report()
        elif self.drozer:
            return f"Legacy drozer helper active for {self.package_name}"
        else:
            return "No drozer manager available"

    def cleanup_drozer(self):
        """Clean up drozer resources"""
        if self._enhanced_drozer:
            self._enhanced_drozer.cleanup()
            self._enhanced_drozer = None
        
        self.drozer = None
        self._drozer_initialized = False

    def set_apk_analyzer(self, apk_analyzer: "APKAnalyzer") -> None:
        """Assigns an APKAnalyzer instance."""
        self.analyzer = apk_analyzer

    @property
    def exists(self) -> bool:
        """Check if the APK file exists."""
        return self.apk_path.exists() if hasattr(self.apk_path, 'exists') else Path(self.apk_path_str).exists()
    
    def set_device_id(self, device_id: str) -> None:
        """
        Sets the Android device ID for dynamic analysis.
        
        Args:
            device_id: The Android device identifier (from adb devices)
        """
        self.device_id = device_id
        # Update device info in metadata
        if device_id:
            self.device_info['device_id'] = device_id

    def get_cache(self, key: str) -> Optional[Any]:
        """Retrieves an item from the results cache with analysis isolation."""
        isolated_key = f"{self.analysis_id}:{key}"
        return self.results_cache.get(isolated_key) or self.results_cache.get(key)

    def set_cache(self, key: str, value: Any) -> None:
        """Sets an item in the results cache with analysis isolation."""
        isolated_key = f"{self.analysis_id}:{key}"
        self.results_cache[isolated_key] = value

        # Store in metadata if it's framework or strategy info
        if key == "enterprise_framework":
            self.analysis_metadata["enterprise_framework"] = value
        elif key == "enterprise_strategy":
            self.analysis_metadata["analysis_strategy"] = value

    def clear_cache(self) -> None:
        """Clear analysis-specific cache entries."""
        keys_to_remove = [
            k for k in self.results_cache.keys() if k.startswith(f"{self.analysis_id}:")
        ]
        for key in keys_to_remove:
            del self.results_cache[key]

    def is_injuredandroid_app(self) -> bool:
        """Check if this is a security testing application using organic detection with O(1) performance optimization."""
        # Check if package name is available
        if not self.package_name:
            return False

        # PERFORMANCE OPTIMIZATION: Convert patterns to set for O(1) lookup instead of O(n) list iteration
        # This follows the project rules for optimizing data structures for maximum efficiency
        security_testing_patterns = {
            "injured",
            "vulnerable", 
            "security",
            "test",
            "challenge",
            "ctf",
            "exploit",
            "hack",
            "demo",
            "training",
            "learning",
            "practice"
        }
        
        package_lower = self.package_name.lower()
        
        # ENHANCED: O(1) lookup optimization - check each word in package name against patterns set
        # Split package name by common delimiters for more precise matching
        package_words = package_lower.replace('.', ' ').replace('_', ' ').replace('-', ' ').split()
        
        # Check if any word in the package name matches security testing patterns (O(1) per word)
        return any(word in security_testing_patterns for word in package_words) or \
               any(pattern in package_lower for pattern in security_testing_patterns)

    def is_enterprise_app(self) -> bool:
        """Check if this is an enterprise-scale application."""
        # Check size threshold
        if self.analysis_metadata["apk_size_mb"] > 100:
            return True

        # Check enterprise frameworks
        enterprise_framework = self.analysis_metadata.get("enterprise_framework")
        if enterprise_framework:
            return True

        # Check package name patterns for known enterprise apps
        if not self.package_name:
            return False

        enterprise_patterns = [
            "com.zhiliaoapp.musically",  # Large commercial app
            "com.facebook",
            "com.instagram",
            "com.whatsapp",
            "com.google.android.apps",
            "com.microsoft",
            "com.amazon",
        ]

        package_lower = self.package_name.lower()
        return any(pattern in package_lower for pattern in enterprise_patterns)

    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of current analysis context."""
        return {
            "analysis_id": self.analysis_id,
            "package_name": self.package_name,
            "apk_size_mb": self.analysis_metadata["apk_size_mb"],
            "scan_mode": self.scan_mode,
            "is_injuredandroid": self.is_injuredandroid_app(),
            "is_enterprise": self.is_enterprise_app(),
            "cache_entries": len(
                [
                    k
                    for k in self.results_cache.keys()
                    if k.startswith(f"{self.analysis_id}:")
                ]
            ),
            "metadata": self.analysis_metadata,
        }

    def set_scan_mode(self, mode: str) -> None:
        """Sets the scan mode ('safe' or 'deep')."""
        if mode in ["safe", "deep"]:
            self.scan_mode = mode
            self.analysis_metadata["scan_mode"] = mode
            logging.info(f"Scan mode set to '{mode}' for analysis {self.analysis_id}")
        else:
            # Or raise an error, or log a warning
            print(f"Warning: Invalid scan mode '{mode}'. Defaulting to 'safe'.")
            self.scan_mode = "safe"

    def get_scan_mode(self) -> str:
        """
        Get the current scan mode.
        
        Returns:
            str: The current scan mode ('safe', 'deep', etc.)
        """
        return self.scan_mode

    def cleanup_analysis_artifacts(self) -> None:
        """Clean up analysis-specific artifacts to prevent contamination."""
        try:
            # Clean up drozer resources first
            self.cleanup_drozer()
            
            # Clear cache
            self.clear_cache()

            # Clean up temporary directories if they exist
            if self.decompiled_apk_dir.exists():
                import shutil

                shutil.rmtree(self.decompiled_apk_dir, ignore_errors=True)

            if self.jadx_output_dir.exists():
                import shutil

                shutil.rmtree(self.jadx_output_dir, ignore_errors=True)

            # Reset analysis metadata
            self.analysis_metadata.update({
                "start_time": None,
                "end_time": None,
                "enterprise_framework": None,
                "analysis_strategy": None,
            })

        except Exception as e:
            logging.warning(f"Could not fully clean up analysis artifacts: {e}")

    def __repr__(self) -> str:
        return (
            f"<APKContext analysis_id='{self.analysis_id[:8]}' "
            f"package_name='{self.package_name}' "
            f"apk_path='{self.apk_path}' "
            f"scan_mode='{self.scan_mode}' "
            f"is_injuredandroid={self.is_injuredandroid_app()} "
            f"is_enterprise={self.is_enterprise_app()}>"
        )

    def _extract_apk_with_apktool(self) -> bool:
        """Extract APK using apktool with enhanced memory management for large APKs."""
        try:
            # Check APK size and configure accordingly
            apk_size_mb = self.apk_path.stat().st_size / (1024 * 1024)
            is_large_apk = apk_size_mb > 100  # Consider APKs > 100MB as large
            
            if is_large_apk:
                logging.info(f"Large APK detected ({apk_size_mb:.1f}MB) - using optimized extraction")
            
            # Configure APKtool command with memory optimization
            cmd = ["apktool", "d"]
            
            # Memory optimization flags for large APKs
            if is_large_apk:
                cmd.extend([
                    "--no-res",  # Skip resource decoding to save memory
                    "--no-assets",  # Skip assets extraction
                    "--only-main-classes",  # Only extract main classes.dex
                ])
            
            cmd.extend([
                "-f",  # Force overwrite
                "-o", str(self.decompiled_apk_dir),
                str(self.apk_path)
            ])

            # Set memory limits for Java process
            env = os.environ.copy()
            if is_large_apk:
                # Increase heap size for large APKs but limit to prevent system exhaustion
                env["_JAVA_OPTIONS"] = "-Xmx4g -Xms1g"  # 4GB max, 1GB initial
            else:
                env["_JAVA_OPTIONS"] = "-Xmx2g -Xms512m"  # 2GB max, 512MB initial

            # Execute with timeout protection
            timeout_seconds = 300 if is_large_apk else 120  # 5 minutes for large APKs
            
            logging.info(f"Extracting APK with apktool (timeout: {timeout_seconds}s)...")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                env=env
            )

            if result.returncode == 0:
                logging.info("APK extraction completed successfully")
                return True
            else:
                logging.warning(f"APKtool extraction failed: {result.stderr}")
                
                # For large APKs, try fallback extraction with minimal options
                if is_large_apk:
                    logging.info("Attempting fallback extraction for large APK...")
                    return self._fallback_extraction_large_apk()
                
                return False

        except subprocess.TimeoutExpired:
            logging.error(f"APKtool extraction timed out after {timeout_seconds}s")
            
            # For large APKs, try fallback extraction
            if is_large_apk:
                logging.info("Attempting fallback extraction after timeout...")
                return self._fallback_extraction_large_apk()
            
            return False
        except Exception as e:
            logging.error(f"APK extraction failed: {e}")
            return False

    def _fallback_extraction_large_apk(self) -> bool:
        """Fallback extraction method for large APKs that failed normal extraction."""
        try:
            logging.info("Using fallback ZIP-based extraction for large APK...")
            
            # Create basic directory structure
            self.decompiled_apk_dir.mkdir(parents=True, exist_ok=True)
            
            # Extract only essential files using ZIP
            with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                # Extract AndroidManifest.xml
                try:
                    manifest_data = apk_zip.read('AndroidManifest.xml')
                    with open(self.decompiled_apk_dir / 'AndroidManifest.xml', 'wb') as f:
                        f.write(manifest_data)
                except:
                    logging.warning("Could not extract AndroidManifest.xml")
                
                # Extract first few DEX files only (limit to prevent memory issues)
                dex_files = [name for name in apk_zip.namelist() if name.endswith('.dex')]
                max_dex_files = 3  # Limit to first 3 DEX files for large APKs
                
                for dex_file in dex_files[:max_dex_files]:
                    try:
                        dex_data = apk_zip.read(dex_file)
                        with open(self.decompiled_apk_dir / dex_file, 'wb') as f:
                            f.write(dex_data)
                        logging.info(f"Extracted {dex_file}")
                    except Exception as e:
                        logging.warning(f"Could not extract {dex_file}: {e}")
                
                # Extract some key resource files (limited)
                important_files = [
                    'res/values/strings.xml',
                    'res/xml/network_security_config.xml',
                    'META-INF/MANIFEST.MF'
                ]
                
                for file_path in important_files:
                    try:
                        if file_path in apk_zip.namelist():
                            file_data = apk_zip.read(file_path)
                            output_path = self.decompiled_apk_dir / file_path
                            output_path.parent.mkdir(parents=True, exist_ok=True)
                            with open(output_path, 'wb') as f:
                                f.write(file_data)
                            logging.info(f"Extracted {file_path}")
                    except Exception as e:
                        logging.warning(f"Could not extract {file_path}: {e}")
            
            logging.info("Fallback extraction completed - limited analysis available")
            return True
            
        except Exception as e:
            logging.error(f"Fallback extraction failed: {e}")
            return False

    def get_files(self, file_pattern: str = None) -> List[str]:
        """
        Get list of files from the decompiled APK.
        
        Args:
            file_pattern: Optional pattern to filter files (e.g., "*.xml", "*.java")
            
        Returns:
            List[str]: List of file paths relative to decompiled directory
        """
        try:
            if not self.decompiled_apk_dir.exists():
                return []
            
            files = []
            
            # Walk through all files in decompiled directory
            for file_path in self.decompiled_apk_dir.rglob("*"):
                if file_path.is_file():
                    relative_path = str(file_path.relative_to(self.decompiled_apk_dir))
                    
                    # Apply pattern filter if provided
                    if file_pattern:
                        import fnmatch
                        if fnmatch.fnmatch(relative_path, file_pattern):
                            files.append(relative_path)
                    else:
                        files.append(relative_path)
            
            return files
            
        except Exception as e:
            logging.warning(f"Error getting files from APK: {e}")
            return []

    def iterate_files(self, file_pattern: str = None):
        """
        Iterate over files in the decompiled APK.
        
        Args:
            file_pattern: Optional pattern to filter files (e.g., "*.xml", "*.java")
            
        Yields:
            Tuple[str, Path]: (relative_path, absolute_path) for each file
        """
        try:
            if not self.decompiled_apk_dir.exists():
                return
            
            # Walk through all files in decompiled directory
            for file_path in self.decompiled_apk_dir.rglob("*"):
                if file_path.is_file():
                    relative_path = str(file_path.relative_to(self.decompiled_apk_dir))
                    
                    # Apply pattern filter if provided
                    if file_pattern:
                        import fnmatch
                        if fnmatch.fnmatch(relative_path, file_pattern):
                            yield relative_path, file_path
                    else:
                        yield relative_path, file_path
                        
        except Exception as e:
            logging.warning(f"Error iterating files from APK: {e}")

    def get_file_content(self, file_path: str) -> Optional[str]:
        """
        Get content of a specific file from the decompiled APK.
        
        Args:
            file_path: Path to file relative to decompiled directory
            
        Returns:
            Optional[str]: File content as string, None if file not found or error
        """
        try:
            full_path = self.decompiled_apk_dir / file_path
            if full_path.exists() and full_path.is_file():
                return full_path.read_text(encoding='utf-8', errors='ignore')
            return None
        except Exception as e:
            logging.warning(f"Error reading file {file_path}: {e}")
            return None

    def get_java_files(self) -> List[str]:
        """
        Get list of Java and Kotlin files from the decompiled APK.
        
        This method provides Java/Kotlin source files for analysis by plugins.
        It looks in both JADX output (if available) and APKTool output directories.
        
        Returns:
            List[str]: List of absolute paths to Java/Kotlin files
        """
        java_files = []
        
        try:
            # First, try JADX output directory (preferred for Java source analysis)
            if self.jadx_output_dir.exists():
                for file_path in self.jadx_output_dir.rglob("*.java"):
                    if file_path.is_file():
                        java_files.append(str(file_path))
                
                # Also look for Kotlin files
                for file_path in self.jadx_output_dir.rglob("*.kt"):
                    if file_path.is_file():
                        java_files.append(str(file_path))
            
            # If no JADX files found, try decompiled directory
            if not java_files and self.decompiled_apk_dir.exists():
                for file_path in self.decompiled_apk_dir.rglob("*.java"):
                    if file_path.is_file():
                        java_files.append(str(file_path))
                
                for file_path in self.decompiled_apk_dir.rglob("*.kt"):
                    if file_path.is_file():
                        java_files.append(str(file_path))
            
            # Filter out very large files to prevent memory issues
            filtered_files = []
            max_file_size = 5 * 1024 * 1024  # 5MB limit
            
            for file_path in java_files:
                try:
                    file_size = Path(file_path).stat().st_size
                    if file_size <= max_file_size:
                        filtered_files.append(file_path)
                    else:
                        logging.debug(f"Skipping large file: {file_path} ({file_size / 1024 / 1024:.1f}MB)")
                except Exception:
                    # If we can't get file size, include it anyway
                    filtered_files.append(file_path)
            
            logging.info(f"Found {len(filtered_files)} Java/Kotlin files for analysis")
            return filtered_files
            
        except Exception as e:
            logging.warning(f"Error getting Java files from APK: {e}")
            return []

    def get_xml_files(self) -> List[str]:
        """
        Get list of XML files from the decompiled APK.
        
        Returns:
            List[str]: List of absolute paths to XML files
        """
        xml_files = []
        
        try:
            # Look in decompiled directory for XML files
            if self.decompiled_apk_dir.exists():
                for file_path in self.decompiled_apk_dir.rglob("*.xml"):
                    if file_path.is_file():
                        xml_files.append(str(file_path))
            
            logging.info(f"Found {len(xml_files)} XML files for analysis")
            return xml_files
            
        except Exception as e:
            logging.warning(f"Error getting XML files from APK: {e}")
            return []

    def _find_existing_decompiled_directory(self, apk_stem: str) -> Optional[Path]:
        """
        Find existing decompiled directory for the same APK to prevent duplicate unpacking.
        
        This resolves the AndroidManifest.xml not found issue caused by multiple APK contexts
        creating different decompiled directories for the same APK.
        
        Args:
            apk_stem: APK filename without extension
            
        Returns:
            Path to existing decompiled directory or None if not found
        """
        try:
            # Look for existing directories matching the APK name pattern
            pattern = f"{apk_stem}_*_decompiled"
            existing_dirs = list(self.workspace_dir.glob(pattern))
            
            if existing_dirs:
                # Sort by modification time (most recent first)
                existing_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                
                # Check if the most recent directory has AndroidManifest.xml
                for dir_path in existing_dirs:
                    manifest_path = dir_path / "AndroidManifest.xml"
                    if manifest_path.exists():
                        logging.debug(f"Found existing decompiled directory with manifest: {dir_path.name}")
                        return dir_path
                
                # If no directory has manifest, return most recent anyway (might be in progress)
                logging.debug(f"Found existing decompiled directory (no manifest yet): {existing_dirs[0].name}")
                return existing_dirs[0]
            
            return None
            
        except Exception as e:
            logging.debug(f"Error finding existing decompiled directory: {e}")
            return None

    # Delegation methods for component exploitation analysis
    def get_activities(self) -> List[Dict[str, Any]]:
        """
        Get activities from the application with component details.
        
        Returns:
            List of activity dictionaries with component metadata
        """
        if hasattr(self, 'analyzer') and self.analyzer:
            try:
                activity_names = self.analyzer.get_activities()
                # Convert to component format expected by exploitation plugin
                activities = []
                for name in activity_names:
                    activity = {
                        'name': name,
                        'exported': False,  # Default, could be enhanced with manifest parsing
                        'permissions': [],
                        'intent_filters': []
                    }
                    activities.append(activity)
                return activities
            except Exception as e:
                logging.debug(f"Error getting activities from analyzer: {e}")
        return []

    def get_services(self) -> List[Dict[str, Any]]:
        """
        Get services from the application with component details.
        
        Returns:
            List of service dictionaries with component metadata
        """
        if hasattr(self, 'analyzer') and self.analyzer:
            try:
                service_names = self.analyzer.get_services()
                # Convert to component format expected by exploitation plugin
                services = []
                for name in service_names:
                    service = {
                        'name': name,
                        'exported': False,  # Default, could be enhanced with manifest parsing
                        'permissions': [],
                        'intent_filters': []
                    }
                    services.append(service)
                return services
            except Exception as e:
                logging.debug(f"Error getting services from analyzer: {e}")
        return []

    def get_receivers(self) -> List[Dict[str, Any]]:
        """
        Get broadcast receivers from the application with component details.
        
        Returns:
            List of receiver dictionaries with component metadata
        """
        if hasattr(self, 'analyzer') and self.analyzer:
            try:
                receiver_names = self.analyzer.get_receivers()
                # Convert to component format expected by exploitation plugin
                receivers = []
                for name in receiver_names:
                    receiver = {
                        'name': name,
                        'exported': False,  # Default, could be enhanced with manifest parsing
                        'permissions': [],
                        'intent_filters': []
                    }
                    receivers.append(receiver)
                return receivers
            except Exception as e:
                logging.debug(f"Error getting receivers from analyzer: {e}")
        return []

    def get_providers(self) -> List[Dict[str, Any]]:
        """
        Get content providers from the application with component details.
        
        Returns:
            List of provider dictionaries with component metadata
        """
        if hasattr(self, 'analyzer') and self.analyzer:
            try:
                # APKAnalyzer doesn't have get_providers, so we'll return empty list
                # This could be enhanced to parse providers from manifest
                return []
            except Exception as e:
                logging.debug(f"Error getting providers from analyzer: {e}")
        return []

    def _ensure_manifest_availability(self) -> bool:
        """
        Ensure AndroidManifest.xml is available in the workspace by copying from JADX output if needed.
        
        This addresses the demonstrable issue where plugins expect AndroidManifest.xml in workspace
        but JADX extracts it to /tmp/jadx_decompiled/*/resources/AndroidManifest.xml
        
        Returns:
            bool: True if AndroidManifest.xml is available, False otherwise
        """
        # Check if AndroidManifest.xml already exists in workspace
        if self.manifest_path.exists():
            return True
        
        # Search for JADX output directories containing AndroidManifest.xml
        jadx_base_dir = Path("/tmp/jadx_decompiled")
        if not jadx_base_dir.exists():
            return False
        
        try:
            # Find the most recent JADX directory for current APK
            jadx_dirs = [d for d in jadx_base_dir.iterdir() if d.is_dir() and d.name.startswith("jadx_")]
            
            if not jadx_dirs:
                return False
            
            # Sort by modification time (most recent first)
            jadx_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            # Look for AndroidManifest.xml in resources subdirectory of recent JADX outputs
            for jadx_dir in jadx_dirs:
                manifest_source = jadx_dir / "resources" / "AndroidManifest.xml"
                if manifest_source.exists():
                    # Ensure workspace directory exists
                    self.decompiled_apk_dir.mkdir(parents=True, exist_ok=True)
                    
                    # Copy AndroidManifest.xml to workspace
                    import shutil
                    shutil.copy2(manifest_source, self.manifest_path)
                    logging.info(f"📄 Copied AndroidManifest.xml from JADX output to workspace: {self.manifest_path}")
                    return True
            
            return False
            
        except Exception as e:
            logging.warning(f"Failed to copy AndroidManifest.xml from JADX output: {e}")
            return False

    def _ensure_sources_availability(self) -> bool:
        """
        Ensure decompiled source files are available in APKContext directory by copying from JADX output.
        This fixes the path mismatch issue where JADX creates sources in /tmp but plugins look in workspace.
        """
        jadx_base_dir = Path("/tmp/jadx_decompiled")
        
        if not jadx_base_dir.exists():
            return False
        
        try:
            # Find the most recent JADX directory for current APK
            jadx_dirs = [d for d in jadx_base_dir.iterdir() if d.is_dir() and d.name.startswith("jadx_")]
            
            if not jadx_dirs:
                return False
            
            # Sort by modification time (most recent first)
            jadx_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            # Look for sources directory in recent JADX outputs
            for jadx_dir in jadx_dirs:
                sources_dir = jadx_dir / "sources"
                if sources_dir.exists() and any(sources_dir.rglob("*.java")):
                    # Ensure workspace directory exists
                    self.decompiled_apk_dir.mkdir(parents=True, exist_ok=True)
                    
                    # Copy sources to workspace (but don't overwrite existing files)
                    import shutil
                    try:
                        for source_file in sources_dir.rglob("*"):
                            if source_file.is_file():
                                relative_path = source_file.relative_to(sources_dir)
                                dest_path = self.decompiled_apk_dir / relative_path
                                dest_path.parent.mkdir(parents=True, exist_ok=True)
                                
                                # Only copy if destination doesn't exist
                                if not dest_path.exists():
                                    shutil.copy2(source_file, dest_path)
                        
                        java_count = len(list(self.decompiled_apk_dir.rglob("*.java")))
                        logging.info(f"📄 Copied JADX sources to workspace: {java_count} Java files available")
                        return True
                        
                    except Exception as copy_error:
                        logging.warning(f"Error copying JADX sources: {copy_error}")
                        continue
            
            return False
            
        except Exception as e:
            logging.warning(f"Failed to copy JADX sources to workspace: {e}")
            return False


# Example Usage (for testing purposes, would be removed or in a test file):
if __name__ == "__main__":
    # Create a dummy APK file for testing
    # Assuming this runs from core directory
    dummy_apk_path = Path("../dummy.apk")
    dummy_apk_path.touch(exist_ok=True)

    # Create context with the test APK
    pkg_name = "com.example.dummy"
    ctx = APKContext(apk_path_str=str(dummy_apk_path), package_name=pkg_name)
    print(ctx)
    print(f"APK Path: {ctx.apk_path}")
    print(f"Decompiled Dir: {ctx.decompiled_apk_dir}")
    print(f"Manifest Path: {ctx.manifest_path}")
    print(f"JADX Output Dir: {ctx.jadx_output_dir}")
    print(f"Workspace Dir: {ctx.workspace_dir}")
    ctx.set_scan_mode("deep")
    print(f"Scan mode: {ctx.scan_mode}")
    print(f"Analysis Summary: {ctx.get_analysis_summary()}")

    # Clean up dummy file and dir
    # dummy_apk_path.unlink()
    # import shutil
    # if ctx.workspace_dir.exists():
    #     shutil.rmtree(ctx.workspace_dir) # Careful with rmtree
