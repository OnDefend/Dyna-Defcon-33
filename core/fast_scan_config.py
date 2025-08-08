
# Fast Scan Mode Configuration
# Use this for quick validation scans

FAST_SCAN_LIMITS = {
    'max_files_per_plugin': 200,
    'max_analysis_time_seconds': 120,
    'batch_size': 25,
    'skip_framework_files': True,
    'reduce_logging': True,
    'parallel_processing': True,
    'quick_crypto_analysis': True,
    'simplified_secret_detection': True
}

def apply_fast_scan_optimizations():
    """Apply fast scan optimizations."""
    import logging
    
    # Reduce logging to WARNING level for performance
    logging.getLogger().setLevel(logging.WARNING)
    
    # Set environment variables for fast mode
    import os
    os.environ['AODS_FAST_MODE'] = '1'
    os.environ['AODS_MAX_FILES'] = '200'
    os.environ['AODS_BATCH_SIZE'] = '25'
    
    return FAST_SCAN_LIMITS
