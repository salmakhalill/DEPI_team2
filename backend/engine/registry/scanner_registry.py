from engine.scanners.injection.sqli_scanner import SQLInjectionScanner
from engine.scanners.injection.xss_scanner import XSSScanner
from engine.scanners.authentication.auth_scanner import AuthScanner
from engine.scanners.file_security.sensitive_file_scanner import SensitiveFileDisclosureScanner
from engine.scanners.file_security.file_upload_scanner import FileUploadScanner
from engine.scanners.file_security.lfi_scanner import LFIScanner
from engine.scanners.file_security.path_traversal_scanner import PathTraversalScanner

SCANNER_REGISTRY = [
    SQLInjectionScanner,
    XSSScanner,
    AuthScanner,
    SensitiveFileDisclosureScanner,
    FileUploadScanner,
    LFIScanner,
    PathTraversalScanner,
]