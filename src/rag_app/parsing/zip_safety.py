"""
압축 문서의 압축폭탄(zip bomb) 방어.

DOCX/XLSX 같은 오피스 문서는 실체가 ZIP이라, 작게 압축된 파일이 풀 때 수백 GB로
부풀도록 조작될 수 있다. 파서가 그런 파일을 그대로 열면 디스크와 메모리가 마른다.
그래서 파싱 전에 압축 해제 크기·비율·파일 수를 확인한다.

원래 문서 자동 색인(ingestion) 모듈에 있었는데, 챗봇 기능을 걷어내면서 이 방어는
파서의 것이므로 파싱 패키지로 옮겼다. 내용은 그대로다.
"""

import zipfile
from pathlib import Path
from dataclasses import dataclass

from ..domain.exceptions import ZipBombError
from ..observability.logging import get_logger, get_current_job_id

logger = get_logger(__name__)

MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MB
MAX_UNCOMPRESSED_RATIO = 100  # 100:1 compression ratio
MAX_FILE_COUNT = 1000


class ZipBombCheckResult:
    """Result of zip bomb detection."""
    is_safe: bool
    uncompressed_size: int
    file_count: int
    compression_ratio: float


class ZipBombDetector:
    """Detects zip bombs in ZIP-based document formats (DOCX, XLSX, PPTX)."""
    
    def __init__(
        self,
        max_uncompressed_size: int = MAX_UNCOMPRESSED_SIZE,
        max_uncompressed_ratio: int = MAX_UNCOMPRESSED_RATIO,
        max_file_count: int = MAX_FILE_COUNT,
    ):
        self.max_uncompressed_size = max_uncompressed_size
        self.max_uncompressed_ratio = max_uncompressed_ratio
        self.max_file_count = max_file_count
    
    def check(self, file_path: Path) -> ZipBombCheckResult:
        """
        Check a ZIP-based file for decompression bombs.
        
        Args:
            file_path: Path to ZIP-based file (DOCX, XLSX, PPTX).
            
        Returns:
            ZipBombCheckResult with safety assessment.
            
        Raises:
            ZipBombError: If zip bomb detected.
        """
        job_id = get_current_job_id()
        
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                file_count = len(zf.infolist())
                
                if file_count > self.max_file_count:
                    result = ZipBombCheckResult(
                        is_safe=False,
                        uncompressed_size=0,
                        file_count=file_count,
                        compression_ratio=0.0,
                    )
                    raise ZipBombError(
                        file_path, 
                        uncompressed_size=0, 
                        file_count=file_count
                    )
                
                total_uncompressed = 0
                for info in zf.infolist():
                    total_uncompressed += info.file_size
                    
                    if total_uncompressed > self.max_uncompressed_size:
                        result = ZipBombCheckResult(
                            is_safe=False,
                            uncompressed_size=total_uncompressed,
                            file_count=file_count,
                            compression_ratio=0.0,
                        )
                        raise ZipBombError(
                            file_path,
                            uncompressed_size=total_uncompressed,
                            file_count=file_count,
                        )
                
                # Calculate compression ratio
                compressed_size = file_path.stat().st_size
                if compressed_size > 0:
                    ratio = total_uncompressed / compressed_size
                    if ratio > self.max_uncompressed_ratio:
                        result = ZipBombCheckResult(
                            is_safe=False,
                            uncompressed_size=total_uncompressed,
                            file_count=file_count,
                            compression_ratio=ratio,
                        )
                        raise ZipBombError(
                            file_path,
                            uncompressed_size=total_uncompressed,
                            file_count=file_count,
                        )
                else:
                    ratio = 0.0
                
                return ZipBombCheckResult(
                    is_safe=True,
                    uncompressed_size=total_uncompressed,
                    file_count=file_count,
                    compression_ratio=ratio,
                )
                
        except zipfile.BadZipFile as e:
            # Not a valid zip file - let parser handle it
            logger.debug("not_zip_file", f"Not a valid zip file: {file_path}",
                        job_id=job_id, file_path=str(file_path))
            return ZipBombCheckResult(
                is_safe=True,
                uncompressed_size=0,
                file_count=0,
                compression_ratio=0.0,
            )
        except ZipBombError:
            raise
        except Exception as e:
            logger.error("zip_check_failed", f"Zip bomb check failed: {e}",
                        job_id=job_id, file_path=str(file_path),
                        error_code=type(e).__name__)
            # On unexpected error, assume safe and let parser handle
            return ZipBombCheckResult(
                is_safe=True,
                uncompressed_size=0,
                file_count=0,
                compression_ratio=0.0,
            )
