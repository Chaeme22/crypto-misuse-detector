"""
Semantic chunking with token-aware sizing, overlap, and structure preservation.
"""

import re
import hashlib
from dataclasses import dataclass, replace
from datetime import datetime
from typing import List, Optional, Tuple
from uuid import UUID

from ..config.schema import AppConfig
from ..domain.models import ParsedBlock, ParsedDocument, EmbeddedChunk
from ..domain.enums import BlockType
from ..processing.sentence_splitter import CompositeSentenceSplitter, create_sentence_splitter
from ..observability.logging import get_logger


logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ChunkingConfig:
    """Configuration for chunking behavior."""
    target_tokens: int = 700
    overlap_tokens: int = 100
    max_tokens: int = 900
    preserve_page_boundary: bool = True
    min_chunk_tokens: int = 50
    table_handling: str = "separate"  # "separate", "inline", "expand"


DEFAULT_CHUNKING_CONFIG = ChunkingConfig()


class TokenCounter:
    """Token counter using model tokenizer or approximation."""
    
    def __init__(self, model_name: str = "BAAI/bge-m3"):
        self.model_name = model_name
        self._tokenizer = None
        self._init_tokenizer()
    
    def _init_tokenizer(self):
        """Initialize tokenizer if available."""
        try:
            from transformers import AutoTokenizer
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            logger.info("tokenizer_loaded", f"Loaded tokenizer for {self.model_name}")
        except Exception as e:
            logger.warning("tokenizer_fallback", f"Using character approximation: {e}")
            self._tokenizer = None
    
    def count(self, text: str) -> int:
        """Count tokens in text."""
        if not text:
            return 0
        
        if self._tokenizer:
            try:
                return len(self._tokenizer.encode(text, add_special_tokens=False))
            except Exception:
                pass
        
        # Fallback: rough approximation (Korean ~1.3 chars/token, English ~4 chars/token)
        korean_chars = len(re.findall(r'[가-힣]', text))
        other_chars = len(text) - korean_chars
        return int(korean_chars / 1.3 + other_chars / 4)


class Chunker:
    """
    Semantic chunker that creates overlapping chunks respecting document structure.
    
    Strategy:
    1. Group blocks by page/section
    2. Split blocks into sentences
    3. Pack sentences into chunks up to target_tokens
    4. Add overlap from previous chunk
    5. Respect page boundaries if configured
    """
    
    def __init__(
        self, 
        config: ChunkingConfig = DEFAULT_CHUNKING_CONFIG,
        token_counter: Optional[TokenCounter] = None,
        sentence_splitter: Optional[CompositeSentenceSplitter] = None,
    ):
        self.config = config
        self.token_counter = token_counter or TokenCounter()
        self.sentence_splitter = sentence_splitter or CompositeSentenceSplitter()
        
        # Validate config
        if config.overlap_tokens >= config.target_tokens:
            raise ValueError("overlap_tokens must be less than target_tokens")
        if config.max_tokens < config.target_tokens:
            raise ValueError("max_tokens must be >= target_tokens")
    
    def chunk_document(
        self, 
        document: ParsedDocument,
        document_id: UUID,
        version_id: UUID,
        index_profile_id: str,
    ) -> List[EmbeddedChunk]:
        """
        Chunk a parsed document into EmbeddedChunks.
        
        Args:
            document: ParsedDocument to chunk.
            document_id: Document UUID.
            version_id: Version UUID.
            index_profile_id: Index profile identifier.
            
        Returns:
            List of EmbeddedChunk objects (without embeddings).
        """
        # Split blocks into sentences
        sentence_blocks = self._split_into_sentences(document.blocks, document.language)
        
        # Group by page/section for boundary preservation
        grouped = self._group_by_boundary(sentence_blocks)
        
        chunks = []
        chunk_index = 0
        previous_chunk_tail = ""
        
        for group in grouped:
            group_chunks = self._chunk_group(
                group=group,
                document_id=document_id,
                version_id=version_id,
                index_profile_id=index_profile_id,
                chunk_index_start=chunk_index,
                previous_tail=previous_chunk_tail,
            )
            
            if group_chunks:
                chunks.extend(group_chunks)
                chunk_index += len(group_chunks)
                # Save tail for overlap
                previous_chunk_tail = group_chunks[-1].content[-self.config.overlap_tokens*4:]  # rough char estimate
        
        # Post-process: remove empty, deduplicate
        chunks = self._post_process(chunks)
        
        logger.info("document_chunked", 
                   f"Document chunked into {len(chunks)} chunks",
                   document_id=str(document_id),
                   chunk_count=len(chunks))
        
        return chunks
    
    def _split_into_sentences(
        self, 
        blocks: Tuple[ParsedBlock, ...], 
        language: str
    ) -> List[ParsedBlock]:
        """Split blocks into sentence-level blocks, with table linearization applied."""
        processed_blocks = []
        for b in blocks:
            if b.block_type == BlockType.TABLE:
                processed_blocks.append(self._linearize_table_block(b))
            else:
                processed_blocks.append(b)
        
        return self.sentence_splitter.split_blocks(processed_blocks, language)
    
    def _linearize_table_block(self, block: ParsedBlock) -> ParsedBlock:
        """Linearize table block text into standard header + row format if not already formatted."""
        text = block.text.strip()
        if not text:
            return block
        
        # If already formatted with [Header] or [Row], keep as is
        if "[Header]" in text or "[Row" in text:
            return block
        
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) <= 1:
            return block
        
        # If markdown or pipe separated table
        linearized_lines = []
        first_line = lines[0]
        
        if "|" in first_line:
            headers = [c.strip() for c in first_line.split("|") if c.strip()]
            header_str = " | ".join(headers)
            linearized_lines.append(f"[Header] {header_str}")
            
            row_idx = 1
            for line in lines[1:]:
                # Skip markdown separator lines like |---|---|
                if re.match(r'^[|\s:-]+$', line):
                    continue
                cells = [c.strip() for c in line.split("|") if c.strip()]
                row_str = " | ".join(cells)
                linearized_lines.append(f"[Row {row_idx}] {row_str}")
                row_idx += 1
            
            linearized_text = "\n".join(linearized_lines)
            return ParsedBlock(
                block_type=block.block_type,
                text=linearized_text,
                page_number=block.page_number,
                sheet_name=block.sheet_name,
                slide_number=block.slide_number,
                section_path=block.section_path,
                sequence=block.sequence,
                metadata={**block.metadata, "is_linearized_table": True},
            )
        
        return block
    
    def _group_by_boundary(self, blocks: List[ParsedBlock]) -> List[List[ParsedBlock]]:
        """
        Group blocks by page boundary if configured, else by section path.

        조항으로 묶는 쪽이 기본이다. 인용 단위가 조항이고, 페이지 경계는 조항 가운데를
        가른다. 다만 조항 하나가 목표 크기보다 작은 경우가 많아(문서별 중앙값 54~1110토큰)
        조항마다 끊으면 조각 청크가 쏟아진다. 그래서 목표 크기에 닿기 전까지는 다음 조항을
        이어 붙이고, 넘어선 뒤에 오는 조항 경계에서 끊는다.
        """
        if not self.config.preserve_page_boundary:
            groups: List[List[ParsedBlock]] = []
            current: List[ParsedBlock] = []
            current_key = None
            current_tokens = 0

            for block in blocks:
                key = block.section_path
                if current and key != current_key and current_tokens >= self.config.target_tokens:
                    groups.append(current)
                    current, current_tokens = [], 0
                current.append(block)
                current_tokens += self.token_counter.count(block.text)
                current_key = key

            if current:
                groups.append(current)
            return groups

        groups = []
        current_group = []
        current_page = None
        
        for block in blocks:
            page = block.page_number
            
            if current_page is not None and page != current_page:
                # Page boundary - start new group
                if current_group:
                    groups.append(current_group)
                current_group = [block]
                current_page = page
            else:
                current_group.append(block)
                current_page = page
        
        if current_group:
            groups.append(current_group)
        
        return groups
    
    def _chunk_group(
        self,
        group: List[ParsedBlock],
        document_id: UUID,
        version_id: UUID,
        index_profile_id: str,
        chunk_index_start: int,
        previous_tail: str = "",
    ) -> List[EmbeddedChunk]:
        """Chunk a group of blocks into overlapping chunks."""
        chunks = []
        chunk_index = chunk_index_start
        current_chunk_sentences = []
        current_tokens = 0
        
        # Add overlap from previous chunk
        if previous_tail:
            overlap_tokens = self.token_counter.count(previous_tail)
            if overlap_tokens > 0:
                current_chunk_sentences.append(ParsedBlock(
                    block_type=BlockType.PARAGRAPH,
                    text=previous_tail,
                    metadata={"is_overlap": True},
                ))
                current_tokens = overlap_tokens
        
        for block in group:
            sent_tokens = self.token_counter.count(block.text)
            
            # Check if adding this sentence exceeds max
            if current_tokens + sent_tokens > self.config.max_tokens and current_chunk_sentences:
                # Finalize current chunk
                chunk = self._create_chunk(
                    sentences=current_chunk_sentences,
                    document_id=document_id,
                    version_id=version_id,
                    index_profile_id=index_profile_id,
                    chunk_index=chunk_index,
                    group=group,
                )
                if chunk:
                    chunks.append(chunk)
                    chunk_index += 1
                
                # Start new chunk with overlap
                overlap_sentences = self._get_overlap_sentences(current_chunk_sentences)
                current_chunk_sentences = overlap_sentences
                current_tokens = sum(self.token_counter.count(s.text) for s in overlap_sentences)
            
            # Add sentence to current chunk
            current_chunk_sentences.append(block)
            current_tokens += sent_tokens
        
        # Finalize last chunk
        if current_chunk_sentences:
            chunk = self._create_chunk(
                sentences=current_chunk_sentences,
                document_id=document_id,
                version_id=version_id,
                index_profile_id=index_profile_id,
                chunk_index=chunk_index,
                group=group,
            )
            if chunk:
                chunks.append(chunk)
        
        return chunks
    
    def _get_overlap_sentences(self, sentences: List[ParsedBlock]) -> List[ParsedBlock]:
        """Get sentences for overlap from end of chunk."""
        overlap_tokens = 0
        overlap_sentences = []
        
        for sent in reversed(sentences):
            sent_tokens = self.token_counter.count(sent.text)
            if overlap_tokens + sent_tokens <= self.config.overlap_tokens:
                overlap_sentences.insert(0, sent)
                overlap_tokens += sent_tokens
            else:
                break
        
        return overlap_sentences
    
    def _create_chunk(
        self,
        sentences: List[ParsedBlock],
        document_id: UUID,
        version_id: UUID,
        index_profile_id: str,
        chunk_index: int,
        group: List[ParsedBlock],
    ) -> Optional[EmbeddedChunk]:
        """Create an EmbeddedChunk from sentences."""
        if not sentences:
            return None
        
        # Combine text
        content = "\n".join(s.text for s in sentences).strip()
        
        if not content:
            return None
        
        token_count = self.token_counter.count(content)
        
        # Skip if too small (unless this is the first/only chunk)
        if token_count < self.config.min_chunk_tokens and chunk_index > 0:
            return None
        
        # Determine metadata from sentences
        page_numbers = [s.page_number for s in sentences if s.page_number is not None]
        sheet_names = [s.sheet_name for s in sentences if s.sheet_name is not None]
        slide_numbers = [s.slide_number for s in sentences if s.slide_number is not None]
        section_paths = [s.section_path for s in sentences if s.section_path]
        
        # Use most common or first
        page_number = page_numbers[0] if page_numbers else None
        sheet_name = sheet_names[0] if sheet_names else None
        slide_number = slide_numbers[0] if slide_numbers else None
        section_title = section_paths[-1][-1] if section_paths else None
        # 인용에 쓸 전체 경로. 청크 안에서 마지막으로 확정된 조항을 쓴다.
        section_path = tuple(section_paths[-1]) if section_paths else ()
        
        # Generate deterministic chunk ID
        chunk_id = EmbeddedChunk.generate_chunk_id(document_id, version_id, chunk_index)
        
        return EmbeddedChunk(
            chunk_id=chunk_id,
            document_id=document_id,
            version_id=version_id,
            index_profile_id=index_profile_id,
            content=content,
            chunk_index=chunk_index,
            page_number=page_number,
            sheet_name=sheet_name,
            slide_number=slide_number,
            section_title=section_title,
            section_path=section_path,
            language=sentences[0].metadata.get("language", "ko") if sentences[0].metadata else "ko",
            embedding=[0.0],
            token_count=token_count,
            # 청크를 이룬 블록 중 하나라도 검수 대상이면 청크도 검수 대상이다.
            needs_review=any(s.metadata.get("needs_review") for s in sentences if s.metadata),
        )
    
    def _post_process(self, chunks: List[EmbeddedChunk]) -> List[EmbeddedChunk]:
        """Remove empty chunks and deduplicate."""
        # Remove empty
        chunks = [c for c in chunks if c.content and c.content.strip()]
        
        # Deduplicate by content hash
        seen_hashes = set()
        unique_chunks = []
        
        for chunk in chunks:
            content_hash = hashlib.md5(chunk.content.encode()).hexdigest()
            if content_hash not in seen_hashes:
                seen_hashes.add(content_hash)
                unique_chunks.append(chunk)
        
        # Re-index chunk indices.
        # 필드를 나열해 새로 만들지 않는다. 나열에서 빠진 필드가 조용히 사라진다. 실제로
        # 조항 전체 경로와 검수 표시가 이 자리에서 유실됐고, 색인 결과를 보고서야 알았다.
        for idx, chunk in enumerate(unique_chunks):
            unique_chunks[idx] = replace(chunk, chunk_index=idx)

        return unique_chunks


def create_chunker(config: AppConfig) -> Chunker:
    """Factory function to create chunker from AppConfig."""
    chunking_config = ChunkingConfig(
        target_tokens=config.chunking.target_tokens,
        overlap_tokens=config.chunking.overlap_tokens,
        max_tokens=config.chunking.max_tokens,
        preserve_page_boundary=config.chunking.preserve_page_boundary,
    )
    
    return Chunker(
        config=chunking_config,
        token_counter=TokenCounter(config.models.embedding.model_id),
        sentence_splitter=create_sentence_splitter(config),
    )