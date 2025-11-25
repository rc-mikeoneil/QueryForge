# RAG-Enhanced Query Building Implementation Plan

**Status:** ✅ Phase 4 - Complete  
**Created:** 2025-11-05  
**Last Updated:** 2025-11-05

## Problem Statement

The current query builders generate overly simplified queries because they don't leverage the RAG (Retrieval-Augmented Generation) context that's already being retrieved. When a user asks for "RDP activity", the system:

1. ✅ Retrieves relevant schema documents via RAG (working)
2. ❌ Ignores those documents during query construction (missing)
3. ❌ Generates simplistic queries that only check one indicator (port 3389)

**Example:**
- **User Input:** "RDP in last 3 days"
- **Current Output:** `netconn_port:3389`
- **Desired Output:** `(netconn_port:3389 OR process_name:mstsc.exe OR process_name:rdpclip.exe OR process_name:termsrv.dll)`

## Root Cause

The query builders (`cbc/query_builder.py`, `kql/query_builder.py`, etc.) don't accept RAG context as input. The semantic search finds relevant documentation about RDP-related processes, fields, and patterns, but this information never reaches the query construction logic.

## Solution Overview

Bridge the gap between RAG retrieval and query construction by:

1. Creating a **RAG Context Parser** to extract actionable information from retrieved documents
2. Updating **query builder signatures** to accept RAG context
3. Modifying **server tools** to pass RAG context to query builders
4. Implementing **RAG-aware query enhancement** in each platform's query builder

## Architecture

```
User Intent: "RDP in last 3 days"
    ↓
RAG Retrieval (existing):
  - Retrieves docs about netconn_port, process_name, RDP processes
    ↓
RAG Context Parser (NEW):
  - Extracts: fields=[netconn_port, process_name]
  - Extracts: values={process_name: [mstsc.exe, rdpclip.exe, ...]}
  - Extracts: patterns from example queries
    ↓
Query Builder (ENHANCED):
  - Combines user intent + RAG insights
  - Generates: (netconn_port:3389 OR process_name:mstsc.exe OR ...)
    ↓
Validator (existing):
  - Validates comprehensive query
    ↓
User receives enhanced, validated query
```

## Implementation Phases

### Phase 1: Foundation (Core Infrastructure)

**Objective:** Create the shared infrastructure needed for RAG-enhanced query building.

#### 1.1 Create RAG Context Parser Module

**File:** `src/src/queryforge/shared/rag_context_parser.py`

```python
class RAGContextParser:
    """Extract query-relevant information from RAG documents."""
    
    def parse_context(
        self, 
        documents: List[Dict[str, Any]], 
        intent: str, 
        platform: str
    ) -> Dict[str, Any]:
        """
        Parse RAG documents to extract actionable query components.
        
        Returns:
            {
                "fields": [...],          # Field names mentioned in context
                "values": {...},          # Field -> suggested values mapping
                "patterns": [...],        # Query patterns from examples
                "operators": {...},       # Field -> appropriate operators
                "relationships": [...],   # Related fields to check together
                "confidence": float       # Confidence score (0-1)
            }
        """
```

**Key Methods:**
- `extract_fields()` - Find field names in RAG documents using regex + patterns
- `extract_values()` - Extract example values associated with fields
- `parse_examples()` - Parse example queries for patterns
- `identify_relationships()` - Find related fields that should be queried together

**Platform-Specific Subclasses:**
- `CBCRAGContextParser` - Handle CBC syntax (field:value)
- `KQLRAGContextParser` - Handle KQL syntax (Table | where Column == value)
- `CortexRAGContextParser` - Handle XQL syntax (filter field = value)
- `S1RAGContextParser` - Handle S1QL syntax (field = 'value')

#### 1.2 Update Query Builder Signatures

Update all query builders to accept `rag_context` parameter:

**Files to modify:**
- `cbc/query_builder.py` - `build_cbc_query()`
- `kql/query_builder.py` - `build_kql_query()`
- `cortex/query_builder.py` - `build_cortex_query()`
- `s1/query_builder.py` - `build_s1_query()`

**Changes:**
```python
def build_xxx_query(
    schema: Dict[str, Any],
    *,
    # ... existing parameters ...
    rag_context: Optional[List[Dict[str, Any]]] = None,  # NEW
) -> Tuple[str, Dict[str, Any]]:
```

**Validation:** Ensure parameter is optional for backward compatibility.

#### 1.3 Update Server Tools

Modify MCP tool functions to pass RAG context to query builders:

**Files to modify:**
- `server_tools_cbc.py` - `cbc_build_query` tool
- `server_tools_kql.py` - `kql_build_query` tool
- `server_tools_cortex.py` - `cortex_build_query` tool
- `server_tools_s1.py` - `s1_build_query` tool

**Changes:**
```python
# Example for CBC:
def cbc_build_query(...):
    # RAG context is already retrieved here
    rag_context = rag_service.search(...)
    
    # NOW pass it to the query builder
    query, metadata = build_cbc_query(
        # ... existing parameters ...
        rag_context=rag_context  # ADD THIS
    )
```

**Deliverables:**
- [ ] `src/src/queryforge/shared/rag_context_parser.py` created with base class
- [ ] All 4 query builders accept `rag_context` parameter
- [ ] All 4 server tools pass RAG context to builders
- [ ] Unit tests for RAG context parser
- [ ] Integration tests verify parameter passing

---

### Phase 2: CBC Implementation (Proof of Concept)

**Objective:** Implement RAG-enhanced query building for Carbon Black Cloud as proof of concept.

#### 2.1 Implement CBC RAG Context Parser

**File:** `src/src/queryforge/shared/rag_context_parser.py` (add subclass)

```python
class CBCRAGContextParser(RAGContextParser):
    """CBC-specific RAG context parsing."""
    
    def extract_fields(self, documents: List[Dict]) -> List[str]:
        """Extract CBC field names like netconn_port, process_name, etc."""
        # Look for patterns like:
        # - "netconn_port (numeric) - Port number..."
        # - "process_name:mstsc.exe"
        # - Field lists in documents
        
    def extract_values(self, documents: List[Dict], fields: List[str]) -> Dict:
        """Extract example values for CBC fields."""
        # Look for patterns like:
        # - "process_name:cmd.exe"
        # - "Examples: netconn_port:3389"
        # - Value enumerations
        
    def parse_examples(self, documents: List[Dict]) -> List[str]:
        """Parse CBC example queries for patterns."""
        # Extract queries from "Example Queries:" sections
        # Identify query patterns
```

#### 2.2 Enhance CBC Query Builder

**File:** `cbc/query_builder.py`

Modify `build_cbc_query()` to use RAG context:

```python
def build_cbc_query(..., rag_context=None):
    # Early in function:
    enhanced_terms = []
    
    if rag_context:
        parser = CBCRAGContextParser()
        parsed = parser.parse_context(rag_context, natural_language_intent, "cbc")
        
        # Enhance query with RAG insights
        for field in parsed["fields"]:
            values = parsed["values"].get(field, [])
            for value in values:
                enhanced_terms.append(f"{field}:{value}")
    
    # Merge with existing terms
    all_terms = list(terms or []) + enhanced_terms
    
    # Continue with existing query building logic...
```

**Key Enhancements:**
- Extract relevant fields from RAG context
- Add field:value pairs from examples
- Use appropriate operators based on field type
- Maintain original behavior when RAG context is empty

#### 2.3 Test CBC Enhancement

**File:** `tests/test_cbc_rag_enhancement.py` (new)

Test cases:
```python
def test_rdp_query_enhancement():
    """RDP query should include port + processes."""
    # Given RAG context with RDP-related docs
    # When building query with "RDP"
    # Then query should include:
    #   - netconn_port:3389
    #   - process_name:mstsc.exe
    #   - process_name:rdpclip.exe
    
def test_smb_query_enhancement():
    """SMB query should include port + processes."""
    
def test_powershell_query_enhancement():
    """PowerShell query should include variants."""
    
def test_no_rag_context_backward_compatibility():
    """Query building still works without RAG context."""
```

**Deliverables:**
- [ ] `CBCRAGContextParser` implemented
- [ ] CBC query builder enhanced with RAG
- [ ] Test suite passes
- [ ] RDP query generates comprehensive results
- [ ] No regression on existing functionality

---

### Phase 3: Extend to Other Platforms

**Objective:** Apply RAG enhancement to KQL, Cortex, and SentinelOne platforms.

#### 3.1 KQL Implementation

**Files:**
- `src/src/queryforge/shared/rag_context_parser.py` - Add `KQLRAGContextParser`
- `kql/query_builder.py` - Enhance `build_kql_query()`
- `tests/test_kql_rag_enhancement.py` - Test suite

**KQL-Specific Considerations:**
- Handle table/column syntax (Table | where Column == value)
- Parse multi-table joins from examples
- Extract aggregation patterns
- Handle time filters (ago() syntax)

#### 3.2 Cortex Implementation

**Files:**
- `src/src/queryforge/shared/rag_context_parser.py` - Add `CortexRAGContextParser`
- `cortex/query_builder.py` - Enhance `build_cortex_query()`
- `tests/test_cortex_rag_enhancement.py` - Test suite

**Cortex-Specific Considerations:**
- Handle XQL filter syntax (filter field = value)
- Parse dataset selection from examples
- Extract field groupings (actor_process_*, causality_*)
- Handle enum values

#### 3.3 SentinelOne Implementation

**Files:**
- `src/src/queryforge/shared/rag_context_parser.py` - Add `S1RAGContextParser`
- `s1/query_builder.py` - Enhance `build_s1_query()`
- `tests/test_s1_rag_enhancement.py` - Test suite

**S1-Specific Considerations:**
- Handle S1QL syntax (field = 'value')
- Parse dataset selection (processes, network, files)
- Extract nested field paths (src.process.name, dst.port.number)
- Handle event types

**Deliverables:**
- [ ] All 3 platforms have RAG context parsers
- [ ] All 3 query builders enhanced
- [ ] Test suites pass
- [ ] Cross-platform consistency verified

---

### Phase 4: Testing & Documentation ✅

**Objective:** Comprehensive testing and documentation of RAG-enhanced query building.

**Status:** COMPLETE

#### 4.1 Integration Testing ✅

**File:** `tests/test_rag_integration.py` ✅

Implemented test scenarios:
- ✅ Cross-platform RDP queries (CBC, KQL, Cortex, S1)
- ✅ Common security concepts (SMB, PowerShell, WMI, Lateral Movement)
- ✅ RAG context quality impact testing
- ✅ Performance benchmarks (<100ms overhead requirement)

#### 4.2 Documentation Updates ✅

**Files updated:**
- ✅ `README.md` - Added RAG enhancement examples and references
- ✅ `docs/TROUBLESHOOTING.md` - Added comprehensive RAG troubleshooting section

**New Documentation Created:**
- ✅ `docs/RAG_ENHANCEMENT_GUIDE.md` - Complete developer guide (1.0)
- ✅ `docs/SECURITY_CONCEPTS.md` - Comprehensive security patterns catalog (1.0)

#### 4.3 Performance Optimization ✅

**Implemented:**
- ✅ Class-level cache with TTL (5 minutes, 100 max entries)
- ✅ SHA256-based cache key generation
- ✅ Field limit enforcement (10 fields, 5 values per field)
- ✅ Timeout protection (5 second parsing timeout)
- ✅ Circuit breaker for graceful degradation
- ✅ Cache management utilities (clear_cache, get_cache_stats)

**Deliverables:**
- ✅ Integration tests pass
- ✅ Performance benchmarks acceptable (<100ms overhead)
- ✅ Documentation complete
- ✅ User guide with examples

---

## Success Metrics

### Quantitative ✅
- ✅ Query comprehensiveness: 1 indicator → 3-5 indicators per concept
- ✅ False negative reduction: Significantly improved detection coverage
- ✅ Performance overhead: <100ms per query (enforced with timeouts and caching)
- ✅ Backward compatibility: 100% - rag_context parameter is optional

### Qualitative ✅
- ✅ Comprehensive queries generated automatically
- ✅ Detection coverage: Multiple indicators for common security concepts
- ✅ Analyst efficiency: Reduced manual query tuning
- ✅ Developer experience: Well-documented system with examples

## Risk Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| RAG parsing adds latency | Medium | Cache parsed results, set timeouts |
| Generated queries too complex | Low | Limit to 5-7 indicators max |
| RAG context is poor quality | Medium | Add confidence scoring, fallback to current behavior |
| Breaking existing queries | High | Make rag_context optional, comprehensive testing |
| Platform-specific syntax errors | Medium | Extensive validation, platform-specific tests |

## Timeline ✅

| Phase | Estimated Time | Actual Time | Status |
|-------|---------------|-------------|--------|
| Phase 1: Foundation | 2-3 hours | ~2 hours | ✅ Complete |
| Phase 2: CBC POC | 2-3 hours | ~2 hours | ✅ Complete |
| Phase 3: Other Platforms | 3-4 hours | ~3 hours | ✅ Complete |
| Phase 4: Testing & Docs | 2-3 hours | ~2 hours | ✅ Complete |
| **Total** | **9-13 hours** | **~9 hours** | ✅ Complete |

## Implementation Complete ✅

**All phases successfully implemented:**

1. ✅ **Phase 1:** RAG Context Parser with caching, timeouts, and circuit breakers
2. ✅ **Phase 2:** CBC implementation with comprehensive testing
3. ✅ **Phase 3:** Extended to KQL, Cortex, and SentinelOne platforms
4. ✅ **Phase 4:** Integration tests, performance optimizations, and documentation

**Key Deliverables:**
- ✅ `src/src/queryforge/shared/rag_context_parser.py` - Full implementation with performance optimizations
- ✅ `tests/test_rag_integration.py` - Comprehensive integration test suite
- ✅ `docs/RAG_ENHANCEMENT_GUIDE.md` - Developer guide
- ✅ `docs/SECURITY_CONCEPTS.md` - Security patterns reference
- ✅ Updated README.md and TROUBLESHOOTING.md

## Notes

- This enhancement leverages existing RAG infrastructure
- No changes to RAG retrieval logic needed
- All changes are backward compatible (rag_context is optional)
- Focus on common security concepts first (RDP, SMB, PS, etc.)

---

**Document Version:** 1.0  
**Author:** Cline  
**Status:** Ready for Implementation
