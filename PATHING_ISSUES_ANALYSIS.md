# Pathing Issues Analysis and Fixes

## Summary

Found **critical pathing issues** in 3 platform schema loaders (CBC, KQL, CBR) that use incorrect `sys.path` manipulation to import shared modules.

## Issues Found

### 1. CBC Schema Loader (`src/queryforge/platforms/cbc/schema_loader.py`)
**Line 13-15:**
```python
# Import path validation utilities
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from queryforge.shared.security import validate_schema_path, validate_glob_results
```

**Problem:** Incorrectly inserts `parent.parent` which resolves to `src/queryforge/platforms/` instead of the proper Python package path.

### 2. KQL Schema Loader (`src/queryforge/platforms/kql/schema_loader.py`)
**Line 9-11:**
```python
# Import path validation utilities
sys.path.insert(0, str(Path(__file__).parent.parent))
from queryforge.shared.security import validate_schema_path, validate_glob_results
```

**Problem:** Same incorrect `sys.path` manipulation as CBC.

### 3. CBR Schema Loader (`src/queryforge/platforms/cbr/schema_loader.py`)
**Line 12-14:**
```python
# Import path validation utilities
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from queryforge.shared.security import validate_schema_path, validate_glob_results
```

**Problem:** Same incorrect `sys.path` manipulation as CBC and KQL.

## Why This is Wrong

1. **Incorrect Path Resolution:**
   - `Path(__file__).parent.parent` from `src/queryforge/platforms/cbc/schema_loader.py` resolves to `src/queryforge/platforms/`
   - This is NOT the correct Python package root

2. **Violates Python Package Structure:**
   - QueryForge is a proper Python package under `src/queryforge/`
   - Imports should use proper package notation: `from queryforge.shared.security import ...`
   - The package is already in `sys.path` when installed or when working directory is set correctly

3. **Can Cause Import Conflicts:**
   - Manipulating `sys.path` can cause module import conflicts
   - May import wrong versions of modules or cause circular import issues

4. **Not Needed for Other Platforms:**
   - Cortex, S1 platforms correctly import without `sys.path` manipulation
   - Server modules correctly use proper imports

## Correct Approach

All other modules (Cortex, S1, server tools) properly import using package notation:

**Example from `server_tools_cbc.py`:**
```python
from queryforge.platforms.cbc.query_builder import (
    DEFAULT_BOOLEAN_OPERATOR,
    build_cbc_query,
)
from queryforge.platforms.cbc.schema_loader import normalise_search_type
from queryforge.platforms.cbc.validator import CBCValidator
from queryforge.server.server_runtime import ServerRuntime
from queryforge.server.server_tools_shared import attach_rag_context
```

**Example from Cortex schema_loader.py (CORRECT):**
```python
from __future__ import annotations

import hashlib
import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)
# No sys.path manipulation needed!
```

## Solution

Remove the `sys.path` manipulation and use proper package imports:

```python
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Proper package import - no sys.path manipulation needed
from queryforge.shared.security import validate_schema_path, validate_glob_results

logger = logging.getLogger(__name__)
```

## Files to Fix

1. `src/queryforge/platforms/cbc/schema_loader.py` - Remove lines 13-15, use proper import
2. `src/queryforge/platforms/kql/schema_loader.py` - Remove lines 9-11, use proper import
3. `src/queryforge/platforms/cbr/schema_loader.py` - Remove lines 12-14, use proper import

## Impact Assessment

**Low Risk Fix:**
- All platform loaders are used within the QueryForge package context
- The package is properly installed via `pip install -e .` or similar
- Tests import from package root, so imports will work correctly
- Server runtime properly sets up Python path for MCP server execution

**Testing Required:**
- Run existing unit tests to verify imports work
- Test MCP server startup to ensure schema loaders function
- Validate query building still works for all three platforms
