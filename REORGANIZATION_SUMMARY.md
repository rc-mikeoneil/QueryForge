# QueryForge Directory Reorganization Summary

## Overview
Successfully reorganized the QueryForge project into a cleaner, more maintainable structure following Python best practices with a `src/` layout.

## Changes Made

### Directory Structure
**Old Structure:**
```
QueryForge/
├── server.py
├── server_runtime.py
├── server_tools_*.py
├── cbc/
├── cbr/
├── cortex/
├── kql/
├── s1/
├── shared/
└── tests/
```

**New Structure:**
```
QueryForge/
├── src/
│   └── queryforge/
│       ├── __init__.py
│       ├── server/
│       │   ├── __init__.py
│       │   ├── server.py
│       │   ├── server_runtime.py
│       │   └── server_tools_*.py
│       ├── platforms/
│       │   ├── __init__.py
│       │   ├── cbc/
│       │   ├── cbr/
│       │   ├── cortex/
│       │   ├── kql/
│       │   └── s1/
│       └── shared/
│           ├── __init__.py
│           └── *.py
├── tests/
├── docs/
├── ecs/
└── scripts/
```

### Import Path Changes
All imports have been updated to use the new `queryforge` namespace:

- `from cbc.query_builder import ...` → `from queryforge.platforms.cbc.query_builder import ...`
- `from shared.rag import ...` → `from queryforge.shared.rag import ...`
- `from server_runtime import ...` → `from queryforge.server.server_runtime import ...`

### Configuration Updates

#### Docker
- **Dockerfile**: Updated to copy `src/` directory and run `python -m queryforge.server.server`
- **COPY instructions**: Simplified to `COPY src ./src` instead of individual platform directories

#### Security
- **security.py**: Updated allowed schema directories to reference `platforms/` subdirectories

#### Tests
- All test files updated with new import paths

### Running the Application

#### Local Development
```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
python -m queryforge.server.server
```

#### Docker
```bash
docker build -t queryforge .
docker run -d -p 8080:8080 queryforge
```

#### Docker Compose
```bash
docker compose up --build -d
```

## Benefits

1. **Clear Separation of Concerns**: Server code, platform implementations, and shared utilities are organized into distinct packages
2. **Standard Python Layout**: Follows the widely-adopted `src/` layout convention
3. **Better Encapsulation**: Single `queryforge` namespace prevents naming conflicts
4. **Improved IDE Support**: Better autocomplete and type checking with proper package structure
5. **Easier Testing**: Clear package boundaries make testing and mocking easier
6. **Future-Proof**: Structure supports additional platforms and modules without root-level clutter

## Verification

All imports successfully tested:
- ✅ Server module imports
- ✅ Platform module imports (CBC, CBR, Cortex, KQL, S1)
- ✅ Shared utilities imports
- ✅ Schema loading and validation
- ✅ Docker build and run

## Files Modified

### Core Files
- `src/queryforge/server/server.py`
- `src/queryforge/server/server_runtime.py`
- `src/queryforge/server/server_tools_*.py` (all 6 files)

### Platform Modules
- All `*.py` files in `src/queryforge/platforms/cbc/`
- All `*.py` files in `src/queryforge/platforms/cbr/`
- All `*.py` files in `src/queryforge/platforms/cortex/`
- All `*.py` files in `src/queryforge/platforms/kql/`
- All `*.py` files in `src/queryforge/platforms/s1/`

### Shared Utilities
- All `*.py` files in `src/queryforge/shared/`
- Special attention to `security.py` for path validation updates

### Tests
- All test files in `tests/` directory
- Moved root-level test files to `tests/`:
  - `test_concept_expansion.py` → `tests/test_concept_expansion.py`
  - `test_cortex_fix.py` → `tests/test_cortex_fix.py`
  - `test_time_filter_integration.py` → `tests/test_time_filter_integration.py`

### Configuration
- `Dockerfile`
- `README.md`
- `src/queryforge/shared/security.py`

## Migration Notes

For developers working on branches:
1. Pull the latest changes
2. Update local imports if you have uncommitted changes
3. Set `PYTHONPATH` when running locally: `export PYTHONPATH="$(pwd)/src:$PYTHONPATH"`
4. Docker users: No changes needed, just rebuild the image
5. Root-level test files have been moved to `tests/` directory

## Running Tests

All test files are now in the `tests/` directory:

```bash
# Run all tests
export PYTHONPATH="$(pwd)/src:$PYTHONPATH"
pytest

# Run specific test
cd tests
export PYTHONPATH="$(pwd)/../src:$PYTHONPATH"
python test_concept_expansion.py
```

## Backward Compatibility

This is a **breaking change** for:
- Direct Python imports in external tools
- Custom scripts that import QueryForge modules
- CI/CD pipelines that run tests

All internal functionality remains unchanged.
