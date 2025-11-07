# Troubleshooting Guide

This guide covers common issues you might encounter when using the MCP Security Query Builders and their solutions.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Server Startup Issues](#server-startup-issues)
- [Connection Issues](#connection-issues)
- [Query Building Issues](#query-building-issues)
- [Schema Cache Issues](#schema-cache-issues)
- [RAG Issues](#rag-issues)
- [Docker Issues](#docker-issues)
- [Performance Issues](#performance-issues)
- [Platform-Specific Issues](#platform-specific-issues)

## Installation Issues

### Issue: pip install fails with dependency conflicts

**Symptoms**:
```
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed
```

**Solution**:
1. Create a fresh virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. Upgrade pip:
   ```bash
   pip install --upgrade pip
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Issue: ImportError for fastmcp or other modules

**Symptoms**:
```python
ImportError: No module named 'fastmcp'
```

**Solution**:
1. Verify you're in the virtual environment:
   ```bash
   which python  # Should point to .venv/bin/python
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Check installed packages:
   ```bash
   pip list | grep fastmcp
   ```

### Issue: Python version too old

**Symptoms**:
```
SyntaxError: invalid syntax (union types)
```

**Solution**:
- Upgrade to Python 3.10 or higher
- Check version:
  ```bash
  python --version
  ```
- Install newer Python and recreate virtual environment

## Server Startup Issues

### Issue: Server fails to start with "Address already in use"

**Symptoms**:
```
OSError: [Errno 98] Address already in use
```

**Solution**:
1. Find the process using the port:
   ```bash
   # Linux/Mac
   lsof -i :8080

   # Windows
   netstat -ano | findstr :8080
   ```

2. Kill the process:
   ```bash
   # Linux/Mac
   kill -9 <PID>

   # Windows
   taskkill /PID <PID> /F
   ```

3. Or use a different port:
   ```bash
   MCP_PORT=8081 python server.py
   ```

### Issue: RAG service initialization hangs

**Symptoms**:
```
Initializing unified RAG service with rapidfuzz-based retrieval...
[hangs here]
```

**Solution**:
1. Check if cache directory exists:
   ```bash
   ls -la .cache/
   ```

2. Delete corrupted cache:
   ```bash
   rm -rf .cache/*.pkl
   ```

3. Restart server to rebuild cache

### Issue: Schema loading fails

**Symptoms**:
```
FileNotFoundError: [Errno 2] No such file or directory: 'defender_xdr_kql_schema_fuller'
```

**Solution**:
1. Verify directory structure:
   ```bash
   ls queryforge/kql/
   ```

2. Check if schema files exist:
   ```bash
   ls queryforge/kql/defender_xdr_kql_schema_fuller/
   ```

3. Re-clone repository if files are missing

### Issue: Permission denied on cache directory

**Symptoms**:
```
PermissionError: [Errno 13] Permission denied: '.cache'
```

**Solution**:
1. Fix permissions:
   ```bash
   chmod -R u+w .cache/
   ```

2. Or delete and recreate:
   ```bash
   rm -rf .cache/
   python server.py  # Will recreate
   ```

## Connection Issues

### Issue: MCP client cannot connect (SSE)

**Symptoms**:
- Client shows connection error
- No response from server

**Solution**:
1. Verify server is running:
   ```bash
   curl http://localhost:8080/sse
   ```

2. Check server logs for errors

3. Verify transport mode:
   ```bash
   MCP_TRANSPORT=sse python server.py
   ```

4. Check firewall rules:
   ```bash
   # Allow port 8080
   sudo ufw allow 8080
   ```

### Issue: stdio transport not working in VS Code Cline

**Symptoms**:
- Cline extension doesn't see tools
- Connection timeout

**Solution**:
1. Check Cline configuration in VS Code settings:
   ```json
   {
     "cline.mcpServers": [
       {
         "name": "Unified Query Builder",
         "type": "stdio",
         "command": ["python", "/full/path/to/server.py"]
       }
     ]
   }
   ```

2. Use absolute paths, not relative

3. Verify Python in PATH:
   ```bash
   which python
   ```

4. Check Python can run server:
   ```bash
   python /full/path/to/server.py
   ```

### Issue: Docker container not reachable

**Symptoms**:
```
curl: (7) Failed to connect to localhost port 8080: Connection refused
```

**Solution**:
1. Check container is running:
   ```bash
   docker ps
   ```

2. Check container logs:
   ```bash
   docker compose logs -f
   ```

3. Verify port mapping:
   ```bash
   docker port <container_name>
   ```

4. Check if service is healthy:
   ```bash
   docker inspect <container_name> | grep -A10 Health
   ```

## Query Building Issues

### Issue: Unknown table error (KQL)

**Symptoms**:
```json
{"error": "Unknown table 'DeviceProcess'. Did you mean 'DeviceProcessEvents'?"}
```

**Solution**:
1. Use suggested table name from error message

2. List available tables:
   ```python
   result = client.call_tool("kql_list_datasets")
   ```

3. Check for typos in table name

### Issue: Unknown field error

**Symptoms**:
```json
{"error": "Unknown field: 'ProcessName'"}
```

**Solution**:
1. Get correct field names:
   ```python
   result = client.call_tool("kql_get_fields", {"table": "DeviceProcessEvents"})
   ```

2. Check field case sensitivity (use exact case)

3. Use column suggestion tool:
   ```python
   result = client.call_tool("kql_suggest_fields", {
       "table": "DeviceProcessEvents",
       "keyword": "process"
   })
   ```

### Issue: Limit exceeds maximum

**Symptoms**:
```json
{"error": "Limit exceeds maximum of 10000"}
```

**Solution**:
1. Reduce limit to 10000 or less
2. Use pagination in your application
3. Add more specific filters to reduce result set

### Issue: Natural language intent returns empty query

**Symptoms**:
```json
{"query": "", "metadata": {...}}
```

**Solution**:
1. Be more specific in intent:
   - Bad: "find stuff"
   - Good: "find PowerShell executions with encoded commands"

2. Include key details:
   - Table name (if known)
   - Time range
   - Specific fields or values

3. Use structured parameters instead

### Issue: Invalid time window format

**Symptoms**:
```json
{"error": "Invalid time window: 'yesterday'"}
```

**Solution**:
Use supported formats:
- "24h" or "1d" (last 24 hours)
- "7d" (last 7 days)
- "30d" (last 30 days)
- "1h" (last hour)

## Schema Cache Issues

### Issue: Stale schema data

**Symptoms**:
- Missing new tables/fields
- Outdated field descriptions

**Solution**:
1. Force refresh KQL schema:
   ```python
   result = client.call_tool("kql_refresh_schema")
   ```

2. Delete cache and restart:
   ```bash
   rm .cache/kql_schema_cache.json
   python server.py
   ```

3. Update schema files from source

### Issue: Corrupted cache file

**Symptoms**:
```
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
```

**Solution**:
1. Delete corrupted cache:
   ```bash
   rm .cache/*.json
   ```

2. Restart server to rebuild cache

### Issue: Schema version mismatch

**Symptoms**:
- Unexpected query failures
- Missing features

**Solution**:
1. Check current version:
   ```python
   result = client.call_tool("kql_get_schema_version")
   ```

2. Update schema files from repository

3. Clear cache and reload

## RAG Issues

### Issue: RAG returns no results

**Symptoms**:
```json
{"matches": []}
```

**Solution**:
1. Check RAG index is initialized:
   ```python
   # Server logs should show:
   # "Unified RAG service initialization complete"
   ```

2. Try broader query terms

3. Don't use platform-specific filter if unsure:
   ```python
   # Instead of:
   result = client.call_tool("retrieve_context", {
       "query": "process field",
       "query_type": "kql"  # May be too restrictive
   })

   # Try:
   result = client.call_tool("retrieve_context", {
       "query": "process field"  # Search all platforms
   })
   ```

### Issue: RAG cache rebuild fails

**Symptoms**:
```
Exception during RAG index build: ...
```

**Solution**:
1. Check available memory:
   ```bash
   free -h
   ```

2. Delete RAG cache:
   ```bash
   rm .cache/*_rag_*.pkl
   ```

3. Restart with fresh build

4. If memory is limited, disable RAG temporarily

### Issue: Slow RAG search

**Symptoms**:
- Queries take >5 seconds
- High CPU usage

**Solution**:
1. Reduce k parameter (fewer results):
   ```python
   result = client.call_tool("retrieve_context", {
       "query": "...",
       "k": 3  # Instead of 10
   })
   ```

2. Use source filter to narrow search:
   ```python
   result = client.call_tool("retrieve_context", {
       "query": "...",
       "query_type": "kql"  # Only search KQL docs
   })
   ```

3. Rebuild cache with optimized settings

### Issue: RAG Enhancement Not Applied to Queries

**Symptoms**:
- Queries remain simplistic (single indicator)
- Expected multi-indicator query not generated
- Example: "RDP" only produces `netconn_port:3389` instead of comprehensive query

**Solution**:
1. Check if RAG context was retrieved:
   ```python
   # Enable debug logging to see RAG retrieval
   import logging
   logging.getLogger("queryforge.rag").setLevel(logging.DEBUG)
   ```

2. Verify confidence score is sufficient:
   ```python
   # Low confidence (< 0.5) results in fallback to basic query
   # Check logs for: "RAG confidence: 0.XX"
   ```

3. Ensure RAG context parser is working:
   ```python
   from shared.rag_context_parser import create_rag_context_parser
   parser = create_rag_context_parser("cbc")
   
   # Check cache stats
   stats = parser.get_cache_stats()
   print(f"Cache size: {stats['size']}/{stats['max_size']}")
   ```

4. Clear RAG parser cache if stale:
   ```python
   from shared.rag_context_parser import RAGContextParser
   RAGContextParser.clear_cache()
   ```

5. Check for parsing errors in logs:
   ```
   "RAG parsing error (falling back to basic query): ..."
   ```

### Issue: RAG Enhancement Performance Degradation

**Symptoms**:
- Query building takes >100ms
- High CPU usage during query building
- Timeouts

**Solution**:
1. Check RAG parser cache statistics:
   ```python
   from shared.rag_context_parser import RAGContextParser
   stats = RAGContextParser.get_cache_stats()
   print(f"Cache size: {stats['size']}/{stats['max_size']}")
   print(f"TTL: {stats['ttl_seconds']}s")
   ```

2. Verify cache is being used (check for cache hits in logs)

3. Adjust parsing limits if needed:
   ```python
   from shared.rag_context_parser import create_rag_context_parser
   parser = create_rag_context_parser("cbc")
   parser.max_fields = 7  # Reduce from default 10
   parser.max_values_per_field = 3  # Reduce from default 5
   parser.parsing_timeout = 3.0  # Reduce from default 5.0
   ```

4. Limit RAG document count:
   ```python
   # When calling retrieve_context
   result = client.call_tool("retrieve_context", {
       "query": "RDP",
       "k": 5  # Reduce from 10
   })
   ```

### Issue: Incorrect Fields Extracted by RAG Parser

**Symptoms**:
- Wrong fields appear in generated queries
- Fields don't match schema
- Validation errors on generated queries

**Solution**:
1. Verify RAG documents have correct field names:
   ```python
   result = client.call_tool("retrieve_context", {
       "query": "your security concept",
       "k": 5
   })
   # Check if field names in documents match schema
   ```

2. Check platform-specific field patterns:
   ```python
   from shared.rag_context_parser import FIELD_PATTERNS
   print(FIELD_PATTERNS["cbc"])  # Check regex pattern
   ```

3. Test field extraction directly:
   ```python
   from shared.rag_context_parser import create_rag_context_parser
   parser = create_rag_context_parser("cbc")
   
   rag_docs = [{"text": "process_name:cmd.exe", "score": 0.9}]
   fields = parser.extract_fields(rag_docs, "cmd")
   print(f"Extracted fields: {fields}")
   ```

4. Verify extracted fields exist in schema:
   ```python
   # For CBC
   result = client.call_tool("cbc_get_fields", {
       "search_type": "process_search"
   })
   # Compare with extracted fields
   ```

### Issue: RAG Enhancement Confidence Too Low

**Symptoms**:
- Consistent low confidence scores (< 0.5)
- RAG enhancement rarely applied
- Logs show: "RAG confidence: 0.2" or similar

**Solution**:
1. Improve RAG document quality:
   - Add more example queries to schema documentation
   - Include field descriptions with examples
   - Use consistent field naming

2. Use more specific query terms:
   ```python
   # Instead of:
   "find activity"
   
   # Use:
   "find RDP connections" or "find PowerShell execution"
   ```

3. Check if documents are relevant:
   ```python
   result = client.call_tool("retrieve_context", {
       "query": "your query",
       "k": 10
   })
   # Review document scores and content
   ```

4. Verify RAG index is built from all schemas:
   ```bash
   ls .cache/*_rag_*.pkl
   # Should see index files for all platforms
   ```

### Issue: RAG Parser Cache Not Working

**Symptoms**:
- Repeated parsing for same queries
- High CPU usage
- Slow query building

**Solution**:
1. Verify cache is enabled (it's enabled by default)

2. Check cache key generation:
   ```python
   from shared.rag_context_parser import create_rag_context_parser
   parser = create_rag_context_parser("cbc")
   
   # Same inputs should generate same cache key
   key1 = parser._generate_cache_key(docs, "RDP", "process_search")
   key2 = parser._generate_cache_key(docs, "RDP", "process_search")
   print(f"Keys match: {key1 == key2}")
   ```

3. Monitor cache growth:
   ```python
   from shared.rag_context_parser import RAGContextParser
   stats = RAGContextParser.get_cache_stats()
   print(f"Cache: {stats['size']}/{stats['max_size']}")
   ```

4. Clear and rebuild if corrupted:
   ```python
   from shared.rag_context_parser import RAGContextParser
   RAGContextParser.clear_cache()
   ```

### Issue: RAG Parser Timeout Exceeded

**Symptoms**:
```
Logs show: "RAG parsing timeout exceeded"
Empty enhancement result returned
```

**Solution**:
1. Check parsing timeout setting:
   ```python
   from shared.rag_context_parser import create_rag_context_parser
   parser = create_rag_context_parser("cbc")
   print(f"Timeout: {parser.parsing_timeout}s")
   ```

2. Increase timeout if needed:
   ```python
   parser.parsing_timeout = 10.0  # Increase from 5.0
   ```

3. Reduce complexity:
   ```python
   # Limit number of RAG documents
   parser.max_fields = 5  # Reduce fields to extract
   ```

4. Check for infinite loops or regex issues in custom parsers

For more information on RAG enhancement, see:
- **[RAG Enhancement Guide](RAG_ENHANCEMENT_GUIDE.md)** - Developer guide
- **[Security Concepts](SECURITY_CONCEPTS.md)** - Recognized security patterns

## Docker Issues

### Issue: Container fails to start

**Symptoms**:
```
Error response from daemon: Container ... is not running
```

**Solution**:
1. Check logs:
   ```bash
   docker compose logs unified-query-builder
   ```

2. Verify Dockerfile syntax:
   ```bash
   docker compose config
   ```

3. Rebuild without cache:
   ```bash
   docker compose build --no-cache
   ```

### Issue: Volume permission errors

**Symptoms**:
```
PermissionError: [Errno 13] Permission denied: '/app/.cache/...'
```

**Solution**:
1. Check volume permissions:
   ```bash
   docker compose exec unified-query-builder ls -la /app/.cache
   ```

2. Fix in Dockerfile:
   ```dockerfile
   RUN mkdir -p /app/.cache && chmod -R 777 /app/.cache
   ```

3. Rebuild and restart:
   ```bash
   docker compose down -v
   docker compose up --build
   ```

### Issue: Image build fails

**Symptoms**:
```
ERROR [stage-1 3/5] RUN pip install -r requirements.txt
```

**Solution**:
1. Check requirements.txt exists:
   ```bash
   ls queryforge/requirements.txt
   ```

2. Build with verbose output:
   ```bash
   docker compose build --progress=plain
   ```

3. Check for network issues (PyPI access)

4. Use different base image if needed

### Issue: Health check always failing

**Symptoms**:
```
Container is unhealthy
```

**Solution**:
1. Check health check endpoint manually:
   ```bash
   docker compose exec unified-query-builder curl http://localhost:8080/sse
   ```

2. Increase health check interval in docker-compose.yml:
   ```yaml
   healthcheck:
     interval: 10s
     timeout: 5s
     retries: 5
   ```

3. Check container logs for startup errors

## Performance Issues

### Issue: Server startup very slow

**Symptoms**:
- Takes >30 seconds to start
- High CPU during startup

**Solution**:
1. Check RAG cache exists:
   ```bash
   ls -lh .cache/*_rag_*.pkl
   ```

2. If cache exists, problem is elsewhere

3. Reduce schema size if possible

4. Use faster storage (SSD vs HDD)

### Issue: High memory usage

**Symptoms**:
- Server uses >1GB RAM
- Out of memory errors

**Solution**:
1. Check memory usage:
   ```bash
   docker stats  # For Docker
   ps aux | grep python  # For local
   ```

2. Reduce RAG cache size:
   ```python
   # In rag.py, reduce document count
   ```

3. Increase available memory

4. Use swap space if needed

### Issue: Slow query building

**Symptoms**:
- Queries take >1 second to build
- High CPU usage

**Solution**:
1. Check if RAG is the bottleneck:
   - Try without natural_language_intent

2. Use structured parameters instead of NL

3. Check schema cache is loaded (not rebuilding)

4. Profile code to find bottleneck:
   ```python
   import cProfile
   cProfile.run('build_query(...)')
   ```

## Platform-Specific Issues

### Microsoft Defender KQL

**Issue: Query works in MCP but fails in Defender**

**Solution**:
1. Check table availability in your environment
2. Verify column names match your Defender version
3. Check time range doesn't exceed retention period
4. Ensure you have proper permissions

**Issue: Schema outdated**

**Solution**:
1. Run schema refresh:
   ```python
   client.call_tool("kql_refresh_schema")
   ```
2. Update schema files from Microsoft Learn

### Carbon Black Cloud

**Issue: Search type not recognized**

**Solution**:
1. Use exact search type names:
   - process_search
   - binary_search
   - alert_search
   - threat_search

2. Check available types:
   ```python
   client.call_tool("cbc_list_datasets")
   ```

**Issue: Query syntax error in CBC**

**Solution**:
1. Check operator reference:
   ```python
   client.call_tool("cbc_get_operator_reference")
   ```
2. Verify field names are correct for search type
3. Check wildcard usage (*, ?)

### Cortex XDR

**Issue: Unknown dataset**

**Solution**:
1. List available datasets:
   ```python
   client.call_tool("cortex_list_datasets")
   ```
2. Use exact dataset names (case-sensitive)
3. Verify dataset exists in your Cortex environment

**Issue: XQL syntax error**

**Solution**:
1. Check operator reference:
   ```python
   client.call_tool("cortex_get_operator_reference")
   ```
2. Verify filter syntax
3. Use XQL functions from reference:
   ```python
   client.call_tool("cortex_get_xql_functions")
   ```

### SentinelOne

**Issue: Dataset inference fails**

**Solution**:
1. Explicitly specify dataset:
   ```python
   client.call_tool("s1_build_query", {
       "dataset": "processes",
       "filters": [...]
   })
   ```

2. Check available datasets:
   ```python
   client.call_tool("s1_list_datasets")
   ```

**Issue: Field not found in dataset**

**Solution**:
1. Get correct fields:
   ```python
   client.call_tool("s1_get_fields", {
       "dataset": "processes"
   })
   ```

2. Check field name case sensitivity

## Logging and Debugging

### Enable Debug Logging

1. **Local Python**:
   ```python
   # In server.py
   logging.basicConfig(level=logging.DEBUG)
   ```

2. **Docker**:
   ```bash
   docker compose logs -f --tail=100
   ```

3. **Specific module**:
   ```python
   logger = logging.getLogger("queryforge.kql")
   logger.setLevel(logging.DEBUG)
   ```

### Common Log Messages

| Message | Meaning | Action |
|---------|---------|--------|
| "Schema cache loaded" | Schema loaded successfully | None |
| "RAG index built" | RAG initialized | None |
| "Failed to build query" | Query building failed | Check error details |
| "Unknown table" | Invalid table name | Use correct table name |
| "Unable to attach RAG context" | RAG search failed | Check RAG cache |

## Getting Help

If you're still experiencing issues:

1. **Check GitHub Issues**: https://github.com/ParadoxReagent/MCPs/issues
2. **Search Documentation**: Check README.md and docs/
3. **Enable Debug Logging**: Capture detailed logs
4. **Create Issue**: Include:
   - Error message
   - Steps to reproduce
   - Environment details (OS, Python version, Docker version)
   - Relevant logs
   - Expected vs actual behavior

## Quick Reference

### Common Commands

```bash
# Reset everything
rm -rf .cache/
docker compose down -v
docker compose up --build

# Check server status
curl http://localhost:8080/sse

# View logs
docker compose logs -f

# Test query building
python -c "from queryforge.kql.query_builder import build_kql_query; print(build_kql_query({}, natural_language_intent='test'))"

# Rebuild RAG cache
rm .cache/*_rag_*.pkl && python server.py
```

### Environment Variables

```bash
MCP_TRANSPORT=sse|stdio    # Transport mode
MCP_HOST=0.0.0.0          # Bind address (SSE only)
MCP_PORT=8080             # Port (SSE only)
PYTHONPATH=/path/to/MCPs  # Python path
```

### File Locations

```
.cache/                          # Cache directory
├── kql_schema_cache.json       # KQL schema cache
├── unified_rag_index.pkl       # RAG embeddings
└── *_version.txt               # Version tracking

queryforge/
├── kql/defender_xdr_kql_schema_fuller/  # KQL schemas
├── cbc/cbc_schema.json                   # CBC schema
├── cortex/cortex_xdr_schema.json        # Cortex schema
└── s1_schemas/                           # S1 schemas
```
