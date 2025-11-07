# QueryForge Roadmap

This document outlines planned enhancements and future directions for the QueryForge MCP query builder suite.

## Current Status

QueryForge currently provides comprehensive query building capabilities for:
- **Microsoft Defender XDR** (KQL) - Full support with schema caching and RAG
- **Carbon Black Cloud** - Complete search-type aware implementation
- **Palo Alto Cortex XDR** - XQL pipeline generation with dataset introspection
- **SentinelOne** - Dataset inference with boolean operator defaults

## Upcoming Enhancements

### Near Term (Next Release)

- **Enhanced SentinelOne Coverage**
  - Additional example queries across all datasets
  - Expanded regression test coverage
  - Performance optimization for large result sets

- **Client Configuration Templates**
  - Streamlined setup guides for popular MCP clients

- **Query Workflow Automation**
  - Query templating system for common hunting patterns
  - Query sharing and collaboration features between analysts
  - Query history and versioning

### Medium Term (3-6 Months)

- **CrowdStrike Query Builder** 🎯
  - Full support for CrowdStrike Falcon LogScale (Humio)
  - Schema loader with field mapping and operator support
  - Natural language query translation for LogScale Query Language
  - Integration with QueryForge architecture
  - RAG-enhanced context retrieval for CrowdStrike documentation
  - Example query catalog for common hunting scenarios
  - Support for both Event Search and Threat Hunting use cases

- **Query Optimization Engine**
  - Automatic query performance analysis
  - Suggestions for query optimization based on platform best practices

- **Advanced RAG Enhancements**
  - Multi-modal embedding support for query patterns
  - Cross-platform query translation (e.g., KQL → XQL → LogScale)
  - Enhanced semantic search with user feedback loop

### Long Term (6-12 Months)

- **Additional Platform Support**
  - TrendMicro
  - OpenSearch

- **Enterprise Features**
  - Role-based access control for query builders
  - Audit logging for query generation and execution
  - Compliance reporting and query governance

- **Intelligence Integration**
  - Threat intelligence enrichment in queries
  - IOC-driven query generation
  - MITRE ATT&CK framework mapping
  - Automated hunting playbook generation

## CrowdStrike Query Builder Details

### Planned Capabilities

The CrowdStrike query builder will provide:

1. **LogScale Query Language Support**
   - Full LQL syntax generation from natural language
   - Support for aggregate functions, groupBy, and statistical operations
   - Time-based filtering and windowing
   - Field extraction and parsing functions

2. **Schema Integration**
   - Falcon Data Replicator (FDR) schema mapping
   - Event type recognition and field validation
   - Dynamic field discovery based on data source
   - Custom field and tag support

3. **Use Case Templates**
   - EDR event analysis queries
   - Threat hunting patterns
   - Incident response queries
   - Compliance and audit queries
   - Performance monitoring queries

4. **MCP Tool Set**
   - `cs_build_query` - Natural language to LQL translation
   - `cs_list_event_types` - Discover available event types
   - `cs_get_field_info` - Field schema and type information
   - `cs_validate_query` - Query syntax validation
   - `cs_retrieve_examples` - Context-aware query examples

### Technical Approach

The implementation will follow the established QueryForge patterns:
- Modular schema loader with caching (`CrowdStrikeSchemaLoader`)
- Query builder with operator normalization (`CrowdStrikeQueryBuilder`)
- RAG document builder for CrowdStrike documentation
- Integration with QueryForge runtime
- Comprehensive test coverage following existing patterns

### Timeline

- **Q1 2026**: Schema extraction and documentation curation
- **Q2 2026**: Core query builder implementation
- **Q3 2026**: RAG integration and example catalog
- **Q4 2026**: Production release and documentation

## Contributing

We welcome community input on roadmap priorities. To suggest features or provide feedback:

1. Open an issue on GitHub with the `enhancement` label
2. Join discussions on existing roadmap items
3. Submit pull requests for documentation improvements
4. Share real-world use cases and requirements

## Roadmap Updates

This roadmap is reviewed and updated quarterly. Last updated: October 2025

---

For questions about the roadmap or to discuss specific features, please open a GitHub issue or refer to [CONTRIBUTING.md](docs/CONTRIBUTING.md).
