# QueryForge Roadmap

This document outlines planned enhancements and future directions for the QueryForge MCP query builder suite.

## Current Status

QueryForge currently provides comprehensive query building capabilities for:
- **Microsoft Defender XDR** (KQL) - Full support with schema caching and RAG
- **Carbon Black Cloud** (CBC) - Complete search-type aware implementation
- **Carbon Black Response** (CBR) - Legacy platform support with field validation
- **Palo Alto Cortex XDR** - XQL pipeline generation with dataset introspection
- **SentinelOne** - Dataset inference with boolean operator defaults
- **CrowdStrike Falcon** (CQL) - Full LogScale Query Language support with comprehensive schema

## Upcoming Enhancements

### Near Term (Next Release)

- **Enhanced SentinelOne Coverage**
  - Additional example queries across all datasets
  - Expanded regression test coverage
  - Performance optimization for large result sets

### Medium Term (3-6 Months)

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

- **Intelligence Integration**
  - Threat intelligence enrichment in queries
  - IOC-driven query generation
  - MITRE ATT&CK framework mapping
  - Automated hunting playbook generation