# QueryForge Documentation

Welcome to the QueryForge documentation! This guide helps you find the right documentation for your needs.

## 🚀 Quick Start

**New to QueryForge?** Start here:
1. [Project README](../README.md) - Overview, features, and quick start
2. [API Reference](API_REFERENCE.md) - MCP tool documentation and examples
3. [Deployment Guide](DEPLOYMENT.md) - How to deploy QueryForge

## 📚 Documentation by Role

### For End Users

**Getting Started**
- [API Reference](API_REFERENCE.md) - Complete MCP tool documentation with examples
- [Security Concepts](SECURITY_CONCEPTS.md) - Security patterns and detection strategies

**Deployment & Operations**
- [Deployment Guide](DEPLOYMENT.md) - Docker deployment instructions
- [Pre-built Embeddings](PREBUILT_EMBEDDINGS.md) - Production deployment with < 2s startup
- [GitHub Actions Setup](GITHUB_ACTIONS_SETUP.md) - CI/CD pipeline configuration

**Troubleshooting**
- [Troubleshooting Guide](TROUBLESHOOTING.md) - Common issues and solutions

### For Developers

**Architecture & Design**
- [Architecture](ARCHITECTURE.md) - System architecture and design decisions
- [RAG Internals](RAG_INTERNALS.md) - Deep dive into the RAG system

**Feature Guides**
- [RAG Enhancement Guide](RAG_ENHANCEMENT_GUIDE.md) - RAG-enhanced query building
- [Embedding Integration](EMBEDDING_INTEGRATION.md) - Technical embedding integration
- [Schema Management](SCHEMA_MANAGEMENT.md) - Managing platform schemas

**Development**
- [Contributing Guide](CONTRIBUTING.md) - How to contribute to QueryForge
- [Testing Guide](TESTING.md) - Testing procedures and best practices

### For DevOps/Platform Engineers

**Deployment & Configuration**
- [Deployment Guide](DEPLOYMENT.md) - Comprehensive deployment instructions
- [Pre-built Embeddings](PREBUILT_EMBEDDINGS.md) - Fast production deployment strategy
- [Embedding Integration](EMBEDDING_INTEGRATION.md) - LiteLLM proxy configuration
- [GitHub Actions Setup](GITHUB_ACTIONS_SETUP.md) - Automated deployment pipelines

**Maintenance**
- [Schema Management](SCHEMA_MANAGEMENT.md) - Schema updates and maintenance
- [Troubleshooting Guide](TROUBLESHOOTING.md) - Operational issues and solutions

### For Security Teams

**Security Documentation**
- [Security Concepts](SECURITY_CONCEPTS.md) - Detection patterns and security use cases
- [Security Fixes](fixes/SECURITY_FIXES_SUMMARY.md) - Security vulnerability remediation
- [Command Flag Security](fixes/COMMAND_FLAG_SECURITY_FIX.md) - Injection prevention

---

## 📖 Documentation by Topic

### Core Features

**Query Building**
- [API Reference](API_REFERENCE.md) - All query builder tools and parameters
- [RAG Enhancement Guide](RAG_ENHANCEMENT_GUIDE.md) - Comprehensive query generation
- [Accuracy Fixes](fixes/ACCURACY_FIXES_SUMMARY.md) - Query accuracy improvements

**Semantic Search (RAG)**
- [RAG Enhancement Guide](RAG_ENHANCEMENT_GUIDE.md) - Complete RAG feature guide
- [RAG Internals](RAG_INTERNALS.md) - Technical implementation details
- [Embedding Integration](EMBEDDING_INTEGRATION.md) - OpenAI embeddings setup
- [Pre-built Embeddings](PREBUILT_EMBEDDINGS.md) - Production deployment optimization

**Security**
- [Security Concepts](SECURITY_CONCEPTS.md) - Threat detection patterns
- [Security Fixes Summary](fixes/SECURITY_FIXES_SUMMARY.md) - Vulnerability remediation
- [Command Flag Security](fixes/COMMAND_FLAG_SECURITY_FIX.md) - Injection prevention

### Platform Support

QueryForge supports multiple security platforms:
- **Carbon Black Cloud (CBC)** - Process search, alert search
- **Cortex XDR** - XQL queries across datasets
- **Microsoft Defender (KQL)** - Advanced hunting queries
- **SentinelOne (S1)** - Deep visibility queries
- **CrowdStrike (CQL)** - LogScale query language

See [API Reference](API_REFERENCE.md) for platform-specific tools and examples.

### Development & Testing

**Development**
- [Architecture](ARCHITECTURE.md) - System design and components
- [Contributing Guide](CONTRIBUTING.md) - Development workflow
- [Testing Guide](TESTING.md) - Test structure and procedures

**Schema Management**
- [Schema Management](SCHEMA_MANAGEMENT.md) - Adding/updating platform schemas
- [Platform-Specific Fixes](fixes/README.md) - Schema loader improvements

### Deployment & Operations

**Initial Deployment**
- [Deployment Guide](DEPLOYMENT.md) - Docker deployment
- [Pre-built Embeddings](PREBUILT_EMBEDDINGS.md) - Production optimization
- [GitHub Actions Setup](GITHUB_ACTIONS_SETUP.md) - CI/CD pipelines

**Configuration**
- [Embedding Integration](EMBEDDING_INTEGRATION.md) - LiteLLM proxy setup
- Environment variables and secrets

**Monitoring & Troubleshooting**
- [Troubleshooting Guide](TROUBLESHOOTING.md) - Common issues
- [RAG Internals](RAG_INTERNALS.md#monitoring-and-debugging) - Performance monitoring

---

## 🔧 Special Topics

### Performance Optimization

**Fast Startup**
- [Pre-built Embeddings](PREBUILT_EMBEDDINGS.md) - < 2 second startup time
- [RAG Internals - Performance](RAG_INTERNALS.md#performance-optimization)

**Query Performance**
- [Accuracy Fixes](fixes/ACCURACY_FIXES_SUMMARY.md) - Query deduplication
- [Time Filter Integration](fixes/TIME_FILTER_INTEGRATION_FIX.md)

### Fixes & Enhancements

**Security Improvements**
- [Security Fixes Summary](fixes/SECURITY_FIXES_SUMMARY.md)
- [Command Flag Security Fix](fixes/COMMAND_FLAG_SECURITY_FIX.md)

**Accuracy Improvements**
- [Accuracy Fixes Summary](fixes/ACCURACY_FIXES_SUMMARY.md)
- [Example Query Prioritization](fixes/EXAMPLE_QUERY_PRIORITIZATION.md)

**Platform-Specific**
- [CQL Fixes](fixes/README.md#crowdstrike-cql)
- [All Fixes Index](fixes/README.md)

### Historical Documentation

Archived implementation plans and historical context:
- [Archive Directory](archive/README.md) - Completed implementation plans

---

## 📋 Documentation Index

### User Guides
| Document | Description | Audience |
|----------|-------------|----------|
| [API Reference](API_REFERENCE.md) | Complete MCP tool documentation | All users |
| [Security Concepts](SECURITY_CONCEPTS.md) | Security patterns and use cases | Security teams |
| [Troubleshooting](TROUBLESHOOTING.md) | Common issues and solutions | All users |

### Technical Guides
| Document | Description | Audience |
|----------|-------------|----------|
| [Architecture](ARCHITECTURE.md) | System architecture | Developers |
| [RAG Internals](RAG_INTERNALS.md) | RAG system deep dive | Developers |
| [RAG Enhancement Guide](RAG_ENHANCEMENT_GUIDE.md) | RAG feature development | Developers |
| [Embedding Integration](EMBEDDING_INTEGRATION.md) | Technical embedding setup | DevOps |
| [Schema Management](SCHEMA_MANAGEMENT.md) | Schema maintenance | Developers |

### Operational Guides
| Document | Description | Audience |
|----------|-------------|----------|
| [Deployment](DEPLOYMENT.md) | Docker deployment | DevOps |
| [Pre-built Embeddings](PREBUILT_EMBEDDINGS.md) | Production optimization | DevOps |
| [GitHub Actions Setup](GITHUB_ACTIONS_SETUP.md) | CI/CD configuration | DevOps |

### Development Guides
| Document | Description | Audience |
|----------|-------------|----------|
| [Contributing](CONTRIBUTING.md) | Contribution guidelines | Contributors |
| [Testing](TESTING.md) | Testing procedures | Developers |

### Fix Documentation
| Document | Description | Audience |
|----------|-------------|----------|
| [Fixes Index](fixes/README.md) | All fixes organized by category | All |
| [Security Fixes](fixes/SECURITY_FIXES_SUMMARY.md) | Security vulnerability remediation | Security |
| [Accuracy Fixes](fixes/ACCURACY_FIXES_SUMMARY.md) | Query accuracy improvements | Developers |

### Historical
| Document | Description | Audience |
|----------|-------------|----------|
| [Archive](archive/README.md) | Completed implementation plans | Developers |

---

## 🎯 Common Use Cases

### "I want to deploy QueryForge in production"
1. [Deployment Guide](DEPLOYMENT.md) - Basic deployment
2. [Pre-built Embeddings](PREBUILT_EMBEDDINGS.md) - Fast startup optimization
3. [Troubleshooting](TROUBLESHOOTING.md) - Common deployment issues

### "I want to integrate QueryForge with my application"
1. [API Reference](API_REFERENCE.md) - MCP tool documentation
2. [Security Concepts](SECURITY_CONCEPTS.md) - Available detection patterns
3. [Troubleshooting](TROUBLESHOOTING.md) - Integration issues

### "I want to contribute to QueryForge"
1. [Contributing Guide](CONTRIBUTING.md) - Development workflow
2. [Architecture](ARCHITECTURE.md) - System design
3. [Testing Guide](TESTING.md) - Test procedures

### "I want to add a new platform"
1. [Architecture](ARCHITECTURE.md) - Platform integration patterns
2. [Schema Management](SCHEMA_MANAGEMENT.md) - Schema structure
3. [Contributing Guide](CONTRIBUTING.md) - PR process

### "I want to understand how RAG works"
1. [RAG Enhancement Guide](RAG_ENHANCEMENT_GUIDE.md) - User-facing guide
2. [RAG Internals](RAG_INTERNALS.md) - Technical implementation
3. [Embedding Integration](EMBEDDING_INTEGRATION.md) - Configuration

### "I'm having issues with queries"
1. [Troubleshooting Guide](TROUBLESHOOTING.md) - Common problems
2. [API Reference](API_REFERENCE.md) - Tool parameters and examples
3. [Accuracy Fixes](fixes/ACCURACY_FIXES_SUMMARY.md) - Known accuracy issues

---

## 📞 Getting Help

**Documentation Issues**
- Check [Troubleshooting Guide](TROUBLESHOOTING.md) first
- Search existing GitHub issues
- Open a new issue with documentation feedback

**Feature Requests**
- Review [Architecture](ARCHITECTURE.md) to understand current design
- Check [Contributing Guide](CONTRIBUTING.md) for proposal process
- Open a feature request issue

**Security Issues**
- Review [Security Fixes](fixes/SECURITY_FIXES_SUMMARY.md) for known issues
- Report security vulnerabilities responsibly
- See security policy in main repository

---

## 🔄 Documentation Updates

This documentation is actively maintained. Recent updates:
- **2025-11-25**: Documentation reorganization, added this index
- **2025-11-05**: RAG enhancement documentation
- **2025-11-01**: Security and accuracy fixes documentation

To contribute to documentation:
1. Read [Contributing Guide](CONTRIBUTING.md)
2. Follow existing document formats
3. Update this index when adding new documents
4. Include version and date information

---

**Documentation Version:** 2.0  
**Last Updated:** 2025-11-25  
**Maintained By:** QueryForge Development Team
