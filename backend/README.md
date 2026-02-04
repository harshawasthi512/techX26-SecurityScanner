# GitHub Security Scanner - Backend

A FastAPI backend for scanning GitHub organizations for secrets and vulnerable cloud buckets.

## Features

- Scan GitHub organizations/users for public/private/forked/archived repositories
- Detect secrets (API keys, passwords, tokens, etc.)
- Find cloud storage buckets (AWS S3, GCP, Azure, DigitalOcean)
- Check bucket vulnerabilities for takeover
- Real-time progress updates via WebSocket
- Scan history stored in SQLite
- Configurable via environment variables

## Setup

1. **Clone the repository**
```bash
git clone <repo-url>
cd backend