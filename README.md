# scalable-auth
A reusable, scalable authentication microservice built with Node.js, Express, and PostgreSQL that can handle millions of requests per second.

Features
🔐 JWT-based authentication with refresh tokens

📧 Email verification system

🔄 Password reset functionality

⚡ Redis-based rate limiting

🛡️ Security headers with Helmet.js

🐘 PostgreSQL with connection pooling

🐳 Docker containerization ready

📊 Health check endpoints

🔍 Input validation and sanitization

🚀 Horizontal scaling capabilities

Architecture

Client UI → Load Balancer → Multiple Node.js Instances → PostgreSQL (with PgBouncer) → Redis

Quick Start

Prerequisites
Node.js 16+

PostgreSQL 12+

Redis 6+

Docker (optional)
