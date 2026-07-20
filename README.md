# Docker Security Audit CLI

## Overview
Docksec is a Go-based CLI tool that scans Docker environments for security misconfigurations and maps findings to the CIS Docker Benchmark.

## Purpose
The purpose of this project is to identify risky Docker configurations before they become security incidents. It checks running containers, Docker daemon settings, images, Dockerfiles, and docker-compose files for issues such as privileged containers, dangerous capabilities, Docker socket mounts, exposed sensitive ports, missing resource limits, and hardcoded secrets.

## Technologies Used
- Go
- Docker Engine / Docker Desktop
- Docker SDK
- CIS Docker Benchmark
- JSON
- SARIF
- YAML
- Static analysis

## Features
- Scans running Docker containers
- Scans Docker daemon settings
- Scans local images
- Scans Dockerfiles
- Scans docker-compose files
- Maps findings to CIS Docker Benchmark controls
- Generates terminal, JSON, and SARIF output
- Supports CI/CD-style failure thresholds

## Custom Features I Added
- Detected containers using the latest image tag
- Detected sensitive ports exposed to all interfaces
- Detected containers missing memory and CPU limits

## Example Commands

```bash
go build -o docksec ./cmd/docksec
./docksec scan
./docksec scan --target containers
./docksec scan --file demo/Dockerfile.insecure
./docksec scan --file demo/docker-compose.insecure.yml
./docksec scan --output json --output-file demo/results.json
./docksec scan --output sarif --output-file demo/results.sarif