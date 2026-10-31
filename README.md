
# AWS-ENG-001 — Automated AWS Infrastructure Platform

## Overview

An AWS infrastructure platform for deploying and operating containerised applications using Terraform and automated CI/CD pipelines.

The initial application is an Email & Domain Health Checker that performs DNS and email configuration checks.

## Architecture

The platform uses AWS ECS Fargate to run containerised workloads, with an Application Load Balancer for incoming traffic.

Infrastructure is provisioned using Terraform, and application deployments are automated through GitHub Actions.

## Technology Stack

- AWS VPC, ECS Fargate, ECR, ALB, IAM and CloudWatch
- Terraform
- Docker
- GitHub Actions
- Python

## Project Status

In development — Phase 1: Environment setup.

## Cost Management

Infrastructure is deployed on demand and removed when not required to minimise AWS costs.
