# EDR Evasions 

## Problem

Modern Windows Endpoint Detection and Response (EDR) solutions suffer from various evasion techniques, such as:

- Raw syscalls
- EDR preloading
- Early cascade injection

These techniques allow adversaries to bypass security measures, making detection and response ineffective.

## Goal of This Project

The goal of this project is to provide Proof-of-Concept (PoC) implementations for early detection of various evasion and process injection attempts. The focus will be on achieving:

- Minimal false positives
- Minimal user-space hacks, avoiding conflicts with existing security solutions
- Comprehensive detection without degrading system performance

## Plan
- Evasion PoC Development
- Memory Scanner Development
- Countermeasures analysis
- Malware Loader Analysis
- False Positive Identification



This project aims to bridge the gap in EDR detection mechanisms by improving early-stage threat identification without interfering with security solution operations.

