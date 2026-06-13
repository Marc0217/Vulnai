# VulnAI

AI-Assisted Modular Penetration Testing Automation Platform

## Overview

VulnAI is a modular penetration testing automation platform developed as part of the BSc Cyber Security dissertation project at York St John University.

The platform integrates multiple security assessment tools into a single workflow and uses AI-assisted reporting to improve reporting efficiency while maintaining human oversight.

The objective of the project is to evaluate whether AI-assisted automation can improve penetration testing workflow efficiency without significantly impacting vulnerability detection capability.

---

## Features

- Automated Nmap scanning
- Service detection and scan orchestration
- Nikto integration
- Gobuster integration
- SQLMap integration
- Nuclei integration
- AI-assisted vulnerability analysis
- Automated PDF report generation
- Web-based management interface
- Modular architecture for future tool integration

---

## Technology Stack

### Backend
- FastAPI
- Python

### Frontend
- HTML
- CSS
- JavaScript

### Security Tools
- Nmap
- Nikto
- Gobuster
- SQLMap
- Nuclei

### AI Integration
- OpenAI API

---

## Installation

### Clone Repository

```bash
git clone https://github.com/Marc0217/Vulnai.git
cd Vulnai
```

### Create Virtual Environment

```bash
python -m venv .venv
```

### Activate Virtual Environment

Linux:

```bash
source .venv/bin/activate
```

Windows:

```bash
.venv\Scripts\activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Configuration

Create a `.env` file and configure the required API keys and application settings.

Example:

```env
OPENAI_API_KEY=your_api_key_here
```

---

## Running the Application

Start the FastAPI server:

```bash
uvicorn main:app --reload
```

or use the startup method included within the project.

Once running, open:

```
http://localhost:8000
```

---

## Workflow

1. User submits a target.
2. Nmap performs initial discovery.
3. Services are identified.
4. Appropriate follow-up modules are selected.
5. Security tools execute automatically.
6. Results are aggregated.
7. AI-assisted analysis is performed.
8. PDF reports are generated.

---

## Project Structure

```text
VulnAI/
│
├── backend/
├── frontend/
├── scans/
├── reports/
├── static/
├── templates/
├── requirements.txt
├── README.md
└── .env
```

---

## Limitations

- Evaluation was conducted using a limited number of test environments.
- Results may vary depending on target complexity and network conditions.
- AI-generated outputs require human validation.
- The platform is intended to assist security professionals rather than replace expert judgement.

---

## Academic Context

This project was developed for the dissertation module of the BSc Cyber Security programme at York St John University.

Project Title:

**VulnAI: An AI-Assisted Modular Penetration Testing Automation Platform**

---

## Author

Marcos Dominguez Garcia

York St John University  
BSc Cyber Security
