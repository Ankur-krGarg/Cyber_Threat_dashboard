# Cyber Threat Intelligence Dashboard

A dynamic, AI-powered cyber threat intelligence platform that visualizes global threat activity, provides intelligent insights, and evolves through continuous learning.

---

## Overview

This project is a Python-based data pipeline and intelligence engine intended to be upgraded into an interactive dashboard. It aggregates global cyber threat signals, visualizes trends, supports conversational queries, and uses AI to propose proactive defensive strategies.

---

## Dashboard Details

The planned dashboard will be a **centralized cyber threat intelligence hub** with the following capabilities:

### 1. **Global Threat Mapping**
- **City, Region, and Continent Visualization**  
  Interactive maps showing where threats are originating.  
  - Heatmap overlays for severity.
  - Clickable markers to drill down to local intelligence.

### 2. **Graphical Analytics**
- **Trend Graphs**  
  Time-series plots for daily, weekly, and monthly threat occurrences.
- **Comparative Graphs**  
  Bar and pie charts comparing:
  - Threat types (e.g., ransomware, phishing, DDoS)
  - Source origins by geography
  - Affected industries
- **Map-Based Correlation Views**  
  Geo maps correlating severity, spread, and detection time.

### 3. **Intelligent Threat Chatbot**
- Natural-language interface for querying threats:
  - “Show ransomware incidents from Europe in the last month.”
  - “What is the latest information on the Trojan from Singapore?”
- Summarizes stored intelligence and contextualizes threats.

### 4. **Self-Learning Mechanism**
- Continuously updates threat patterns with new data.
- Adaptive classification that improves as more threats are detected.
- Predictive modeling for future threat trends.

### 5. **Threat News & Alerts**
- Real-time news feed with:
  - Upcoming malware campaigns
  - New vulnerability disclosures (CVEs)
  - Dark web chatter alerts

### 6. **AI-Driven Recommendations**
- Provides mitigation strategies based on:
  - Similar past incidents
  - Known vulnerabilities
  - Industry-specific security best practices

### 7. **User Interaction & Personalization**
- Search & filter threats by date, region, industry.
- Save custom dashboards and alert preferences.
- Export charts and reports for SOC and IR teams.

---

## Core Features (Current & Planned)

- **Data Ingestion** from multiple open-source threat feeds (OTX, CERT, CVE databases).
- **Knowledge Graph** for linking related threat entities.
- **AI Models** for classification, clustering, and forecasting.
- **Extensible Storage** for scalable, long-term data retention.

---

## Future Roadmap

1. **Web UI**: Built with Plotly Dash or React for real-time interactivity.
2. **Predictive Models**: Forecast high-risk geographies.
3. **Anomaly Detection**: Highlight unusual patterns in network traffic or threat origin.
4. **Collaboration Tools**: Slack/email alerts, team annotations.
5. **Mobile-Ready Layout**: Monitor threats on any device.

---

## Architecture

** [Data Ingestion] → [Processing / Enrichment] → [Storage (DB, Timeseries)] → [AI Models / Analytics] → [Dashboard + Chatbot Interface] **


- **KG_pipeline**: Extracts and enriches threat data into a Knowledge Graph.
- **ai_agents**: Houses AI modules for classification, prediction, recommendation.
- **processed**: Holds cleansed and structured datasets for visualization.
- **src**: Contains core logic for ETL, model integration, and API endpoints.
- **main_ingestion_pipeline.py**: Orchestrates ingestion from multiple feeds.

---
