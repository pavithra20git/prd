# User Behavior Analytics System for Insider Threat Detection

A runnable Python project for detecting suspicious user behavior using log analytics,
behavioral profiling, anomaly detection, and an interactive Streamlit dashboard.

## Features

- Generates realistic sample user activity logs
- Builds user behavior baselines
- Detects anomalies using Isolation Forest
- Calculates risk scores for suspicious activity
- Shows high-risk users, alerts, timelines, and activity trends
- Includes a simple incident investigation workflow
- Runs locally in VS Code

## Tech Stack

- Python
- Pandas
- NumPy
- Scikit-learn
- Streamlit
- Plotly

## Project Structure

```text
uba-insider-threat-detection/
├── app.py
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── analytics.py
│   ├── config.py
│   └── data_generator.py
├── data/
│   └── .gitkeep
└── README.md
```

## How To Run In VS Code

1. Open this folder in VS Code.

2. Open the VS Code terminal and create a virtual environment:

```powershell
python -m venv .venv
```

3. Activate the virtual environment:

```powershell
.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run this once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

4. Install dependencies:

```powershell
pip install -r requirements.txt
```

5. Start the dashboard:

```powershell
streamlit run app.py
```

6. Open the URL shown in the terminal, usually:

```text
http://localhost:8501
```

## Example Suspicious Activities Detected

- Login outside normal working hours
- Access from unfamiliar device or location
- Excessive file downloads
- Access to sensitive resources
- Large data transfers
- Multiple failed login attempts
- Sudden change in user behavior

## Notes

This is a demonstration project designed for academic and learning purposes. In a
production system, logs would be collected from real sources such as SIEM tools,
identity providers, file servers, endpoint systems, databases, and cloud services.
