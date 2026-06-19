from pathlib import Path


DATA_PATH = Path("data/user_activity_logs.csv")

RISK_LEVEL_COLORS = {
    "Critical": "#dc2626",
    "High": "#f97316",
    "Medium": "#ca8a04",
    "Low": "#16a34a",
}

SENSITIVE_RESOURCES = {
    "finance_records",
    "payroll_database",
    "source_code_repository",
    "customer_pii",
    "executive_reports",
}
