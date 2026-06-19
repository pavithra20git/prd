from datetime import datetime, timedelta
import random

import numpy as np
import pandas as pd

from src.config import SENSITIVE_RESOURCES


USERS = [
    ("U1001", "Aarav Sharma", "Finance"),
    ("U1002", "Meera Iyer", "Engineering"),
    ("U1003", "Rohan Gupta", "Sales"),
    ("U1004", "Nisha Rao", "Human Resources"),
    ("U1005", "Kabir Menon", "Operations"),
    ("U1006", "Ananya Singh", "Engineering"),
    ("U1007", "Vikram Patel", "Finance"),
    ("U1008", "Priya Nair", "Support"),
]

EVENT_TYPES = ["login", "file_access", "download", "database_query", "app_usage"]
LOCATIONS = ["Bengaluru", "Mumbai", "Delhi", "Hyderabad", "Chennai", "Pune"]
DEVICES = ["managed_laptop", "office_desktop", "mobile_device"]
RESOURCES = [
    "email",
    "crm",
    "intranet",
    "project_docs",
    "ticketing_system",
    "finance_records",
    "payroll_database",
    "source_code_repository",
    "customer_pii",
    "executive_reports",
]


def generate_user_activity_logs(days: int = 21, seed: int = 42) -> pd.DataFrame:
    random.seed(seed)
    np.random.seed(seed)

    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(days=days)
    records = []
    event_id = 1

    for user_id, user_name, department in USERS:
        home_location = random.choice(LOCATIONS[:4])
        normal_device = random.choice(DEVICES[:2])
        daily_events = random.randint(8, 16)

        for day in range(days):
            current_day = start + timedelta(days=day)
            for _ in range(daily_events):
                hour = int(np.clip(np.random.normal(13, 3), 8, 19))
                timestamp = current_day.replace(hour=hour) + timedelta(
                    minutes=random.randint(0, 59)
                )
                event_type = random.choices(
                    EVENT_TYPES,
                    weights=[0.2, 0.28, 0.22, 0.15, 0.15],
                )[0]
                resource = random.choice(RESOURCES[:5])
                files_downloaded = random.randint(0, 8) if event_type == "download" else 0
                data_transfer_mb = round(max(0, np.random.normal(25, 15)), 2)
                failed_logins = random.choices([0, 1, 2], weights=[0.88, 0.09, 0.03])[0]

                records.append(
                    {
                        "event_id": event_id,
                        "timestamp": timestamp,
                        "user_id": user_id,
                        "user_name": user_name,
                        "department": department,
                        "event_type": event_type,
                        "resource": resource,
                        "location": home_location,
                        "device": normal_device,
                        "failed_logins": failed_logins,
                        "files_downloaded": files_downloaded,
                        "data_transfer_mb": data_transfer_mb,
                        "sensitive_access": resource in SENSITIVE_RESOURCES,
                    }
                )
                event_id += 1

    anomaly_templates = [
        ("late_login", 2, "login", "executive_reports"),
        ("mass_download", 23, "download", "customer_pii"),
        ("unknown_device", 4, "database_query", "payroll_database"),
        ("source_code_access", 1, "download", "source_code_repository"),
        ("failed_login_spike", 3, "login", "finance_records"),
    ]

    for _ in range(40):
        user_id, user_name, department = random.choice(USERS)
        label, hour, event_type, resource = random.choice(anomaly_templates)
        timestamp = now - timedelta(days=random.randint(0, days - 1), hours=random.randint(0, 12))
        timestamp = timestamp.replace(hour=hour, minute=random.randint(0, 59))

        records.append(
            {
                "event_id": event_id,
                "timestamp": timestamp,
                "user_id": user_id,
                "user_name": user_name,
                "department": department,
                "event_type": event_type,
                "resource": resource,
                "location": random.choice(["Singapore", "Dubai", "London", "Unknown"]),
                "device": random.choice(["personal_laptop", "unknown_device", "new_mobile"]),
                "failed_logins": random.randint(3, 8)
                if label == "failed_login_spike"
                else random.randint(0, 2),
                "files_downloaded": random.randint(25, 90)
                if event_type == "download"
                else random.randint(0, 5),
                "data_transfer_mb": round(random.uniform(250, 1500), 2),
                "sensitive_access": resource in SENSITIVE_RESOURCES,
            }
        )
        event_id += 1

    df = pd.DataFrame(records)
    return df.sort_values("timestamp").reset_index(drop=True)
