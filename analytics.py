import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from src.config import SENSITIVE_RESOURCES


def build_behavior_profiles(df: pd.DataFrame) -> pd.DataFrame:
    profile = (
        df.assign(hour=df["timestamp"].dt.hour)
        .groupby(["user_id", "user_name", "department"])
        .agg(
            common_location=("location", lambda value: value.mode().iat[0]),
            common_device=("device", lambda value: value.mode().iat[0]),
            avg_login_hour=("hour", "mean"),
            avg_files_downloaded=("files_downloaded", "mean"),
            avg_data_transfer_mb=("data_transfer_mb", "mean"),
            sensitive_access_count=("sensitive_access", "sum"),
            total_events=("event_id", "count"),
        )
        .round(2)
        .reset_index()
    )
    return profile


def prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    features = df.copy()
    features["hour"] = features["timestamp"].dt.hour
    features["day_of_week"] = features["timestamp"].dt.dayofweek
    features["is_after_hours"] = ~features["hour"].between(8, 19)
    features["is_sensitive_resource"] = features["resource"].isin(SENSITIVE_RESOURCES)
    return features


def detect_anomalies(original_df: pd.DataFrame, features: pd.DataFrame) -> pd.DataFrame:
    categorical_columns = ["user_id", "event_type", "resource", "location", "device"]
    numeric_columns = [
        "hour",
        "day_of_week",
        "failed_logins",
        "files_downloaded",
        "data_transfer_mb",
        "is_after_hours",
        "is_sensitive_resource",
    ]

    encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    encoded = encoder.fit_transform(features[categorical_columns])
    numeric = features[numeric_columns].astype(float).to_numpy()
    feature_matrix = np.hstack([numeric, encoded])
    scaled = StandardScaler().fit_transform(feature_matrix)

    model = IsolationForest(n_estimators=150, contamination=0.07, random_state=42)
    anomaly_prediction = model.fit_predict(scaled)
    anomaly_score = -model.score_samples(scaled)

    result = original_df.copy()
    result["is_anomaly"] = anomaly_prediction == -1

    base_score = np.interp(
        anomaly_score,
        (anomaly_score.min(), anomaly_score.max()),
        (5, 85),
    )
    rule_score = (
        features["is_after_hours"].astype(int) * 12
        + features["is_sensitive_resource"].astype(int) * 10
        + (features["failed_logins"] >= 3).astype(int) * 18
        + (features["files_downloaded"] >= 25).astype(int) * 20
        + (features["data_transfer_mb"] >= 250).astype(int) * 15
        + result["is_anomaly"].astype(int) * 12
    )

    result["risk_score"] = np.clip(base_score + rule_score, 0, 100).round().astype(int)
    result["risk_level"] = result["risk_score"].apply(assign_risk_level)
    result["alert_reason"] = result.apply(explain_alert, axis=1)
    return result


def assign_risk_level(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 45:
        return "Medium"
    return "Low"


def explain_alert(row: pd.Series) -> str:
    reasons = []
    if row["is_anomaly"]:
        reasons.append("ML anomaly")
    if row["timestamp"].hour < 8 or row["timestamp"].hour > 19:
        reasons.append("after-hours activity")
    if row["sensitive_access"]:
        reasons.append("sensitive resource access")
    if row["failed_logins"] >= 3:
        reasons.append("multiple failed logins")
    if row["files_downloaded"] >= 25:
        reasons.append("excessive downloads")
    if row["data_transfer_mb"] >= 250:
        reasons.append("large data transfer")
    return ", ".join(reasons) if reasons else "normal activity"


def get_incident_summary(df: pd.DataFrame) -> pd.DataFrame:
    risk_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    summary = (
        df.assign(risk_rank=df["risk_level"].map(risk_rank))
        .groupby("user_id")
        .agg(
            events=("event_id", "count"),
            anomalies=("is_anomaly", "sum"),
            max_risk=("risk_score", "max"),
            sensitive_access=("sensitive_access", "sum"),
            highest_rank=("risk_rank", "max"),
        )
    )
    rank_to_level = {value: key for key, value in risk_rank.items()}
    summary["highest_risk_level"] = summary["highest_rank"].map(rank_to_level)
    return summary.drop(columns=["highest_rank"])
