from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from src.analytics import (
    build_behavior_profiles,
    detect_anomalies,
    get_incident_summary,
    prepare_features,
)
from src.config import DATA_PATH, RISK_LEVEL_COLORS
from src.data_generator import generate_user_activity_logs


st.set_page_config(
    page_title="UBA Insider Threat Detection",
    layout="wide",
)


def load_data() -> pd.DataFrame:
    Path("data").mkdir(exist_ok=True)
    if not DATA_PATH.exists():
        df = generate_user_activity_logs()
        df.to_csv(DATA_PATH, index=False)
    return pd.read_csv(DATA_PATH, parse_dates=["timestamp"])


def risk_badge(level: str) -> str:
    color = RISK_LEVEL_COLORS.get(level, "#64748b")
    return (
        f"<span style='background:{color};color:white;padding:0.25rem 0.6rem;"
        f"border-radius:999px;font-size:0.8rem;font-weight:700'>{level}</span>"
    )


def format_date_range(data: pd.DataFrame) -> str:
    if data.empty:
        return "No events selected"
    start = data["timestamp"].min().strftime("%d %b %Y")
    end = data["timestamp"].max().strftime("%d %b %Y")
    return f"{start} to {end}"


def render_kpi_card(label: str, value: str, detail: str, accent: str) -> None:
    st.markdown(
        f"""
        <div class="kpi-card" style="border-top-color:{accent}">
            <div class="kpi-label">{label}</div>
            <div class="kpi-value">{value}</div>
            <div class="kpi-detail">{detail}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def style_chart(fig):
    fig.update_layout(
        template="plotly_white",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"family": "Inter, Segoe UI, Arial", "color": "#111827"},
        margin={"l": 24, "r": 16, "t": 32, "b": 24},
        legend_title_text="",
    )
    fig.update_xaxes(gridcolor="#eef2f7", zeroline=False)
    fig.update_yaxes(gridcolor="#eef2f7", zeroline=False)
    return fig


st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: "Inter", "Segoe UI", sans-serif;
    }

    .stApp {
        background:
            radial-gradient(circle at top left, rgba(20, 184, 166, 0.12), transparent 28rem),
            linear-gradient(180deg, #f8fafc 0%, #eef2f7 100%);
    }

    .main .block-container {
        padding-top: 1.15rem;
        padding-bottom: 2rem;
        max-width: 1420px;
    }

    section[data-testid="stSidebar"] {
        background: #ffffff;
        border-right: 1px solid #e5e7eb;
    }

    .app-hero {
        background: linear-gradient(135deg, #111827 0%, #17313a 52%, #0f766e 100%);
        border: 1px solid rgba(255,255,255,0.18);
        border-radius: 8px;
        padding: 1.35rem 1.5rem;
        color: #ffffff;
        box-shadow: 0 18px 38px rgba(15, 23, 42, 0.16);
        margin-bottom: 1rem;
    }

    .hero-eyebrow {
        color: #99f6e4;
        font-size: 0.78rem;
        font-weight: 800;
        letter-spacing: 0;
        text-transform: uppercase;
        margin-bottom: 0.45rem;
    }

    .hero-title {
        color: #ffffff;
        font-size: 2rem;
        line-height: 1.15;
        font-weight: 800;
        margin: 0;
    }

    .hero-subtitle {
        color: #dbeafe;
        margin: 0.55rem 0 0;
        max-width: 880px;
        font-size: 0.98rem;
    }

    .hero-strip {
        display: flex;
        flex-wrap: wrap;
        gap: 0.75rem;
        margin-top: 1rem;
    }

    .hero-pill {
        background: rgba(255,255,255,0.11);
        border: 1px solid rgba(255,255,255,0.18);
        border-radius: 8px;
        color: #f8fafc;
        padding: 0.5rem 0.7rem;
        font-size: 0.82rem;
        font-weight: 600;
    }

    .kpi-card {
        background: #ffffff;
        border: 1px solid #e5e7eb;
        border-top: 4px solid #0f766e;
        border-radius: 8px;
        padding: 1rem 1.05rem;
        min-height: 128px;
        box-shadow: 0 12px 26px rgba(15, 23, 42, 0.07);
    }

    .kpi-label {
        color: #64748b;
        font-size: 0.78rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0;
    }

    .kpi-value {
        color: #111827;
        font-size: 2rem;
        font-weight: 800;
        line-height: 1.1;
        margin-top: 0.45rem;
    }

    .kpi-detail {
        color: #475569;
        font-size: 0.82rem;
        line-height: 1.35;
        margin-top: 0.45rem;
    }

    .section-card {
        background: #ffffff;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 1rem;
        box-shadow: 0 10px 24px rgba(15, 23, 42, 0.06);
        margin-bottom: 1rem;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        overflow: hidden;
    }

    h1, h2, h3 {
        color: #111827;
        letter-spacing: 0;
    }

    div[data-testid="stTabs"] button p {
        font-weight: 700;
        color: #334155;
    }

    div[data-testid="stTabs"] button[aria-selected="true"] p {
        color: #0f766e;
    }

    .stButton > button {
        border-radius: 8px;
        border: 1px solid #0f766e;
        color: #ffffff;
        background: #0f766e;
        font-weight: 700;
    }

    .stButton > button:hover {
        border-color: #115e59;
        background: #115e59;
        color: #ffffff;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


df = load_data()
profiles = build_behavior_profiles(df)
features = prepare_features(df)
scored_df = detect_anomalies(df, features)
incident_summary = get_incident_summary(scored_df)

with st.sidebar:
    st.header("Control Panel")
    selected_users = st.multiselect(
        "Users",
        options=sorted(scored_df["user_id"].unique()),
        default=sorted(scored_df["user_id"].unique()),
    )
    selected_levels = st.multiselect(
        "Risk Levels",
        options=["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"],
    )
    min_score = st.slider("Minimum Risk Score", 0, 100, 0)

    if st.button("Regenerate Demo Logs", use_container_width=True):
        new_df = generate_user_activity_logs()
        new_df.to_csv(DATA_PATH, index=False)
        st.rerun()

filtered_df = scored_df[
    scored_df["user_id"].isin(selected_users)
    & scored_df["risk_level"].isin(selected_levels)
    & (scored_df["risk_score"] >= min_score)
].copy()

st.markdown(
    f"""
    <div class="app-hero">
        <div class="hero-eyebrow">Security Operations Dashboard</div>
        <div class="hero-title">User Behavior Analytics System</div>
        <p class="hero-subtitle">
            Insider threat monitoring with behavioral baselines, Isolation Forest anomaly detection,
            risk scoring, alert review, and user investigation timelines.
        </p>
        <div class="hero-strip">
            <div class="hero-pill">Source: data/user_activity_logs.csv</div>
            <div class="hero-pill">Analysis window: {format_date_range(scored_df)}</div>
            <div class="hero-pill">Model: Isolation Forest</div>
            <div class="hero-pill">Risk scale: 0-100</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

if filtered_df.empty:
    st.warning("No events match the selected filters. Adjust the control panel to continue.")
    st.stop()

critical_count = int((filtered_df["risk_level"] == "Critical").sum())
anomaly_count = int(filtered_df["is_anomaly"].sum())
avg_risk = round(filtered_df["risk_score"].mean(), 1)
selected_event_count = len(filtered_df)

cols = st.columns(4)
with cols[0]:
    render_kpi_card(
        "Total Events",
        f"{selected_event_count:,}",
        "Number of log records currently included after sidebar filters.",
        "#0f766e",
    )
with cols[1]:
    render_kpi_card(
        "Anomalies",
        f"{anomaly_count:,}",
        "Events marked abnormal by the Isolation Forest ML model.",
        "#7c3aed",
    )
with cols[2]:
    render_kpi_card(
        "Critical Alerts",
        f"{critical_count:,}",
        "Events with risk score 85 or above.",
        "#dc2626",
    )
with cols[3]:
    render_kpi_card(
        "Average Risk",
        f"{avg_risk}",
        "Mean risk score across the selected event set.",
        "#f97316",
    )

with st.expander("How these KPI counts are calculated", expanded=False):
    st.markdown(
        """
        - **Total Events** comes from every selected row in `data/user_activity_logs.csv`.
        - **Anomalies** are events where the Isolation Forest model returns an abnormal label.
        - **Critical Alerts** are events where the calculated risk score is `85` or higher.
        - **Average Risk** is the mean of all selected `risk_score` values.
        - The risk score combines the ML anomaly score with security rules such as after-hours activity,
          sensitive resource access, excessive downloads, failed logins, and large data transfers.
        """
    )

tab_overview, tab_alerts, tab_users, tab_investigation, tab_profiles = st.tabs(
    ["Overview", "Alerts", "Users", "Investigation", "Behavior Profiles"]
)

with tab_overview:
    left, right = st.columns([1.1, 1])

    with left:
        st.subheader("Risk Events Over Time")
        events_by_time = (
            filtered_df.set_index("timestamp")
            .resample("6h")
            .agg(events=("event_id", "count"), avg_risk=("risk_score", "mean"))
            .reset_index()
        )
        fig = px.line(
            events_by_time,
            x="timestamp",
            y=["events", "avg_risk"],
            markers=True,
            color_discrete_sequence=["#0f766e", "#f97316"],
            labels={"value": "Count / Score", "timestamp": "Time"},
        )
        fig = style_chart(fig)
        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Risk Level Distribution")
        risk_counts = (
            filtered_df["risk_level"]
            .value_counts()
            .reindex(["Critical", "High", "Medium", "Low"])
            .dropna()
            .reset_index()
        )
        risk_counts.columns = ["risk_level", "count"]
        fig = px.bar(
            risk_counts,
            x="risk_level",
            y="count",
            color="risk_level",
            color_discrete_map=RISK_LEVEL_COLORS,
        )
        fig = style_chart(fig)
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Top Risk Users")
    top_users = (
        filtered_df.groupby("user_id")
        .agg(
            avg_risk=("risk_score", "mean"),
            max_risk=("risk_score", "max"),
            anomalies=("is_anomaly", "sum"),
            events=("event_id", "count"),
        )
        .sort_values(["max_risk", "avg_risk"], ascending=False)
        .head(10)
        .reset_index()
    )
    st.dataframe(top_users, use_container_width=True, hide_index=True)

with tab_alerts:
    st.subheader("Security Alerts")
    alert_df = filtered_df[filtered_df["risk_score"] >= 50].sort_values(
        "risk_score", ascending=False
    )
    visible_columns = [
        "timestamp",
        "user_id",
        "department",
        "event_type",
        "resource",
        "location",
        "device",
        "failed_logins",
        "files_downloaded",
        "data_transfer_mb",
        "risk_score",
        "risk_level",
        "alert_reason",
    ]
    st.dataframe(alert_df[visible_columns], use_container_width=True, hide_index=True)

with tab_users:
    st.subheader("User Risk Comparison")
    user_risk = (
        filtered_df.groupby(["user_id", "department"])
        .agg(
            events=("event_id", "count"),
            avg_risk=("risk_score", "mean"),
            max_risk=("risk_score", "max"),
            anomalies=("is_anomaly", "sum"),
            sensitive_access=("sensitive_access", "sum"),
        )
        .reset_index()
    )
    fig = px.scatter(
        user_risk,
        x="events",
        y="avg_risk",
        size="anomalies",
        color="department",
        color_discrete_sequence=px.colors.qualitative.Set2,
        hover_data=["user_id", "max_risk", "sensitive_access"],
        labels={"events": "Total Events", "avg_risk": "Average Risk Score"},
    )
    fig = style_chart(fig)
    st.plotly_chart(fig, use_container_width=True)
    st.dataframe(
        user_risk.sort_values("max_risk", ascending=False),
        use_container_width=True,
        hide_index=True,
    )

with tab_investigation:
    st.subheader("Incident Investigation")
    selected_user = st.selectbox(
        "Select User",
        options=sorted(scored_df["user_id"].unique()),
        index=0,
    )
    user_events = scored_df[scored_df["user_id"] == selected_user].sort_values("timestamp")
    summary = incident_summary.loc[selected_user]

    col_a, col_b, col_c, col_d = st.columns(4)
    col_a.metric("Events", int(summary["events"]))
    col_b.metric("Anomalies", int(summary["anomalies"]))
    col_c.metric("Max Risk", int(summary["max_risk"]))
    col_d.metric("Sensitive Access", int(summary["sensitive_access"]))

    st.markdown(
        f"Current highest risk level: {risk_badge(str(summary['highest_risk_level']))}",
        unsafe_allow_html=True,
    )

    timeline = px.scatter(
        user_events,
        x="timestamp",
        y="risk_score",
        color="risk_level",
        color_discrete_map=RISK_LEVEL_COLORS,
        size="files_downloaded",
        hover_data=["event_type", "resource", "location", "device", "alert_reason"],
        labels={"timestamp": "Time", "risk_score": "Risk Score"},
    )
    timeline = style_chart(timeline)
    st.plotly_chart(timeline, use_container_width=True)

    st.dataframe(
        user_events[
            [
                "timestamp",
                "event_type",
                "resource",
                "location",
                "device",
                "risk_score",
                "risk_level",
                "alert_reason",
            ]
        ].sort_values("timestamp", ascending=False),
        use_container_width=True,
        hide_index=True,
    )

with tab_profiles:
    st.subheader("Behavior Profiles")
    st.dataframe(profiles, use_container_width=True, hide_index=True)

    st.subheader("Activity Heatmap")
    heatmap_data = (
        scored_df.assign(hour=scored_df["timestamp"].dt.hour)
        .pivot_table(
            index="user_id",
            columns="hour",
            values="event_id",
            aggfunc="count",
            fill_value=0,
        )
    )
    fig = px.imshow(
        heatmap_data,
        aspect="auto",
        color_continuous_scale=["#f8fafc", "#99f6e4", "#0f766e", "#f97316", "#dc2626"],
        labels={"x": "Hour of Day", "y": "User", "color": "Events"},
    )
    fig = style_chart(fig)
    st.plotly_chart(fig, use_container_width=True)
