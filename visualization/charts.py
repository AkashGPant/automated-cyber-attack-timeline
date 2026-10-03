import plotly.express as px

def create_timeline_chart(events_df):
    if events_df.empty:
        return None
    fig = px.scatter(events_df, x="timestamp", y="severity", color="severity",
                     hover_data=["event_type", "source", "description"],
                     title="Cyber Attack Timeline",
                     color_discrete_map={
                         "INFO": "green",
                         "LOW": "blue",
                         "MEDIUM": "orange",
                         "HIGH": "red",
                         "CRITICAL": "darkred"
                     })
    return fig

def create_risk_distribution(events_df):
    if events_df.empty:
        return None
    fig = px.pie(events_df, names="severity", title="Event Severity Distribution",
                 color="severity",
                 color_discrete_map={
                     "INFO": "green",
                     "LOW": "blue",
                     "MEDIUM": "orange",
                     "HIGH": "red",
                     "CRITICAL": "darkred"
                 })
    return fig
