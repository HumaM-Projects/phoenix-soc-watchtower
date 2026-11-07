import streamlit as st
import pandas as pd
from detector import analyze_logs, REQUIRED_COLUMNS
from storage import init_db, save_note, load_note, get_connection

st.set_page_config(page_title="SOC Watchtower", page_icon="🛡️", layout="wide")
init_db()
st.markdown("""
<style>
.stApp{background:#08111f;color:#e5edf7}
[data-testid="stSidebar"]{background:#0d1929}
.block-container{max-width:1450px;padding-top:1.5rem}
h1,h2,h3{color:#f4f7fb!important}
.metric-card{background:#12243a;border:1px solid #29435f;border-radius:12px;padding:15px}
</style>""", unsafe_allow_html=True)

st.title("🛡️ SOC WATCHTOWER")
st.caption("Security Operations Center • Defensive log triage and investigation")
with st.sidebar:
    st.header("CONTROL CENTER")
    source=st.radio("LOG SOURCE",["Demo dataset","Upload CSV"])
    uploaded=st.file_uploader("Upload sanitized CSV",type=["csv"]) if source=="Upload CSV" else None
    threshold=st.slider("Failed-login threshold",3,10,5)
    window=st.slider("Detection window (minutes)",5,60,10)

if source=="Demo dataset":
    df=pd.read_csv("sample_logs.csv")
elif uploaded is not None:
    try: df=pd.read_csv(uploaded)
    except Exception as e: st.error(f"CSV error: {e}"); st.stop()
else:
    st.info("Upload CSV columns: "+", ".join(REQUIRED_COLUMNS)); st.stop()

missing=[c for c in REQUIRED_COLUMNS if c not in df.columns]
if missing: st.error("Missing columns: "+", ".join(missing)); st.stop()
try: events,alerts=analyze_logs(df,threshold,window)
except Exception as e: st.error(f"Analysis error: {e}"); st.stop()

high=int((alerts.severity=="High").sum()) if not alerts.empty else 0
m1,m2,m3,m4=st.columns(4)
m1.metric("EVENTS ANALYZED",len(events))
m2.metric("ALERTS GENERATED",len(alerts))
m3.metric("HIGH SEVERITY",high)
m4.metric("UNIQUE SOURCE IPs",events.source_ip.nunique())

left,right=st.columns(2)
with left:
    st.subheader("Alert severity distribution")
    if alerts.empty: st.info("No alerts generated.")
    else: st.bar_chart(alerts.severity.value_counts().reindex(["High","Medium","Low"],fill_value=0))
with right:
    st.subheader("Event timeline")
    t=events.copy()
    t["timestamp"]=pd.to_datetime(t.timestamp,errors="coerce")
    t=t.dropna(subset=["timestamp"]).set_index("timestamp").resample("h").size().rename("Events")
    if not t.empty: st.line_chart(t)

st.header("◈ ALERT TRIAGE")
if alerts.empty:
    st.success("No alerts to investigate.")
else:
    severities=st.multiselect("Filter severity",["High","Medium","Low"],default=["High","Medium","Low"])
    visible=alerts[alerts.severity.isin(severities)]
    st.dataframe(visible[["alert_id","timestamp","severity","rule","source_ip","username","count","mitre"]],
                 use_container_width=True,hide_index=True)
    options={f"{r.alert_id} | {r.severity} | {r.rule} | {r.username}":r.alert_id
             for r in visible.itertuples()}
    if options:
        choice=st.selectbox("Select an alert to investigate",list(options))
        aid=options[choice]
        selected=alerts.loc[alerts.alert_id==aid].iloc[0]
        st.header("◈ INCIDENT INVESTIGATION")
        c1,c2,c3=st.columns(3)
        c1.markdown(f"**Alert ID**\n\n`{aid}`")
        c2.markdown(f"**Severity**\n\n{selected.severity}")
        c3.markdown(f"**Detection rule**\n\n{selected.rule}")
        c1,c2,c3=st.columns(3)
        c1.markdown(f"**Timestamp**\n\n{selected.timestamp}")
        c2.markdown(f"**Source IP**\n\n`{selected.source_ip}`")
        c3.markdown(f"**Username**\n\n`{selected.username}`")
        st.write(f"**Related event count:** {selected['count']}")
        st.write(f"**MITRE ATT&CK association:** {selected.mitre}")
        st.write(f"**Why this alert fired:** {selected.reason}")
        st.write(f"**Recommended defensive review:** {selected.recommended_action}")
        key=f"notes_{aid}"
        if key not in st.session_state: st.session_state[key]=load_note(aid)
        notes=st.text_area("Analyst investigation notes",key=key,height=140,
                           placeholder="What did you check? What is confirmed? What remains to verify?")
        if st.button("💾 Save investigation notes",type="primary"):
            save_note(aid,notes,selected.severity,selected.source_ip,selected.username,
                      selected.rule,selected.mitre)
            st.success("Saved permanently in the local SQLite database.")

st.header("◈ INVESTIGATION HISTORY")
history=pd.read_sql_query("SELECT alert_id,severity,source_ip,username,rule,mitre,notes,updated_at FROM investigations ORDER BY updated_at DESC",get_connection())
if history.empty: st.info("No saved investigations yet. Save notes for an alert to create a history record.")
else:
    st.dataframe(history.drop(columns=["notes"]),use_container_width=True,hide_index=True)
    st.download_button("⬇ Download investigation history CSV",
                       history.to_csv(index=False).encode("utf-8"),
                       "soc_investigation_history.csv","text/csv")

st.header("◈ RAW SECURITY EVENTS")
st.dataframe(events,use_container_width=True,hide_index=True)
if not alerts.empty:
    st.download_button("⬇ Download alert report CSV",alerts.to_csv(index=False).encode("utf-8"),
                       "soc_watchtower_alerts.csv","text/csv")
st.caption("Educational defensive prototype. Alerts are indicators for human review, not proof of compromise.")
