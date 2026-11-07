import pandas as pd

REQUIRED_COLUMNS=["timestamp","source_ip","username","event_type","status","details"]

def analyze_logs(raw,threshold=5,window_minutes=10):
    df=raw.copy()
    for col in REQUIRED_COLUMNS:
        if col not in df.columns: raise ValueError(f"Missing required column: {col}")
    df["timestamp"]=pd.to_datetime(df["timestamp"],errors="coerce")
    for col in ["source_ip","username","event_type","status","details"]:
        df[col]=df[col].fillna("").astype(str).str.strip()
    df["_event"]=df.event_type.str.lower()
    df["_status"]=df.status.str.lower()
    valid=df.dropna(subset=["timestamp"]).sort_values("timestamp")
    auth=valid[valid._event.isin(["login","authentication"])]
    failures=auth[auth._status.isin(["failed","failure","denied"])]
    successes=auth[auth._status.isin(["success","successful","allowed"])]
    alerts=[]; n=1
    for ip,group in failures.groupby("source_ip"):
        group=group.sort_values("timestamp")
        for start in group.timestamp.tolist():
            matched=group[(group.timestamp>=start)&(group.timestamp<=start+pd.Timedelta(minutes=window_minutes))]
            if len(matched)>=threshold:
                alerts.append(dict(alert_id=f"SW-{n:04d}",timestamp=matched.timestamp.max(),
                    severity="High",rule="Repeated authentication failures",source_ip=ip,
                    username=", ".join(sorted(set(matched.username))),count=len(matched),
                    mitre="T1110 – Brute Force (contextual association)",
                    reason=f"{len(matched)} failed authentication events from this source within {window_minutes} minutes.",
                    recommended_action="Review identity-provider logs, confirm expected activity, and follow the organization's account-security procedure."))
                n+=1; break
    for _,row in successes.iterrows():
        earlier=failures[(failures.username==row.username)&(failures.timestamp<=row.timestamp)]
        if len(earlier)>=3:
            alerts.append(dict(alert_id=f"SW-{n:04d}",timestamp=row.timestamp,severity="Medium",
                rule="Successful login after repeated failures",source_ip=row.source_ip,
                username=row.username,count=len(earlier),
                mitre="T1078 – Valid Accounts (contextual association)",
                reason=f"A successful login occurred after {len(earlier)} earlier failed attempts for this username.",
                recommended_action="Verify the login with the account owner and review surrounding authentication events."))
            n+=1
    privileged=successes[successes.username.str.lower().str.contains(r"admin|root|administrator",regex=True)]
    for _,row in privileged.iterrows():
        alerts.append(dict(alert_id=f"SW-{n:04d}",timestamp=row.timestamp,severity="Low",
            rule="Privileged account login – review",source_ip=row.source_ip,username=row.username,
            count=1,mitre="Account monitoring – no direct technique assigned",
            reason="A successful login used a username that appears privileged; this is not inherently malicious.",
            recommended_action="Check whether the account, source, and login time are authorized."))
        n+=1
    cols=["alert_id","timestamp","severity","rule","source_ip","username","count","mitre","reason","recommended_action"]
    out=pd.DataFrame(alerts,columns=cols)
    if not out.empty:
        out=out.sort_values("timestamp",ascending=False).reset_index(drop=True)
        out["timestamp"]=out.timestamp.dt.strftime("%Y-%m-%d %H:%M:%S")
    return df.drop(columns=["_event","_status"]),out
