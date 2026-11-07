import pandas as pd
from detector import analyze_logs

def test_repeated_failures():
    rows=[dict(timestamp=f"2026-11-07 08:0{i}:00",source_ip="10.0.0.5",
        username="student",event_type="login",status="failed",details="training") for i in range(5)]
    _,alerts=analyze_logs(pd.DataFrame(rows))
    assert (alerts.severity=="High").any()
