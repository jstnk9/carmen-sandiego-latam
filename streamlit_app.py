import altair as alt
import numpy as np
import pandas as pd
import streamlit as st
import json
import altair as alt


"""
# Welcome to Streamlit!

Edit `/streamlit_app.py` to customize this app to your heart's desire :heart:.
If you have any questions, checkout our [documentation](https://docs.streamlit.io) and [community
forums](https://discuss.streamlit.io).

In the meantime, below is an example of what you can do with just a few lines of code:
"""
f = open("panama2.json", "r", encoding="utf8")
results = json.load(f)

data = []
for obj in results:
      data.append({
          "type_description": obj["attributes"]["type_description"] if 'type_description' in obj["attributes"] else 'unknown',
          "sha256": obj["attributes"]["sha256"] if 'sha256' in obj["attributes"] else 'unknown',
          "threat_category": obj.get("attributes").get("threat_severity").get("data").get("threat_severity_data").get("data").get("popular_threat_category") if obj.get("attributes").get("threat_severity").get("data").get("threat_severity_data").get("data").get("popular_threat_category") else 'unknown',
          "submission_date": pd.to_datetime(obj["attributes"]["first_submission_date"], unit='s') if 'first_submission_date' in obj["attributes"] else '',
          "threat_label": obj.get("attributes").get("popular_threat_classification").get("data").get("suggested_threat_label") if obj.get("attributes").get("popular_threat_classification") else 'unknown',
          "detections": obj.get("attributes").get("last_analysis_stats").get("data").get("malicious") if obj.get("attributes").get("last_analysis_stats").get("data").get("malicious") else -1,
          "malware_config": obj.get("attributes").get("malware_config").get("data").get("families")[0].get("family") if obj.get("attributes").get("malware_config") and obj.get("attributes").get("malware_config").get("data").get("families") else 'unknown',
      })
# Creating a DataFrame from the list of dictionaries
df = pd.DataFrame(data)
#df

df_top = df[df['malware_config'] != 'unknown'].groupby('malware_config').agg(count=('sha256', 'count')).reset_index().sort_values('count', ascending=False).head(10)

st.Chart(df_top).mark_bar().encode(
      st.X('malware_config'),
      st.Y('count', sort='-y')
).properties(width=600,title="TOP 10 Principales familias de malware")
