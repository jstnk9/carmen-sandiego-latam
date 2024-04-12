import altair as alt
import numpy as np
import pandas as pd
import streamlit as st
import json
import altair as alt
import streamlit as st

option = st.selectbox(
    'How would you like to be contacted?',
    ('Selecciona un pais','Panama', 'Republica Dominicana', 'Ecuador', 'Mexico', 'Colombia', 'Venezuela', 'Argentina', 'Brasil', 'Peru', 'Chile', 'Uruguay', 'Paraguay'))

countries = {
    "Panama": "panama2.json",
    "Republica Dominicana": "republicadominicana2.json",
    "Ecuador" : "ecuador2.json",
    "Mexico": "mexico2.json",
    "Colombia": "colombia2.json",
    "Venezuela": "venezuela2.json",
    "Argentina": "argentina2.json",
    "Brasil": "brazil2.json",
    "Peru": "peru2.json",
    "Chile": "chile2.json",
    "Uruguay": "uruguay2.json",
    "Paraguay": "paraguay2.json"
}

if option in countries:
    f = open(countries.get(option), "r", encoding="utf8")
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

    st.altair_chart(alt.Chart(df_top).mark_bar().encode(
        alt.X('malware_config'),
        alt.Y('count', sort='-y')
    ).properties(width=600,title="TOP 10 Principales familias de malware"))

else:
    st.write('La opcion %s no se encuentra disponible'%(option))


