import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os

st.set_page_config(page_title="Network Traffic Dashboard", layout="wide")

st.title("📡 Mini Network Traffic Dashboard")

# Auto-refresh every 5 seconds
# st_autorefresh = st.experimental_rerun()

# Check if CSV exists
csv_file = r"C:\Users\Asad Ali\Desktop\SentinelX\network_traffic.csv"
if not os.path.exists(csv_file):
    st.warning("CSV file not found! Run the sniffer first.")
    st.stop()

# Load data
df = pd.read_csv(csv_file)

# ---- KPIs ----
st.subheader("📊 Key Metrics")
total_packets = len(df)
tcp_count = len(df[df["Protocol"]=="TCP"])
udp_count = len(df[df["Protocol"]=="UDP"])
icmp_count = len(df[df["Protocol"]=="ICMP"])
other_count = len(df[df["Protocol"]=="Other"])

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Packets", total_packets)
col2.metric("TCP Packets", tcp_count)
col3.metric("UDP Packets", udp_count)
col4.metric("ICMP Packets", icmp_count)
col5.metric("Other Packets", other_count)

# ---- Protocol Distribution Chart ----
st.subheader("📈 Protocol Distribution")
fig, ax = plt.subplots()
df["Protocol"].value_counts().plot(kind='bar', color=['blue','green','red','gray'], ax=ax)
plt.xlabel("Protocol")
plt.ylabel("Count")
plt.grid(axis='y')
st.pyplot(fig)

# ---- Top IPs ----
st.subheader("🌐 Top Source & Destination IPs")
st.write("Top 5 Source IPs:")
st.table(df["Source IP"].value_counts().head(5))

st.write("Top 5 Destination IPs:")
st.table(df["Destination IP"].value_counts().head(5))

# ---- Top Ports ----
st.subheader("🔌 Top Destination Ports")
if "Destination Port" in df.columns:
    st.table(df["Destination Port"].value_counts().head(5))
else:
    st.info("Port data not available. Run sniffer with port detection enabled.")
 
st.subheader("Top Source Ports")  
if "Source Port" in df.columns:
    st.table(df["Source Port"].value_counts().head(5))
else:
    st.info("Port data not available. Run sniffer with port detection enabled.")
    
st.subheader("📅 Traffic Over Time")
if "Time" in df.columns:
    df["Time"] = pd.to_datetime(df["Time"])
    traffic_over_time = df.set_index("Time").resample("1Min").size()
    fig2, ax2 = plt.subplots()
    traffic_over_time.plot(ax=ax2)
    plt.xlabel("Time")
    plt.ylabel("Packet Count")
    plt.grid()
    st.pyplot(fig2)
else:
    st.info("Time data not available. Run sniffer with timestamp enabled.")
    
    

# ---- Auto refresh ----
st.experimental_rerun()      