import streamlit as st
from scapy.all import *


if "items" not in st.session_state:
    st.session_state["items"] = {
        "alert": [
            "attaque 1",
            "normal",
            "attaque 4",
            "attaque 3",
        ],
    }

st.title("Jeanne d'Arc")

st.data_editor(
    st.session_state["items"],
    column_config={
        "alert": st.column_config.ListColumn(
            "Most recent alert",
            help="The sales volume in the last 6 months",
            width="medium",
        ),
    },
    hide_index=True,
)


def packetTraitement():
    def callback(packet):
        st.session_state["items"]["alert"].append(packet.summary)
        st.rerun()
        return
    return callback


sniff(prn=packetTraitement())
