import streamlit as st
import gspread
import pandas as pd
from google.oauth2.service_account import Credentials
import datetime as dt
import re
from typing import List
import random, time
from gspread.exceptions import APIError, WorksheetNotFound
from datetime import datetime, date, timedelta
import pytz


users = st.secrets.get("users", {})


def authenticate():
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if "username" not in st.session_state:
        st.session_state["username"] = ""

    # Hvis vi allerede er logget ind, så stop her
    if st.session_state["authenticated"]:
        return

    st.title("Log ind")
    username = st.text_input("Brugernavn")
    password = st.text_input("Adgangskode", type="password")

    if st.button("Login"):
        if username in users and users[username] == password:
            st.session_state["authenticated"] = True
            st.session_state["username"] = username
            st.rerun()

        else:
            st.error("Forkert brugernavn eller adgangskode")

    st.stop()  # vis ikke resten, hvis ikke logget ind



authenticate()
user = st.session_state["username"]


st.caption("HELLO!")