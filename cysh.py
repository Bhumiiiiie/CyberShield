import hashlib
import os
import re
import math
import streamlit as st

# Streamlit page setup
st.set_page_config(page_title="CyberShield: A Framework for Cybercrime Investigators", layout="centered")

# Updated Title
st.title("🛡️ CyberShield: A Framework for Cybercrime Investigators")
st.write("---")

# Helper functions
def log_analysis_tool():
    st.header("📝 Advanced Log Analysis Tool")
    log_file = st.file_uploader("Upload a log file", type=["txt", "log"], key="logfile")
    if log_file:
        logs = log_file.read().decode("utf-8").splitlines()
        if not logs:
            st.warning("The log file is empty.")
            return

        filter_option = st.selectbox("Filter by log level:", ["Show all logs", "INFO", "ERROR", "WARNING"])
        custom_search = st.text_input("Or enter a custom keyword or regex to search logs:")



        filtered_logs = []
        log_stats = {"INFO": 0, "ERROR": 0, "WARNING": 0}

        for line in logs:
            for level in log_stats:
                if level in line:
                    log_stats[level] += 1

            if filter_option != "Show all logs" and filter_option in line:
                filtered_logs.append(line)
            elif custom_search and re.search(custom_search, line):
                filtered_logs.append(line)
            elif filter_option == "Show all logs" and not custom_search:
                filtered_logs.append(line)

        st.markdown(f"**Log Summary:** ✅ INFO: `{log_stats['INFO']}` | ❌ ERROR: `{log_stats['ERROR']}` | ⚠️ WARNING: `{log_stats['WARNING']}`")

        for log in filtered_logs:
            if "ERROR" in log:
                st.error(log)
            elif "WARNING" in log:
                st.warning(log)
            elif "INFO" in log:
                st.info(log)
            else:
                st.text(log)

        st.success(f"{len(filtered_logs)} log entries matched the filter.")




def file_integrity_checker():
    st.header("🛡️ File Integrity Checker")
    file = st.file_uploader("Upload a file to check integrity", type=None, key="integrity")
    original_hash = st.text_input("Enter the original hash (SHA-256):")

    if file and original_hash:
        hash_algo = hashlib.sha256()
        for chunk in iter(lambda: file.read(4096), b""):
            hash_algo.update(chunk)
        current_hash = hash_algo.hexdigest()

        st.text(f"Calculated Hash: {current_hash}")

        if original_hash == current_hash:
            st.success("✅ File integrity is intact.")
        else:
            st.error("⚠️ File integrity has been compromised!")

def calculate_entropy(password):
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"[0-9]", password): charset += 10
    if re.search(r"[!@#$%^&*()_+=\[{\]};:<>|./?,-]", password): charset += 32
    entropy = len(password) * math.log2(charset) if charset > 0 else 0
    return entropy

def password_strength_auditor():
    st.header("🔐 Advanced Password Strength Auditor")
    password = st.text_input("Enter password to check:", type="password")


    if password:
        length_score = min(len(password) / 2, 4)
        digit = bool(re.search(r"\d", password))
        upper = bool(re.search(r"[A-Z]", password))
        symbol = bool(re.search(r"[!@#$%^&*()_+=\[{\]};:<>|./?,-]", password))

        strength_score = length_score
        strength_score += 1 if digit else 0
        strength_score += 1 if upper else 0
        strength_score += 1 if symbol else 0

        entropy = calculate_entropy(password)
        st.markdown(f"🔢 **Estimated Entropy:** `{entropy:.2f} bits`")

        if strength_score >= 7:
            st.success("Strong password! 🔥 Excellent security.")
        elif strength_score >= 5:
            st.info("Moderately strong password. Consider adding more symbols or increasing length.")
        else:
            st.warning("Weak password. Try using a longer password with mixed characters.")

        # Real-time tips
        st.markdown("### 💡 Suggestions:")
        if len(password) < 8:
            st.markdown("- Increase password length to at least 12 characters.")
        if not upper:
            st.markdown("- Add uppercase letters (A-Z).")
        if not digit:
            st.markdown("- Add numbers (0-9).")
        if not symbol:

            st.markdown("- Add special characters (e.g., @, #, $, !).")

def phishing_url_detector():
    st.header("🎯 Phishing URL Detector")
    url = st.text_input("Enter URL to check:")

    if url:
        if not url.startswith("http://") and not url.startswith("https://"):
            st.error("Invalid URL format. Must start with 'http://' or 'https://'.")
            return

        suspicious_patterns = ["login", "secure", "account", "update"]
        for pattern in suspicious_patterns:
            if pattern in url.lower():
                st.warning("This URL contains suspicious keywords. Potential phishing site!")
                return

        suspicious_domains = ["example.com", "phishingsite.com"]
        domain = re.findall(r'https?://([A-Za-z_0-9.-]+).*', url)
        if domain and domain[0] in suspicious_domains:
            st.warning("This URL points to a suspicious domain!")
            return

        st.success("URL seems safe. ✅")

# Main Menu (without Hash Generator now)
menu = st.sidebar.selectbox("Select Tool",
    ("🏠 Home", "📝 Log Analysis Tool", "🛡️ File Integrity Checker", "🔐 Password Strength Auditor", "🎯 Phishing URL Detector")
)



# Sidebar User Guide + Hash Generator
with st.sidebar:
    if st.button("📖 User Guide / Tool Info"):
        st.sidebar.markdown("""
        ---
        ## 📚 User Guide
        ### About This Toolkit
        CyberShield provides essential tools for basic digital forensics and cybersecurity tasks.

        ### Tools Included:
        - **Log Analysis Tool:** Upload and filter logs based on severity.
        - **File Integrity Checker:** Verify if a file has been tampered with using SHA-256 hashes.
        - **Password Strength Auditor:** Analyze password strength based on best practices.
        - **Phishing URL Detector:** Check URLs for phishing signs and unsafe domains.

        ### How to Use:
        1. Select the desired tool from the dropdown above.
        2. Follow the tool's on-screen instructions.
        3. Review results to assist your investigation or improve security.

        ---
        Stay alert, stay safe! 🛡️
        """)

    st.write("---")
    st.subheader("🔢 Hash Generator")




    file = st.file_uploader("Upload a file", key="hashfile_sidebar")
    hash_type = st.selectbox("Select hash algorithm:", ("MD5", "SHA-1", "SHA-256"), key="hashalg_sidebar")

    if file:
        if hash_type == "MD5":
            hash_algo = hashlib.md5()
        elif hash_type == "SHA-1":
            hash_algo = hashlib.sha1()
        else:
            hash_algo = hashlib.sha256()

        for chunk in iter(lambda: file.read(4096), b""):
            hash_algo.update(chunk)

        generated_hash = hash_algo.hexdigest()
        st.text_area("Generated Hash", generated_hash, height=150)

        st.download_button("⬇️ Download Hash", generated_hash, file_name="hash_result.txt")

# Main Content
if menu == "🏠 Home":
    st.subheader("Welcome 👋")
    st.markdown("""
    This toolkit helps you:
    - Analyze logs 📋
    - Check file integrity 🔍
    - Audit password strength 🔑
    - Detect phishing URLs 🛡️



    **Select a tool from the sidebar! ➡️**
    """)

elif menu == "📝 Log Analysis Tool":
    log_analysis_tool()

elif menu == "🛡️ File Integrity Checker":
    file_integrity_checker()

elif menu == "🔐 Password Strength Auditor":
    password_strength_auditor()

elif menu == "🎯 Phishing URL Detector":
    phishing_url_detector()
