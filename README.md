# 🛡️ Threat Pulse: Context-Aware Security System (Local AI Edition)

**Real-Time Threat Detection with AI-Powered Explanation & Alerting**

Threat Pulse is a next-gen security tool that detects cyber threats in real-time using Deep Learning, explains them using Generative AI, and alerts security teams instantly via WhatsApp.

---

## 🚀 Key Features

*   **Real-Time Anomaly Detection**: Uses a local **TensorFlow Autoencoder** to spot unknown threats.
*   **AI-Powered Summaries**: Integrates **SambaNova AI (Meta-Llama-3.3-70B)** to explain *why* an alert is critical.
*   **Instant Alerts**: Sends detailed incident reports to **WhatsApp** (via Twilio).
*   **Live Dashboard**: Interactive **Streamlit** dashboard for monitoring and investigation.
*   **Privacy-First**: Runs locally. No cloud data ingestion required.

---

## 🛠️ Tech Stack

*   **AI/ML**: TensorFlow (Keras), Scikit-Learn
*   **GenAI**: SambaNova API (Meta-Llama-3.3-70B-Instruct)
*   **Backend**: Python, Watchdog
*   **Database**: SQLite (Local)
*   **Alerting**: Twilio (WhatsApp)
*   **Dashboard**: Streamlit, Plotly

---

## 📦 Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/your-repo/threat-pulse.git
    cd threat-pulse
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure Environment**:
    Create a `.env` file in the root directory:
    ```ini
    # Twilio Configuration
    TWILIO_ACCOUNT_SID=your_sid
    TWILIO_AUTH_TOKEN=your_token
    TWILIO_WHATSAPP_FROM=whatsapp:+14155238886
    TO_WHATSAPP=whatsapp:+your_number

    # SambaNova AI Key (Free Tier)
    SAMBANOVA_API_KEY=your_sambanova_key
    ```
    *Important: For Twilio Sandbox, send `join <your-keyword>` to the Twilio number first!*

---

## 🚦 How to Run

**One-Click Start (Windows):**
```powershell
.\start_enterprise.ps1
```

This will automatically:
1.  Start the **Ingestion Service** (Background PID).
2.  Start the **Traffic Simulator** (Background PID).
3.  Launch the **Dashboard** in your browser.

---

## 🧪 Simulation & Testing

The system includes a traffic generator that simulates real-world attacks:
*   **SQL Injection Attempts**
*   **Brute Force Attacks**
*   **Data Exfiltration**
*   **Normal User Behavior**

Watch the **Logs** folder or the **Dashboard** to see attacks being detected and explained in real-time.

---

## 📂 Project Structure

*   `src/`: Core logic (Ingestion, Database, Model).
*   `dashboard/`: Streamlit UI code.
*   `utils/`: Helper scripts (Alerting, GenAI Client, Data Generation).
*   `logs_ingest/`: Directory watched for new log files.
*   `security_events.db`: Local SQLite database.

---

## ⚠️ Troubleshooting

*   **WhatsApp not working?** ensuring you have joined the Twilio Sandbox by sending `join <keyword>` to `+14155238886`.
*   **No AI Summary?** Check your `SAMBANOVA_API_KEY` quota or internet connection.
