# Context-Aware Cyber Threat Detection (SOC Edition)

**Real-Time Security Operations Center & Alerting System**

## 🚀 Features
- **SOC Command Center**: A dark-mode, sci-fi style dashboard for security operators.
- **Instant Alerts**: Sends Telegram messages immediately when high-risk events occur.
- **Incident Management**: Tracks threats from "OPEN" to "RESOLVED" directly in the UI.
- **Live Traffic Simulation**: Automatically mimics a web server under attack.

## 🛠️ Configuration (Telegram Alerts)
To enable real-world alerts, you must configure your Telegram Bot:

1.  Open `utils/alerting.py`.
2.  Replace the placeholders:
    ```python
    TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN_HERE" 
    TELEGRAM_CHAT_ID = "YOUR_CHAT_ID_HERE"
    ```
    *(If you don't have these, alerts will simply print to the console).*

## 🎬 How to Run the "SOC Demo"
1.  **Launch the System**:
    ```powershell
    powershell -ExecutionPolicy Bypass -File start_enterprise.ps1
    ```
2.  **Login**:
    -   **Operator ID**: `admin`
    -   **Access Key**: `admin123`

3.  **Witness the Live Attack**:
    -   The system will start "Secure" (Green Banner).
    -   The **Traffic Simulator** will start generating random events.
    -   Suddenly, a **Critical Attack** (SQL Injection / Admin Access) will occur.
    -   **RESULT**:
        1.  Banner turns **RED** (Critical Status).
        2.  An **Incident Card** appears on the left.
        3.  You receive a **Real Telegram Notification** on your phone.
    
4.  **Respond**:
    -   Click **INVESTIGATE** on the dashboard to change status.
    -   Click **RESOLVE** once handled.
    -   Banner returns to Green.

## 📂 Project Structure
- `start_enterprise.ps1`: One-click launcher.
- `dashboard/app.py`: The SOC Control Room interface.
- `utils/alerting.py`: Telegram integration logic.
- `src/database.py`: Stores Logs and Incidents.
