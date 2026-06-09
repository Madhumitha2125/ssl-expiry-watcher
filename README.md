# SSL Certificate Expiry Watcher 🔒

A Streamlit-based dashboard to scan, monitor, and manage SSL certificate expiry dates for your domains. It features automated status checks, AI-powered risk reporting, and customizable alert notifications.

## Features

- **📊 Monitor Dashboard**: View the expiry status of all your monitored domains at a glance.
- **📈 Scan History Trend**: Inspect advanced certificate details and view historical trends of days left until expiry.
- **🤖 AI-Powered Risk Reports**: Generate intelligent reports summarizing risks based on your current certificate statuses using Groq and OpenRouter.
- **📥 Import & Manage**: Easily add domains manually or by uploading a `.txt` or `.csv` file.
- **⚙️ Alert Settings**: Configure Slack Webhooks and SMTP email settings to automatically receive warnings for critical or expiring certificates.
- **📊 Export Data**: Export scan results to a CSV file for your records.

## Technologies Used

- **Frontend/Backend**: [Streamlit](https://streamlit.io/)
- **Language**: Python
- **Data Handling**: Pandas, SQLite (via built-in Python `sqlite3`)
- **Visualizations**: Altair
- **AI Models**: Groq (`llama3-70b-8192`) with fallback to OpenRouter (`meta-llama/llama-3.1-8b-instruct`)

## Setup & Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd ssl-expiry-watcher
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```bash
   streamlit run app.py
   ```

## Configuration

The application uses a `.env` file to manage sensitive keys and configuration. The file will be auto-generated upon the first run, or you can create it manually. You can also configure these settings directly from the **Alert Settings** tab within the dashboard.

### Environment Variables (`.env`)

```ini
GROQ_API_KEY=your_groq_api_key
OPENROUTER_API_KEY=your_openrouter_api_key
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@example.com
SMTP_PASSWORD=your_email_password
EMAIL_TO=recipient@example.com
```

### Thresholds
By default, the application categorizes certificate statuses as follows (can be modified in `config.py`):
- **SAFE**: > 30 days remaining
- **WARNING**: 7 - 30 days remaining
- **CRITICAL**: < 7 days remaining

## Usage

1. Open the dashboard in your browser (usually `http://localhost:8501`).
2. Go to the **Import & Manage** tab to add domains to your watchlist.
3. Use the **Monitor Dashboard** to review statuses and generate AI Risk Reports.
4. Go to **Alert Settings** to configure Slack or Email alerts and send a test notification.
5. Click **Re-scan All Monitored Domains** in the sidebar to refresh the expiry details at any time.

## License

MIT License
