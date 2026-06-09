"""
Background Scheduler for automated SSL scanning and alerting.
"""
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from database import get_all_monitored_domains, upsert_results
from ssl_checker import scan_domains
from alerts_service import check_and_send_alerts

logger = logging.getLogger(__name__)

# Global scheduler instance
_scheduler = None

def run_automated_scan():
    """Runs a background scan for all monitored domains and triggers alerts if necessary."""
    logger.info("Starting scheduled background scan...")
    domains = get_all_monitored_domains()
    if not domains:
        logger.info("No domains to monitor in background scan.")
        return

    try:
        results = scan_domains(domains)
        upsert_results(results)
        alert_status = check_and_send_alerts(results)
        logger.info(f"Background scan completed for {len(domains)} domains. Alerts sent: {alert_status.get('sent', False)}")
    except Exception as e:
        logger.error(f"Error during background scan: {e}")


def start_scheduler(hours: int = 24):
    """Starts the background scheduler if it isn't already running."""
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler()
        # Add the job to run immediately and then at the specified interval
        _scheduler.add_job(
            run_automated_scan,
            trigger=IntervalTrigger(hours=hours),
            id='daily_ssl_scan',
            name='Daily SSL Expiry Scan',
            replace_existing=True
        )
        _scheduler.start()
        logger.info(f"Background scheduler started. Next run in {hours} hours.")


def stop_scheduler():
    """Stops the background scheduler."""
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown()
        _scheduler = None
        logger.info("Background scheduler stopped.")
