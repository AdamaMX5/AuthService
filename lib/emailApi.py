import httpx
from typing import Dict, Any, Optional
from datetime import datetime
import json


import logging
logger = logging.getLogger(__name__)

EMAIL_SERVICE_URL = "https://email.yourapp.com"


async def send_email(to_email: str, subject: str, body: str, html: Optional[bool] = False) -> bool:
    """Send an email using the external email service."""
    payload: Dict[str, Any] = {
        "to_email": to_email,
        "subject": subject,
        "body": body,
        "html": html
    }
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(f"{EMAIL_SERVICE_URL}/send", json=payload)
            response.raise_for_status()
            result = response.json()
            if result.get("success"):
                logger.info(f"Email queue to sent to {to_email} with subject '{subject}'")
                return True
            else:
                logger.error(f"Failed to send email to {to_email}: {result.get('error')}")
                return False
    except httpx.HTTPError as e:
        logger.error(f"HTTP error occurred while sending email to {to_email}: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error occurred while sending email to {to_email}: {str(e)}")
        return False


async def send_verification_email(
        user_email: str, verification_token: str, user_id: str) -> Dict[str, Any]:
    """Send an email verification email to the user."""
    verification_link = f"https://user.yourapp.com/verify-email?token={verification_token}&user_id={user_id}"
    text = f"Wellcome to our Project,<br>Please verify your email by clicking the following link: {verification_link}"
    subject = "Email Verification"
    success = await send_email(user_email, subject, text, html=True)


async def send_password_reset_email(
        user_email: str, reset_token: str, user_id: str) -> Dict[str, Any]:
    """Send a password reset email to the user."""
    reset_link = f"https://user.yourapp.com/reset-password?token={reset_token}&user_id={user_id}"
    text = f"You requested a password reset.<br>Please reset your password by clicking the following link: {reset_link}"
    text += "<br>If you did not request this, please ignore this email."
    subject = "Password Reset Request"
    success = await send_email(user_email, subject, text, html=True)
