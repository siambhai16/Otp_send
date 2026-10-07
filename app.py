import json
import secrets
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


# =========================
# Load Config
# =========================

with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)


GMAIL = config["gmail"]
APP_PASSWORD = config["app_password"]
API_KEY = config["api_key"]


# =========================
# Flask
# =========================

app = Flask(__name__)


limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)


# =========================
# Send Email
# =========================

def send_otp_email(receiver, otp):

    subject = "Your OTP Verification Code"

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>OTP Verification</title>
    </head>

    <body style="
        margin:0;
        padding:30px;
        background:#f4f6f8;
        font-family:Arial,sans-serif;
    ">

        <div style="
            max-width:500px;
            margin:auto;
            background:white;
            padding:30px;
            border-radius:12px;
            text-align:center;
        ">

            <h2>OTP Verification</h2>

            <p>Your verification code is:</p>

            <div style="
                font-size:32px;
                font-weight:bold;
                letter-spacing:8px;
                margin:25px 0;
            ">
                {otp}
            </div>

            <p>
                Please do not share this OTP with anyone.
            </p>

            <p style="color:#777;">
                If you didn't request this code,
                you can ignore this email.
            </p>

        </div>

    </body>
    </html>
    """

    message = MIMEMultipart("alternative")

    message["From"] = GMAIL
    message["To"] = receiver
    message["Subject"] = subject

    message.attach(
        MIMEText(html, "html", "utf-8")
    )

    # Gmail SMTP
    with smtplib.SMTP(
        "smtp.gmail.com",
        587,
        timeout=20
    ) as server:

        server.starttls()

        server.login(
            GMAIL,
            APP_PASSWORD
        )

        server.sendmail(
            GMAIL,
            receiver,
            message.as_string()
        )


# =========================
# Send OTP API
# =========================

@app.route("/send_otp", methods=["GET"])
@limiter.limit("10 per minute")
def send_otp():

    # API key
    api_key = request.args.get("api_key")

    if not api_key or not secrets.compare_digest(
        api_key,
        API_KEY
    ):
        return jsonify({
            "success": False,
            "error": "Invalid API key"
        }), 401


    # Get parameters
    otp = request.args.get("otp")
    receiver = request.args.get("gmail")


    if not otp:
        return jsonify({
            "success": False,
            "error": "OTP is required"
        }), 400


    if not receiver:
        return jsonify({
            "success": False,
            "error": "Gmail is required"
        }), 400


    # OTP validation
    if not otp.isdigit():

        return jsonify({
            "success": False,
            "error": "OTP must contain numbers only"
        }), 400


    if len(otp) < 4 or len(otp) > 8:

        return jsonify({
            "success": False,
            "error": "OTP must be 4-8 digits"
        }), 400


    # Basic email validation
    if "@" not in receiver:

        return jsonify({
            "success": False,
            "error": "Invalid email address"
        }), 400


    try:

        send_otp_email(
            receiver,
            otp
        )

        return jsonify({
            "success": True,
            "message": "OTP sent successfully",
            "to": receiver
        })


    except smtplib.SMTPAuthenticationError:

        return jsonify({
            "success": False,
            "error": "Gmail authentication failed"
        }), 500


    except Exception as e:

        return jsonify({
            "success": False,
            "error": "Failed to send email"
        }), 500


# =========================
# Home
# =========================

@app.route("/")
def home():

    return jsonify({
        "status": "online",
        "service": "OTP Mail API"
    })


# =========================
# Run
# =========================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )