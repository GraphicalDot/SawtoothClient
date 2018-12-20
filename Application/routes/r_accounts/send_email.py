
import smtplib
import email.utils
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import random
from db import accounts_query

import coloredlogs, logging
coloredlogs.install()

async def ses_email(app, recipient, user_id, validity, subject, recovery=False):
    #com with your "From" address.
    # This address must be verified.
    SENDER = 'admin@remedium.in'
    SENDERNAME = 'Remedium'

    # Replace recipient@example.com with a "To" address. If your account
    # is still in the sandbox, this address must be verified.
    RECIPIENT  = recipient

    # Replace smtp_username with your Amazon SES SMTP user name.

    USERNAME_SMTP = app.config.USERNAME_SMTP

    # Replace smtp_password with your Amazon SES SMTP password.
    PASSWORD_SMTP = app.config.PASSWORD_SMTP

    # (Optional) the name of a configuration set to use for this message.
    # If you comment out this line, you also need to remove or comment out
    # the "X-SES-CONFIGURATION-SET:" header below.
    #CONFIGURATION_SET = "ConfigSet"

    # If you're using Amazon SES in an AWS Region other than US West (Oregon),
    # replace email-smtp.us-west-2.amazonaws.com with the Amazon SES SMTP
    # endpoint in the appropriate region.
    HOST = app.config.HOST_SMTP
    PORT = app.config.PORT_SMTP

    # The subject line of the email.
    SUBJECT = subject

    # The email body for recipients with non-HTML email clients.


    if recovery:
        email_otp = random.randint(100000,999999)
        BODY_TEXT = ("Remedium\r\n"
                     "This email was sent from Remedium to recover your password, in an event of lost password"
                     "Your email OTP is %s"%email_otp
                    )
        # The HTML body of the email.
        BODY_HTML = """<html>
        <head></head>
        <body>
          <h1>Remedium </h1>
          <p>This email was sent from
            <a href='http://www.remedium.in/'>Remedium</a>
            to recover your password, in an event of lost password</p>
        <p>Your email OTP is %s</p>
        </body>
        </html>
                    """%email_otp

    # Create message container - the correct MIME type is multipart/alternative.
    msg = MIMEMultipart('alternative')
    msg['Subject'] = SUBJECT
    msg['From'] = email.utils.formataddr((SENDERNAME, SENDER))
    msg['To'] = RECIPIENT
    # Comment or delete the next line if you are not using a configuration set
    #msg.add_header('X-SES-CONFIGURATION-SET',CONFIGURATION_SET)

    # Record the MIME types of both parts - text/plain and text/html.
    part1 = MIMEText(BODY_TEXT, 'plain')
    part2 = MIMEText(BODY_HTML, 'html')

    # Attach parts into message container.
    # According to RFC 2046, the last part of a multipart message, in this case
    # the HTML message, is best and preferred.
    msg.attach(part1)
    msg.attach(part2)

    # Try to send the message.
    try:
        server = smtplib.SMTP(HOST, PORT)
        server.ehlo()
        server.starttls()
        #stmplib docs recommend calling ehlo() before & after starttls()
        server.ehlo()
        server.login(USERNAME_SMTP, PASSWORD_SMTP)
        server.sendmail(SENDER, RECIPIENT, msg.as_string())
        server.close()
    # Display an error message if something goes wrong.
    except Exception as e:
        logging.error("Error: ", e)
    else:
        await accounts_query.insert_otps(app, "email", email_otp, user_id, recipient, validity)

        logging.error("Email sent!")
    return email_otp
