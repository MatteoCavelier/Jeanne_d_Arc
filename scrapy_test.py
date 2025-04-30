from scrapy.mail import MailSender
import smtplib
from smtplib import SMTP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# setup mailer
# mailer = MailSender(mailfrom="jeannedarc.avertissement@gmail.com", smtpuser="jeannedarc.avertissement@gmail.com",
#					smtphost="smtp.gmail.com", smtpport=465, smtppass="Je@nneD@RC")

# send mail
# mailer.send(to=["jeannedarc.avertissement@gmail.com"], subject="Scrapy Mail",
#	body="Hi ! GeeksForGeeks")


import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def send_email():
    gmailUser = 'jeannedarc.avertissement@outlook.fr'  # Ton adresse Outlook
    gmailPassword = 'cemaecusjqeodcrh'  # Ton mot de passe d'application
    recipient = 'jeannedarc.avertissement@outlook.fr'  # Destinataire

    msg = MIMEMultipart()
    msg['From'] = gmailUser
    msg['To'] = recipient
    msg['Subject'] = "Test de l'envoi d'email via Outlook"

    # Corps du message
    msg.attach(MIMEText("Hello, ceci est un test d'envoi d'e-mail avec Python !"))

    try:
        # Connexion au serveur SMTP d'Outlook
        mailServer = smtplib.SMTP('smtp.office365.com', 587)
        mailServer.ehlo()  # Identifie le client au serveur SMTP
        mailServer.starttls()  # Sécurise la connexion
        mailServer.ehlo()  # Re-négocie le protocole après le chiffrement

        # Authentification
        mailServer.login(gmailUser, gmailPassword)

        # Envoi de l'e-mail
        mailServer.sendmail(gmailUser, recipient, msg.as_string())
        print("E-mail envoyé avec succès !")
    except Exception as e:
        print(f"Erreur lors de l'envoi : {e}")
    finally:
        mailServer.close()  # Fermeture de la connexion au serveur SMTP


# Envoi de l'email
send_email()
