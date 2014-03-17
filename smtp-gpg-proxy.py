import asyncore
import gnupg
import base64
import config

from email.parser import Parser
from email.mime.application import MIMEApplication
from secure_smtpd import ProxyServer

class GPGServer(ProxyServer):

    def process_message(self, peer, mailfrom, rcpttos, data):
        gpg = gnupg.GPG(gnupghome=config.gpg_home)
        msg = Parser().parsestr(data)
        print "From: %s" % msg['from']
        print "To: %s" % msg['to']
        print "Subject: %s" % msg['subject']

        keyid = None
        if msg['subject'][-10:-8] == "0x": # Regular KeyID (0x12345678)
            keyid = msg['subject'][-10:]
            newsub = msg['subject'][:-10]
            del msg['subject']
            msg['subject'] = newsub
        elif msg['subject'][-18:-16] == "0x": # Long KeyID (0x1234567890ABCDEF)
            keyid = msg['subject'][-18:]
            newsub = msg['subject'][:-18]
            del msg['subject']
            msg['subject'] = newsub
        elif msg['subject'][-42:-40] == "0x": # Full Fingerprint w/o spaces
            keyid = msg['subject'][-40:]
            newsub = msg['subject'][:-42]
            del msg['subject']
            msg['subject'] = newsub

        if keyid != None or config.gpg_sign_all:
            print "Encryption / signing requested."
            if keyid != None:
                print "KeyID: %s" % keyid
                print "New Subject: %s" % newsub

            # TODO: Add header indicating that this program was used
            cnt = 0
            attach_later = []
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                filename = part.get_filename()
                if filename != None:
                    cnt += 1
                    print "Attachment %i: %s" % (cnt, filename)
                    attachment = part.get_payload(decode=True)
                    if keyid:
                        att_encrypted = gpg.encrypt(attachment, [keyid, config.encrypt_to], 
                            sign=config.signing_key, always_trust = True) # TODO: Handle missing Key
                        part.set_payload(base64.b64encode(str(att_encrypted)))
                        part.set_type("application/octet-stream")
                        ct_parts = part['Content-Type'].split('"')
                        new_ct = ct_parts[0] + '"' + '"'.join(ct_parts[1:-1]) + '.gpg"' + ct_parts[-1]
                        del part['Content-Type']
                        part['Content-Type'] = new_ct
                        cd_parts = part['Content-Disposition'].split('"')
                        new_cd = cd_parts[0] + '"' + '"'.join(cd_parts[1:-1]) + '.gpg"' + cd_parts[-1]
                        del part['Content-Disposition']
                        part['Content-Disposition'] = new_cd
                    else:
                        def convertDetachedSig(mimeobj):
                            mimeobj.set_payload(base64.b64encode(mimeobj.get_payload()))
                            mimeobj.add_header('Content-Disposition', 'attachment', filename=filename + ".sig")
                            mimeobj.add_header('Content-Transfer-Encoding', 'base64')

                        att_signed = gpg.sign(attachment, keyid=config.signing_key,
                            detach=True)
                        att_sig = MIMEApplication(str(att_signed), _subtype="octet-stream", _encoder=convertDetachedSig)
                        attach_later.append(att_sig)
                else:
                    body = part.get_payload(decode=True)
                    if keyid != None:
                        body += config.mail_signature_encrypted
                        cbody = gpg.encrypt(body, [keyid, config.encrypt_to], 
                            sign=config.signing_key, always_trust = True) # TODO: Handle missing Key
                    else:
                        body += config.mail_signature_signed
                        cbody = gpg.sign(body, keyid=config.signing_key,
                            clearsign=True)
                    part.set_payload(str(cbody))

            for att in attach_later:
                msg.attach(att)
            data = str(msg)[str(msg).find("\n")+1:] # TODO: Convert to non-horrible syntax

        print
        ProxyServer.process_message(self, peer, mailfrom, rcpttos, data)


def run():
    foo = GPGServer(('localhost', 25), 
        (config.smtp_out_add, config.smtp_out_port), 
        ssl_out_only=config.smtp_out_force_ssl)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    run()
