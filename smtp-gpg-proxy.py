import asyncore
import gnupg
import base64

from email.parser import Parser
from secure_smtpd import ProxyServer

class GPGServer(ProxyServer):
    def __init__(self, *args, **kwargs):
        self.signing_key = kwargs['signing_key']
        self.gnupghome = kwargs['gnupghome']
        del kwargs['gnupghome']
        del kwargs['signing_key']
        ProxyServer.__init__(self, *args, **kwargs)

    
    def process_message(self, peer, mailfrom, rcpttos, data):
        gpg = gnupg.GPG(gnupghome=self.gnupghome)
        msg = Parser().parsestr(data)
        print "From: %s" % msg['from']
        print "To: %s" % msg['to']
        print "Subject: %s" % msg['subject']

        if msg['subject'][-10:-8] == "0x": # TODO: Allow specification of full fingerprint
            keyid = msg['subject'][-10:]
            newsub = msg['subject'][:-10]
            del msg['subject']
            msg['subject'] = newsub

            print "Encryption requested."
            print "KeyID: %s" % keyid
            print "New Subject: %s" % newsub

            # TODO: Add header indicating that this program was used
            cnt = 0
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                filename = part.get_filename()
                if filename != None:
                    cnt += 1
                    print "Attachment %i: %s" % (cnt, filename)
                    attachment = part.get_payload(decode=True)
                    att_encrypted = gpg.encrypt(attachment, [keyid, self.signing_key], sign=self.signing_key, always_trust = True) # TODO: Handle missing Key
                    # TODO: Seperate signing and self-encryption key
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
                    body = part.get_payload(decode=True)
                    body += "\n\n--\nDiese Nachricht wurde automatisch signiert." # TODO: Put this into a config variable
                    cbody = gpg.encrypt(body, [keyid, self.signing_key], sign=self.signing_key, always_trust = True) # TODO: Handle missing Key
                    # TODO: Seperate signing and self-encryption key
                    part.set_payload(str(cbody))

            data = str(msg)[str(msg).find("\n")+1:] # TODO: Convert to non-horrible syntax

        print ""
        ProxyServer.process_message(self, peer, mailfrom, rcpttos, data)


def run(remotesrv, remoteport, signkey, gnupghome):
    foo = GPGServer(('localhost', 25), (remotesrv, remoteport), ssl_out_only=True, signing_key = signkey, gnupghome=gnupghome)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    remotesrv = raw_input("Please enter the remote server address (smtp.strato.de): ")
    remoteport = int(raw_input("Please enter the remote server port (465): "))
    signkey = "6B1606D7135190326DA7FA56400F348F831A9263"
    gnupghome = "/home/max/.gnupg"
    print
    run(remotesrv, remoteport, signkey, gnupghome)
