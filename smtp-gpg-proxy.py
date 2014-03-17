import asyncore

from email.parser import Parser
from secure_smtpd import ProxyServer

class GPGServer(ProxyServer):
    no = 0
    def process_message(self, peer, mailfrom, rcpttos, data):
        self.no += 1
        msg = Parser().parsestr(data)
        print "MSG #%i" % self.no
        print "From: %s" % msg['from']
        print "To: %s" % msg['to']
        print "Subject: %s" % msg['subject']

        attachments = {}
        body = ""
        cnt = 0
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            filename = part.get_filename()
            if filename != None:
                cnt += 1
                print "Attachment %i: %s" % (cnt, filename)
                attachments[filename] = part.get_payload(decode=True)
            else:
                print "Mail body found."
                body = part.get_payload(decode=True)
                # body += "\n\n--\nModified by Python."
                # part.set_payload(body)
        data = str(msg)[str(msg).find("\n")+1:] # TODO: Convert to non-horrible syntax

        ProxyServer.process_message(self, peer, mailfrom, rcpttos, data)


def run(remotesrv, remoteport):
    foo = GPGServer(('localhost', 25), (remotesrv, remoteport), ssl_out_only=True)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    remotesrv = raw_input("Please enter the remote server address (smtp.strato.de): ")
    remoteport = int(raw_input("Please enter the remote server port (465): "))
    run(remotesrv, remoteport)
