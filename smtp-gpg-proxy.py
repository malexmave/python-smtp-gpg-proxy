from datetime import datetime
import asyncore
from smtpd import SMTPServer

class GPGServer(SMTPServer):
    no = 0
    def process_message(self, peer, mailfrom, rcpttos, data):
        print data
        self.no += 1


def run():
    foo = GPGServer(('localhost', 25), None)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
	run()
