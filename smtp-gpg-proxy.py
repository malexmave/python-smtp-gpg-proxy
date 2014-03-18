import asyncore
import base64
import config
import getpass
import gnupg
import time

from email.parser import Parser
from email.mime.application import MIMEApplication
from secure_smtpd import ProxyServer

__version__ = "0.0.0"

def printLog(msg, level):
    if config.logging in level:
        print msg

def keyExists(keyid, gpg):
    # python-gnupg does not give an error message if the key does not exist.
    # This is a workaround to determine if a public key exists.
    if str(gpg.encrypt('test', keyid, always_trust=True)) != '':
        return True
    return False

def handleMissingKey(keyid, gpg):
    """If a public key is missing, this function handles the situation 
    according to config.err_pubkey_not_found.

    returns:
        0 - Continue with encryption
        1 - Continue without encryption
        2 - Abort
    """
    if config.err_pubkey_not_found == config.PK_ABORT:
        printLog("ERROR: Key not in keyring, aborting",
            [config.LOG_TIME, config.LOG_META, config.LOG_ERR])
        return 2
    elif config.err_pubkey_not_found == config.PK_SEND_UNENCRYPTED:
        printLog("ERROR: Key not in keyring, sending unencrypted",
            [config.LOG_TIME, config.LOG_META, config.LOG_ERR])
        return 1
    else:
        gpg.recv_keys(config.keyserver, keyid)
        if not keyExists(keyid, gpg):
            if config.err_pubkey_not_found == config.PK_RECV_FROM_KS_ABORT:
                printLog("ERROR: Key not in keyring and not on keyserver, aborting",
                    [config.LOG_TIME, config.LOG_META, config.LOG_ERR])
                return 2
            elif config.err_pubkey_not_found == config.PK_RECV_FROM_KS_SEND:
                printLog("ERROR: Key not in keyring and not on keyserver, sending unencrypted",
                    [config.LOG_TIME, config.LOG_META, config.LOG_ERR])
                return 1
            else:
                printLog("ERROR: Unknown option for config.err_pubkey_not_found",
                    [config.LOG_TIME, config.LOG_META, config.LOG_ERR])
                return 2
        return 0

def canSign(keyid, gpg, pp=None):
    # Find out if a key can sign, and if not, why not
    x = gpg.sign('test', keyid=keyid, passphrase=pp)
    if str(x) == "":
        if "secret key not available" in x.stderr:
            printLog("ERROR: Secret key for KeyID %s not available." % keyid,
                [config.LOG_META, config.LOG_TIME, config.LOG_ERR])
            return False
        if "NEED_PASSPHRASE" in x.stderr:
            printLog("ERROR: Secret key for KeyID %s is passphrase-protected."
                % keyid, [config.LOG_META, config.LOG_TIME, config.LOG_ERR])
            pp = getpass.getpass("Please enter the passphrase for %s: " % keyid)
            config.pp = pp
            return canSign(keyid, gpg, pp)
        else:
            print x.stderr
            return False
    return True

class GPGServer(ProxyServer):

    def process_message(self, peer, mailfrom, rcpttos, data):
        try:
            orig = data
            gpg = gnupg.GPG(gnupghome=config.gpg_home)
            msg = Parser().parsestr(data)
            printLog("%s: 1 Message" % time.strftime('%c'), [config.LOG_META, config.LOG_TIME])
            printLog("From: %s" % msg['from'], [config.LOG_META])
            printLog("To: %s" % msg['to'], [config.LOG_META])
            printLog("Subject: %s" % msg['subject'], [config.LOG_META])
    
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
                keyid = msg['subject'][-42:]
                newsub = msg['subject'][:-42]
                del msg['subject']
                msg['subject'] = newsub
            if keyid and not keyExists(keyid, gpg):
                action = handleMissingKey(keyid, gpg)
                if action == 1:
                    keyid = None
                if action == 2:
                    return 1
    
            if keyid != None or config.gpg_sign_all:
                if keyid != None:
                    printLog("KeyID: %s" % keyid, [config.LOG_META])
                    printLog("New Subject: %s" % newsub, [config.LOG_META])
    
                msg.add_header("X-Encryption-Proxy", "smtp-gpg-proxy v%s" % __version__)
                attach_later = []
                for part in msg.walk():
                    if part.get_content_maintype() == "multipart":
                        continue
                    filename = part.get_filename()
                    if filename != None:
                        attachment = part.get_payload(decode=True)
                        if keyid:
                            att_encrypted = gpg.encrypt(attachment, [keyid, config.encrypt_to], 
                                sign=config.signing_key, always_trust = True, passphrase=config.pp)
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
                                detach=True, passphrase=config.pp)
                            att_sig = MIMEApplication(str(att_signed), _subtype="octet-stream", _encoder=convertDetachedSig)
                            attach_later.append(att_sig)
                    else:
                        body = part.get_payload(decode=True)
                        if keyid != None:
                            body += config.mail_signature_encrypted
                            cbody = gpg.encrypt(body, [keyid, config.encrypt_to], 
                                sign=config.signing_key, always_trust = True, passphrase=config.pp)
                        else:
                            body += config.mail_signature_signed
                            cbody = gpg.sign(body, keyid=config.signing_key,
                                clearsign=True, passphrase=config.pp)
                        part.set_payload(str(cbody))
    
                for att in attach_later:
                    msg.attach(att)
                data = str(msg)[str(msg).find("\n")+1:] # TODO: Convert to non-horrible syntax
            printLog("", [config.LOG_META])
        except KeyboardInterrupt:
            printLog("Caught KeyboardInterrupt, exiting.", 
                [config.LOG_ERR, config.LOG_META, config.LOG_TIME])
            return 1
        except Exception, e:
            printLog("Exception:\n" + repr(e), [config.LOG_ERR, config.LOG_META, config.LOG_TIME])
            if config.err_unknown_error == config.UE_ABORT:
                return 1
            elif config.err_unknown_error == config.UE_TRY_SEND_ORIG:
                data = orig
            elif config.err_unknown_error != config.UE_TRY_SEND_CURRENT:
                printLog("ERROR: Unknown value for config.err_unknown_error.", 
                    [config.LOG_ERR, config.LOG_META, config.LOG_TIME])
                return 1
        ProxyServer.process_message(self, peer, mailfrom, rcpttos, data)


def run():
    gpg = gnupg.GPG(gnupghome=config.gpg_home)
    if not canSign(config.signing_key, gpg):
        return 1
    if not keyExists(config.encrypt_to, gpg):
        printLog("ERROR: Key %s (encrypt_to) not found." % config.encrypt_to,
            [config.LOG_META, config.LOG_TIME, config.LOG_ERR])
        return 1

    foo = GPGServer((config.smtp_in_add, config.smtp_in_port), 
        (config.smtp_out_add, config.smtp_out_port), 
        ssl_out_only=config.smtp_out_force_ssl)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    run()
