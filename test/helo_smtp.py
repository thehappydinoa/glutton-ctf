from smtplib import SMTP
with SMTP("34.69.170.149", port=25) as smtp:
    # smtp.noop()
    code, msg = smtp.helo("FOO")
    print(f'code = {code}\nmsg = {msg}')
    errs = smtp.sendmail("foo@bar.com", "foo@censys.io", "some message body.")
    print(f'errs = {errs}')
