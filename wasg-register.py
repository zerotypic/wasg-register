#!/usr/bin/python
#
# wasg-register : Registers for a new Wireless@SG SSA account
#
# Python equivalent of the Wireless@SG app available at:
#    https://www2.imda.gov.sg/programme-listing/wireless-at-sg/Wireless-at-SG-for-Consumers
#

from __future__ import print_function

import sys
import os
import requests
import urllib
import argparse
import datetime
import codecs
from Crypto.Cipher import AES

# ISP URLs were taken from WSG.Common.dll
# Test URL is for debugging.
ISP_ESSA_URLS = {
    "singtel" : "https://singtel-wsg.singtel.com/essa",
    "starhub" : "https://api.wifi.starhub.net.sg/essa",
    "myrepublic" : "https://wireless-sg-app.myrepublic.net/essa",
    "test" : "http://localhost:8080/essa",
}
DEFAULT_ISP="singtel"

# The transaction ID (transid) appears to be created from the WiFi
# interface's GUID in Windows, which is probably based on the MAC
# address. The below transid was found within WSG.Common.dll, and is used
# when there is no "DeviceManager" available. It seems to work fine.
DEFAULT_TRANSID = "053786654500000000000000"

VERBOSE = False

class Exn(Exception): pass
class HTTPNotFoundExn(Exn): pass
class MalformedResponseExn(Exn): pass

def LOG(m):
    if VERBOSE:
        sys.stderr.write(m + os.linesep)
    #endif
#enddef

# Helper function to validate server responses.
def _validate(resp, key, val=None, fatal=False):
    def _raise(m): raise MalformedResponseExn(m)
    err = print if not fatal else _raise
    if not key in resp:
        err("Warning: Server response did not contain key '%s'." % (key,))
    elif val != None and resp[key] != val:
        err("Warning: Unexpected server response, key '%s' is '%s', not '%s'." \
            % (key, resp[key], val))
        #endif
    #endif
#enddef

def request_registration(isp,
                         salutation, name, uid, mobile,
                         country, dob, email, transid):

    r = requests.get(ISP_ESSA_URLS[isp],
                     params={
                         "api" : "create_user_r1a",
                         "salutation" : salutation,
                         "name" : name,
                         "uid" : uid,
                         "mobile" : mobile,
                         "nationality" : country,
                         "dob" : dob,
                         "email" : email,
                         "tid" : transid,
                     })

    if r.status_code != requests.codes.ok:
        raise HTTPNotFoundExn("Failed to make request query.")
    #endif
    
    try:
        resp = r.json()
    except ValueError:
        raise MalformedResponseExn("Malformed response from server.")
    #endtry

    _validate(resp, "api", "create_user_r1a")
    _validate(resp, "version", "2.1")
    _validate(resp, "body", fatal=True)
    _validate(resp["body"], "success_code", fatal=True)

    return resp["body"]["success_code"]

#enddef

def validate_otp(isp, uid, mobile, otp, success_code, transid):

    r = requests.get(ISP_ESSA_URLS[isp],
                     params={
                         "api" : "create_user_r1b",
                         "uid" : uid,
                         "mobile" : mobile,
                         "otp" : otp,
                         "success_code" : success_code,
                         "tid" : transid
                     })

    if r.status_code != requests.codes.ok:
        raise HTTPNotFoundExn("Failed to make validation query.")
    #endif
    
    try:
        resp = r.json()
    except ValueError:
        raise MalformedResponseExn("Malformed response from server.")
    #endtry

    _validate(resp, "api", "create_user_r1b")
    _validate(resp, "version", "2.3")
    _validate(resp, "body", fatal=True)
    _validate(resp["body"], "userid", fatal=True)
    _validate(resp["body"], "enc_userid", fatal=True)
    _validate(resp["body"], "enc_password", fatal=True)

    return (str(resp["body"]["userid"]),
            str(resp["body"]["enc_userid"]),
            str(resp["body"]["enc_password"]))
    
#enddef

def build_decrypt_key(date, transid, otp):
    date_hex = "%03x" % (int(date.strftime("%e%m").strip()),)
    otp_hex = "%05x" % (int(otp),)
    key_hex = date_hex + transid + otp_hex
    return key_hex.decode("hex")
#enddef

def decrypt(key, ciphertext):
    aes = AES.AESCipher(key)
    pt = aes.decrypt(ciphertext)
    # Remove PKCS#7 padding.
    return pt[:-ord(pt[-1])]
#enddef

def errquit(m):
    LOG("Error: " + m)
    return 1
#enddef

def main():

    parser = argparse.ArgumentParser(
        description="Wireless@SG registration utility.",
    )

    parser.add_argument("mobile",
                        type=str,
                        help="Mobile phone number")
    parser.add_argument("nric",
                        type=str,
                        help="NRIC or equivalent ID number")

    parser.add_argument("-I", "--isp",
                        type=str,
                        choices=ISP_ESSA_URLS.keys(),
                        default=DEFAULT_ISP,
                        help="ISP to register with")
    
    parser.add_argument("-s", "--salutation",
                        type=str,
                        default="Dr",
                        help="Salutation")
    
    parser.add_argument("-n", "--name",
                        type=str,
                        default="Some Person",
                        help="Full name")

    parser.add_argument("-c", "--country",
                        type=str,
                        default="SG",
                        help="Nationality country code")

    parser.add_argument("-d", "--dob",
                        type=str,
                        default="1990-01-01",
                        help="Date of Birth")

    parser.add_argument("-e", "--email",
                        type=str,
                        default="nonexistent@noaddresshere.com",
                        help="Email address")

    parser.add_argument("-t", "--transid",
                        type=str,
                        default=DEFAULT_TRANSID,
                        help="Transaction ID")

    parser.add_argument("-1", "--registration-phase-only",
                        action="store_true",
                        help="Terminate after registration phase, returns success code.")
    
    parser.add_argument("-O", "--otp",
                        type=str,
                        help="OTP received on mobile. Note that if this is set, then wasg-register will skip the registration phase and move immediately to OTP validation. success-code must also be provided.")

    parser.add_argument("-S", "--success-code",
                        type=str,
                        help="Success code received during registration phase. Note that if this is set, then wasg-register will skip the registration phase and move immediately to OTP validation. OTP must also be provided.")

    parser.add_argument("-D", "--decryption-date",
                        type=str,
                        help="Date the OTP was generated, for use in decryption, in YYMMDD format.")

    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        help="Be verbose.")
    
    args = parser.parse_args()

    global VERBOSE
    VERBOSE = args.verbose

    otp = None
    success_code = None
    
    if args.otp == None and args.success_code == None:
        # Begin registration phase.

        success_code = request_registration(
            args.isp,
            args.salutation,
            args.name,
            args.nric,
            args.mobile,
            args.country,
            args.dob,
            args.email,
            args.transid)

        LOG("Got success code: %s" % (success_code,))

        if args.registration_phase_only:
            print("Success code: %s" % (success_code,))
            return 0
        #endif

        print("OTP will be sent to mobile phone number %s" % (args.mobile,))
        otp = input("Enter OTP to continue: ")

    else:
        # Skipping registration phase, make sure we have OTP and success code.
        if args.otp == None or args.success_code == None:
            return errquit("Both success code and OTP must be provided to skip registration phase.")
        #endif

        success_code = args.success_code
        otp = args.otp

    #endif
        
    (userid, enc_userid_hex, enc_password_hex) = validate_otp(
        args.isp,
        args.nric,
        args.mobile,
        otp,
        success_code,
        args.transid)

    enc_userid = enc_userid_hex.decode("hex")
    enc_password = enc_password_hex.decode("hex")
    
    if args.decryption_date != None:
        decryption_date = datetime.datetime.strptime(args.decryption_date, "%Y%m%d")
    else:
        decryption_date = datetime.datetime.now()
    #endif

    try_dates = (decryption_date,
                 decryption_date + datetime.timedelta(1),
                 decryption_date + datetime.timedelta(-1))

    found = False
    for date in try_dates:
        key = build_decrypt_key(date, args.transid, otp)
        if decrypt(key, enc_userid) == userid:
            LOG("Successfully decrypted using date %s." % (date.strftime("%Y%m%d"),))
            found = True
            break
        #endif
    #endfor

    if not found:
        return errquit("Decryption failed. Try a different date?")
    #endif

    LOG("Decryption key: %s" % (key.encode("hex"),))

    password = decrypt(key, enc_password)

    print("Credentials:")
    print("\tuserid = %s" % (repr(userid),))
    print("\tpassword = %s" % (repr(password),))
        
    return 0
    
#enddef

if __name__ == "__main__": sys.exit(main())
