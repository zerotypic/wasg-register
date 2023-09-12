wasg-register : Registers for a new Wireless@SG SSA account
===========================================================

wasg-register.py is a Python implementation of the Wireless@SG SSA
registration protocol.

Please see [this article](https://medium.com/@zerotypic/making-wireless-sgx-work-on-linux-92216c66fdb7)
for more information (note, article might be out of date due to API
changes since it was written).

## Dependencies

```
python3 -m pip install -r requirements.txt
```

Note: Requires a version of pycryptodome that supports AES in CCM mode.

## Basic Usage

To create an account, you need to supply a valid mobile number (to which
an OTP will be sent via SMS) and a date of birth. A mobile number / date
of birth pair will be used to uniquely identify a user account.

```
# To use: python3 wasg-register.py <mobile number> <dob>
$ python3 wasg-register.py 659XXXXXXX 24031980
OTP will be sent to mobile phone number 659XXXXXXX
Enter OTP to continue: XXXXXX
Credentials:
 userid = 'XXX'
 password = 'XXX'
```
where `dob` is a date of birth in DDMMYYYY format.

If you have previously created an account with the same mobile number /
date of birth pair, you can request for a new set of credentials using
*retrieve mode*:

```
$ python3 wasg-register.py -r 659XXXXXXX 24031980
OTP will be sent to mobile phone number 659XXXXXXX
Enter OTP to continue: XXXXXX
Credentials:
 userid = 'XXX'
 password = 'XXX'
```

### Docker

You can use Docker to build an image with all the dependencies included.

```
# Build
$ docker build -t wasg-register .

# Register mode
$ docker run -it --rm wasg-register 659XXXXXXX 24031980
[snip]

# Retrieve mode
$ docker run -it --rm wasg-register -r 659XXXXXXX 24031980
[snip]
```

## Options

(correct as of 2020-01-09)

```
usage: wasg-register.py [-h] [-I {test,myrepublic,singtel}] [-s SALUTATION]
                        [-n NAME] [-g GENDER] [-c COUNTRY] [-e EMAIL]
                        [-t TRANSID] [-1] [-O OTP] [-S SUCCESS_CODE]
                        [-D DECRYPTION_DATE] [-r] [-v]
                        mobile dob

Wireless@SG registration utility.

positional arguments:
  mobile                Mobile phone number
  dob                   Date of birth in DDMMYYYY format

optional arguments:
  -h, --help            show this help message and exit
  -I {test,myrepublic,singtel}, --isp {test,myrepublic,singtel}
                        ISP to register with
  -s SALUTATION, --salutation SALUTATION
                        Salutation
  -n NAME, --name NAME  Full name
  -g GENDER, --gender GENDER
                        Gender
  -c COUNTRY, --country COUNTRY
                        Nationality country code
  -e EMAIL, --email EMAIL
                        Email address
  -t TRANSID, --transid TRANSID
                        Transaction ID
  -1, --registration-phase-only
                        Terminate after registration phase, returns success
                        code.
  -O OTP, --otp OTP     OTP received on mobile. Note that if this is set, then
                        wasg-register will skip the registration phase and
                        move immediately to OTP validation. success-code must
                        also be provided.
  -S SUCCESS_CODE, --success-code SUCCESS_CODE
                        Success code received during registration phase. Note
                        that if this is set, then wasg-register will skip the
                        registration phase and move immediately to OTP
                        validation. OTP must also be provided.
  -D DECRYPTION_DATE, --decryption-date DECRYPTION_DATE
                        Date the OTP was generated, for use in decryption, in
                        YYMMDD format.
  -r, --retrieve-mode   Run in retrieve mode, for existing accounts.
  -v, --verbose         Be verbose.
```

## Configuration Tips

### WPA Supplicant

Koo Zhengqun supplied a `wpa_supplicant.conf` configuration for Wireless@SGx that works in Void Linux:

```
network={
        ssid="Wireless@SGx"
        key_mgmt=WPA-EAP
        eap=PEAP
        identity="<userid>"
        password="<password>"
}
```

### NetworkManager

[@chuanhao01](https://github.com/chuanhao01) supplied a `<an id/name>.nmconnection` configuartion for Wireless@SGx that works in Archlinux:
```
[wifi-security]
key-mgmt=wpa-eap

[connection]
id=<an id/name>
uuid=<valid UUID>
type=wifi

[wifi]
mode=infrastructure
ssid=Wireless@SGx
security=802-11-wireless-security

[802-1x]
eap=peap
phase2-auth=mschapv2
identity=<userid>
password=<password>

[ipv4]
method=auto

[ipv6]
addr-gen-mode=stable-privacy
method=auto

[proxy]
```

Credit and more instructions can be found [here](https://github.com/wylermr/NetworkManager-WPA2-Enterprise-Setup).

## Credits

Thanks to Zamiel Chia (@IkaEren) for reversing the new API and password
decryption routine.

## License

GNU General Public License v3.0

See [LICENSE](/LICENSE) for full text.
