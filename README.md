wasg-register : Registers for a new Wireless@SG SSA account
===========================================================

wasg-register.py is a Python implementation of the Wireless@SG SSA
registration protocol.

Please see [this article](https://medium.com/@zerotypic/making-wireless-sgx-work-on-linux-92216c66fdb7)
for more information.

## Basic Usage

```
# Basic usage: ./wasg-register.py <mobile number> <nric>
$ ./wasg-register.py 659XXXXXXX SXXXXXXXX
OTP will be sent to mobile phone number 659XXXXXXX
Enter OTP to continue: XXXXXX
Credentials:
 userid = 'XXX'
 password = 'XXX'
```

## Options

(correct as of 2019-08-02)

```
usage: wasg-register.py [-h] [-I {test,starhub,myrepublic,singtel}]
                        [-s SALUTATION] [-n NAME] [-c COUNTRY] [-d DOB]
                        [-e EMAIL] [-t TRANSID] [-1] [-O OTP]
                        [-S SUCCESS_CODE] [-D DECRYPTION_DATE] [-v]
                        mobile nric

Wireless@SG registration utility.

positional arguments:
  mobile                Mobile phone number
  nric                  NRIC or equivalent ID number

optional arguments:
  -h, --help            show this help message and exit
  -I {test,starhub,myrepublic,singtel}, --isp {test,starhub,myrepublic,singtel}
                        ISP to register with
  -s SALUTATION, --salutation SALUTATION
                        Salutation
  -n NAME, --name NAME  Full name
  -c COUNTRY, --country COUNTRY
                        Nationality country code
  -d DOB, --dob DOB     Date of Birth
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
  -v, --verbose         Be verbose.
```


## License

GNU General Public License v3.0

See [LICENSE](/LICENSE) for full text.
