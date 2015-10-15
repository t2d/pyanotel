word_len = 16  # 128 bit
variable_delimiter = '\n'
paging_port = 60000

locations = {"location0000Pool": ("192.168.222.101", paging_port),
             "location00Office": ("192.168.222.102", paging_port),
             "location000DSLab": ("192.168.222.105", paging_port)
             }

user1_id = b'1234567890123456'
user1_secret = b'1234567890123456'
user2_id = b'<sdfga$198asd#+*'  # id must be hashable
user2_secret = 'l{\x87\xff\xad\x82\x14\xd1\xf8\xca\xb44.e\xdf~'

preshared_secrets = {
    user1_id: user1_secret,
    user2_id: user2_secret
}

# lifetime of a pseudonym
LIFETIME = 3600  # 1 hour in seconds


class Header():
    INITCALL = 0
    ANSWERCALL = 1
    PAGING = 2
    LOCATIONUPDATE = 3
    LOCATIONANNOUNCEMENT = 4
    REGISTER = 5
    PSEUDONYMUPDATE = 6
    STORE_CID = 7
    MSG = 8
    RAWNOW = 9
    SIGN = 10
    ERROR = 99


class N():
    ip = "127.0.0.1"
    port = 50001
    external_ip = "192.168.222.1"


class P():
    ip = "127.0.0.1"
    port = 50000
    external_ip = "192.168.222.1"
    private_key = b'Ps private key'
    public_key = '+-:biiw8b#!i%o/rolc}o@|E&'


class L():
    ip = "127.0.0.1"
    port = 50002
    public_key = '*w,WDove9irc&-?wBM7)zDc|9'
    private_key = b'Ls private key'


class B():
    ip = "127.0.0.1"
    port = 50003
    external_ip = "192.168.222.1"
    private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAmCKGsdGJcFi6CFysYoiITLt1MqYhUdvsvBUmJWkbmWJrgi8O
H3vvSWTeHDM73gUZzEyslU8G9dpkrL0p1TtrKfg9fzcuLGZf6M+3ifVB6lGcQSrb
hKoLjXzbaFWOXcWwXr31uRznuHmBSYxpHOhlnShXn1lr7tMyBvln5XMpGquc7Ynp
Au9o4lObNdqT1fVkrZrruqQHY6TLIy9bJ7cjusZk6/qI6keucd/WhD2o8iIAQt5Y
sOtxUMP1EFH6/+/laXfW1ca7JVXEyHb0d6uLaON3l5UzSkoMNmBBD9gUu0kG+Oke
PCOyFx3cPPd2nHKjygwBTG1g4JIt3cuqNfVRuwIDAQABAoIBAC9DSqUje5czeVfv
sn5J/E4aTqaVhfRwZnNn/pnQtYpJUSz4gWK2lfgvJfGM2SR4YTNe/p7EFl16o5wm
iEB+XSSEwlYrRmT0yQcCwPpS/09UWz7Dmb71NPGXwHIBYmEvcUN9sED6AeMFnGzE
+kLI0Aiq583Rcf6YDgqsoOJfjH2EKG8dserZkoP0IzrOVZgFSpCtFVzi0BsrTJ41
xdF69r942PeEa2ihF2TJZRBEBhTbDtov+nMku/DqDVNP1DlqO7KB0m8ybn36U923
YqKmiUAvl14VFV2FYl8foUTrNb2KBJpNfMrTwoISCeZtXR3NKwU0uzlYeZ8K8I5S
rTRgGUECgYEAwVbgI6UsoiqGVoGDoBelif6gz7LLW709Phih8LI2PrYj6XiaouSn
xDD3lPLZOynsP+ghOa+CTPSh6g5pX4CUDJkfxtzxcN6L38UQsRPqGnrFk6CJ2r87
YRhcbYzvy9Ujh0wlWR/wHfXMYN+g6Z1sFxCVObvheaFW9SGIgQ88uv0CgYEAyXD3
Njh/t1vhS8JNSl8eOyyeGEi5bM6Y8WkTjSv2exEc5N0gfYv0nGyNmhDTTJOWXwS/
4RqRfWk8HicP19Xikor37/jFoJO6rrHH1J16rYBDNvsDDd+Ej3/DPi30HvGd4Ja1
mSYNY18fo+Vx3dSMUsFQJddQnm0ksdRDN4wmKRcCgYBcAc/gprY65inP+Qp+oUIy
DW7R6LBGFCSU7HwEY4rVBTDJ5o8QfegowXTQ+VDPiv/W2c0V+qPzo2d6TyluPW43
IJeyt2pe4EmIT+vFmUiLGWn0+y0fYGoNpt41dCCZy/CAbohHhZ9rYpHEeCfHhRbv
UwDw3KxMia8sMK0ZXfr0sQKBgA+GeFcidZ1xJGUNXZ2cxRy0bJ7chAYBykHY4lvg
Bognon11GXrznW+s4iD8qPxe55j9Kbi0rn/m6247fnoZDvRSZ5eEKd8dY6bxJsCZ
Poo+t292Wx7nmjThGPAi5Iy5/HwBwY9DIocFHtAn7+Wz6vi5026HMLx1Fv3pqSCP
2aUTAoGAEPUbZSQBPBE8V2V1tWOmztiCC8YeHdw+i2Nh67hTchGPpvbheXIQMGa6
9Gmv1/hZJJtQ4bc36MZPE1yZQKb3phlQ02Xt9FuN+O4fxcETda5TPWZkhDaHnH0k
Um640r4jXVpqPGl+VI2oCPqVgmSJFrm0GX3RETczw0A+k0ddECY=
-----END RSA PRIVATE KEY-----
"""
    public_key = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCYIoax0YlwWLoIXKxiiIhMu3UypiFR2+y8FSYlaRuZYmuCLw4fe+9JZN4cMzveBRnMTKyVTwb12mSsvSnVO2sp+D1/Ny4sZl/oz7eJ9UHqUZxBKtuEqguNfNtoVY5dxbBevfW5HOe4eYFJjGkc6GWdKFefWWvu0zIG+Wflcykaq5ztiekC72jiU5s12pPV9WStmuu6pAdjpMsjL1sntyO6xmTr+ojqR65x39aEPajyIgBC3liw63FQw/UQUfr/7+Vpd9bVxrslVcTIdvR3q4to43eXlTNKSgw2YEEP2BS7SQb46R48I7IXHdw893accqPKDAFMbWDgki3dy6o19VG7'
