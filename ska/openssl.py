# Copyright 2011 Alexey V Michurin <a.michurin@gmail.com>. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
#    1. Redistributions of source code must retain the above copyright notice, this list of
#       conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above copyright notice, this list
#       of conditions and the following disclaimer in the documentation and/or other materials
#       provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY Alexey V Michurin ''AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL Alexey V Michurin OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those of the
# authors and should not be interpreted as representing official policies, either expressed
# or implied, of Alexey V Michurin.

from key import gen_salt
from shortcuts import \
    enc_bf_ecb, dec_bf_ecb, \
    enc_bf_cbc, dec_bf_cbc, \
    enc_aes_ecb, dec_aes_ecb, \
    enc_aes_cbc, dec_aes_cbc


__all__ = ('openssl_enc_bf_ecb', 'openssl_dec_bf_ecb',
           'openssl_enc_bf_cbc', 'openssl_dec_bf_cbc',
           'openssl_enc_aes_128_ecb', 'openssl_dec_aes_128_ecb',
           'openssl_enc_aes_192_ecb', 'openssl_dec_aes_192_ecb',
           'openssl_enc_aes_256_ecb', 'openssl_dec_aes_256_ecb',
           'openssl_enc_aes_128_cbc', 'openssl_dec_aes_128_cbc',
           'openssl_enc_aes_192_cbc', 'openssl_dec_aes_192_cbc',
           'openssl_enc_aes_256_cbc', 'openssl_dec_aes_256_cbc')


def __enc_header(salted, salt):
    if salted:
        if salt is None:
            salt = gen_salt(8)
        return 'Salted__' + salt, salt
    return '', ''

def __dec_header(cipher):
    if cipher[:8] == 'Salted__':
        return cipher[8:16], cipher[16:]
    return '', cipher


def openssl_enc_bf_ecb(passphrase, text, salted=True, salt=None):
    header, salt = __enc_header(salted, salt)
    return header + enc_bf_ecb(text, salt, passphrase, 16)

def openssl_dec_bf_ecb(passphrase, cipher):
    salt, c = __dec_header(cipher)
    return dec_bf_ecb(c, salt, passphrase, 16)

def openssl_enc_bf_cbc(passphrase, text, salted=True, salt=None):
    header, salt = __enc_header(salted, salt)
    return header + enc_bf_cbc(text, salt, passphrase, 16)

def openssl_dec_bf_cbc(passphrase, cipher):
    salt, c = __dec_header(cipher)
    return dec_bf_cbc(c, salt, passphrase, 16)

def openssl_enc_aes_128_ecb(passphrase, text, salted=True, salt=None):
    header, salt = __enc_header(salted, salt)
    return header + enc_aes_ecb(text, salt, passphrase, 16)

def openssl_dec_aes_128_ecb(passphrase, cipher):
    salt, c = __dec_header(cipher)
    return dec_aes_ecb(c, salt, passphrase, 16)

def openssl_enc_aes_192_ecb(passphrase, text, salted=True, salt=None):
    header, salt = __enc_header(salted, salt)
    return header + enc_aes_ecb(text, salt, passphrase, 24)

def openssl_dec_aes_192_ecb(passphrase, cipher):
    salt, c = __dec_header(cipher)
    return dec_aes_ecb(c, salt, passphrase, 24)

def openssl_enc_aes_256_ecb(passphrase, text, salted=True, salt=None):
    header, salt = __enc_header(salted, salt)
    return header + enc_aes_ecb(text, salt, passphrase, 32)

def openssl_dec_aes_256_ecb(passphrase, cipher):
    salt, c = __dec_header(cipher)
    return dec_aes_ecb(c, salt, passphrase, 32)

def openssl_enc_aes_128_cbc(passphrase, text, salted=True, salt=None):
    header, salt = __enc_header(salted, salt)
    return header + enc_aes_cbc(text, salt, passphrase, 16)

def openssl_dec_aes_128_cbc(passphrase, cipher):
    salt, c = __dec_header(cipher)
    return dec_aes_cbc(c, salt, passphrase, 16)

def openssl_enc_aes_192_cbc(passphrase, text, salted=True, salt=None):
    header, salt = __enc_header(salted, salt)
    return header + enc_aes_cbc(text, salt, passphrase, 24)

def openssl_dec_aes_192_cbc(passphrase, cipher):
    salt, c = __dec_header(cipher)
    return dec_aes_cbc(c, salt, passphrase, 24)

def openssl_enc_aes_256_cbc(passphrase, text, salted=True, salt=None):
    header, salt = __enc_header(salted, salt)
    return header + enc_aes_cbc(text, salt, passphrase, 32)

def openssl_dec_aes_256_cbc(passphrase, cipher):
    salt, c = __dec_header(cipher)
    return dec_aes_cbc(c, salt, passphrase, 32)


if __name__ == '__main__':
    from testutil import qrepr, ok, pad
    text = 'Red leather, Yellow leather.'
    passphrase = 'Aluminum, linoleum.'
    for rem, enc_op, dec_op, salted, ref_cipher in (
('openssl -bf-ecb -salt', openssl_enc_bf_ecb, openssl_dec_bf_ecb, True, 'Salted__\x5DbEzK\xE2\x60\x96E\x25\xBC\x5B\x28\xC9\xCCY\xF7\xCF\xDAE\x0F\xCF\xBA\xBD\xF2\xD2\x91\xB3\x5E\xBA\x2F\x1C\xC9\x2F\xE2e\xF6\x8C\xFB\xD8'),
('openssl -bf-ecb -nosalt', openssl_enc_bf_ecb, openssl_dec_bf_ecb, False, '\x06Z\x98oaQ\x3C\x86\xD0\x96\x23v\x8D\xEF\xE1\xDB\x0A\x14\x08\x80\x09\x3F\xE0\xF8\xAA\x17\xDB\x2B\x90\xE3Y\x5D'),
('openssl -bf-cbc -salt', openssl_enc_bf_cbc, openssl_dec_bf_cbc, True, 'Salted__\xEE\x88\xE9\x01\x05Z\x0E\xA9\xB0\xC7\xB3\x24\x2DM\x92t0\x8D2\x2D\x2Ft\x7Fh\x14\xB0\x02\xB5\x97\x86\xDA\xC5O\x5C1A\xE6\xEF\xF6\x18'),
('openssl -bf-cbc -nosalt', openssl_enc_bf_cbc, openssl_dec_bf_cbc, False, 'g\xEC\x11\xC2\x28\xD4\xB5W\xD6\x14W\xC1\x0BT\x20TP\xCAa\xB0\x96D\x05\xD2\xE5\xBE\xE6i\xB4\x06\xF6\xA1'),
('openssl -aes-128-ecb -salt', openssl_enc_aes_128_ecb, openssl_dec_aes_128_ecb, True, 'Salted__\x28\xA1\x2E\x80\xA3\x84\xD3\x1F_\xDF7\x97\xBC4\x60P\x03\xB3l\x13\x9F\x25A\xBD\xA2C\x23M\x24S\xAC\x2C\x25k\xC7c\xFD\xDAoD'),
('openssl -aes-128-ecb -nosalt', openssl_enc_aes_128_ecb, openssl_dec_aes_128_ecb, False, '\xB2\x5E\x0FO\xC4\xFD\xAE\x8F\x99\xA8\x18\x93\x83\xD2\x3A\x9B\x9A3\x98\xCBk\xDC\x195\xC85\x2D\xAB\xB6U\x9F\xD5'),
('openssl -aes-192-ecb -salt', openssl_enc_aes_192_ecb, openssl_dec_aes_192_ecb, True, 'Salted__\xBA\x0A\xAD\x0F\xB1\xAC\x9ET\xA3\xE8\x19\xC7P\xFDaY\x3B\xD9\x95\xB0I\x2EZ8\x40y\xA3\x0B\x3E\x0Dn\xF6\xA9Y6J\xAC\x5D\x9E\x17'),
('openssl -aes-192-ecb -nosalt', openssl_enc_aes_192_ecb, openssl_dec_aes_192_ecb, False, '\xD7\xAC\x2A\x21\x84\x94O\xA3\xB7\x90\xCBj\xFB\xA8\xA0\x3D\x11\xB1\x10\x23\xD4\x2C\xEBu4\x3E\xE4\xDDO\x12b\x27'),
('openssl -aes-256-ecb -salt', openssl_enc_aes_256_ecb, openssl_dec_aes_256_ecb, True, 'Salted__\x27_\xF1\xDF\xD3\x3D5\xE3M6\x1E\x92c\xF9\x98Z4\xD30\xCA\xA5q\x15\xB4\xB5\xD27\xEF\xD0\x2A\xF7\x3F\xB0\xD2\xD4\x9FW\xEA\x3E\x0E'),
('openssl -aes-256-ecb -nosalt', openssl_enc_aes_256_ecb, openssl_dec_aes_256_ecb, False, '\xCE\xAC6\xC4\xED\xCF\x98\xFA\x91o\x8B\x20\xD0e\xD4x\x8Ek5\xC3\xE7\x16\x5C\xA2\xB5Y\xC7\x89\x0F_\x07\xFF'),
('openssl -aes-128-cbc -salt', openssl_enc_aes_128_cbc, openssl_dec_aes_128_cbc, True, 'Salted__\x2Dd\x22\xDD\x7D\x93\xDC\xA6\xCBj\x9Cu\x2D\xA0\xB2\x26\x5D\xF9\x3B\x8D\xB4s7\x92a\xD1\x98\x9E\x04Pmo\x16\x0A\xD2\x14\x92\xB0l\x2E'),
('openssl -aes-128-cbc -nosalt', openssl_enc_aes_128_cbc, openssl_dec_aes_128_cbc, False, '\x04Us\x99\xBC\x0F\xAF\xDB\xEB\xD9\x91\xF1\x3C\x0Dr3\xF9\xA8\xE7i\x3FF\xF7M\x236\xA6\xC3XJ\x87\xDA'),
('openssl -aes-192-cbc -salt', openssl_enc_aes_192_cbc, openssl_dec_aes_192_cbc, True, 'Salted__\xB0t\x95\xC1\x8E\xE8\xCDr\x03\x1E\x9D\x1AfJx\xA0\xDCU\x0Ap\xF0\xD0\xE96\x8AoJ\x17\xE5\x8A\x81\xC7\x5E\xB3\xCD\xD8\xE0\xFE\x90S'),
('openssl -aes-192-cbc -nosalt', openssl_enc_aes_192_cbc, openssl_dec_aes_192_cbc, False, '\xC5\xBAF\xECm\xEA\x00\xC4\x1Bv\x01\xEC\x99\x9C\x81\xE2\xD7\x1D\xE8\x3E\x17\xF3\x89\x90\xBF\x5B\x0B\x98Q\x00\x40G'),
('openssl -aes-256-cbc -salt', openssl_enc_aes_256_cbc, openssl_dec_aes_256_cbc, True, 'Salted__5\x5B\x0A\xE8M\xC9\xF8\xC7K\xBE\xFE\x84\x9CK\xC2\x08\xDD\x2C\x9E\xFE\xB5\xCD\x1B\x11\x201\xB95C\x0A\xAA\xD9N\x0B\x01n\xB2\xA5\x18W'),
('openssl -aes-256-cbc -nosalt', openssl_enc_aes_256_cbc, openssl_dec_aes_256_cbc, False, '\xE1\xD7cS\xE5\x60\x1A\x27\xB8\xBCe\x2F\xFA\x06\xDC\x17\xEF\x26\x91\x83\x3AfG\x87\xB4\x9D\x0B5\xF7s\x9C\x02'),
    ):
        if salted:
            salt = ref_cipher[8:16]
        else:
            salt = None
        e = enc_op(passphrase, text, salted, salt)
#        print repr(e)
#        print repr(ref_cipher)
        test_enc = ok(e == ref_cipher)
        t = dec_op(passphrase, e)
#        print repr(t)
#        print repr(text)
        test_dec = ok(t == text)
        # random salt
        t = dec_op(passphrase, enc_op(passphrase, text))
        test_rand = ok(t == text)
        print pad(rem, 50), \
              'enc:', test_enc, \
              'dec:', test_dec, \
              'rand_salt:', test_enc
    __how_to_preapre_test_vectors__=r'''
#!/bin/sh

data='Red leather, Yellow leather.'
pass='Aluminum, linoleum.'

echo "data = '$data'"
echo "password = '$pass'"
for mode in -bf-ecb -bf-cbc \
            -aes-128-ecb -aes-192-ecb -aes-256-ecb \
            -aes-128-cbc -aes-192-cbc -aes-256-cbc
do
  for saltmode in -salt -nosalt
  do
    cryp=`echo -n "$data" | openssl enc "$mode" "$saltmode" -pass "pass:$pass" -
    perl -MMIME::Base64 -pe '$_=decode_base64($_);s-([^\w\d_])-sprintf(q|\x%02X|
    enc=`echo "$mode" | perl -pe 's|-|_|g;s-^-openssl_enc-;'`
    dec=`echo "$mode" | perl -pe 's|-|_|g;s-^-openssl_dec-;'`
    salted='False'
    if test "_$saltmode" = '_-salt'
    then
        salted='True'
    fi
    echo "('openssl $mode $saltmode', $enc, $dec, $salted, '$cryp'),"
  done
done
'''
