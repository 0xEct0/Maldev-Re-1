# define byte string
enc_string = b'\x14\x25\x32\x36\x23\x32\x03\x38\x38\x3b\x3f\x32\x3b\x27\x64\x04\x39\x36\x27\x24\x3f\x38\x23\x57'

xor_key = b'\x57' 

plaintext = []

for byte in enc_string:
    xor_byte = byte ^ xor_key[0]
    plaintext.append( xor_byte )

byte_string = bytes( plaintext )

resulting_string = byte_string.decode('utf-8')

print( resulting_string )