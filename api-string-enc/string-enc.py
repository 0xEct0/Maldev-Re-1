import random

def generate_xor_key():
    # return 0x57 # define a key here if needed
    return random.getrandbits( 8 )

def xor_encrypt( data, key ):
    data += b'\0' 
    return bytes( [b ^ key for b in data] )

def format_variable_name( name ):
    if '.' in name:
        name = name.replace( '.', '_' )
    return name + '_encrypted'

def main():
    key = generate_xor_key()

    with open( 'xor-list.txt', 'r' ) as file:
        api_names = file.readlines()

    for api_name in api_names:
        api_name = api_name.strip()  
        api_name_bytes = api_name.encode()

        encrypted_api_name = xor_encrypt( api_name_bytes, key )
        c_formatted_encrypted = ', '.join( f'0x{b:02x}' for b in encrypted_api_name )
        c_formatted_key = f'0x{key:02x}'

        variable_name = format_variable_name( api_name )
        
        print( f"unsigned char {variable_name}[] = {{{c_formatted_encrypted}}};\n" )

    print( f"unsigned char key = {c_formatted_key};" ) 

if __name__ == '__main__':
    main()
