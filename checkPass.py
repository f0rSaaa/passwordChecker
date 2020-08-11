import requests
import hashlib
import sys


#password123------<Response [400]> not good
#CBFDAC6008F9CAB4083784CBD1874F76618D2A97----- <Respones [400]>
#<Response [200]> is good
#CBFDA----- <Response [200]>


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    # print(res) 
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res
         
# def read_res(response):
#     print(response.text)

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    print(hashes)
    for h, count in hashes:
        # print(h, count)
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    # print(password.encode('utf-8'))         #b'123'
    # print(hashlib.sha1(password.encode('utf-8')))      #<sha1 HASH object @ 0x03841970>
    # print(hashlib.sha1(password.encode('utf-8')).hexdigest())  #40bd001563085fc35165329ea1ff5c5ecbdbbeef
    # #convert to upper as it is in API
    # print(hashlib.sha1(password.encode('utf-8')).hexdigest().upper()) #40BD001563085FC35165329EA1FF5C5ECBDBBEEF
    # print(hashlib.sha1(password).hexdigest().upper())    #TypeError: Unicode-objects must be encoded before hashing
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    print(first5_char, tail)
    response = request_api_data(first5_char)
    print(response)
    # return read_res(response)
    return get_password_leaks_count(response, tail)


pwned_api_check('123')
# request_api_data('123')

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... youu should probably change your password')
        else:
            prin(f'{password} was NOT found. Carry on!!!')
    return 'done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
