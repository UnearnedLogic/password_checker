import requests
import hashlib
import sys



def request_api_data(hashed_code):

    url = 'https://api.pwnedpasswords.com/range/' + f'{hashed_code}'
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check the api and try again")
    return res

def get_password_leaks_count(hashes, hash_to_check):

    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):

    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    hashes = request_api_data(first5_char)
    return get_password_leaks_count(hashes,tail)


def get_arguments(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was found {count} times, change your password")
        else:
            print(f"{password} was not found, use it")
    return 'Done BRO'


if __name__ == '__main__':
    sys.exit(get_arguments(sys.argv[1:]))