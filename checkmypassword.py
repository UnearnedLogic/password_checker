import requests
import hashlib
import tkinter as tk

MESSAGES = {
    "password_found": "'{password}' was found {count} times! Change your password immediately.",
    "password_safe": "'{password}' was NOT found! It seems safe to use.",
    "api_error": "Error fetching: {status_code}, check the API and try again.",
    "general_error": "An error occurred: {exception}"
}

# Function to request data from the API based on the password hash prefix
def request_api_data(hashed_code):
    #Makes a request to the 'Have I Been Pwned' API using the first 5 characters of SHA-1 hash.

    url = 'https://api.pwnedpasswords.com/range/' + f'{hashed_code}'
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(MESSAGES["api_error"].format(status_code=res.status_code))
    return res

# Function to count how many times the password hash appears in the leaked database
def get_password_leaks_count(hashes, hash_to_check):

    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

# Function to check if a password exists in the breached password database
def pwned_api_check(password):

    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    hashes = request_api_data(first5_char)
    return get_password_leaks_count(hashes,tail)

# Function to handle user input and display the result
def display_message(password, result):
    count = pwned_api_check(password)

    if not password.strip():
        result_label.config(text="Password cannot be empty.", fg="red")
        return

    try:
        if count:
            message = MESSAGES["password_found"].format(password=password, count=count)
        else:
            message = MESSAGES["password_safe"].format(password=password)

        result.config(text=message, fg="green" if count == 0 else "red")
    except Exception as e:
        result.config(text=f"An error occurred: {str(e)}", fg="red")


if __name__ == '__main__':

    root = tk.Tk()

    root.title("Password Checker")

    root.geometry("800x300")

    label = tk.Label(root, text="Enter your password", font=("Arial", 30), pady=20)
    label.pack()

    my_entry = tk.Entry(root, width=40)
    my_entry.pack()

    result_label = tk.Label(root, text="", font=("Arial", 16), fg="black")

    button = tk.Button(root, text="Check Password", command=lambda: display_message(my_entry.get(), result_label))
    button.pack()

    result_label.pack(pady=20)

    root.mainloop()