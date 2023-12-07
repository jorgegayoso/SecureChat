import subprocess
import os
import sys

class TTP:
    def __init__(self, script_dir):
        self.clientkeys_dir = os.path.join(script_dir, "clientkeys")
        self.serverkeys_dir = os.path.join(script_dir, "serverkeys")
        self.ttpkeys_dir = os.path.join(script_dir, "ttpkeys")

        #Creates "clientkeys", "serverkeys"and  "ttpkeys" if they dont exist already
        self.create_directories([self.clientkeys_dir, self.serverkeys_dir, self.ttpkeys_dir]) 

    def create_directories(self, directories):
        for dir in directories:
            if not os.path.exists(dir):
                os.makedirs(dir)

    def generate_key_pair(self, output_dir, key_name):
        #Generate private key
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", os.path.join(output_dir, f"{key_name}.pem")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        #Generate public key from private key
        subprocess.run(["openssl", "pkey", "-in", os.path.join(output_dir, f"{key_name}.pem"), "-pubout", "-out", os.path.join(output_dir, f"{key_name}_public.pem")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def register_user(self, user_name):
        self.generate_key_pair(self.clientkeys_dir, user_name)

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__)) #Get the script's directory
    ttp = TTP(script_dir)
     
    if len(sys.argv) == 3 and sys.argv[1] == "register_user":
        client_name = sys.argv[2]
        ttp.register_user(client_name)
