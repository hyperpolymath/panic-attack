
import pickle
import subprocess

def unsafe_deserialization(data):
    return pickle.loads(data)  # Unsafe!

def command_injection(user_input):
    subprocess.call("echo " + user_input, shell=True)  # Unsafe!
