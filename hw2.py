from Crypto.Cipher import AES as AES_C
from os import urandom


# ----- helper functions -----
def AES(key, m):
	if type(key) != bytes or len(key) != 16: raise TypeError("key must be a length-16 bytestring")
	if type(m) != bytes or len(m) != 16: raise TypeError("m must be a length-16 bytestring")
	# The PyCryptodome library doesn't expose the block cipher directly, it has a weird interface and wants us to specify a mode of operation
	# Since m is one block long, AES_k(m) is equivalent to encrypting m in ECB mode
	cipher = AES_C.new(key, AES_C.MODE_ECB)
	return cipher.encrypt(m)

def xor_bytestrings(a, b):
	""" xor two bytestrings together. The returned bytestring has length min(len(a), len(b)) """
	return bytes([ ai ^ bi for (ai,bi) in zip(a,b) ])

# ----- the fun part -----


def SADMAC(key, msg):
	# It's the Super Advanced Deluxe MAC, or SADMAC for short!

	# First: we uniquely pad the message by appending a 0xff byte (always) and then the smallest number (0 or more) of 0x00 bytes needed to make the length a multiple of 16
	msg += b"\xff"
	msg += b"\x00" * (-len(msg) % 16) # note that in python, X % Y is always between 0 (inclusive) and Y (exclusive), regardless of the signs of X or Y
	assert len(msg) % 16 == 0

	# Then: xor together AES_K(M_i) for each message block M_i
	out = bytes(16) # initially 16 zero bytes
	for i in range(0, len(msg), 16): # this is the equivalent of C's for (int i = 0; i < len(msg) ; i += 16)
		out = xor_bytestrings(out, AES(key, msg[i:i+16]))
	# Then call AES_K on that to produce the 16-byte tag
	return AES(key, out)
		
def query_auth_server(packet):
	"""
	The system you're logging into forwards your login request to an authentication server.
	The auth server sends back a packet that starts with either "Access Granted!!" or "Access Denied!!!" (encoded as ASCII)
	and then has a bunch of extra data afterward. The auth server uses a MAC to authenticate this packet.
	
	We'll assume you can get the server to send any packet that starts with "Access Denied!!!" (along with the correct tag for that packet)
	But of course you'd *like* to produce the correct tag for a packet that starts with "Access Granted!!"

	This function returns the correct tag on a packet, using the auth server's secret key, but only if the packet starts with "Access Denied!!!"
	"""
	if type(packet) != bytes:
		raise TypeError(f"packet must be a bytestring, but instead it had type {type(packet)}")

	if not packet.startswith(b"Access Denied!!!"):
		raise ValueError("You can only get the server to send responses that start with 'Access Denied!!!'")

	# Remember, you don't have access to server_key_DO_NOT_USE (except that you can call this function).
	# If you try to use it, your code may work locally, but won't work on the autograder.
	return SADMAC(server_key_DO_NOT_USE, packet)

# ----- now here's where you write your code -----

def list_collaborators():
	# TODO: Edit the string below to list your collaborators. The autograder won't accept your submission until you do.
	return "no collaborators."

def run_attack():
	# TODO: your code here!
	denied_pkt = b"Access Denied!!!"
	denied_tag = query_auth_server(denied_pkt)
	granted_packet= b"Access Granted!!"
	return granted_packet, denied_tag

	# You should return a tuple consisting of
	# 1) a packet that starts with b"Access Granted!!" (as a bytestring), and 
	# 2) your forged SADMAC tag for that packet (a bytestring)
	return (b"TODO access granted packet goes here", b"TODO forged tag goes here")

# ------------------------------------------------------------------------------
# You don't need to (and should not) edit anything below, but feel free to read it if you're curious!
# It's for letting you test your code locally and for interfacing with the autograder

def run_locally():
	global server_key_DO_NOT_USE
	# As the name suggests, DO NOT USE. It may work locally but won't work on the autograder.
	# This is the key that lives on the auth server, which you don't have access to.
	server_key_DO_NOT_USE = urandom(16)

	msg, tag = run_attack()
	win = True
	if SADMAC(server_key_DO_NOT_USE, msg) != tag:
		print("Tag did not verify! Your login fails.")
		win = False
	if not msg.startswith(b"Access Granted!!"):
		print("Message didn't start with 'Access Granted!!'; this won't let you log in")
		win = False
	if win:
		print("Success! You send the packet and tag to the victim device and it lets you log in.")
	

def interact_with_autograder():
	# Run in 'autograder' mode, where our queries to the auth server get written to a fifo,
	# and then the responses from the auth server get read from another fifo,
	# and our final output goes into a file.
	with open("collaborators", "w") as f:
		f.write(list_collaborators())
	with open("queries", "w") as f_out:
		with open("responses", "r") as f_in:
			# replace the existing query_auth_server function
			global query_auth_server
			def query_auth_server(packet):
				f_out.write(packet.hex() + "\n")
				f_out.flush()
				response = f_in.readline()
				if response.startswith("Error"):
					raise ValueError(response)
				return bytes.fromhex(response.strip())
			# now run the attack code
			msg, tag = run_attack()
	with open("output","w") as f_out:
		print(msg.hex(), file=f_out)
		print(tag.hex(), file=f_out)

if __name__ == "__main__":
	from sys import argv
	if len(argv) >= 2 and argv[1] == "--autograder":
		interact_with_autograder()
	else:
		run_locally()