import crypt


def parse_password(encrypted_password):

	#Example Linux SHA512crypt hash: test1:$6$v4vuax5jVZGMHHcw$YdHpHA4F3RQJSEx6V7P0yS7sz63q/8o9H7JQvnRa41ebVoR28NQxNMWLIHx5ju8w2akvq8cd.JX0A.sONqFFl.:18591:0:99999:7:::

	user = encrypted_password.split(":")[0]

	algorithm = encrypted_password.split(":")[1].split("$")[1]

	salt = encrypted_password.split(":")[1].split("$")[2]

	password = encrypted_password.split(":")[1].split("$")[3]

	return (user, algorithm, salt, password)



def test_pass(encrypted_password):

	#Parse encrypted Linux passwords
	(user, algorithm, salt, password) = parse_password(encrypted_password)
	print("[*] Cracking password for user: {}".format(user))

	password_file = open("password_list.txt", "r")

	#Iterate through password dictionary
	for p in password_file.readlines():
		crypt_p = crypt.crypt(p.strip("\n"), "${}${}$".format(algorithm, salt))

		if crypt_p == encrypted_password.split(":")[1]:
			print("[+] Password found: {}".format(p))
			return

	password_file.close()
	print("[-] Password not found.")



def main():

	#Linux /etc/shadow file containing users' SHA512crypt hashes
	shadow_file = open("passwords.txt", "r")

	for p in shadow_file:
		test_pass(p)

	shadow_file.close()
	print("[*] End of file.")



if __name__ == "__main__":
	main()
