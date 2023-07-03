# Password Manager in C

Uses argon2id for password hashing and matching, aes for data encryption and 
sha256 for keycreation.

The password store is basically only password protected. 
**Please if you feel tempted to use it, which I hope you are not, use at your own risk!!!**

In the case you want to play around, here's how to start:

0. Be on a linux machine (haven't tested anything else)
1. Clone Repo
2. Make sure you have [argon2](`https://github.com/P-H-C/phc-winner-argon2`) and [openssl3](`https://wiki.openssl.org/index.php/OpenSSL_3.0`) ready.
3. Check [build.sh](`./build.sh`) for paths to the libs mentioned in nr. 2.
4. Make [build.sh](`./build.sh`) executable.
5. Execute: ``./build.sh`` in your shell of choice.
6. Usage: 
pswm <command | 'name of store'> [subcommand]\
	Commands:\
		new ..... creates a new store\
	Subcommands (follow store name):\
		dump ...... prints contents of store\
		set ....... sets key value pair, overwrites value if already exists\
		get ....... gets value for key\
		del ....... deletes entry by key\
		destroy ... deletes storage\



