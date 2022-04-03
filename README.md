# KAON Minting Client


#### NOTE!! Tests are out of date, please ignore them.


Create Wallets and Mint KAON
----------------------------


Clone this repository to your local machine. Init the module by removing the `go.mod` file
and running `go mod init`.


```
rm go.mod
go mod init github.com/programmedtorun/key_mgmt
```


Build and run using the `go build main.go` 
and the `go run main.go` commands. 


----


Basic CLI Flow
--------------


The KAON Minting Command Line Interface (CLI) enables you to create a wallet and to start
minting KAON, Note* Minting algorithm is not yet implemented. Wallets are directories which 
are stored in a directory called `private_key`. Each wallet (directory) has a name and 
associated `.dat` files. Upon initially running the program from the command line, 
there will be no wallet files present. The program will state:


```
No wallet directories detected. Would you like to create one? Select 'y' or 'n'
```


The next prompt asks what you would like to name your wallet. You
must select a name that is at least 3 characters long and alphanumeric, characters
such as `. - _` are allowed. 


```
SUCCESS!! Your new wallet name is: <wallet_dir_name_you_give>
```


Now, in order to encrypt and store your private key in the wallet dir, you must 
create a password. The password you create must be:


1. Alphanumeric
2. Uppercase letters, OK
3. Free of spaces
4. Between 8 - 32 characters
5. Special characters, OK


After choosing your password you must re-enter to confirm selection. The KAON
Minter will randomly salt and hash your password with 4096 iterations. 


```
SUCCESS!! Your pass phrase has been hashed.
SUCCESS!! Your RSA Private Key has been encrypted.
SUCCESS!! Your salt has been stored in the file: private_key/<wallet_dir_name_you_give>/salt.dat
SUCCESS!! Your hashed password has been stored in the file: private_key/<wallet_dir_name_you_give>/hashed_pw.dat
SUCCESS!! Your encrypted RSA private key has been stored in the file: private_key/<wallet_dir_name_you_give>/cipher.dat
```


At this point you may choose to mint with your newly created file, 

```
OK! let's get started on minting KAON!! Meant to mint ;). Is "<wallet_dir_name_you_give>" the wallet you wish to use to mint?
``` 
exit, or list files. 


Wallet Directories Present
-------------------------


When there are multiple wallet directories present in the key_mgmt/private_key directory, 
meaning you have created multiple wallets. Then the program will ask, given a listing of 
these directories, if you wish to: mint, exit, create a new wallet **_or_** change the password
of an existing wallet.  


```
Options:
-> Type the NUMBER of the wallet you wish to use to mint KAON.
-> Type 'c' to create a new wallet.
-> Type 'cp' to change your pass phrasetype.
-> Type 'e' to exit.
```
