# KAON Minter



Create Wallets and Mint KAON
----------------------------


For the KAON Go Distribution program as of March 4, 2022 please use the new-dist-go branch

Clone this repository to your local machine. Build and run using the `go build main.go` 
and the `go run main.go` commands. 


----


Basic CLI Flow
--------------


The KAON Minter Command Line Interface (CLI) enables you to create a wallet and start
minting KAON! Wallets are essentially files stored in a directory called `private_key`. 
Upon initially running the program from the command line, there will be no wallet files
present. The program will ask:


```
No private key files detected. Would you like to create one? Select 'y' or 'n'
```


The next prompt asks what you would like to name your private key wallet file. You
must select a name that is at least 3 characters long and alphanumeric, characters
such as `. - _` are allowed. Note, the file extension `.txt` will be appended to 
the file name you choose. 


```
SUCCESS!! Your new private key file name is: <your_file_name>.txt
```


Now, in order to encrypt and store your private key in the wallet file, you must 
create a pass phrase, the pass phrase you create must be:


1. Alphanumeric
2. Uppercase letters, OK
3. Free of spaces
4. Between 8 - 32 characters
5. Special characters, OK


After choosing your pass phrase you must re-enter to confirm selection. The KAON
Minter will randomly salt and hash your pass phrase with 4096 iterations. 


```
SUCCESS!! Your pass phrase has been hashed.
SUCCESS!! Your RSA Private Key has been encrypted.
SUCCESS!! Your encrypted RSA Private Key has been stored in the file: <your_file_name>.txt.
```


At this point you may choose to mint with your newly created file, 
`Is <your_file_name>.txt the file you wish to use to mint?` exit, or list private key files.


Private Key Files Present
-------------------------


When there are multiple private key wallet files present in the private key directory, 
meaning you have created multiple wallets. Then the program will ask, given a listing of 
these files, if you wish to: mint, exit, create a new file **_or_** change the pass 
phrase of an existing file.  


```
Type the number of the file you wish to use to mint KAON, type 'e' to exit, 'cp' to change your pass phrase, or if you wish to create a new file type 'c'
```
