# Cryptopals 

This are my solutions to the [Matasano Cryptopals cryptographic challenges][1].

The code is written in pure Python 3 and it is extensively documented.

## How to run

I recommend using a Python virtual environment. Here is a very small cheat sheet for it:

```sh
# Install virtualenv if not already installed
$ pip3 install virtualenv

# Create the virtual environment
$ virtualenv -p python3 venv

# Activate the virtual environment
$ source venv/bin/activate

# Install the dependencies
$ pip3 install requests 
$ pip3 install flask 
$ pip3 install pycrypto

# Deactivate the environment (after you are done running the challenges):
$ deactivate
```

When the environment is ready, you can run each challenge by simply calling `python S*C**.py`, after 
 replacing `*` with the number of the set, and `**` with the number of the challenge. Beware that:
 - Some challenges take a long time to run.
 - For some challenges you might need to run the server first.


## What are these challenges?

Cryptopals is a collection of exercises that demonstrate attacks on real world ciphers and protocols. 
 Exercises exploit both badly designed systems and subtle implementation bugs in theoretically rock solid crypto.

## Thoughts and notes

These challenges are among the best programming / math / crypto exercises I have done.

By solving all of them not only I learned more about applied cryptography, but also I honed my
 programming skills in Python.
  
I wrote down some thoughts and notes in the comments of the code.

As an additional note, I personally found sets 5 and 6 to be - on average - easier than the previous ones, although
  in the website they state that they should be "significantly harder".

## Coming in the future

 - Solutions to sets 7 and 8: I am looking forward to when the set 8 challenges will be published 
on the website.

## Contribute

Please feel invited to contribute by creating a pull request to submit the code or bug fixes you would like 
to be included in my solutions.

## License

Everything in this repository is distributed under the terms of the MIT License. 
See file "LICENSE" for further reference.

   [1]: <http://www.cryptopals.com>
