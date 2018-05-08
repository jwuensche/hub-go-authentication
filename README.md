# Hub-Auth-Service
This repository contains an Authentication service build with go. It uses scrypt
as encryption algorithm for passwords and additionally encrypts set usernames
because this service does not require any information about the user.

# How to use
```bash
git clone git@bitbucket.org:jwuensche/hub-auth-service.git
//or http if you have not added your ssh key to bitbucket

go build -o hub-go-auth
./hub-go-auth
```
