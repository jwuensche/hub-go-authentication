# Hub-Auth-Service
This repository contains an Authentication service build with go. It uses scrypt
as encryption algorithm for passwords and additionally encrypts set usernames
because this service does not require any information about the user.

# How to use
```bash
git clone git@bitbucket.org:jwuensche/hub-auth-service.git
#or http if you have not added your ssh key to bitbucket

go build -o hub-go-auth
./hub-go-auth
```

or if you want to build and run the docker image
```bash
make docker
docker create volume hub_go_auth

#and then to the created container run
make run
```

The Dockerfile will use the golang container to compile and run the container.
Default wise the container will use port 9000 this can be changed in the
Makefile.