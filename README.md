# HubGoAuthentication
This repository contains a simple and lightweight authentication service build with go.

## How to start
```bash
git clone git@bitbucket.org:jwuensche/hub-auth-service.git
#or http if you have not added your ssh key to github

go build -o hub-go-auth
./hub-go-auth
```

or if you want to build and run the docker image
```bash
make docker
docker create volume hub_go_auth

#to run the created container
make run
```

The Dockerfile will use the golang container to compile and run the container.
Per default the container will use port 9000 this can be changed in the
Makefile.

## Configuration
Configuration files are located in the config directory and will be generated
by the service if none are present.

Current files are:
- config.yml
```yml
port : 9000 #Assign port, This is currently not checked so don't enter any invalid ports.
```

## Usage
Request can be send by posting json to the specified routes which are:
- /auth
```json
{
  "User": "foo",
  "Password" : "bar"
}
```
- /checkToken
```json
{
  "Token" : "foobar"
}
```
- /register
```json
{
  "Name": "foo",
  "Password": "bar"
}
```
- /logout
```json
{
  "Token":"foobar"
}
```
- /changePassword
```json
{
  "User":"foo",
  "CurrentPassword":"bar",
  "NewPassword":"rab"
}
```

## How to test
Run
```
  go test
```
in your terminal to execute existing tests.

## Current Issues
- Tests currently not including errors thrown by used packages like json or os
