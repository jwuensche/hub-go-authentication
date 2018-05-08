docker:
	sudo docker build -t hub_auth .

run:
	@echo starting container on port 9000
	sudo docker run -p 9000:9000 --mount 'type=volume,src=hub_auth_volume,target=/go/src/hub-go-auth/' hub_auth
