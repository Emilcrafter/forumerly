# DO NOT touch

# run your container
docker container rm  lbs-services --force || echo "Service does not exist, creating"
docker run -it -p 127.0.0.1:6379:6379 -p 127.0.0.1:8087:8087 -p 127.0.0.1:27017-27019:27017-27019 --name lbs-services jacarte/lbs-services:latest
