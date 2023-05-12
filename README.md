# forumerly
A web forum with all basic functionality based on NodeJS, Express, and MongoDB.

# Requirements
- Docker
- NodeJS

# How to launch
- Run Authentication Server, Redis and MongoDB services. Use  `./launch.sh` to enable the services. Note that the application needs the services to be running to correctly work.  Notice that the `launch.sh` script will wipe out the database every time it runs, thus, try to execute this script into a separate terminal.

- Run ```npm install```
- Run ```node app.js``` and open the browser in ```localhost:3000```
- Stop the third-party services running ```./stop.sh```
- Wipe the data of the third-party services running ```./wipe.sh```
