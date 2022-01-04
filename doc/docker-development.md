# Setup QuickFeed for local develoment using Docker

## Prerequisites
- Docker
- Go
- npm // Maybe not

## Register an OAuth application in GitHub

First you need to register your application [here](https://github.com/settings/applications/new). Your homepage URL and authorization callback URL must be set to `https://127.0.0.1` and `https://127.0.0.1/auth/github/callback` respectively.

`NOTE`: Webhooks do not work when using a local IP when running QuickFeed.

---
## Configuring environment variables

Create a copy of the `.env-template` file in the project root folder and name it `.env`. Substitute the values as you see fit.

`TODO: Maybe add more details to the .env-template rather than having it here?` 

```go
// GitHub OAUTH App keys
GITHUB_KEY="<Client ID of your OAuth app>"
GITHUB_SECRET="<Secret Key for your OAuth app>"

// Envoy Config
// Replace filename with the name 
// of file generated in Generating TLS certificates
ENVOY_CONFIG=./<filename>
// Quickfeed server domain or ip
// Replace with a domain or ip if you do not want to run locally
DOMAIN="127.0.0.1"
// The filename of a database, if any. 
// If left blank a new database is created
DATABASE=""
// Used to indicate whether or not to re-compile the frontend continously
// Comment out to disable this functionality
DEVELOPMENT=true

```

---
## Generating TLS certificates

If running on Linux (and Mac?), simply run `make envoy-config`. This will generate an Envoy configuration file in `./ci/docker/envoy` in the format `envoy-${DOMAIN}.yaml`, along with certificates for the domain specified in your .envs file.

On Windows you can run `go run .\cmd\envoy\envoy_config_gen.go --tls`.

`NOTE`: Replace `ENVOY_CONFIG=./<filename>` in `.envs` with the name of the file generated in this step.

---

## Compile the frontend

Navigate to `/dev` and run `npm install`, followed by `npx webpack`. Compiling the frontend on your host machine is required prior to building the Docker containers. `TODO: Figure out if it really is` 

The folder containing the source and compiled code will be mounted as a volume in the container. The container will continously re-compile the code as you make changes to it on your host machine.

## Building and running QuickFeed using docker-compose

Start QuickFeed by running `docker-compose up` from the root project folder.

---
## Running QuickFeed from WSL

To run QuickFeed from WSL you might have to forward ports `80` and `443` from your host machine to your WSL container.

### Step 1
First you need to determine the IP address of your WSL container. You can do this by running the `ifconfig` command in WSL. One of the first lines in the output will look similar to the below output:
```
inet 172.27.173.21  netmask 255.255.240.0  broadcast 172.27.175.255
```

In the above case the ip address is `172.27.173.21`.

### Step 2

To forward the ports you need to open a terminal in Windows (might need to run as administrator) and run the following commands, where you replace `conntectaddress` with the ip address you got in step 1:

`netsh interface portproxy add v4tov4 listenport=80 listenaddress=0.0.0.0 connectport=80 connectaddress=172.27.173.21`

`netsh interface portproxy add v4tov4 listenport=443 listenaddress=0.0.0.0 connectport=443 connectaddress=172.27.173.21`

