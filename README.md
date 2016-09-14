# deadpool

deadpool restarts unresponsive EC2 instances.

## Setup

### AWS Credentials

You will need to run the server as an appropriately privileged user.  The privileges you need depend on the monitoring plugins you use.  See policy_template.json for an AWS policy template for an AWS policy that has the needed privileges for most cases.

### Configuration File

See example_config.yaml for reference.  It is fairly extensively commented.  Adjust it to suit your needs, then save it as `/etc/deadpool.yaml`.

### Running

If you have your configuration file saved as `/etc/deadpool.yaml`, then just run `deadpool`.  If not, then run `deadpool --config /path/to/config/file`.  You can also run with `--dryrun` to prevent it from making changes to EC2 instances.

### Health Check

To hit the health check endpoint, do this: `curl -H "Authorization: $SECRET_KEY" http://deadpool.example.com/health`.  `$SECRET_KEY` should match the `secret_key` you set in the configuration file.

## Building

deadpool uses [glide](https://glide.sh/) to wrangle dependencies.  Install it first.

To install dependencies, just run `glide install`.

To build, run `make` (or `make linux|osx|windows` to build for just one platform).

## Thanks

Many thanks to my employer, [Exosite](https://exosite.com/), which gives its employees the freedom to open-source broadly useful tools like this.
