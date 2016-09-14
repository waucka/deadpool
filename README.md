# deadpool

deadpool restarts unresponsive EC2 instances.

## Setup

### AWS Credentials

You will need to run the server as an appropriately privileged user.  The privileges you need depend on the monitoring plugins you use.  See policy_template.json for an AWS policy template for an AWS policy that has the needed privileges for most cases.

### Configuration File

See example_config.yaml for reference.  It is fairly extensively commented.  Adjust it to suit your needs, then save it as `/etc/deadpool.yaml`.

### Health Check

To hit the health check endpoint, do this: `curl -H "Authorization: $SECRET_KEY" http://deadpool.example.com/health`.  `$SECRET_KEY` should match the `secret_key` you set in the configuration file.

## Thanks

Many thanks to my employer, [Exosite](https://exosite.com/), which gives its employees the freedom to open-source broadly useful tools like this.
