# allow-hostname
allow-hostname is a bash script to simplify the access control from dynamic hostnames, typically by the use of a ddns system, by interacting with the host firewall and/or the access control mechanisms available in cloud providers.

## How it works
Every time allow-hostname script is executed, 
- it resolves the hostname set in the variable HOSTNAME
- if aws mode is activated, it allows in the defined security group all traffic to port 22/tcp from the resolved IP address, and keeps track of it using the aws ssm param store.
- if iptables or ufw modes are activated, it allows all from the resolved IP address in the respective firewall, using a comment in the rule to track the hostname rule.
- Uses the respective track method to remove access to any old IP address where the HOSTNAME doesn't resolve anymore.

Typically the script is executed via cron to make the checks periodically and keep this way the rules updated when HOSTNAME's IP changes.

## Requirements
- iptables and ufw modes only require the respective firewall fully operative in the OS.
- aws mode requires the aws client configured to allow write access to the specified security group in the script and to aws ssm param store.  

## Disclaimer
Please make sure to understand how this script works and use at your own risk. When the host system is using a not trusted and properly secured dns for resolving, the usage of the script can lead to security problems. Please treat the HOSTNAME variable as a secret and make it difficult to correlate the dynamic hostname and the hosts where the script is running, to avoid focused dns attacks.  

## Install
Download and edit the script to activate the desired modes and to set the hostname. From there, make it executable and run it manually or via cron.
```
sudo wget https://raw.githubusercontent.com/jmhoms/allow-hostname/main/allow-hostname.bash -O /usr/local/bin/allow-hostname.bash
vi /usr/local/bin/allow-hostname.bash
sudo chmod 700 /usr/local/bin/allow-hostname.bash
sudo echo “*/5 * * * * root /usr/local/bin/allow-hostname.bash 2>&1 | logger -t allow-hostname” > /etc/cron.d/allow-hostname
sudo chown root:root /etc/cron.d/allow-hostname
sudo chmod 644 /etc/cron.d/allow-hostname
```
