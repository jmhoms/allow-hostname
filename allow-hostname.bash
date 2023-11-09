#!/usr/bin/env bash
#
# allow-hostname is a bash script to simplify the access control
# from dynamic hostnames, typically by the use of a ddns system,
# by interacting with the host firewall and/or the access control
# mechanisms available in cloud providers.
#
# Documentation and the latest version can be found at
# https://www.github.com/jmhoms/allow-hostname
#
# Copyright (C) 2021 Josep M Homs
#
# This program is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of
# the License, or any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see http://www.gnu.org/licenses/
#
#
# ---- Version : 1.2.0
#
# ---- Parameters
#
# Define the host name to allow
HOSTNAME=your.dynamic.hostname.com
# Set to yes to enable IPTABLES Mode
IPTMODE=no
# Set to yes to enable UFW Mode
UFWMODE=no
# Set to yes to enable NFT Mode
NFTMODE=no
# Set to yes to enable AWS Mode
AWSMODE=no
# Specify the Security Group ID if AWS Mode is enabled
AWSSGID=sg-xxxxxxxxxxxxxxxxx
#
# ---- Do not modify code below ----

function is_ip_valid()
{
  # store parameter as variable
  local ip=$1
  # init as error the code to return
  local code=1
  # if the parameter consists of 4 numbers from 1 to 3 digits, separated by dots
  if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    # create an array with the 4 numbers by replacing the dots by spaces (default IFS)
    iparr=(`echo $ip | tr '.' ' '`)
    # if the 4 numbers are less or equal to 255 assign 0 to return code, meaning no error
    if [[ ${iparr[0]} -le 255 && ${iparr[1]} -le 255 && ${iparr[2]} -le 255 && ${iparr[3]} -le 255 ]]; then
      code=0
    fi
  fi
  # return the code
  return $code
}

# IPTABLES MODE
# If mode is active
if [[ $IPTMODE = "yes" ]]; then
  # Check for root privileges, otherwise quit
  if [[ $EUID -eq 0 ]]; then
    # Check that iptables is present, otherwise quit
    /usr/sbin/iptables -V
    if [[ $? -eq 0 ]]; then
      # resolve hostname
      new_ip=$(host $HOSTNAME | head -n1 | cut -f4 -d ' ')
      if is_ip_valid $new_ip; then
        # check for an existant ip in the iptables rules for this hostname
        old_ip=$(/usr/sbin/iptables -L INPUT -n --line-numbers | grep $HOSTNAME | head -n1 | tr -s ' ' | cut -f4 -d ' ')
        # update the rules if the hostname is resolving to a new ip
        if [ "$new_ip" != "$old_ip" ] ; then
          # if a rule for a previous ip exist, delete it
          if [ -n "$old_ip" ] ; then
            # check the rule number
            rule_num=$(/usr/sbin/iptables -L INPUT -n --line-numbers | grep $HOSTNAME | head -n1 | tr -s ' ' | cut -f1 -d ' ')
            # and delete the rule
            /usr/sbin/iptables -D INPUT $rule_num
          fi
          # add a rule with the new ip and the hostname as a comment
          /usr/sbin/iptables -A INPUT -p tcp -s $new_ip -m conntrack --ctstate NEW -j ACCEPT -m comment --comment "$HOSTNAME"
          echo "allow-hostname: iptables rule added to allow everything from IP address $new_ip"
        fi
      else
         echo "allow-hostname: hostname specified does not resolve. Quitting..."
      fi
    else
      echo "allow-hostname: this script requires that iptables is present to use the iptables mode. Quitting..."
    fi
  else
    echo "allow-hostname: this script must be run with root privileges when using the iptables mode. Quitting..."
  fi
fi

# UFW MODE
# If mode is active
if [[ $UFWMODE = "yes" ]]; then
  # Check for root privileges, otherwise quit
  if [[ $EUID -eq 0 ]]; then
    # Check if ufw is active, otherwise quit
    /usr/sbin/ufw status | grep -qw active
    if [[ $? -eq 0 ]]; then
      # resolve hostname
      new_ip=$(host $HOSTNAME | head -n1 | cut -f4 -d ' ')
      if is_ip_valid $new_ip; then
        # check for an existant ip in the ufw rules for this hostname
        old_ip=$(/usr/sbin/ufw status | grep $HOSTNAME | head -n1 | tr -s ' ' | cut -f3 -d ' ')
        # update the rules if the hostname is resolving to a new ip
        if [ "$new_ip" != "$old_ip" ] ; then
          # if a rule for a previous ip exist, delete it
          if [ -n "$old_ip" ] ; then
            /usr/sbin/ufw delete allow from $old_ip to any
          fi
          # add a rule with the new ip and the hostname as a comment
          /usr/sbin/ufw allow from $new_ip to any comment $HOSTNAME
          echo "allow-hostname: ufw rule added to allow everything from IP address $new_ip"
        fi
      else
        echo "allow-hostname: hostname specified does not resolve. Quitting..."
      fi
    else
      echo "allow-hostname: this script requires that ufw is installed and active to use the ufw mode. Quitting..."
    fi
  else
    echo "allow-hostname: this script must be run with root privileges when using the ufw mode. Quitting..."
  fi
fi

# AWS MODE
# If mode is active
if [[ $AWSMODE = "yes" ]]; then
  # if aws cli is available
  awscheck=$(aws --version 2>&1)
  if [[ $? -eq 0 ]]; then
    # and jq is available
    jqcheck=$(jq --version 2>&1)
    if [[ $? -eq 0 ]]; then
      # resolve hostname
      new_ip=$(host $HOSTNAME | head -n1 | cut -f4 -d ' ')
      if is_ip_valid $new_ip; then
        # get current ip
        old_ip=$(aws ssm get-parameter --name "/allow-hostname/ip" |& jq -r ".Parameter.Value" 2>&1)
        if [ "$new_ip" != "$old_ip" ]; then
          if is_ip_valid $old_ip; then
            # remove the existing ingress permission
            old_cidr="${old_ip}"/32
            echo "allow-hostname: removing ingress permission for ${old_cidr} in security group ${AWSSGID}"
            removing=$(aws ec2 revoke-security-group-ingress \
              --group-id "${AWSSGID}" \
              --protocol tcp \
              --port 22 \
              --cidr "${old_cidr}" 2>&1)
            if [[ $? -ne 0 ]]; then
              echo "allow-hostname: unexpected error while trying to remove the ingress permission, supervision required."
            fi
          fi
          # authorize the new ip
          new_cidr="${new_ip}"/32
          echo "allow-hostname: adding ingress permission for ${new_cidr} in security group ${AWSSGID}"
          perm='[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges":'
          perm+='[{"CidrIp": "'"${new_cidr}"'", "Description": "Allow Hostname Script"}]}]'
          adding=$(aws ec2 authorize-security-group-ingress \
            --group-id "${AWSSGID}" \
            --ip-permissions "${perm}" 2>&1)
          # if sg is successfully updated or already contains the desired rule
          if [[ $? -eq 0 || $adding =~ "InvalidPermission.Duplicate" ]]; then
            if [[ $adding =~ "InvalidPermission.Duplicate" ]]; then
              echo "allow-hostname: ingress permission for ${new_cidr} ALREADY EXISTS in security group ${AWSSGID}"
            fi
            # store the current ip in aws ssm param store
            echo "allow-hostname: saving IP address ${new_cidr} in AWS SSM Param Store..."
            store=$(aws ssm put-parameter --name "/allow-hostname/ip" --type "String" --value "${new_ip}" --overwrite 2>&1)
            if [[ $? -ne 0 ]]; then
              echo "allow-hostname: unexpected error while trying to store the new IP address in AWS SSM param store."
            fi
          else
            echo "allow-hostname: unexpected error while trying to add ingress permission. Quitting..."
          fi
        fi
      else
        echo "allow-hostname: hostname does not resolve. Quitting..."
      fi
    else
      echo "allow-hostname: jq is not available. Quitting..."
    fi
  else
    echo "allow-hostname: AWS client not available. Quitting..."
  fi
fi

# NFT MODE
# If mode is active
if [[ $NFTMODE = "yes" ]]; then
  # Check for root privileges, otherwise quit
  if [[ $EUID -eq 0 ]]; then
    # Create a table if it does not exist
    nft list tables | grep -qw "inet filter" || nft add table inet filter
    # Create a chain for allow-hostname rules if it doesn't exist
    nft list table inet filter | grep -qw allow-hostname || nft add chain inet filter allow-hostname
    # Ensure that there's a jump rule from the input chain to allow-hostname chain
    nft list ruleset 2>/dev/null | grep -qw 'jump allow-hostname' || nft insert rule inet filter input jump allow-hostname
    # Resolve hostname
    new_ip=$(host $HOSTNAME | head -n1 | cut -f4 -d ' ')
    if is_ip_valid $new_ip; then
      # Check for an existing IP in the nft rules for this hostname
      old_ip=$(nft list ruleset 2>/dev/null | grep "comment \"$HOSTNAME\"" | sed -e 's/^.*saddr \([^ ]*\).*$/\1/')
      # Update the rules if the hostname is resolving to a new IP
      if [ "$new_ip" != "$old_ip" ] ; then
        # If a rule for a previous IP exists, delete it
        if [ -n "$old_ip" ] ; then
          nft flush chain inet filter allow-hostname
        fi
        # Add a rule with the new IP and the hostname as a comment
        nft add rule inet filter allow-hostname ip saddr $new_ip accept comment \"$HOSTNAME\"
        echo "allow-hostname: nft rule added to allow everything from IP address $new_ip"
      fi
    else
      echo "allow-hostname: hostname specified does not resolve. Quitting..."
    fi
  else
    echo "allow-hostname: this script must be run with root privileges when using the nft mode. Quitting..."
  fi
fi
