#!/bin/bash

# This script updates passwords in XML files for specified users and servers

env="$1"
declare -A passwords
passwords=( ["david"]="$2" ["warner"]="$3" )

# Associative array mapping servers to users
declare -A server_users
server_users=(
  ["server1"]="david warner"
  ["server2"]="david"
  ["server3"]="warner"
)

# Iterate over each server
for server in "${!server_users[@]}"; do
  echo "Processing server: $server"
  users="${server_users[$server]}"

  # Iterate over each user in the current server
  for username in $users; do
    if [ -n "${passwords[$username]}" ]; then
      echo "Processing password for $username on $server..."
      new_password="${passwords[$username]}"

      for cluster_dir in apisec invex; do 
        xml_file="$cluster_dir/$env.xml"
        if [ ! -f "$xml_file" ]; then
          echo "Error: File $xml_file does not exist."
          continue
        fi

        echo "Processing $xml_file for user $username"

        encryptionMethod=$(grep -oP "(?<=<alias name=\"aliasPw${username}\" password=\"{)[^:]+(?=:)" "$xml_file") || {
          echo "Error: Failed to extract encryption method for $username in $xml_file"
          continue
        }

        if [[ -z $encryptionMethod ]]; then
          echo "### WARNING ### No encryption method found for $username in $xml_file"
          continue
        fi

        if [[ $encryptionMethod == "AES" ]]; then
          echo "Detected AES encryption method for $username"
          aes_encrypted_password=$(echo "$new_password" | openssl enc -aes-256-cbc -a -salt -pbkdf2 -pass pass:mysecretpass) || {
            echo "Error: AES encryption failed for $username"
            continue
          }
          sed -i "/<alias name=\"aliasPw${username}\"/s|password=\"[^\"]*\"|password=\"{AES:${aes_encrypted_password}}\"|" "$xml_file" || {
            echo "Error: Failed to update AES password in $xml_file for $username"
            continue
          }

        elif [[ $encryptionMethod == "RSA" ]]; then
          echo "Detected RSA encryption method for $username"
          openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
          openssl rsa -pubout -in private_key.pem -out public_key.pem

          rsa_encrypted_password=$(echo -n "$new_password" | openssl pkeyutl -encrypt -pubin -inkey public_key.pem | base64 | tr -d '\n') || {
            echo "Error: RSA encryption failed for $username"
            continue
          }

          sed -i "/<alias name=\"aliasPw${username}\"/s|password=\"[^\"]*\"|password=\"{RSA:${rsa_encrypted_password}}\"|" "$xml_file" || {
            echo "Error: Failed to update RSA password in $xml_file for $username"
            continue
          }

          # Clean up RSA keys
          rm -f private_key.pem public_key.pem
        else
          echo "### WARNING ### Unknown encryption method for $username in $xml_file"
        fi

        echo "Updated password in $xml_file"
      done
    else
      echo "### WARNING ### No new password provided for $username on $server"
    fi
  done
done