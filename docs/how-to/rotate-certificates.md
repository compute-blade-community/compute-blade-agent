# Rotate the API certificates

With `listen.authenticated: true` the agent creates a CA, a server certificate and a client certificate on its first
start. The CA is valid for 10 years, the server and client certificates for 1 year. The agent doesn't renew them:
once a certificate expires, `bladectl` can't connect anymore. Rotate them before that.

Check when they expire:

```bash
sudo openssl x509 -enddate -noout -in /etc/compute-blade-agent/server.pem
sudo awk '/client-certificate-data/ {print $2; exit}' /root/.config/bladectl/config.yaml | base64 -d |
  openssl x509 -enddate -noout
```

## Renew the server and client certificates

Keeping the CA means the new client certificate works with every client that trusts the CA already.

```bash
sudo rm /etc/compute-blade-agent/server.pem /etc/compute-blade-agent/server-key.pem
sudo rm /root/.config/bladectl/config.yaml
sudo systemctl restart compute-blade-agent
```

The agent writes a new server certificate and a new bladectl config with a new client certificate. Copy the client
credentials to your workstation again, as in [Manage a rack from your workstation](../tutorials/manage-a-rack.md).

## Replace the CA as well

Do this if the CA key may have leaked. Every client certificate signed by the old CA stops working.

```bash
sudo rm /etc/compute-blade-agent/{ca,ca-key,server,server-key}.pem
sudo rm /root/.config/bladectl/config.yaml
sudo systemctl restart compute-blade-agent
```

The server certificate lists the blade's IP addresses at the time it was created. If the blade got a new IP address
and you connect by IP, renew the server certificate too.
