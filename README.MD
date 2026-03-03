# Env Extract
Securely extract environment variables (or any sensitive data) from an automated deployment setup.  
This project provides an easy to deploy, drop-in controller that exposes an endpoint returning a structured, password-protected ZIP file. By default, it packages environment variables, but you can include anything you want.  
  
# How It Works
The endpoint returns a ZIP file with the following structure:  
```bash
 env.zip
 ├── data.zip
 │   ├── data.txt
 ├── password.txt
```
  
`env.zip`  
Publicly accessible from the endpoint.  
  
`data.zip`  
Password-protected archive containing the actual data (data.txt).  
  
`password.txt`  
Contains the password for data.zip, encrypted using RSA.  
  
So even though `env.zip` is publicly downloadable, only someone with the private RSA key can access the protected contents.  

# RSA Key Setup
The repository includes a sample priv.pem, which is password-protected.  
You should generate your own key pair for production use.  
  
Generate private key:  
`openssl genrsa -aes128 -out priv.pem 2048`  
  
Generate public key (to put in the controller):  
`openssl rsa -in priv.pem -pubout -out pub.pem`  
  
Decrypt the private key (used for decrypting `password.txt` and obtaing password for `data.zip`):  
`openssl pkey -in priv.pem`  
