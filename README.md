# Xray-script
> This is a shell script to install Xray and configure it
## Nginx + VLESS + WebSocket + WARP
 - **Nginx**: for reverse proxy
 - **WARP**: used to proxy custom requests
## Quick Start
 1. Buy a domain.
 2. Apply for a SSL certificate(*.key and *.pem).
 3. Rename the certificate to `cert.key` and `cert.pem`.
 4. Run the shell script.
    ```shell
    bash -c "$(curl -L https://raw.githubusercontent.com/th1nk-er/Xray-script/main/install.sh)"
    ```
## Screenshot
![menu](./resources/menu.jpg)