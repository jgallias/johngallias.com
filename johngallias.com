# /etc/ngnix/sites-enabled/johngallias.com
#

server {
    listen      80;
    server_name johngallias.com www.johngallias.com;
    return 301 https://johngallias.com$request_uri;
}

server {
    listen 443 ssl;
    server_name johngallias.com www.johngallias.com;

    # Setting up a SSL Cert from Comodo
    # https://gist.github.com/bradmontgomery/6487319
    ssl_certificate /etc/ssl/ssl-bundle.crt;
    ssl_certificate_key /etc/ssl/johngallias.key;

    # Mozilla SSL Generator
    # https://mozilla.github.io/server-side-tls/ssl-config-generator/?server=nginx-1.2.1&openssl=1.0.1e&hsts=yes&profile=modern
    #ssl_session_timeout 1d;
    #ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    # For OwnCloud Compatibilty (Tested with above values, causes subdomain to fail!)
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Diffie-Hellman parameter for DHE ciphersuites, recommended 2048 bits
    # https://weakdh.org
    # openssl dhparam -out dhparams.pem 2048
    ssl_dhparam /etc/ssl/dhparams.pem;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK';
    ssl_prefer_server_ciphers on;

    # OCSP Stapling ---
    # fetch OCSP records from URL in ssl_certificate and cache them
    ssl_stapling on;
    ssl_stapling_verify on;

    ## verify chain of trust of OCSP response using Root CA and Intermediate certs
    ssl_trusted_certificate /etc/ssl/trusted.crt;

    # Setting up HSTS in nginx
    # https://scotthelme.co.uk/setting-up-hsts-in-nginx/
    # "try removing the 'always' directive if you are on a lower version of nginx."
    # HSTS Preloading
    # https://scotthelme.co.uk/hsts-preloading/
    add_header Strict-Transport-Security "max-age=31536000; includeSubdomains; preload";

    # HPKP: HTTP Public Key Pinning
	  # https://scotthelme.co.uk/hpkp-http-public-key-pinning/
	  #add_header Public-Key-Pins "pin-sha256='IITFcB2mWf17aVldaK7tBMcAqaVZmnxAFp9/artnMQg='; \
    #pin-sha256='x/F2WxM+Qpq49yp9olVCmmXkFyRfCajp15MTo5fG6as='; \
    #pin-sha256='ucXpS34/Ifp38F//GQJUTIO81kPH2qYtS8s+6LTshCw='; \
    #max-age=10; includeSubdomains; report-uri='https://report-uri.io/report/f5e374bca6feba77b6f7fffe49c0d11a'";

    # Content Security Policy - An Introduction
    # https://scotthelme.co.uk/content-security-policy-an-introduction/
    # CSP Generator:
    # https://report-uri.io/home/generate
    # NOTE: Generator will say to use child-src instead of frame-src, but this breaks recaptcha
    # Tested: doesn't hurt to include both frame-src and child-src, but frame-src required
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.google.com https://www.google-analytics.com https://www.gstatic.com https://fonts.googleapis.com https://apis.google.com https://www.google.com/recaptcha https://www.gstatic.com/recaptcha; img-src 'self' https://ssl.gstatic.com/ https://secure.gravatar.com/; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://www.gstatic.com; font-src 'self' https://fonts.gstatic.com https://www.gstatic.com; child-src 'self' https://www.google.com/recaptcha/ https://api-b339ce13.duosecurity.com; frame-src 'self' https://www.google.com/recaptcha/ https://api-b339ce13.duosecurity.com;";

	  # X-Frame-Options
	  # https://scotthelme.co.uk/hardening-your-http-response-headers/#x-frame-options
    # "try removing the 'always' directive if you are on a lower version of nginx."
    add_header X-Frame-Options "SAMEORIGIN";

    # X-Xss-Protection
    # https://scotthelme.co.uk/hardening-your-http-response-headers/#x-xss-protection
    # "try removing the 'always' directive if you are on a lower version of nginx."
    add_header X-Xss-Protection "1; mode=block";

    # X-Content-Type-Options
    # https://scotthelme.co.uk/hardening-your-http-response-headers/#x-content-type-options
    # "try removing the 'always' directive if you are on a lower version of nginx."
    add_header X-Content-Type-Options "nosniff";

    # Removing Headers - Server
    # https://scotthelme.co.uk/hardening-your-http-response-headers/#server
    server_tokens off;


    root /var/www;
    index index.php index.html index.htm;

    location / {
        try_files $uri $uri/ /index.php?q=$uri&$args;
    }

    location ~ \.php$ {
        try_files $uri =404;
        #fastcgi_pass unix:/var/run/php5-fpm.sock;
        fastcgi_pass 127.0.0.1:9000;
	fastcgi_index index.php;
        #include fastcgi_params;
	include fastcgi.conf;
    }

    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }

    location ~ /\. {
        deny all;
    }

    location ~* /(?:uploads|files)/.*\.php$ {
        deny all;
    }

}
