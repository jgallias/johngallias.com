# /etc/ngnix/sites-enabled/johngallias.com

server {
    listen      80;
    server_name johngallias.com www.johngallias.com;
    
    # https://www.digitalocean.com/community/tutorials/how-to-secure-nginx-with-let-s-encrypt-on-ubuntu-14-04?comment=42611
    
    location /.well-known/acme-challenge {
        root /var/www/letsencrypt;
    }
    
    location / {
        return 301 https://johngallias.com$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name johngallias.com www.johngallias.com;
    
    # Let's Encrypt
    # 
    # https://www.nginx.com/blog/free-certificates-lets-encrypt-and-nginx/
    # https://community.letsencrypt.org/t/error-during-installation-dns-problem-query-timed-out-looking-up-mx/12688
    # https://www.digitalocean.com/community/tutorials/how-to-secure-nginx-with-let-s-encrypt-on-ubuntu-14-04?comment=42611
    #
    ssl_certificate /etc/letsencrypt/live/johngallias.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/johngallias.com/privkey.pem;

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
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";

    # Content Security Policy - An Introduction
    # https://scotthelme.co.uk/content-security-policy-an-introduction/
    #
    # CSP Generator:
    # https://report-uri.io/home/generate
    # NOTE: Generator will say to use child-src instead of frame-src, but this breaks recaptcha
    # Tested: doesn't hurt to include both frame-src and child-src, but frame-src required for recaptcha
    #
    # script-src must have 'unsafe-eval' for WordPress Media Library features!
    # http://www.html5rocks.com/en/tutorials/security/content-security-policy/
    # 
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google-analytics.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://www.gstatic.com; font-src 'self' data: https://fonts.gstatic.com https://www.gstatic.com; img-src 'self' data: https://ps.w.org/ https://ssl.gstatic.com/ https://secure.gravatar.com/ https://www.google-analytics.com; child-src 'self' https://api-b339ce13.duosecurity.com; report-uri https://johngallias.report-uri.io/r/default/csp/enforce";

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
