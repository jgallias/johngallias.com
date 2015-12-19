# /etc/nginx/sites-available/owncloud.johngallias.com
# https://doc.owncloud.org/server/8.2/admin_manual/installation/nginx_configuration.html

upstream php-handler {
  server 127.0.0.1:9000;
  #server unix:/var/run/php5-fpm.sock;
}

server {
  listen 80;
  server_name owncloud.johngallias.com;
  # enforce https
  return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name owncloud.johngallias.com;

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

  # ownCloud
  # https://doc.owncloud.org/server/8.2/admin_manual/installation/nginx_configuration.html
  add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload;";
  add_header X-Content-Type-Options nosniff;
  add_header X-Frame-Options "SAMEORIGIN";
  add_header X-XSS-Protection "1; mode=block";
  add_header X-Robots-Tag none;

    # Path to the root of your installation
  root /var/www/owncloud/;
  # set max upload size
  client_max_body_size 10G;
  fastcgi_buffers 64 4K;

  # Disable gzip to avoid the removal of the ETag header
  gzip off;

  # Uncomment if your server is build with the ngx_pagespeed module
  # This module is currently not supported.
  #pagespeed off;

  index index.php;
  error_page 403 /core/templates/403.php;
  error_page 404 /core/templates/404.php;

  rewrite ^/.well-known/carddav /remote.php/carddav/ permanent;
  rewrite ^/.well-known/caldav /remote.php/caldav/ permanent;

  # The following 2 rules are only needed for the user_webfinger app.
  # Uncomment it if you're planning to use this app.
  #rewrite ^/.well-known/host-meta /public.php?service=host-meta last;
  #rewrite ^/.well-known/host-meta.json /public.php?service=host-meta-json last;

  location = /robots.txt {
    allow all;
    log_not_found off;
    access_log off;
  }

  location ~ ^/(build|tests|config|lib|3rdparty|templates|data)/ {
    deny all;
  }

  location ~ ^/(?:\.|autotest|occ|issue|indie|db_|console) {
    deny all;
  }

  location / {

    rewrite ^/remote/(.*) /remote.php last;

    rewrite ^(/core/doc/[^\/]+/)$ $1/index.html;

    try_files $uri $uri/ /index.php;
  }

  location ~ \.php(?:$|/) {
    fastcgi_split_path_info ^(.+\.php)(/.+)$;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_param PATH_INFO $fastcgi_path_info;
    fastcgi_param HTTPS on;
    fastcgi_param modHeadersAvailable true; #Avoid sending the security headers twice
    fastcgi_pass php-handler;
    fastcgi_intercept_errors on;
  }

  # Adding the cache control header for js and css files
  # Make sure it is BELOW the location ~ \.php(?:$|/) { block
  location ~* \.(?:css|js)$ {
    add_header Cache-Control "public, max-age=7200";
    # Add headers to serve security related headers
    add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload;";
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Robots-Tag none;
    # Optional: Don't log access to assets
    access_log off;
  }

  # Optional: Don't log access to other assets
  location ~* \.(?:jpg|jpeg|gif|bmp|ico|png|swf)$ {
    access_log off;
  }
}
