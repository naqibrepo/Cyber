# LEMP (nginx)

------------------------------------------------------------------
# Step 1 – Installing the Nginx Web Server
```
sudo apt update
sudo apt install nginx
ip addr show
hostname -I 		# public IP address
curl -4 icanhazip.com	#  you're querying the website "icanhazip.com" to retrieve your public IPv4 address
```
------------------------------------------------------------------
# Step 2 — Installing MySQL
```
sudo apt install mysql-server
sudo mysql_secure_installation	#  This script will remove some insecure default settings and lock down access to your database system.

install php8.1-fpm, which stands for “PHP fastCGI process manager”	# Apache has by default but nginx not
```
------------------------------------------------------------------
# Step 3 – Installing PHP
```
sudo apt install php8.1-fpm php-mysql
```
------------------------------------------------------------------
# Step 4 — Configuring Nginx to Use the PHP Processor
```
we can create server blocks (similar to virtual hosts in Apache)	# virtual host is important when we our webserver is hosting multiple site. So, web server can retrieve the data from the specific directory related to the website. /var/www/[your_domain]


/var/www/html		# default directory:
/var/www/your_domain	# directory for one website

sudo mkdir /var/www/your_domain
sudo chown -R $USER:$USER /var/www/your_domain

sudo nano /etc/nginx/sites-available/your_domain	# Config file for our website. Configuration looks something like below:

server {
    listen 80;
    server_name your_domain www.your_domain;
    root /var/www/your_domain;

    index index.html index.htm index.php;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
     }

    location ~ /\.ht {
        deny all;
    }

}


listen — Defines what port Nginx will listen on. In this case, it will listen on port 80, the default port for HTTP.
root — Defines the document root where the files served by this website are stored.
index — Defines in which order Nginx will prioritize index files for this website. It is a common practice to list index.html files with higher precedence than index.php files to allow for quickly setting up a maintenance landing page in PHP applications. You can adjust these settings to better suit your application needs.
server_name — Defines which domain names and/or IP addresses this server block should respond for. Point this directive to your server’s domain name or public IP address.
location / — The first location block includes a try_files directive, which checks for the existence of files or directories matching a URL request. If Nginx cannot find the appropriate resource, it will return a 404 error.
location ~ \.php$ — This location block handles the actual PHP processing by pointing Nginx to the fastcgi-php.conf configuration file and the php8.1-fpm.sock file, which declares what socket is associated with php8.1-fpm.
location ~ /\.ht — The last location block deals with .htaccess files, which Nginx does not process. By adding the deny all directive, if any .htaccess files happen to find their way into the document root, they will not be served to visitors.


sudo ln -s /etc/nginx/sites-available/your_domain /etc/nginx/sites-enabled/
sudo unlink /etc/nginx/sites-enabled/default

# restore
sudo ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/

sudo nginx -t	# check syntax error
sudo systemctl reload nginx

# Create a test html file
nano /var/www/your_domain/index.html
<html>
  <head>
    <title>your_domain website</title>
  </head>
  <body>
    <h1>Hello World!</h1>

    <p>This is the landing page of <strong>your_domain</strong>.</p>
  </body>
</html>

<html>Hello World!</html>	# basic html code


------------------------------------------------------------------
Step 5 –Testing PHP with Nginx

# it returns information about the server. We use it as a php test file.
nano /var/www/your_domain/info.php
<?php
phpinfo();

Note: The above file should be deleted because returning a lot of info

------------------------------------------------------------------
Step 6 — Testing Database Connection from PHP (Optional)
dummy data and query

# We create example_database, add example_user, and give the user all privileges for the database.

CREATE DATABASE example_database;
CREATE USER 'example_user'@'%' IDENTIFIED WITH mysql_native_password BY 'password';
GRANT ALL ON example_database.* TO 'example_user'@'%';

# The example_user creates todo_list table, add contents to it.
mysql -u example_user -p

CREATE TABLE example_database.todo_list (
	item_id INT AUTO_INCREMENT,
	content VARCHAR(255),
	PRIMARY KEY(item_id)
);

INSERT INTO example_database.todo_list (content) VALUES ("My first important item");


# We create php file that connect us to the database:
nano /var/www/your_domain/todo_list.php

# The following PHP script connects to the MySQL database and queries for the content of the todo_list table, exhibiting the results in a list.

----------------------
<?php
$user = "example_user";
$password = "password";
$database = "example_database";
$table = "todo_list";

try {
  $db = new PDO("mysql:host=localhost;dbname=$database", $user, $password);
  echo "<h2>TODO</h2><ol>"; 
  foreach($db->query("SELECT content FROM $table") as $row) {
    echo "<li>" . $row['content'] . "</li>";
  }
  echo "</ol>";
} catch (PDOException $e) {
    print "Error!: " . $e->getMessage() . "<br/>";
    die();
}


---------------------

# better practice:
# remove the database information from the source code, instead, use variables, add the info in another file that is not accessible to the webserver, and reference to that file.

1. create config.php
<?php
return [
    'host' => 'localhost',
    'database' => 'example_database',
    'user' => 'example_user',
    'password' => 'password'
];
?>


2. edit the todo_list.php
<?php
// Include the configuration file
$config = include 'config.php';
$host = $config['host'];
$database = $config['database'];
$user = $config['user'];
$password = $config['password'];
$table = "todo_list";

try {
  $db = new PDO("mysql:host=$host;dbname=$database", $user, $password);
  echo "<h2>TODO</h2><ol>"; 
  foreach($db->query("SELECT content FROM $table") as $row) {
    echo "<li>" . $row['content'] . "</li>";
  }
  echo "</ol>";
} catch (PDOException $e) {
    print "Error!: " . $e->getMessage() . "<br/>";
    die();
}
?>


===============================================================================

# How To Create a Self-Signed SSL Certificate for Nginx in Ubuntu 20.04

------------------------------------------------------------------
# Step 1 — Creating the SSL Certificate
```
# create a self-signed key and certificate pair:
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt

# create a strong Diffie-Hellman (DH) group:
sudo openssl dhparam -out /etc/nginx/dhparam.pem 4096

```

------------------------------------------------------------------
# Step 2 — Configuring Nginx to Use SSL
```
# Creating a Configuration Snippet Pointing to the SSL Key and Certificate
sudo nano /etc/nginx/snippets/self-signed.conf
ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;

# Creating a Configuration Snippet with Strong Encryption Settings
https://cipherlist.eu/			# encryption settings used for popular software
sudo nano /etc/nginx/snippets/ssl-params.conf
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_dhparam /etc/nginx/dhparam.pem; 
ssl_ciphers EECDH+AESGCM:EDH+AESGCM;
ssl_ecdh_curve secp384r1;
ssl_session_timeout  10m;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
# Disable strict transport security for now. You can uncomment the following
# line if you understand the implications.
#add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";


# Adjusting the Nginx Configuration to Use SSL
sudo cp /etc/nginx/sites-available/your_domain /etc/nginx/sites-available/your_domain.bak
sudo nano /etc/nginx/sites-available/your_domain
# edit the below parts in the file to be like:
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    include snippets/self-signed.conf;
    include snippets/ssl-params.conf;
...
...
}
# also add below - listens on port 80 and performs the redirect to HTTPS
server {
    listen 80;
    listen [::]:80;

    server_name your_domain.com www.your_domain.com;

    return 302 https://$server_name$request_uri;
}

------------------------------------------------------------------
# Step 3 — Adjusting the Firewall



------------------------------------------------------------------
# Step 4 — Enabling the Changes in Nginx

# particular setting generates a warning since your self-signed certificate can’t use SSL stapling.
sudo nginx -t		# check for errors

sudo systemctl restart nginx

------------------------------------------------------------------
# Step 5 — Testing Encryption

------------------------------------------------------------------
# Step 6 — Changing to a Permanent Redirect
sudo nano /etc/nginx/sites-available/your_domain
return 301 https://$server_name$request_uri;	# edit 302 to 301


```

