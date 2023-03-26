# PowerDNS-Admin
A PowerDNS web interface with advanced features.

[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/PowerDNS-Admin/PowerDNS-Admin.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/PowerDNS-Admin/PowerDNS-Admin/context:python)
[![Language grade: JavaScript](https://img.shields.io/lgtm/grade/javascript/g/PowerDNS-Admin/PowerDNS-Admin.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/PowerDNS-Admin/PowerDNS-Admin/context:javascript)

#### Sponsors:
[<img src="powerdnsadmin/static/img/logo_entri.svg" width="30%"/>](https://www.entri.com)

[<button>
 <svg aria-hidden="true" height="16" viewBox="0 0 16 16" version="1.1" width="16" data-view-component="true" class="octicon octicon-heart icon-sponsor color-fg-sponsors mr-2">
  <path d="m8 14.25.345.666a.75.75 0 0 1-.69 0l-.008-.004-.018-.01a7.152 7.152 0 0 1-.31-.17 22.055 22.055 0 0 1-3.434-2.414C2.045 10.731 0 8.35 0 5.5 0 2.836 2.086 1 4.25 1 5.797 1 7.153 1.802 8 3.02 8.847 1.802 10.203 1 11.75 1 13.914 1 16 2.836 16 5.5c0 2.85-2.045 5.231-3.885 6.818a22.066 22.066 0 0 1-3.744 2.584l-.018.01-.006.003h-.002ZM4.25 2.5c-1.336 0-2.75 1.164-2.75 3 0 2.15 1.58 4.144 3.365 5.682A20.58 20.58 0 0 0 8 13.393a20.58 20.58 0 0 0 3.135-2.211C12.92 9.644 14.5 7.65 14.5 5.5c0-1.836-1.414-3-2.75-3-1.373 0-2.609.986-3.029 2.456a.749.749 0 0 1-1.442 0C6.859 3.486 5.623 2.5 4.25 2.5Z"></path>
 </svg>
 <span>Sponsor</span>
</button>](https://github.com/sponsors/pawel-kow?o=esb)


#### Features:
- Multiple domain management
- Domain template
- User management
- User access management based on domain
- User activity logging
- Support Local DB / SAML / LDAP / Active Directory user authentication
- Support Google / Github / Azure / OpenID OAuth
- Support Two-factor authentication (TOTP)
- Dashboard and pdns service statistics
- DynDNS 2 protocol support
- Edit IPv6 PTRs using IPv6 addresses directly (no more editing of literal addresses!)
- Limited API for manipulating zones and records
- Full IDN/Punycode support

## Running PowerDNS-Admin
There are several ways to run PowerDNS-Admin. The easiest way is to use Docker.
If you are looking to install and run PowerDNS-Admin directly onto your system check out the [Wiki](https://github.com/PowerDNS-Admin/PowerDNS-Admin/wiki#installation-guides) for ways to do that.

### Docker
This are two options to run PowerDNS-Admin using Docker.
To get started as quickly as possible try option 1. If you want to make modifications to the configuration option 2 may be cleaner.

#### Option 1: From Docker Hub
The easiest is to just run the latest Docker image from Docker Hub:
```
$ docker run -d \
    -e SECRET_KEY='a-very-secret-key' \
    -v pda-data:/data \
    -p 9191:80 \
    ngoduykhanh/powerdns-admin:latest
```
This creates a volume called `pda-data` to persist the SQLite database with the configuration.

#### Option 2: Using docker-compose
1. Update the configuration   
   Edit the `docker-compose.yml` file to update the database connection string in `SQLALCHEMY_DATABASE_URI`.
   Other environment variables are mentioned in the [legal_envvars](https://github.com/PowerDNS-Admin/PowerDNS-Admin/blob/master/configs/docker_config.py#L5-L46).
   To use the Docker secrets feature it is possible to append `_FILE` to the environment variables and point to a file with the values stored in it.   
   Make sure to set the environment variable `SECRET_KEY` to a long random string (https://flask.palletsprojects.com/en/1.1.x/config/#SECRET_KEY)

2. Start docker container
   ```
   $ docker-compose up
   ```

You can then access PowerDNS-Admin by pointing your browser to http://localhost:9191.

### Development
#### Install on Mac

1. Create virtualenv
2. Install all needed dev libraries:
```commandline
brew install mysql-connector-c
export PATH="/usr/local/opt/mysql-client/bin:$PATH"
brew install Libxmlsec1
pip install -r requirements.txt
brew install node
brew install yarn
change default config to add SQLLite and change bind IP address
export FLASK_APP=run.py
flask db upgrade
yarn install
```


## Screenshots
![dashboard](https://user-images.githubusercontent.com/6447444/44068603-0d2d81f6-9fa5-11e8-83af-14e2ad79e370.png)

## LICENSE
MIT. See [LICENSE](https://github.com/PowerDNS-Admin/PowerDNS-Admin/blob/master/LICENSE)

