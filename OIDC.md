# OIDC Setup

To use Auth0 with Airflow, we need to set a custom SecurityManager for Flask in `webserver_config.py`.

```
SECURITY_MANAGER_CLASS = AirflowOIDCSecurityManager
```

To set the correct values for Auth0, several configuration values need to be passed as environment variables.  There is an example below that shows the basic setup (the values can be retrieved from the Auth0 applicaton settings).

Airflow security manager configuration: https://github.com/apache/airflow/blob/8a8e65a374a5d29ef2ceb380915eda26071ea7fe/airflow/www/app.py#L93
flask docs: https://flask-appbuilder.readthedocs.io/en/latest/security.html#your-custom-security
Auth0 python docs: https://auth0.com/docs/quickstart/webapp/python/01-login

# Auth0

Auth0 also needs to be configured with the following settings:

```
// Allowed Callback URLs
http://localhost:8080/oidc_callback

// Allowed Logout URLs
http://localhost:8080
```

# Building + Running the Docker Image

You need to run the docker image with the following dependencies:

```
docker build --rm --build-arg PYTHON_DEPS="authlib>=0.13 six>=1.13.0 azure-storage-blob==2.1.0" -t joemcbride/docker-airflow .
```

Run the docker image inline so you can see the logs

```
docker run -p 8080:8080 \
-e AUTH0_CLIENT_ID='' \
-e AUTH0_CLIENT_SECRET='' \
-e AUTH0_API_BASE_URL='https://{tenant}.auth0.com' \
-e AUTH0_ACCESS_TOKEN_URL='https://{tenant}.auth0.com/oauth/token' \
-e AUTH0_AUTHORIZE_URL='https://{tenant}.auth0.com/authorize' \
-e AUTH0_SCOPE='openid profile email' \
-e AUTH0_LOGIN_REDIRECT_URL='http://localhost:8080/oidc_callback' \
joemcbride/docker-airflow webserver
```

Here's and example `docker-compose.yml` file:

```
version: '3'
services:
  airflow:
    image: "joemcbride/docker-airflow"
    ports:
      - "8080:8080"
    volumes:
      - ./dags:/usr/local/airflow/dags
      - ./files:/usr/local/airflow/files
    environment:
      LOAD_EX: n
      AUTH0_CLIENT_ID: ${AUTH0_CLIENT_ID}
      AUTH0_CLIENT_SECRET: ${AUTH0_CLIENT_SECRET}
      AUTH0_API_BASE_URL: https://${AUTH0_TENANT}.auth0.com
      AUTH0_ACCESS_TOKEN_URL: https://${AUTH0_TENANT}.auth0.com/oauth/token
      AUTH0_AUTHORIZE_URL: https://${AUTH0_TENANT}.auth0.com/authorize
      AUTH0_SCOPE: openid profile email
      AUTH0_LOGIN_REDIRECT_URL: http://localhost:8080/oidc_callback
```

and an associated `.env` file:

```
AUTH0_CLIENT_ID=...
AUTH0_CLIENT_SECRET=...
AUTH0_TENANT=...
```

# Flask Logs

I set the logging level to `DEBUG` in `airflow.cfg`.

```
fab_logging_level = DEBUG
```
