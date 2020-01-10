# OIDC Setup

To use Auth0 with Airflow, we need to set a custom SecurityManager for Flask in `webserver_config.py`.

```
SECURITY_MANAGER_CLASS = AirflowOIDCSecurityManager
```

To set the correct values for Auth0, a `client_secrets.json` file is required in the `config` folder.  There is an `client_secrets_example.json` that shows the basic setup (the values can be retrieved from the Auth0 applicaton settings).

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
docker build --rm --build-arg PYTHON_DEPS="authlib>=0.13 six>=1.13.0" -t puckel/docker-airflow .
```

Run the docker image inline so you can see the logs

```
docker run -p 8080:8080 puckel/docker-airflow webserver
```

# Flask Logs

I set the logging level to `DEBUG` in `airflow.cfg`.

```
fab_logging_level = DEBUG
```