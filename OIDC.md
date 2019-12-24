# OIDC Setup

To use Auth0 with Airflow, we need to set a custom SecurityManager for Flask in `webserver_config.py`.

```
SECURITY_MANAGER_CLASS = AirflowOIDCSecurityManager
```

I tried to use https://github.com/ministryofjustice/fab-oidc as the Security Manager, though I kept getting too many redirects.  fab-oidc is a small wrapper around https://github.com/puiterwijk/flask-oidc.  May need to write our own custom Security Manager or figure out what configuration I have incorrect.

To set the correct values for Auth0, a `client_secrets.json` file is required in the `config` folder.  There is an `client_secrets_example.json` that shows the basic setup (the values can be retrieved from the Auth0 applicaton settings).

Airflow security manager configuration: https://github.com/apache/airflow/blob/8a8e65a374a5d29ef2ceb380915eda26071ea7fe/airflow/www/app.py#L93
flask docs: https://flask-appbuilder.readthedocs.io/en/latest/security.html#your-custom-security
fab-oidc docs: https://github.com/ministryofjustice/fab-oidc
flask-oidc docs: https://flask-oidc.readthedocs.io/en/latest/

# Building + Running the Docker Image

You need to run the docker image with the `fab-oidc` dependency.

```
docker build --rm --build-arg PYTHON_DEPS="fab-oidc>=0.0.9" -t puckel/docker-airflow .
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