build: docker_run_local

clean:
	-find . -type f -name "*.pyc" -delete
	-find . -type d -name "__pycache__" -delete

requirements:
	pip install -r requirements.txt

FLAKE8 := flake8 .
LOCUST := \
	locust \
		--locustfile ./locustfile.py \
		--clients=$$LOCUST_NUM_CLIENTS \
		--hatch-rate=$$LOCUST_HATCH_RATE \
		--no-web \
		--only-summary

PYTEST := \
	pytest tests \
		--capture=no \
		--driver PhantomJS \
		--driver-path /usr/bin/phantomjs $(pytest_args) \
		$(pytest_args)

SET_LOCAL_LOCUST_ENV_VARS := \
	export DIRECTORY_API_URL=http://www.api.dev.playground.directory.uktrade.io/; \
	export DIRECTORY_SSO_URL=http://www.sso.dev.playground.directory.uktrade.io/; \
	export DIRECTORY_UI_URL=http://www.dev.playground.directory.uktrade.io/; \
	export LOCUST_NUM_CLIENTS=5; \
	export LOCUST_HATCH_RATE=5; \
	export SSO_USER_ID=120

SET_LOCAL_LOCUST_PROPER_LOAD := \
	export LOCUST_NUM_CLIENTS=150; \
	export LOCUST_HATCH_RATE=150; \
	export LOCUST_TIMEOUT=120

# TODO: set these to docker network names when docker works fully
SET_LOCAL_PYTEST_ENV_VARS := \
	export DIRECTORY_API_URL=http://www.api.dev.playground.directory.uktrade.io/; \
	export DIRECTORY_SSO_URL=http://www.sso.dev.playground.directory.uktrade.io/; \
	export DIRECTORY_UI_URL=http://www.dev.playground.directory.uktrade.io/; \
	export SSO_USER_ID=120

# make test_load is the command for actual load test running
# unlike make test, this will run load tests with the proper load
# we're testing for
test_load:
	$(SET_LOCAL_LOCUST_ENV_VARS); \
	$(SET_LOCAL_LOCUST_PROPER_LOAD); \
	$(LOCUST)

test_integration:
	$(SET_LOCAL_PYTEST_ENV_VARS); \
	$(PYTEST)

test_linting:
	$(FLAKE8)

# make test is what CircleCI runs. Load tests on CircleCI are run at
# 1 client per second, just to check the load tests themselves work.
test: test_linting test_integration
	$(SET_LOCAL_LOCUST_ENV_VARS); \
	$(LOCUST)

DOCKER_REMOVE_ALL := \
	docker ps -a | \
	grep -e directorytests_ | \
	awk '{print $$1 }' | \
	xargs -I {} docker rm -f {}

docker_remove_all:
	$(DOCKER_REMOVE_ALL)

DOCKER_SET_DIRECTORY_API_ENV_VARS := \
	export DIRECTORY_API_PORT=8000; \
	export DIRECTORY_API_DEBUG=true; \
	export DIRECTORY_API_SECRET_KEY=test; \
	export DIRECTORY_API_UI_SECRET=test; \
	export DIRECTORY_API_POSTGRES_USER=test; \
	export DIRECTORY_API_POSTGRES_PASSWORD=test; \
	export DIRECTORY_API_POSTGRES_DB=directory_test; \
    export DIRECTORY_API_SQS_ENROLMENT_QUEUE_NAME=directory-enrolment-test; \
    export DIRECTORY_API_SQS_INVALID_ENROLMENT_QUEUE_NAME=directory-enrolment-test-invalid; \
	export DIRECTORY_API_DATABASE_URL=postgres://test:test@postgres:5432/directory_test

DOCKER_SET_DIRECTORY_UI_ENV_VARS := \
	export DIRECTORY_UI_API_CLIENT_API_KEY=test; \
	export DIRECTORY_UI_API_CLIENT_BASE_URL=http://directory_api_webserver:8000; \
	export DIRECTORY_UI_PORT=8001; \
	export DIRECTORY_UI_SECRET_KEY=test; \
	export DIRECTORY_UI_DEBUG=true

DOCKER_SET_DIRECTORY_TESTS_ENV_VARS := \
	export DIRECTORY_TESTS_DIRECTORY_API_URL=http://directory_api_webserver:8000; \
	export DIRECTORY_TESTS_DIRECTORY_SSO_URL=http://www.sso.dev.playground.directory.uktrade.io/; \
	export DIRECTORY_TESTS_DIRECTORY_UI_URL=http://directory_ui_webserver:8001; \
	export DIRECTORY_TESTS_LOCUST_HATCH_RATE=150; \
	export DIRECTORY_TESTS_LOCUST_NUM_CLIENTS=150; \
	export DIRECTORY_TESTS_API_CLIENT_KEY=$$API_CLIENT_KEY

DOCKER_COMPOSE_CREATE_ENVS := python ./docker/env_writer.py ./docker/env.json
DOCKER_COMPOSE_REMOVE_AND_PULL := docker-compose rm -f && docker-compose pull

docker_run: docker_remove_all
	$(DOCKER_SET_DIRECTORY_TESTS_ENV_VARS) && \
	$(DOCKER_COMPOSE_CREATE_ENVS) && \
	$(DOCKER_COMPOSE_REMOVE_AND_PULL) && \
	docker-compose run directory_tests

DOCKER_COMPOSE_CREATE_ENVS_LOCAL := ./docker/create_envs.sh
DOCKER_COMPOSE_REMOVE_AND_PULL_LOCAL := docker-compose -f docker-compose.yml -f docker-compose-local.yml rm -f && docker-compose -f docker-compose.yml -f docker-compose-local.yml pull

docker_run_local: docker_remove_all
	$(DOCKER_SET_DIRECTORY_TESTS_ENV_VARS) && \
	$(DOCKER_SET_DIRECTORY_API_ENV_VARS) && \
	$(DOCKER_SET_DIRECTORY_UI_ENV_VARS) && \
	$(DOCKER_COMPOSE_CREATE_ENVS_LOCAL) && \
	$(DOCKER_COMPOSE_REMOVE_AND_PULL_LOCAL) && \
	docker-compose -f docker-compose-local.yml build && \
	docker-compose -f docker-compose-local.yml run directory_tests_local

docker_shell: docker_remove_all
	$(DOCKER_SET_DIRECTORY_TESTS_ENV_VARS) && \
	$(DOCKER_SET_DIRECTORY_API_ENV_VARS) && \
	$(DOCKER_SET_DIRECTORY_UI_ENV_VARS) && \
	$(DOCKER_COMPOSE_CREATE_ENVS_LOCAL) && \
	$(DOCKER_COMPOSE_REMOVE_AND_PULL_LOCAL) && \
	docker-compose -f docker-compose-local.yml build && \
	docker-compose -f docker-compose-local.yml run directory_tests_local sh

.PHONY: build clean requirements test docker_remove_all docker_run_local docker_run docker_run_with_local
