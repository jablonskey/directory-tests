# -*- coding: utf-8 -*-
"""Paver configuration file."""
import multiprocessing

from paver.easy import *
from paver.setuputils import setup

setup(
    name="behave-browserstack",
    version="0.1.0",
    author="BrowserStack",
    author_email="support@browserstack.com",
    description="Behave Integration with BrowserStack",
    license="MIT",
    keywords="parallel selenium with browserstack",
    url="https://github.com/browserstack/lettuce-browserstack",
    packages=['features']
)


def run_behave_test(feature: str, task_id: int = 0):
    sh("TASK_ID={} "
       "behave -k --format progress3 --no-logcapture --tags=-wip --tags=-skip "
       "--tags=~fixme features/{}.feature"
       .format(task_id, feature))


@task
@consume_nargs(1)
def run(args):
    """Run single, local and parallel test using different config."""
    jobs = []
    for i in range(6):
        p = multiprocessing.Process(
            target=run_behave_test, args=("home-page", i))
        jobs.append(p)
        p.start()


@task
def test():
    """Run all tests"""
    sh("paver run parallel")
