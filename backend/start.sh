#!/bin/sh
set -e
alembic upgrade head
exec supervisord -c supervisord.conf
