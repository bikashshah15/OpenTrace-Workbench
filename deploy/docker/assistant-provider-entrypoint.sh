#!/bin/sh
set -eu
exec python -P -m services.assistant_provider.server
