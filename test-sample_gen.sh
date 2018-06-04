#!/bin/bash

set -e

./create-local-release-no-tests.sh

USER_ID=$(id -u)

FOLDER_SAMPLE=$(pwd)/_sample-templates
FOLDER_PLUGINS_JARS=$(pwd)/_plugins-jars
rm -rf $FOLDER_SAMPLE $FOLDER_PLUGINS_JARS
mkdir -p $FOLDER_SAMPLE $FOLDER_IMPORT $FOLDER_PLUGINS_JARS

# Put the jars in the plugins folder
echo ---[ Put the jars in the plugins folder ]---
tar -zxvf foilen-extra-plugins.tgz -C $FOLDER_PLUGINS_JARS

# Create sample data
echo ---[ Create sample data ]---
docker run -ti \
  --rm \
  --env PLUGINS_JARS=/plugins \
  --user $USER_ID \
  --volume $FOLDER_SAMPLE:/data \
  --volume $FOLDER_PLUGINS_JARS:/plugins \
  foilen-infra-plugin-app-test-docker:master-SNAPSHOT \
  create-sample \
  /data
