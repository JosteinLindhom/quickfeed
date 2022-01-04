#!/bin/sh

if [ $DEVELOPMENT ]
then
    echo "QuickFeed is set to run in development mode"
    cd dev
    npx webpack &
    cd ..
fi
echo "Starting QuickFeed"
quickfeed -service.url $DOMAIN -database.file $DATABASE