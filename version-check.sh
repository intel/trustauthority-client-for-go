#! /bin/bash

# get current branch version from makefile
version=$(cat tdx-cli/Makefile | grep "VERSION :=" | cut -d '=' -f 2 | tr -d ' ')
# Get version by removing prefix v from version string Ex: v1.0.1
version=${version:1}
echo "version in current branch is - $version"

# get version from latest tag
latest_tag=$(git tag --sort=creatordate | tail -1)
latest_tag_version=$(git show "$latest_tag:tdx-cli/Makefile" | grep "VERSION :=" | cut -d '=' -f 2 | tr -d ' ')
# Get version by removing prefix v from version string Ex: v1.0.1
latest_tag_version=${latest_tag_version:1}
echo "latest tag is - $latest_tag, version in latest tag is $latest_tag_version"

# compare major version and exit if latest branch major version is less than target branch major version
if [ $(echo $version | cut -d '.' -f 1) -lt $(echo $latest_tag_version | cut -d '.' -f 1) ]; then
    echo "version bump required - major version $version must always be higher than or equal to latest tag major version $latest_tag_version"
    exit 1
# if major version of local is equal to major of latest tag version, check minor version
elif [ $(echo $version | cut -d '.' -f 1) -eq $(echo $latest_tag_version | cut -d '.' -f 1) ] && [ $(echo $version | cut -d '.' -f 2) -lt $(echo $latest_tag_version | cut -d '.' -f 2) ]; then
    echo "version bump required - minor version $version must always be equal or higher than latest tag minor version $latest_tag_version"
    exit 1
# if major version of local is equal to major of latest tag version, and minor version of both are equal, then check the patch version
elif [ $(echo $version | cut -d '.' -f 1) -eq $(echo $latest_tag_version | cut -d '.' -f 1) ] && [ $(echo $version | cut -d '.' -f 2) -eq $(echo $latest_tag_version | cut -d '.' -f 2) ] && [ $(echo $version | cut -d '.' -f 3) -le $(echo $latest_tag_version | cut -d '.' -f 3) ]; then
    echo "version bump required - patch version $version must always be high than latest tag patch version $latest_tag_version"
    exit 1
else
    echo "version check passed successfully"
fi

