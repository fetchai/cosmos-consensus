#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOTDIR="${DIR}/../.."


TM_BASELINE_VERSION=$(grep -P "TMBaselineSemVer\s+=\s+\".*\"" ${ROOTDIR}/version/version.go  |  cut -d'=' -f2 | tr -d '" ')

FOOTER=$(sed \
        -e "s/\\\$TMBaselineSemVer\\\$/${TM_BASELINE_VERSION}/g" \
        ${DIR}/footer.md
)

echo "$FOOTER"
