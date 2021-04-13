#!/bin/bash
set -euo pipefail

MAIN_BRANCH="master"
git checkout "${MAIN_BRANCH}"

git fetch
git pull origin "${MAIN_BRANCH}"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOTDIR="${DIR}/.."

read -r -p "Enter new release version (current: $(git describe)): " version
[[ "${version}" =~ ^v([0-9]+\.){2}[0-9]+$ ]] || (echo "invalid version \"${version}\""; exit 1)

if git tag | grep -q "${version}"; then
   echo "Tag \"${version}\" already exists. Please provide a new version or delete existing tag."
   exit 1
fi

# Update TMBaselineSemVer in version.go to match the new version
CURRENT_CORE_VERSION=$(grep -P "TMCoreSemVer\s+=\s+\".*\"" "${ROOTDIR}/version/version.go" |  cut -d'=' -f2 | tr -d '" ') 
echo "Current TMCoreSemVer: ${CURRENT_CORE_VERSION}"
if [ "${CURRENT_CORE_VERSION}" != "${version//v}" ]; then
   read -r -p "Do you want to update TMCoreSemVer to \"${version//v}\" in version/version.go ? [Y/n] " input
   case $input in
      [nN])
   ;;
      *)
      sed -i "/TMCoreSemVer/s/\"${CURRENT_CORE_VERSION}\"/\"${version//v}\"/" "${ROOTDIR}/version/version.go"
      git add "${ROOTDIR}/version/version.go"
      git commit -m "chores: bump TMCoreSemVer to ${version//v}"
      git push origin "${MAIN_BRANCH}"
      echo "Updated TMCoreSemVer to ${version//v} in version/version.go"
   ;;
   esac
fi

git tag -a "${version}" -m "${version}"
git push origin "${version}"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

HEADER=""
read -r -p "Do you want to edit release note header? [y/N] " input
case $input in
    [yY])
    TMP=$(mktemp)
    echo "${HEADER}" > "${TMP}"
    ${EDITOR} "${TMP}"
    HEADER=$(cat "${TMP}")
    rm "${TMP}"
 ;;
    *)
 ;;
esac

FOOTER=$(bash -c "${DIR}/release_notes/gen_footer.sh")
read -r -p "Do you want to edit release note footer? [y/N] " input
case $input in
    [yY])
    TMP=$(mktemp)
    echo "${FOOTER}" > "${TMP}"
    ${EDITOR} "${TMP}"
    FOOTER=$(cat "${TMP}")
    rm "${TMP}"
 ;;
    *)
 ;;
esac

go install github.com/goreleaser/goreleaser@v0.162.0
goreleaser release --rm-dist --release-header <(echo "${HEADER}") --release-footer <(echo "${FOOTER}")
