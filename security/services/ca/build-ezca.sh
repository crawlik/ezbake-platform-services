#!/bin/bash

#   Copyright (C) 2013-2015 Computer Sciences Corporation
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


set -e -x

REPO_ROOT="$(pwd)"
BUILDROOT="${REPO_ROOT}/BUILD"
PACKAGEROOT=$(mktemp -d)
APP_ROOT="${PACKAGEROOT}/opt/ezca"
mkdir -p "${BUILDROOT}" && cd "${BUILDROOT}"

PYENVV=2.7.6
PYENV=ezca2.1
BRANCH=master

PYBIN=/opt/python-2.7.6/bin

PYINSTALLER_REPO="https://github.com/infochimps-forks/pyinstaller.git;/opt/pyinstaller;master"
REPOS=(${PYINSTALLER_REPO})

function copy_to_build() {
    local src="$1"
    local dest="${2}/$(basename "${src}")"

    echo "Copying ${src}/ to ${dest}"
	rsync -r "${src}"/ "${dest}"
}

function install_package() {
    local name="$1"
    local dir="$2"

    echo "${name} not installed. Installing now"
    pushd "${dir}"
    python setup.py clean -a
    sudo $PYBIN/pip install -r requirements.txt
    pyenv rehash
    popd
}

function install_maven() {
    local dir="$1"
    echo "Running maven package of ${dir}"
    (cd "${dir}" && mvn clean package -DskipTests) || (echo "failed to package ${dir}"; exit 1)
}

echo "cloning the repos from git"
for x in ${REPOS[@]}; do
    x=(${x[0]//;/ })
    repo="${x[0]}"
    dir="${x[1]}"
    branch="${x[2]}"

    if [ -d "${dir}" ]; then
        echo "${dir} already checked out"
        #(cd "${dir}" && git pull) 
    else
        echo "cloning ${repo} into ${dir}"
        git clone "${repo}" "${dir}"
    fi

    echo "cheking out ${branch}"
    (cd "${dir}" && git checkout "${branch}")
done

# Copy local resources to the build directory
copy_to_build "${REPO_ROOT}/ezpz" "${BUILDROOT}"
copy_to_build "${REPO_ROOT}/ezpersist" "${BUILDROOT}"
copy_to_build "${REPO_ROOT}/service" "${BUILDROOT}"
copy_to_build "${REPO_ROOT}/ezca-bootstrap" "${BUILDROOT}"

eval "$(pyenv init -)"
pyenv shell system

$PYBIN/pip list | grep 'setuptools' || curl -L https://bootstrap.pypa.io/get-pip.py | python
$PYBIN/pip list | grep 'zope.interface' || sudo $PYBIN/pip install zope.interface

# Install main ezbake libs
sudo $PYBIN/pip install -r "${REPO_ROOT}/requirements.txt"

# Install EzCA packages
install_package "ezpz" "ezpz"
install_package "ezpersist" "ezpersist"
install_package ezca "service"

install_maven "ezca-bootstrap"

echo "Building with pyinstaller"

LD_LIBRARY_PATH=/root/.pyenv/versions/${PYENV}/lib pyinstaller -y "service/bin/ezcaservice.py" --hidden-import=pkg_resources

echo "Packaging"
mkdir -p "${PACKAGEROOT}"/etc
mkdir -p ${APP_ROOT}/{bin,config,app}

# Copy app files
cp -r dist/ezcaservice "${APP_ROOT}/app/"
cp ezca-bootstrap/target/ezca-bootstrap-*-jar-with-dependencies.jar "${APP_ROOT}/bin/ezca-bootstrap"
cp "${REPO_ROOT}"/scripts/bin/* "${APP_ROOT}/bin/"
cat > "${APP_ROOT}/config/ezca.properties" <<'EOF'
ezbake.shared.secret.environment.variable=EZBAKE_ENCRYPTION_SECRET
EOF

# Copy system config files
cp -r "${REPO_ROOT}"/scripts/etc/. "${PACKAGEROOT}/etc"

sudo useradd ezca || true

# Update file permissions
chmod -R o-rwx "${APP_ROOT}"
chmod +x "${APP_ROOT}/bin/init"
chmod +x "${APP_ROOT}/bin/start"
chmod +x "${APP_ROOT}/bin/stop"
sudo chown -R root:root "${PACKAGEROOT}/etc"
sudo chown -R root:root "${PACKAGEROOT}/opt"
sudo chown -R ezca:ezca "${PACKAGEROOT}/opt/ezca"

# change back to the repo root
cd "${REPO_ROOT}"

#$(date +"%Y%m%d%H%M") \
sudo fpm -f -s dir -t rpm \
    -n EzCA -v 2.1 --iteration 1 \
    -C "${PACKAGEROOT}" \
    --rpm-use-file-permissions \
    --rpm-auto-add-directories \
    --rpm-auto-add-exclude-directories /etc/logrotate.d \
    opt etc

sudo rm -rf "${PACKAGEROOT}"
