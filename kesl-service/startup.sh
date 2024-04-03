#!/bin/sh -u

readonly LOG_PATH=/var/log/kaspersky/kesl-service
readonly KESL_SETUP_ANSWERS=kesl-setup.conf
readonly KESL_SETUP_COMMAND="/opt/kaspersky/kesl/bin/kesl-setup.pl --autoinstall=${KESL_SETUP_ANSWERS}"
readonly KESL_START_COMMAND="/etc/init.d/kesl start"
readonly KLNAGENT_SETUP_ANSWERS=klnagent.conf
readonly KLNAGENT_SETUP_COMMAND=/opt/kaspersky/klnagent64/lib/bin/setup/postinstall.pl
readonly KLNAGENT_BIN_NAME=klnagent
readonly KLNAGENT_START_COMMAND=/opt/kaspersky/klnagent64/sbin/${KLNAGENT_BIN_NAME}

function kesl_autoanswers() {
cat <<EOF>> ${KESL_SETUP_ANSWERS}
EULA_AGREED=yes
PRIVACY_POLICY_AGREED=Yes
USE_KSN=yes
UPDATE_EXECUTE=no
INSTALL_LICENSE=
CONFIGURE_SELINUX=yes
GROUP_CLEAN=no
EOF
}

configure_klnagent()
{
    echo "    start ${KLNAGENT_SETUP_COMMAND}"
    KLAUTOANSWERS=${PWD}/klnagent.conf ${KLNAGENT_SETUP_COMMAND} >${LOG_PATH}/klnagent.setup.log 2>&1
    touch /.klnagent-configured
}

configure_kesl()
{
    if [ -f ${KESL_SETUP_ANSWERS} ]; then
        echo "    old ${KESL_SETUP_ANSWERS} found, delete"
        rm ${KESL_SETUP_ANSWERS}
    fi
    kesl_autoanswers
    touch /var/opt/kaspersky/kesl/private/.containerenv
    rm -f /opt/kaspersky/kesl/bin/fanotify-checker
    echo "    start ${KESL_SETUP_COMMAND}"
    ${KESL_SETUP_COMMAND} >${LOG_PATH}/kesl.setup.log 2>&1
    touch /.kesl-configured
}

run_klnagent()
{
    if ! /usr/bin/pkill -0 ${KLNAGENT_BIN_NAME} 1>/dev/null 2>&1; then
        echo "    run ${KLNAGENT_START_COMMAND}"
        ${KLNAGENT_START_COMMAND}
    else
        echo "    klnagent is already running"
    fi
}

Main()
{
    echo "create service dir's"
    mkdir -p ${LOG_PATH}
    mkdir -p /var/log/kaspersky/kesl
    mkdir -p /var/log/kaspersky/kesl-user
    mkdir -p /var/log/kaspersky/klnagent64
    mkdir -p /var/opt/kaspersky/kesl/private

    echo "update storage.conf"
    sed -i 's/driver = "overlay"/driver = "vfs"/g' /etc/containers/storage.conf

    echo "klnagent:"
    if [ -f 'klnagent.conf' ]; then
        echo '    klnagent.conf found, configure klnagent'
        if [ ! -f /.klnagent-configured ]; then
            configure_klnagent
        else
            echo "    klnagent is already configured"
        fi
        run_klnagent
    else
        echo "    klnagent.conf not found, klnagent disabled"
    fi

    echo "kesl:"
    if [ ! -f /.kesl-configured ]; then
        echo "    configure kesl"
        configure_kesl
    else
        echo "    kesl already configured, run ${KESL_START_COMMAND}"
        ${KESL_START_COMMAND} >${LOG_PATH}/kesl.setup.log 2>&1
    fi
}

Main
