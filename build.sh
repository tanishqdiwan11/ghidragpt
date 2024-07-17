#!/bin/bash

set -e

GHIDRA_PATH=""
GHIDRA_INSTALL_DIR=/ghidra

SCRIPT_DIR=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
cd "$SCRIPT_DIR"

GRADLE_VERSION=8.3
GRADLE_CHECKSUM=591855b517fc635b9e04de1d05d5e76ada3f89f5fc76f87978d1b245b4f69225

function install_dependencies() {
    echo "[+] Installing dependencies" >&2

    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux dependencies
        if command -v pacman &> /dev/null; then
            sudo pacman -S --noconfirm jdk17-openjdk wget unzip
        elif command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y openjdk-17-jdk wget unzip
        else
            echo "Unsupported package manager. Please install dependencies manually."
            exit 1
        fi
    else
        echo "Unsupported OS. Please install dependencies manually."
        exit 1
    fi

    if ! command -v gradle &> /dev/null
    then
        echo "[+] Installing Gradle" >&2
        wget -q -O gradle.zip "https://downloads.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip"
        echo "${GRADLE_CHECKSUM} gradle.zip" | sha256sum --check -
        unzip gradle.zip
        sudo mv gradle-${GRADLE_VERSION} /opt/gradle
        sudo ln -s /opt/gradle/bin/gradle /usr/bin/gradle
        rm gradle.zip
    fi
}

function clean() {
    echo "[+] Cleaning build directories" >&2
    rm -rf ghidragpt/build || true
    rm -rf ghidragpt/dist || true
    rm -rf ghidragpt/lib || true
}

function build() {
    echo "[+] Building the ghidragpt Plugin" >&2

    export GHIDRA_INSTALL_DIR="$GHIDRA_PATH"
    pushd ghidragpt > /dev/null 2>&1
    gradle

    cp dist/*.zip "$GHIDRA_PATH/Extensions/Ghidra"
    echo "[+] Built and copied the plugin to $GHIDRA_PATH/Extensions/Ghidra/"
    popd > /dev/null 2>&1
}

function usage() {
    echo "Usage: $0 [OPTION...] [CMD]" >&2
    echo "  -p PATH        PATH to local Ghidra installation" >&2
    echo "  -c             Clean" >&2
    echo "  -h             Show this help" >&2
}

while getopts "p:ch" opt; do
    case "$opt" in
        p)
            GHIDRA_PATH=$(realpath ${OPTARG})
            ;;
        c) 
            clean
            exit 0
            ;;
        h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $opt" >&2
            usage
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

if [ -z $GHIDRA_PATH ] || [ ! -d $GHIDRA_PATH ] ; then
    echo "GHIDRA_PATH is not configured or is not a directory"
    exit 1
fi

install_dependencies
build

exit 0
